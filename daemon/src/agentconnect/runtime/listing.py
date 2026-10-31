"""The owner's listing: publish, door renewal, withdraw and status
(SPEC 6.6.1, 13.2; docs/discovery.md).

One listing per runtime, for one (directory, name). Publishing is the
human's decision (the local API's human-only routes call :meth:`preview`
and :meth:`publish`); everything after it runs without anyone:

* **Doors.** A door is an HPKE key pair the core generates, registered at
  the relay for this instance's mailbox. Its private key is kept in the
  daemon's encrypted database (and in memory as an ``agentconnect_core.Door``,
  which zeroizes it when dropped) and deleted an hour after the door
  expires, once every knock it could have received has lapsed. A door the
  relay may hold is never forgotten: until the relay confirms it closed
  (``door_not_open`` or success), its row stays, ``closing``, without its key.
* **Renewal.** At half a door's lifetime the discovery worker registers a
  fresh door and publishes the listing again, re-signed by the core with
  only ``door``, ``seq`` and ``issued_at`` changed (``Listing.renew``), so
  a renewal can't change what the human approved. The old door stays
  registered until it expires. A renewal that keeps failing for an hour,
  or a door that expires before a renewal lands, raises ``listing_stale``.
  Only ``token_revoked``, ``bad_token`` and ``name_held`` stop renewing.
* **Withdraw.** Either token may withdraw (it only reduces exposure, SPEC
  13.2.3): every door is closed at the relay first, the keys are deleted at
  once, then the signed withdrawal goes to the directory.

A failed publish puts the listing back exactly as it was before the attempt
(``restore_state``): a withdrawn listing stays withdrawn.

Every step is recorded before the next one starts, so a crash anywhere
resumes from the database: a door ``registering`` is registered again
(the relay's "already exists" counts as done), signed bytes in ``pending``
are posted again byte for byte (idempotent at the directory).

``seq`` is ``max(max_signed_seq + 1, now)`` and ``max_signed_seq`` is never
lowered, so a ``seq`` is never reused, not even after a lost answer.

What a directory answers is untrusted: its codes are mapped onto the set
this daemon knows (``agentconnect.directory_client``), its owner state onto
the SPEC's states, and its ``detail`` is cleaned before a person sees it.
Logs carry event types and reason codes only: no directory, name, door id
or domain (SPEC 8.3, docs/discovery.md).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import agentconnect_core as ac
from agentconnect import log
from agentconnect.backoff import Backoff
from agentconnect.config import DirectoryConfig
from agentconnect.directory_client import (
    DirectoryClient,
    DirectoryError,
    clean_detail,
    owner_state,
)
from agentconnect.ownerfile import Fetcher, OwnerFileFetcher
from agentconnect.relay import RelayError, b64
from agentconnect.runtime.engine import Engine, canonical
from agentconnect.runtime.errors import ApiError
from agentconnect.store import Store

LOG = log.get("agentconnect.listing")

TOKEN_WARNING_SECS = 14 * 86_400  # SPEC 13.2.1: warn 14 days before the token expires
MIN_TOKEN_LEFT_SECS = 7200  # no renewal with less token life left
STALE_AFTER_SECS = 3600  # a renewal or withdrawal failing this long is reported
WITHDRAW_GIVE_UP_SECS = 7 * 86_400  # past every door's life: stop retrying the withdrawal
DOOR_WARNING_SECS = 86_400  # a door this close to expiry while a republish waits
RETRY_BASE_SECS = 60
RETRY_CAP_SECS = 3600
CLOSE_RETRY_SECS = 300
EXPIRY_SLACK_SECS = 3600  # a door the relay found too long is retried this much shorter
MAX_IDLE_PASSES = 3  # passes in a row with work due at once before the worker pauses

#: The card file's fields: the listing's text (``ListingContent``). An Agent
#: Card's other fields (its interfaces, signatures, extensions) are not text
#: the human writes; the core adds what a listing needs.
CONTENT_FIELDS = frozenset(
    {
        "name",
        "description",
        "version",
        "provider",
        "capabilities",
        "defaultInputModes",
        "defaultOutputModes",
        "skills",
    }
)
LIVE = frozenset({"publishing", "published", "stale"})
# States that hold the runtime's one listing (D2): another can't be published.
HOLDING = LIVE | {"withdrawing"}
#: ``withdrawn_locally``: a forced withdrawal; the directory may still list it.
WITHDRAWABLE = HOLDING | {"expired", "withdraw_failed", "withdrawn_locally"}
#: What ``force`` may end: a withdrawal the directory hasn't taken.
FORCEABLE = frozenset({"withdrawing", "withdraw_failed"})
PENDING_DOOR = frozenset({"registering", "registered"})
OPEN_DOOR = frozenset({"current", "retiring"})
#: SPEC 6.6.1/13.2: the refusals of a renewal that stop renewing. Any other
#: refusal is retried (with a fresh door and signature) and reported.
STOP_RENEWING = frozenset({"token_revoked", "bad_token", "name_held", "unknown_key"})
#: Relay answers to a door registration that say the relay doesn't hold it.
NOT_REGISTERED = frozenset({"bad_request", "quota_exceeded"})
#: The directory's refusals (directory/README.md) and the status the local
#: API answers them with; any other refusal is ``502 directory``.
REFUSAL_STATUS = {
    "name_held": 409,
    "bad_token": 403,
    "token_revoked": 403,
    "unknown_key": 403,
    "bad_signature": 403,
    "wrong_identity": 403,
    "owner_revoked": 403,
    "wrong_relay": 400,
    "wrong_directory": 400,
    "bad_door": 400,
    "stale_ts": 400,
    "bad_listing": 400,
    "unknown_directory": 400,
    "too_large": 413,
}


def _warning(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _due(at: int | None, now: int) -> bool:
    return at is None or at <= now


def _error(code: str, at: int) -> str:
    return json.dumps({"code": code, "at": at})


@dataclass(frozen=True)
class Draft:
    """A checked publish request: what the human is shown and approves."""

    entry: DirectoryConfig
    name: str
    token: bytes  # the ListingToken, canonical
    token_info: dict[str, Any]
    content: bytes  # the canonical ListingContent
    owner_domain: str | None

    @property
    def sha256(self) -> str:
        """What the human approves: everything that will be signed except the
        door, ``seq`` and ``issued_at``, which publish chooses."""
        approved = {
            "content": json.loads(self.content),
            "directory": self.entry.host,
            "name": self.name,
            "owner_domain": self.owner_domain,
            "token": json.loads(self.token),
        }
        return hashlib.sha256(canonical(approved)).hexdigest()


class ListingManager:
    """The runtime's listing and its doors (one :class:`Engine`)."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._lock = asyncio.Lock()  # one publish, withdraw or worker pass at a time
        self._wake = asyncio.Event()
        options = engine.options
        self._fetcher: Fetcher = options.owner_fetcher or OwnerFileFetcher()
        # door_id -> its key pair: what the owner opens knocks with.
        self._doors: dict[str, ac.Door] = {}
        # door_id -> (next close attempt, attempts) for doors the relay
        # hasn't confirmed closed; after a restart they are tried at once.
        self._close_retry: dict[str, tuple[int, int]] = {}
        self._load_doors()

    # -- plumbing -------------------------------------------------------------

    @property
    def _store(self) -> Store:
        return self._engine.store

    def _now(self) -> int:
        return self._engine.now()

    def _lifetime(self) -> int:
        seam = self._engine.options.door_lifetime_secs
        return seam if seam is not None else self._engine.config.listing_door_lifetime_secs

    def _client(self, row: dict[str, Any]) -> DirectoryClient:
        entry = self._engine.config.directory(str(row["directory"]))
        if entry is None:
            raise DirectoryError("unknown_directory", 400, "the directory is no longer configured")
        return DirectoryClient(entry, transport=self._engine.options.directory_transport)

    def _refresh(self, row: dict[str, Any]) -> dict[str, Any]:
        fresh = self._store.listing(row["directory"], row["name"])
        if fresh is None:  # pragma: no cover - rows are never deleted
            msg = "listing row vanished"
            raise RuntimeError(msg)
        return fresh

    def _door_row(self, door_id: str) -> dict[str, Any] | None:
        return next((d for d in self._store.doors() if d["door_id"] == door_id), None)

    def _load_doors(self) -> None:
        """The door keys from the database, once. A key that doesn't load
        (the core checks the key pair) is dropped and its door closed by the
        worker; it is logged without its id."""
        for door_id, secret in self._store.door_secrets():
            try:
                door = ac.Door.from_secret_bytes(secret)
            except (ac.AgentConnectError, ac.CoreError):
                LOG.warning("door_key_unreadable")
                self._store.drop_door_secret(door_id, "closing")
                continue
            self._doors[door_id] = door

    def door(self, door_id: str) -> ac.Door | None:
        """The key pair of one of this runtime's doors, while it is kept."""
        return self._doors.get(door_id)

    async def _commit(
        self, effects: Callable[[], None], events: list[tuple[str, str, dict[str, Any]]]
    ) -> None:
        """``effects`` and the events they raise, in one transaction; the
        adapter hears of the events once it commits. Each event's id comes
        from its cause, so a repeat after a crash is the same event."""

        async def body() -> str:
            effects()
            for kind, cause, data in events:
                await self._engine.emit(None, kind, cause=cause, **data)
            return ""

        await self._engine._apply("listing", body)

    # -- the human's publish ----------------------------------------------------

    def _draft(self, body: dict[str, Any]) -> Draft:
        directory, card, token = body.get("directory"), body.get("card"), body.get("token")
        owner_domain = body.get("owner_domain")
        if not isinstance(directory, str):
            raise ApiError(400, "bad_request", "directory must be a string")
        if not isinstance(card, dict) or not isinstance(token, dict):
            raise ApiError(400, "bad_request", "card and token must be JSON objects")
        if owner_domain is not None and not isinstance(owner_domain, str):
            raise ApiError(400, "bad_request", "owner_domain must be a string")
        entry = self._engine.config.directory(directory)
        if entry is None:
            msg = "that directory is not configured: add a [[directory]] table with its keys"
            raise ApiError(400, "unknown_directory", msg)
        now = self._now()
        token_bytes = canonical(token)
        try:
            info = ac.verify_listing_token(token_bytes, entry.host, list(entry.keys), now)
        except ac.AgentConnectError as e:
            raise _token_error(e) from None
        name = str(info["name"])
        pinned = info["owner_domain"]
        if owner_domain is not None and pinned is not None and owner_domain != pinned:
            msg = f"the token pins the owner domain {pinned}"
            raise ApiError(400, "bad_request", msg)
        domain = pinned if pinned is not None else owner_domain
        try:
            ac.check_token_binding(token_bytes, entry.host, name, self._engine.me, domain)
        except ac.AgentConnectError:
            msg = (
                "the token is for another identity: the operator issues it for the identity "
                "`agentconnect status` shows"
            )
            raise ApiError(403, "token_not_for_identity", msg) from None
        extra = sorted(set(card) - CONTENT_FIELDS)
        if extra:
            msg = f"the card file holds the listing's text only; remove: {', '.join(extra)}"
            raise ApiError(400, "bad_card", msg)
        try:
            content = ac.canonical_listing_content(canonical(card))
            # A dry run of the signature: the owner-domain and provider rules
            # are checked now, before a door is registered.
            ac.sign_listing_content(
                content,
                self._engine.identity,
                directory=entry.host,
                relay=self._engine.config.relay_host,
                seq=1,
                issued_at=now,
                token_json=token_bytes,
                owner_domain=domain,
            )
        except ac.AgentConnectError as e:
            raise ApiError(400, "bad_card", str(e)) from None
        return Draft(entry, name, token_bytes, info, content, domain)

    def _single(self, draft: Draft) -> None:
        """D2: one listing per runtime. Another one must be withdrawn first."""
        for row in self._store.listings():
            same = (row["directory"], row["name"]) == (draft.entry.host, draft.name)
            if not same and row["state"] in HOLDING:
                msg = "this runtime already has a listing; withdraw it first"
                raise ApiError(409, "listing_exists", msg)

    def _warnings(self, draft: Draft) -> list[dict[str, str]]:
        warnings = []
        groups = len([g for g in self._store.groups() if g.status == "active"])
        if groups:
            warnings.append(
                _warning(
                    "identity_in_groups",
                    f"This identity is a member of {groups} group(s). A listed identity is "
                    "public: anyone can tell that a member with it, in any group, is the "
                    "listed agent. A dedicated identity for listing is safer.",
                )
            )
        if int(draft.token_info["expires_at"]) - self._now() < TOKEN_WARNING_SECS:
            warnings.append(
                _warning(
                    "token_expires_soon",
                    "The listing token expires within 14 days; ask the operator for a new one.",
                )
            )
        return warnings

    async def _owner_file_warning(self, draft: Draft) -> dict[str, str] | None:
        """Whether the owner domain already vouches for this identity in this
        listing, from this daemon's own fetch of its owner file."""
        domain = str(draft.owner_domain)
        fetched = await self._fetcher.fetch(domain)
        result = "failed"
        if fetched.data is not None:
            result = ac.owner_fetch_result(
                fetched.data, self._engine.me, draft.entry.host, draft.name
            )["result"]
        if result == "vouches":
            return None
        if result == "failed":
            return _warning(
                "owner_file_unreachable",
                f"{domain}/.well-known/agentconnect.json could not be fetched or read; until "
                "it lists the entry below, the owner shows as not verified.",
            )
        return _warning(
            "owner_file_missing_identity",
            f"{domain}/.well-known/agentconnect.json doesn't vouch for this identity in this "
            "listing; add the entry below.",
        )

    async def preview(self, body: dict[str, Any]) -> dict[str, Any]:
        """What :meth:`publish` would sign, for the human to check: nothing
        is registered, signed or sent (other than the owner-file fetch)."""
        draft = self._draft(body)
        self._single(draft)
        warnings = self._warnings(draft)
        entry = None
        if draft.owner_domain is not None:
            entry = {
                "identity": self._engine.me,
                "fingerprint": self._engine.identity.fingerprint,
                "listings": [f"{draft.entry.host}/a/{draft.name}"],
            }
            warning = await self._owner_file_warning(draft)
            if warning is not None:
                warnings.append(warning)
        info = draft.token_info
        return {
            "directory": draft.entry.host,
            "name": draft.name,
            "identity": self._engine.me,
            "fingerprint": self._engine.identity.fingerprint,
            "content": json.loads(draft.content),
            "content_sha256": draft.sha256,
            "owner_domain": draft.owner_domain,
            "token": {
                "token_id": b64(info["token_id"]),
                "issued_at": int(info["issued_at"]),
                "expires_at": int(info["expires_at"]),
                "key_id": b64(info["key_id"]),
            },
            "owner_file_entry": entry,
            "warnings": warnings,
        }

    async def publish(self, body: dict[str, Any]) -> dict[str, Any]:
        """The human's publish: register a fresh door, sign, post. A
        directory that doesn't answer is retried by the worker with the same
        bytes (``retrying``); a refusal raises with the directory's code."""
        draft = self._draft(body)
        sha = body.get("content_sha256")
        if not isinstance(sha, str):
            raise ApiError(400, "bad_request", "content_sha256 must be a string")
        if sha != draft.sha256:
            msg = "the card, the token or the directory changed since it was shown; preview again"
            raise ApiError(409, "card_changed", msg)
        async with self._lock:
            self._single(draft)
            row = await self._begin(draft)
            outcome = await self._round(row, interactive=True)
            row = self._refresh(row)
        self._wake.set()
        doors = self._store.doors(row["directory"], row["name"])
        door = next((d for d in reversed(doors) if d["state"] in ("current", *PENDING_DOOR)), None)
        retrying = outcome == "retrying"
        return {
            "directory": row["directory"],
            "name": row["name"],
            "url": _url(row),
            "seq": int(row["max_signed_seq"] if retrying else row["seq"]),
            "state": row["state"],
            "door_expires_at": None if door is None else int(door["expires_at"]),
            "renews_at": row["next_renewal_at"],
            "token_expires_at": int(row["token_expires_at"]),
            "owner_domain": row["owner_domain"],
            "owner_state": row["owner_state"],
            "warnings": self._warnings(draft),
            "retrying": retrying,
        }

    async def _begin(self, draft: Draft) -> dict[str, Any]:
        """Record the approved text and token as ``publishing``, with the
        state to go back to if this publish fails; a door still waiting from
        an earlier attempt is closed."""
        host, name, now = draft.entry.host, draft.name, self._now()
        prev = self._store.listing(host, name)
        stale_doors = [d for d in self._store.doors(host, name) if d["state"] in PENDING_DOOR]
        token = draft.token.decode()
        restore_state, restore_renewal_at = "refused", None
        if prev is not None and prev["state"] == "publishing":  # a republish over a retry
            restore_state, restore_renewal_at = prev["restore_state"], prev["restore_renewal_at"]
        elif prev is not None:
            restore_state, restore_renewal_at = prev["state"], prev["next_renewal_at"]
        row = {
            **(prev or {}),
            "directory": host,
            "name": name,
            "state": "publishing",
            "content": draft.content.decode(),
            "token": token,
            "token_expires_at": int(draft.token_info["expires_at"]),
            "owner_domain": draft.owner_domain,
            "pending": None,
            "pending_door": None,
            "next_renewal_at": None,
            "retry_at": None,
            "attempts": 0,
            "failing_since": None,
            "last_error": None,
            "token_warned": 0 if prev is None or prev["token"] != token else prev["token_warned"],
            "restore_state": restore_state,
            "restore_renewal_at": restore_renewal_at,
            "created_at": now if prev is None else prev["created_at"],
            "updated_at": now,
        }
        with self._store.tx():
            self._store.put_listing(row)
        for d in stale_doors:
            await self._close_door(d)
        return self._refresh(row)

    # -- doors --------------------------------------------------------------------

    def _pending_door(self, row: dict[str, Any]) -> dict[str, Any] | None:
        if row["pending_door"] is not None:
            door = self._door_row(str(row["pending_door"]))
            if door is not None and str(door["door_id"]) in self._doors:
                return door
            # Signed for a door that is gone: sign again for a fresh one.
            host, name = row["directory"], row["name"]
            self._store.update_listing(host, name, pending=None, pending_door=None)
            row["pending"] = row["pending_door"] = None
        doors = self._store.doors(row["directory"], row["name"])
        return next(
            (d for d in doors if d["state"] in PENDING_DOOR and str(d["door_id"]) in self._doors),
            None,
        )

    def _new_door(self, row: dict[str, Any], expires_at: int | None = None) -> dict[str, Any]:
        """A fresh door, recorded (``registering``, with its key) before the
        relay hears of it."""
        now = self._now()
        if expires_at is None:
            expires_at = min(now + self._lifetime(), int(row["token_expires_at"]))
        door = self._engine.client.generate_door(expires_at)
        door_id = b64(door.id)
        with self._store.tx():
            self._store.add_door(
                door_id=door_id,
                directory=row["directory"],
                name=row["name"],
                secret=door.to_secret_bytes(),
                expires_at=expires_at,
                now=now,
            )
        self._doors[door_id] = door
        found = self._door_row(door_id)
        if found is None:  # pragma: no cover - just inserted
            msg = "door row vanished"
            raise RuntimeError(msg)
        return found

    def _drop_door(self, door_id: str) -> None:
        """Delete a door's key and row: the relay doesn't hold it, or it is over."""
        self._doors.pop(door_id, None)
        self._store.delete_door(door_id)

    def _closing(self, door_id: str) -> None:
        """The key goes at once; the row stays until the relay confirms."""
        self._doors.pop(door_id, None)
        self._store.drop_door_secret(door_id, "closing")

    async def _close_door(self, door: dict[str, Any]) -> bool:
        """Close a door at the relay. Its key is deleted at once, whatever the
        relay says. Only success or ``door_not_open`` (unknown, expired or
        closed already) counts as closed; any other answer (``auth_failed``
        for a skewed clock, no answer) leaves it ``closing``, and the worker
        tries again with a fresh signature."""
        door_id = str(door["door_id"])
        self._closing(door_id)
        try:
            await self._engine.rest.close_door(door_id)
            closed = True
        except RelayError as e:
            closed = e.code == "door_not_open"
        if closed:
            self._store.delete_door(door_id)
            self._close_retry.pop(door_id, None)
        else:
            # Tried again after a backoff (5 min doubling to an hour), not on
            # every pass.
            _, attempts = self._close_retry.get(door_id, (0, 0))
            delay = min(RETRY_CAP_SECS, CLOSE_RETRY_SECS * 2 ** min(attempts, 16))
            self._close_retry[door_id] = (self._now() + delay, attempts + 1)
        return closed

    def _close_due(self, door: dict[str, Any], now: int) -> bool:
        """Whether a ``closing`` door's next close attempt is due."""
        due, _ = self._close_retry.get(str(door["door_id"]), (now, 0))
        return str(door["state"]) != "closing" or due <= now

    async def _free_door_slot(self, keep: str, row: dict[str, Any]) -> None:
        """The relay holds at most 4 open doors per mailbox: close the doors
        no listing uses, or else the oldest retiring one."""
        doors = [d for d in self._store.doors() if d["door_id"] != keep]
        unused = [d for d in doors if d["state"] in (*PENDING_DOOR, "closing")]
        if not unused:
            retiring = [
                d
                for d in self._store.doors(row["directory"], row["name"])
                if d["state"] == "retiring"
            ]
            unused = sorted(retiring, key=lambda d: int(d["expires_at"]))[:1]
        for d in unused:
            await self._close_door(d)

    async def _register(self, row: dict[str, Any], door: dict[str, Any]) -> dict[str, Any]:
        """Register a door at the relay. "Already exists" means an earlier
        attempt got through (the id is ours and not yet public)."""
        shortened = freed = False
        while True:
            try:
                await self._engine.rest.create_door(str(door["door_id"]), int(door["expires_at"]))
            except RelayError as e:
                if e.code == "bad_request" and "already exists" in e.detail:
                    pass
                elif e.code == "bad_request" and "expires_at" in e.detail and not shortened:
                    # The relay's clock is behind ours: ask for an hour less.
                    shortened = True
                    self._drop_door(str(door["door_id"]))
                    door = self._new_door(row, int(door["expires_at"]) - EXPIRY_SLACK_SECS)
                    continue
                elif e.code == "quota_exceeded" and not freed:
                    freed = True
                    await self._free_door_slot(str(door["door_id"]), row)
                    continue
                else:
                    raise
            self._engine.failpoints.hit("door.after_register")
            self._store.update_door(str(door["door_id"]), state="registered")
            door["state"] = "registered"
            return door

    # -- one round: door, signature, post ---------------------------------------

    def _sign(self, row: dict[str, Any], door: dict[str, Any]) -> ac.Listing:
        now = self._now()
        seq = max(int(row["max_signed_seq"]) + 1, now)
        key = self._doors[str(door["door_id"])]
        if row["state"] == "publishing":
            return ac.sign_listing_content(
                str(row["content"]).encode(),
                self._engine.identity,
                directory=str(row["directory"]),
                relay=self._engine.config.relay_host,
                seq=seq,
                issued_at=now,
                token_json=str(row["token"]).encode(),
                door=key,
                owner_domain=row["owner_domain"],
            )
        # A renewal: the human's listing, re-signed with only the door, seq
        # and issued_at changed (SPEC 6.6.1, 13.2.2).
        previous = ac.verify_listing(bytes(row["published"]))
        return previous.renew(self._engine.identity, seq, max(now, previous.issued_at), key)

    async def _round(self, row: dict[str, Any], *, interactive: bool) -> str:
        """Drive one publish or renewal as far as it goes now: ``published``,
        ``retrying`` (the worker goes on later), ``refused`` or ``waiting``."""
        door = await self._door_for(row)
        if door is None:
            return "waiting"
        if door["state"] == "registering":
            registered = await self._registered(row, door, interactive=interactive)
            if registered is None:
                return "retrying"
            door = registered
        row = self._refresh(row)
        if row["pending"] is None:
            signed = self._sign(row, door)
            self._store.update_listing(
                row["directory"],
                row["name"],
                max_signed_seq=signed.seq,
                pending=signed.bytes,
                pending_door=door["door_id"],
                updated_at=self._now(),
            )
            self._engine.failpoints.hit("listing.after_sign")
            row = self._refresh(row)
        return await self._post(row, door, interactive=interactive)

    async def _door_for(self, row: dict[str, Any]) -> dict[str, Any] | None:
        """The door this round publishes: the one waiting, or a fresh one;
        None when the token has too little life left to renew."""
        now = self._now()
        door = self._pending_door(row)
        if door is None:
            if row["state"] != "publishing" and int(row["token_expires_at"]) - now < (
                MIN_TOKEN_LEFT_SECS
            ):
                # The door runs out with the token; a new token is a new publish.
                self._store.update_listing(
                    row["directory"], row["name"], next_renewal_at=None, retry_at=None
                )
                return None
            return self._new_door(row)
        made, expires = int(door["created_at"]), int(door["expires_at"])
        if now - made > (expires - made) // 2:
            # Half the waiting door's life went by without the relay or the
            # directory: a fresh door (and signature), so a listing never
            # carries a door about to expire, and at most three are open
            # (current, retiring and this one).
            await self._discard_pending(row, door)
            return self._new_door(row)
        return door

    async def _registered(
        self, row: dict[str, Any], door: dict[str, Any], *, interactive: bool
    ) -> dict[str, Any] | None:
        """The door, registered; None when the worker tries again later."""
        try:
            return await self._register(row, door)
        except RelayError as e:
            if not interactive:
                await self._retry_later(row, e.code)
                return None
            # The relay may hold the door if its answer was lost: keep the
            # row until it confirms the close.
            door_id = str(door["door_id"])
            if e.code in NOT_REGISTERED:
                self._drop_door(door_id)
            else:
                self._closing(door_id)
            await self._restore(row, e.code)
            msg = f"the relay didn't register the door ({e.code}); nothing was published"
            raise ApiError(502, "relay", msg) from None

    async def _post(self, row: dict[str, Any], door: dict[str, Any], *, interactive: bool) -> str:
        client: DirectoryClient | None = None
        try:
            client = self._client(row)
            answer = await client.publish(bytes(row["pending"]))
        except DirectoryError as e:
            if client is not None and e.maybe_accepted and await self._landed(client, row):
                answer = {}  # it is listed as signed; the answer just can't be read
            elif (e.transient or e.maybe_accepted) and not (interactive and e.code == "blocked"):
                await self._retry_later(row, e.code)
                return "retrying"
            else:
                return await self._refusal(row, door, e, interactive)
        self._engine.failpoints.hit("listing.after_post")
        await self._published(row, door, answer)
        return "published"

    async def _landed(self, client: DirectoryClient, row: dict[str, Any]) -> bool:
        """Whether the directory lists exactly the bytes posted (it answered
        with a 2xx that couldn't be read)."""
        try:
            return await client.fetch_listing(str(row["name"])) == bytes(row["pending"])
        except DirectoryError:
            return False

    async def _discard_pending(self, row: dict[str, Any], door: dict[str, Any]) -> None:
        await self._close_door(door)
        self._store.update_listing(row["directory"], row["name"], pending=None, pending_door=None)
        row["pending"] = row["pending_door"] = None

    async def _refusal(
        self, row: dict[str, Any], door: dict[str, Any], e: DirectoryError, interactive: bool
    ) -> str:
        """A refusal (of known bytes; never an unreadable 2xx). A publish is
        put back as it was. A renewal stops only for the SPEC's reasons;
        otherwise it is tried again with a fresh door and signature."""
        LOG.warning("listing_refused", code=e.code)
        if row["state"] != "publishing" and e.code not in STOP_RENEWING:
            await self._discard_pending(row, door)
            await self._retry_later(row, e.code, report=True)
            return "retrying"
        await self._close_door(door)
        if row["state"] == "publishing":
            await self._restore(row, e.code)
        else:
            await self._stop_renewing(row, e.code)
        if not interactive:
            return "refused"
        status = REFUSAL_STATUS.get(e.code)
        message = f"the directory refused the listing ({e.code})"
        if e.detail:
            message += f": {clean_detail(e.detail)}"
        if status is None:
            raise ApiError(502, "directory", message)
        raise ApiError(status, e.code, message)

    async def _published(
        self, row: dict[str, Any], door: dict[str, Any], answer: dict[str, Any]
    ) -> None:
        listing = ac.verify_listing(bytes(row["pending"]))
        host, name, now = str(row["directory"]), str(row["name"]), self._now()
        door_id, expires_at = str(door["door_id"]), int(door["expires_at"])
        renews_at = listing.issued_at + (expires_at - listing.issued_at) // 2
        reported = owner_state(answer)
        renewal = row["state"] != "publishing"

        def effects() -> None:
            for d in self._store.doors(host, name):
                if d["state"] == "current" and d["door_id"] != door_id:
                    self._store.update_door(d["door_id"], state="retiring")
            self._store.update_door(door_id, state="current")
            self._store.update_listing(
                host,
                name,
                state="published",
                published=listing.bytes,
                published_sha256=listing.sha256.hex(),
                published_at=now,
                seq=listing.seq,
                pending=None,
                pending_door=None,
                next_renewal_at=renews_at,
                owner_state=reported if reported is not None else row["owner_state"],
                retry_at=None,
                attempts=0,
                failing_since=None,
                stale_since=None,
                last_error=None,
                restore_state=None,
                restore_renewal_at=None,
                updated_at=now,
            )

        kind = "listing_renewed" if renewal else "listing_published"
        data: dict[str, Any] = {
            "directory": host,
            "name": name,
            "seq": listing.seq,
            "door_expires_at": expires_at,
        }
        if not renewal:
            data |= {"url": listing.url, "token_expires_at": listing.token_expires_at}
        await self._commit(effects, [(kind, f"{kind}/{host}/{name}/{listing.seq}", data)])
        LOG.info(kind)

    def _restored(self, row: dict[str, Any]) -> dict[str, Any]:
        """The listing as it was before this publish began (``restore_state``):
        a refused publish never lists anything the human didn't publish
        again, and a withdrawn, expired or stale listing stays so."""
        state = row["restore_state"] or "refused"
        fields: dict[str, Any] = {
            "state": state,
            "next_renewal_at": row["restore_renewal_at"] if state in LIVE else None,
            "restore_state": None,
            "restore_renewal_at": None,
        }
        if row["published"] is not None:
            previous = ac.verify_listing(bytes(row["published"]))
            params = json.loads(previous.bytes)["capabilities"]["extensions"][0]["params"]
            fields |= {
                "content": previous.content.decode(),
                "token": canonical(params["token"]).decode(),
                "token_expires_at": previous.token_expires_at,
                "owner_domain": previous.owner_domain,
                "seq": previous.seq,
            }
        return fields

    async def _restore(self, row: dict[str, Any], code: str) -> None:
        now = self._now()
        fields = self._restored(self._refresh(row)) | {
            "pending": None,
            "pending_door": None,
            "retry_at": None,
            "attempts": 0,
            "failing_since": None,
            "last_error": _error(code, now),
            "updated_at": now,
        }
        await self._commit(
            lambda: self._store.update_listing(row["directory"], row["name"], **fields), []
        )

    async def _stop_renewing(self, row: dict[str, Any], code: str) -> None:
        """A renewal refused for good: the current door keeps working until it
        expires, and the human is told."""
        host, name, now = str(row["directory"]), str(row["name"]), self._now()
        since = row["stale_since"] if row["stale_since"] is not None else now
        fields = {
            "state": "stale",
            "pending": None,
            "pending_door": None,
            "next_renewal_at": None,
            "retry_at": None,
            "attempts": 0,
            "failing_since": None,
            "stale_since": since,
            "last_error": _error(code, now),
            "updated_at": now,
        }
        data = {
            "directory": host,
            "name": name,
            "reason": "refused",
            "code": code,
            "since": since,
            "door_expires_at": self._current_expiry(host, name),
        }
        await self._commit(
            lambda: self._store.update_listing(host, name, **fields),
            [("listing_stale", f"listing_stale/{host}/{name}/refused/{since}", data)],
        )

    def _current_expiry(self, host: str, name: str) -> int | None:
        current = [d for d in self._store.doors(host, name) if d["state"] == "current"]
        return int(current[-1]["expires_at"]) if current else None

    async def _retry_later(self, row: dict[str, Any], code: str, *, report: bool = False) -> None:
        """No answer, or not now: the same request goes again after a backoff
        (60 s doubling to an hour). A renewal failing for an hour (or at once,
        with ``report``, for a refusal) makes the listing ``stale``; the old
        door keeps working until it expires. A withdrawal failing for an hour
        is reported, and after 7 days it is given up (``withdraw_failed``)."""
        host, name, now = str(row["directory"]), str(row["name"]), self._now()
        attempts = int(row["attempts"]) + 1
        delay = min(RETRY_CAP_SECS, RETRY_BASE_SECS * 2 ** min(attempts - 1, 16))
        failing_since = row["failing_since"] if row["failing_since"] is not None else now
        fields: dict[str, Any] = {
            "retry_at": now + delay,
            "attempts": attempts,
            "failing_since": failing_since,
            "last_error": _error(code, now),
            "updated_at": now,
        }
        events = []
        failing = now - failing_since
        if row["state"] in ("published", "stale") and (report or failing >= STALE_AFTER_SECS):
            since = row["stale_since"] if row["stale_since"] is not None else now
            fields |= {"state": "stale", "stale_since": since}
            data = {
                "directory": host,
                "name": name,
                "reason": "publish_failed",
                "code": code,
                "since": since,
                "door_expires_at": self._current_expiry(host, name),
            }
            cause = f"listing_stale/{host}/{name}/publish_failed/{failing_since}"
            events.append(("listing_stale", cause, data))
        if row["state"] == "withdrawing" and failing >= STALE_AFTER_SECS:
            data = {"directory": host, "name": name, "code": code, "since": failing_since}
            if failing >= WITHDRAW_GIVE_UP_SECS:
                fields |= {"state": "withdraw_failed", "retry_at": None}
                cause = f"listing_withdraw_failed/{host}/{name}/{failing_since}"
                events.append(("listing_withdraw_failed", cause, data))
            else:
                cause = f"listing_withdraw_pending/{host}/{name}/{failing_since}"
                events.append(("listing_withdraw_pending", cause, data))
        LOG.info("listing_retry", code=code, attempts=attempts)
        await self._commit(lambda: self._store.update_listing(host, name, **fields), events)

    # -- withdraw (either token; forcing it is the human's) ------------------------

    def _withdrawable(self) -> dict[str, Any] | None:
        for row in self._store.listings():
            if row["state"] in WITHDRAWABLE:
                return row
            # A refused publish may still be listed: something was signed.
            if row["state"] == "refused" and int(row["max_signed_seq"]) > 0:
                return row
        return None

    async def withdraw(self, *, force: bool = False, human: bool = False) -> dict[str, Any]:
        """Close every door at the relay (keys deleted at once), then send
        the signed withdrawal. Allowed to the agent: it only reduces
        exposure (SPEC 13.2.3). ``force`` (the human only, after a
        withdrawal the directory hasn't taken) ends it here only:
        ``withdrawn_locally``, and the directory may go on listing it."""
        if force and not human:
            raise ApiError(403, "human_only", "forcing a withdrawal needs the human token")
        async with self._lock:
            row = self._withdrawable()
            if row is None:
                raise ApiError(404, "not_found", "there is no listing to withdraw")
            if force and row["state"] not in FORCEABLE:
                msg = "force only ends a withdrawal the directory hasn't taken; withdraw first"
                raise ApiError(409, "not_withdrawing", msg)
            if row["state"] != "withdrawing":
                self._store.update_listing(
                    row["directory"],
                    row["name"],
                    state="withdrawing",
                    pending=None,
                    pending_door=None,
                    next_renewal_at=None,
                    retry_at=None,
                    attempts=0,
                    failing_since=None,
                    restore_state=None,
                    restore_renewal_at=None,
                    updated_at=self._now(),
                )
            answer = await self._withdraw_round(self._refresh(row), force=force, now=True)
        self._wake.set()
        if answer.pop("unknown_directory", False):
            msg = (
                "the doors are closed, but the directory is no longer configured, so the "
                "withdrawal can't be sent: add its [[directory]] table back, or force it"
            )
            raise ApiError(400, "unknown_directory", msg)
        return answer

    async def _withdraw_round(
        self, row: dict[str, Any], *, force: bool = False, now: bool = False
    ) -> dict[str, Any]:
        """One attempt. ``now`` (a request, not the worker) tries every door
        again, whatever its close backoff."""
        host, name = str(row["directory"]), str(row["name"])
        closed = 0
        for door in self._store.doors(host, name):
            if now or self._close_due(door, self._now()):
                closed += await self._close_door(door)
        pending = len(self._store.doors(host, name))
        self._engine.failpoints.hit("withdraw.after_close")
        seq = int(row["max_signed_seq"])
        answer = {
            "directory": host,
            "name": name,
            "seq": seq,
            "state": "withdrawing",
            "doors_closed": closed,
            "doors_close_pending": pending,
            "forced": force,
        }
        error: str | None = "forced" if force else None
        if seq > 0 and not force:  # something was signed, so something may be listed
            try:
                seq = await self._send_withdrawal(row)
            except DirectoryError as e:
                if e.transient or e.code in ("stale_ts", "unknown_directory"):
                    # Sent again with a fresh `ts` (300 s skew at the directory).
                    await self._retry_later(row, e.code)
                    if e.code == "unknown_directory":
                        answer["unknown_directory"] = True
                    return answer
                # not_found: nothing was listed. wrong_identity and the rest:
                # the directory won't take a withdrawal from this identity.
                error = None if e.code == "not_found" else e.code
        state = "withdrawn_locally" if force else "withdrawn"
        at = self._now()
        fields: dict[str, Any] = {
            "state": state,
            "retry_at": None,
            "attempts": 0,
            "failing_since": None,
            "updated_at": at,
        }
        if error is not None:
            fields["last_error"] = _error(error, at)
        data = {
            "directory": host,
            "name": name,
            "seq": seq,
            "doors_close_pending": pending,
            "forced": force,
        }
        await self._commit(
            lambda: self._store.update_listing(host, name, **fields),
            [("listing_withdrawn", f"listing_withdrawn/{host}/{name}/{seq}/{state}", data)],
        )
        LOG.info("listing_withdrawn", doors_close_pending=pending, forced=force)
        return answer | {"seq": seq, "state": state}

    async def _send_withdrawal(self, row: dict[str, Any]) -> int:
        """Withdraw everything up to ``max_signed_seq`` (a publish whose answer
        was lost may have landed). ``stale_seq`` (a database restored from a
        backup) is retried once at the seq the directory lists, if that
        listing is this identity's."""
        client = self._client(row)
        host, name = str(row["directory"]), str(row["name"])
        seq = int(row["max_signed_seq"])
        identity = self._engine.identity
        try:
            await client.withdraw(ac.sign_withdrawal(identity, host, name, seq, self._now()))
        except DirectoryError as e:
            if e.code != "stale_seq":
                raise
            listed = await self._listed_seq(client, host, name)
            if listed is None or listed <= seq:
                raise
            seq = listed
            self._store.update_listing(host, name, max_signed_seq=seq)
            await client.withdraw(ac.sign_withdrawal(identity, host, name, seq, self._now()))
        return seq

    async def _listed_seq(self, client: DirectoryClient, host: str, name: str) -> int | None:
        """The ``seq`` the directory lists under ``name``, if it is a valid
        listing of this identity for this directory."""
        try:
            listing = ac.verify_listing(await client.fetch_listing(name))
        except (DirectoryError, ac.AgentConnectError):
            return None
        same = (listing.identity, listing.directory, listing.name) == (self._engine.me, host, name)
        return listing.seq if same else None

    # -- status (either token) ---------------------------------------------------

    def _latest(self, states: frozenset[str]) -> dict[str, Any] | None:
        return next((r for r in self._store.listings() if r["state"] in states), None)

    def status(self) -> dict[str, Any]:
        """The runtime's listing as it stands: the one it holds, else the
        latest one in any state. No door key is read."""
        rows = self._store.listings()
        if not rows:
            return {"listing": None}
        row, now = self._latest(HOLDING) or rows[0], self._now()
        doors = self._store.doors(row["directory"], row["name"])
        current = next((d for d in reversed(doors) if d["state"] == "current"), None)
        door = None
        if current is not None:
            expires = int(current["expires_at"])
            door = {
                "expires_at": expires,
                "renews_at": row["next_renewal_at"],
                "expiring": expires - now < DOOR_WARNING_SECS,
            }
        error = json.loads(row["last_error"]) if row["last_error"] else None
        retrying = None
        if row["state"] in ("publishing", "withdrawing") and row["failing_since"] is not None:
            retrying = {
                "since": int(row["failing_since"]),
                "code": None if error is None else error["code"],
            }
        expires_at = int(row["token_expires_at"])
        return {
            "listing": {
                "directory": row["directory"],
                "name": row["name"],
                "url": _url(row),
                "state": row["state"],
                "seq": int(row["seq"]),
                "published_at": row["published_at"],
                "identity": self._engine.me,
                "fingerprint": self._engine.identity.fingerprint,
                "door": door,
                "doors_open": len(
                    [d for d in doors if d["state"] in OPEN_DOOR and int(d["expires_at"]) > now]
                ),
                "token": {"expires_at": expires_at, "warn_at": expires_at - TOKEN_WARNING_SECS},
                "owner_domain": row["owner_domain"],
                "owner_state": row["owner_state"],
                "last_error": error,
                "retrying": retrying,
            }
        }

    # -- the discovery worker ---------------------------------------------------

    async def run(self) -> None:
        """Renew, retry, expire and delete keys when each is due; a pass that
        fails is logged by type and retried after a backoff."""
        backoff = Backoff(base=1.0, cap=300.0, rng=self._engine.options.backoff_rng)
        busy = 0
        while True:
            self._wake.clear()
            try:
                due = await self.step()
                backoff.reset()
            except Exception as e:
                LOG.warning("discovery_step_failed", error=type(e).__name__)
                due = self._now() + backoff.next()
            # Work due at once runs at once, but a pass that makes no progress
            # can't spin: after a few in a row, the worker pauses a second.
            busy = busy + 1 if due is not None and due <= self._now() else 0
            if busy > MAX_IDLE_PASSES:
                due, busy = self._now() + 1, 0
            await self._wait(due)

    async def _wait(self, due: float | None) -> None:
        """Until ``due`` (Unix seconds on the runtime's clock) or a wake-up.
        One timer, set against the clock itself (``Clock.sleep_until``), so
        neither a busy loop nor a test moving a fake clock re-arms it."""
        woken = asyncio.ensure_future(self._wake.wait())
        waits: set[asyncio.Future[Any]] = {woken}
        if due is not None:
            # A deadline, not a retry pause: the fake clock doesn't count it.
            waits.add(asyncio.ensure_future(self._engine.clock.sleep_until(due, deadline=True)))
        try:
            await asyncio.sleep(0)  # the timer is set before anyone is told
            self._engine._pulse()  # a pass ended: waiters re-check
            await asyncio.wait(waits, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for w in waits:
                w.cancel()

    async def step(self) -> float | None:
        """One pass over the doors and listings. Returns when the next thing
        is due (Unix seconds; at or before now when it is overdue), or None
        when nothing is scheduled."""
        async with self._lock:
            await self._sweep_doors()
            for row in self._store.listings():
                await self._tend(row)
            return self._next_due()

    async def _sweep_doors(self) -> None:
        now = self._now()
        for door in self._store.doors():
            door_id, expires_at = str(door["door_id"]), int(door["expires_at"])
            if door["state"] == "closing":
                if now >= expires_at:  # the relay forgets it anyway
                    self._store.delete_door(door_id)
                    self._close_retry.pop(door_id, None)
                elif self._close_due(door, now):
                    await self._close_door(door)
                continue
            # SPEC 6.6.1: the key goes an hour after the door expires, once
            # every knock it could have received has lapsed.
            if now >= expires_at + ac.DOOR_GRACE_SECS:
                self._drop_door(door_id)
                LOG.info("door_key_deleted")

    async def _tend(self, row: dict[str, Any]) -> None:
        now, state = self._now(), row["state"]
        if state == "withdrawing":
            if _due(row["retry_at"], now):
                await self._withdraw_round(row)
            return
        if state not in LIVE:
            return
        host, name = str(row["directory"]), str(row["name"])
        expires_at = int(row["token_expires_at"])
        if now >= expires_at:
            await self._expire(row)
            return
        if not row["token_warned"] and now >= expires_at - TOKEN_WARNING_SECS:
            await self._commit(
                lambda: self._store.update_listing(host, name, token_warned=1),
                [
                    (
                        "listing_token_expiring",
                        f"listing_token_expiring/{host}/{name}/{expires_at}",
                        {"directory": host, "name": name, "token_expires_at": expires_at},
                    )
                ],
            )
        await self._door_checks(row)
        row = self._refresh(row)
        if not _due(row["retry_at"], now):
            return
        renew_at = row["next_renewal_at"]
        if row["state"] == "publishing" or (renew_at is not None and now >= renew_at):
            await self._round(row, interactive=False)

    async def _door_checks(self, row: dict[str, Any]) -> None:
        """Tell the human when the listed door is about to expire while a
        republish waits, and when it expired before a renewal landed."""
        host, name, now = str(row["directory"]), str(row["name"]), self._now()
        current = [d for d in self._store.doors(host, name) if d["state"] == "current"]
        if not current:
            return
        door_id, expires = current[-1]["door_id"], int(current[-1]["expires_at"])
        publishing = row["state"] == "publishing"
        since = row["stale_since"] if row["stale_since"] is not None else now
        data = {"directory": host, "name": name, "since": since, "door_expires_at": expires}
        if expires <= now:
            # A republish that waits stays `publishing`; the human is told all the same.
            fields = {} if publishing else {"state": "stale", "stale_since": since}
            await self._commit(
                lambda: self._store.update_listing(host, name, updated_at=now, **fields),
                [
                    (
                        "listing_stale",
                        f"listing_stale/{host}/{name}/door_expired/{door_id}",
                        data | {"reason": "door_expired"},
                    )
                ],
            )
        elif publishing and expires - now < DOOR_WARNING_SECS:
            await self._commit(
                lambda: None,
                [
                    (
                        "listing_stale",
                        f"listing_stale/{host}/{name}/door_expiring/{door_id}",
                        data | {"reason": "door_expiring"},
                    )
                ],
            )

    async def _expire(self, row: dict[str, Any]) -> None:
        """The token expired: the listing counts as withdrawn everywhere
        (SPEC 13.2.1). Its doors are closed and their keys deleted; a new
        token is a new publish."""
        host, name, now = str(row["directory"]), str(row["name"]), self._now()
        for door in self._store.doors(host, name):
            await self._close_door(door)
        fields = {
            "state": "expired",
            "pending": None,
            "pending_door": None,
            "next_renewal_at": None,
            "retry_at": None,
            "attempts": 0,
            "failing_since": None,
            "restore_state": None,
            "restore_renewal_at": None,
            "updated_at": now,
        }
        await self._commit(
            lambda: self._store.update_listing(host, name, **fields),
            [
                (
                    "listing_token_expired",
                    f"listing_token_expired/{host}/{name}/{row['token_expires_at']}",
                    {"directory": host, "name": name},
                )
            ],
        )
        LOG.info("listing_token_expired")

    def _next_due(self) -> float | None:
        """When the next thing is due. Overdue work (the clock moved during
        the pass) counts, so it runs at once; what this pass already handled
        (an expired current door, a warning given) doesn't."""
        now = self._now()
        times: list[int] = []
        for door in self._store.doors():
            expires_at = int(door["expires_at"])
            if door["state"] == "closing":
                due, _ = self._close_retry.get(str(door["door_id"]), (now, 0))
                times.append(min(due, expires_at))
            else:
                times.append(expires_at + ac.DOOR_GRACE_SECS)
            if door["state"] == "current":
                times += [t for t in (expires_at - DOOR_WARNING_SECS, expires_at) if t > now]
        for row in self._store.listings():
            if row["state"] == "withdrawing":
                times.append(row["retry_at"] or now + RETRY_BASE_SECS)
            if row["state"] not in LIVE:
                continue
            expires_at = int(row["token_expires_at"])
            times.append(expires_at)
            if not row["token_warned"]:
                times.append(expires_at - TOKEN_WARNING_SECS)
            # Only when a round would run: a publish, or a renewal scheduled.
            renew_at = row["next_renewal_at"]
            if row["state"] == "publishing" or renew_at is not None:
                times.append(max(int(row["retry_at"] or 0), int(renew_at or 0)))
        return float(min(times)) if times else None


def _url(row: dict[str, Any]) -> str:
    """The listing's address at its directory (``Listing.url``)."""
    return f"https://{row['directory']}/a/{row['name']}.json"


def _token_error(e: ac.AgentConnectError) -> ApiError:
    if e.kind == "unknown_key":
        msg = "the token isn't signed by a key pinned for this directory"
        return ApiError(403, "unknown_key", msg)
    if e.kind in ("malformed", "unsupported_version"):
        return ApiError(400, "bad_token", f"not a listing token: {e}")
    return ApiError(403, "token_invalid", f"the listing token doesn't verify: {e}")
