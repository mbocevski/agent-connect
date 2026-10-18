"""The owner's replay ledgers: one for invite JoinRequests (SPEC 6.2
"Replays"), one for knocks (SPEC 6.6.3 step 6).

Neither request carries freshness of its own and the relay sees both, so
every request that passed the owner's checks is remembered by its id and
its KeyPackageRef, whatever happens to it next, until no copy can pass the
checks again: a knock until ``ts + 3900``, a JoinRequest until its invite's
``expires_at`` plus the core's ``LEDGER_GRACE_SECS``. A remembered request
is dropped silently.

The core's bounded ``ReplayLedger`` answers "seen?"; its entries are
persisted in a table of the encrypted store, written in the transaction that
records what the request led to. The in-memory ledger has no remove, so a
transaction that rolls back is followed by :func:`load`. When the ledger is
full, new requests are refused (``busy``) and nothing live is evicted. Each
invite also has a share of the join ledger (:func:`join_quota`), and an
invite's entries are forgotten once it is revoked or has expired. Purges
run on the clock's current time on every pass and keep nothing from
earlier passes; loading purges nothing.
"""

from __future__ import annotations

from collections.abc import Callable

import agentconnect_core as ac
from agentconnect.config import MIN_JOIN_LEDGER_PER_INVITE
from agentconnect.relay import b64, unb64
from agentconnect.store import Ledger, Store

KNOCK_ID_LEN = 16

#: What a request the ledger refuses is dropped as, by its error kind.
REASONS: dict[Ledger, dict[str, str]] = {
    "knock": {"replay": "knock_replay", "busy": "knock_ledger_full"},
    "join": {"replay": "join_replay", "busy": "join_ledger_full"},
}


def load(store: Store, ledger: Ledger, capacity: int) -> ac.ReplayLedger:
    """The ledger from the database, every row of it, even past a lowered
    capacity: a request seen before a restart must never pass after it.
    Loading purges nothing. A clock that is ahead at start and put right
    before the next pass would otherwise forget live entries; the passes
    purge (for joins right after marking expired invites, at the same now)."""
    rows = store.ledger_rows(0, ledger=ledger)
    core = ac.ReplayLedger(
        max(capacity, len(rows)), id_len=KNOCK_ID_LEN if ledger == "knock" else None
    )
    for entry_id, kp_ref, forget_after in rows:
        core.insert(entry_key(ledger, entry_id), unb64(kp_ref), forget_after)
    return core


def entry_key(ledger: Ledger, entry_id: str) -> bytes:
    """The bytes the core keys an entry by: a knock's raw ``knock_id``, a
    join's request id (the envelope's ``msg_id``) as text."""
    return unb64(entry_id) if ledger == "knock" else entry_id.encode()


def remember(  # noqa: PLR0913
    store: Store,
    ledger: Ledger,
    core: ac.ReplayLedger,
    remember_in: Callable[[ac.ReplayLedger], None],
    *,
    entry_id: str,
    kp_ref: bytes,
    forget_after: int,
    invite_id: str | None = None,
) -> str | None:
    """Inside the transaction that records the request: ``None`` if it is
    new (now remembered, in memory and in the store), else the reason code
    to drop it with (``*_replay``, ``*_ledger_full``)."""
    try:
        remember_in(core)
    except ac.AgentConnectError as e:
        return REASONS[ledger].get(e.kind, f"{ledger}_check:{e.kind}")
    store.ledger_add(entry_id, b64(kp_ref), forget_after, ledger=ledger, invite_id=invite_id)
    return None


def join_quota(max_uses: int, per_invite: int) -> int:
    """How many entries one invite may hold in the join ledger: 4 times its
    uses, at least ``MIN_JOIN_LEDGER_PER_INVITE``, at most ``per_invite``
    (``policy.join_ledger_per_invite``). A leaked link fills only its own
    share."""
    return min(max(4 * max_uses, MIN_JOIN_LEDGER_PER_INVITE), per_invite)


def purge(store: Store, ledger: Ledger, core: ac.ReplayLedger, now: int) -> None:
    """Forget what expired before ``now``: the clock's current time."""
    store.ledger_purge(now, ledger=ledger)
    core.purge(now)
