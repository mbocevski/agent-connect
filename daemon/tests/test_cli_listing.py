"""`agentconnect listing ...` against a fake daemon API (docs/discovery.md)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from agentconnect import cli
from agentconnect.apiclient import ApiClientError
from agentconnect.cli_json import SCHEMAS
from agentconnect.shapes import conforms

runner = CliRunner()
BIDI = chr(0x202E)
CARD = {"name": "Release planner" + BIDI, "description": "Plans.", "version": "1.0.0"}
TOKEN = {"v": 0, "name": "release-planner"}
PREVIEW = {
    "directory": "directory.example.org",
    "name": "release-planner",
    "identity": "ac:v0:me",
    "fingerprint": "3f9a 0c21",
    "content": {
        **CARD,
        "provider": {"organization": "Example Ltd", "url": "https://example.com"},
        "skills": [{"name": "Planning", "description": "Plans."}],
    },
    "content_sha256": "ab" * 32,
    "owner_domain": "example.com",
    "token": {"token_id": "t", "issued_at": 1, "expires_at": 1_800_000_000, "key_id": "k"},
    "owner_file_entry": {"identity": "ac:v0:me", "listings": ["directory.example.org/a/x"]},
    "warnings": [{"code": "identity_in_groups", "message": "This identity is in 2 groups."}],
}
PUBLISHED = {
    "directory": "directory.example.org",
    "name": "release-planner",
    "url": "https://directory.example.org/a/release-planner.json",
    "seq": 1_790_000_000,
    "state": "published",
    "door_expires_at": 1_790_600_000,
    "renews_at": 1_790_300_000,
    "token_expires_at": 1_800_000_000,
    "owner_domain": "example.com",
    "owner_state": "checking",
    "warnings": [],
    "retrying": False,
}
STATUS = {
    "directory": "directory.example.org",
    "name": "release-planner",
    "url": PUBLISHED["url"],
    "state": "published",
    "seq": 7,
    "published_at": 1_790_000_000,
    "identity": "ac:v0:me",
    "fingerprint": "3f9a",
    "door": {"expires_at": 1_790_600_000, "renews_at": 1_790_300_000, "expiring": False},
    "doors_open": 1,
    "token": {"expires_at": 1_800_000_000, "warn_at": 1_798_790_400},
    "owner_domain": "example.com",
    "owner_state": "verified",
    "last_error": {"code": "unreachable", "at": 1_790_000_100},
    "retrying": None,
}
WITHDRAWN = {
    "directory": "directory.example.org",
    "name": "release-planner",
    "seq": 7,
    "state": "withdrawn",
    "doors_closed": 2,
    "doors_close_pending": 0,
    "forced": False,
}


class Fake:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp: Path) -> None:
        self.routes: dict[str, Any] = {
            "POST /v0/listing/preview": PREVIEW,
            "POST /v0/listing/publish": PUBLISHED,
            "GET /v0/listing": {"listing": STATUS},
            "POST /v0/listing/withdraw": WITHDRAWN,
        }
        self.calls: list[tuple[bool, str, Any]] = []
        self.card, self.token = tmp / "card.json", tmp / "token.json"
        self.card.write_text(json.dumps(CARD), encoding="utf-8")
        self.token.write_text(json.dumps(TOKEN), encoding="utf-8")
        fake = self

        class Api:
            def __init__(self, human: bool) -> None:
                self.human = human

            def request(self, method: str, path: str, body: Any = None) -> Any:
                key = f"{method} {path}"
                fake.calls.append((self.human, key, body))
                value = fake.routes[key]
                if isinstance(value, ApiClientError):
                    raise value
                return value

        monkeypatch.setattr(cli, "connect", lambda _c, human=False: Api(human))

    def files(self) -> list[str]:
        return ["--card", str(self.card), "--token", str(self.token)]

    def run(self, *args: str, input: str | None = None) -> Any:
        return runner.invoke(cli.app, list(args), input=input)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Fake:
    return Fake(monkeypatch, tmp_path)


PUBLISH = ("listing", "publish", "--directory", "directory.example.org")


def test_publish_shows_the_card_asks_and_uses_the_human_token(fake: Fake) -> None:
    result = fake.run(*PUBLISH, *fake.files(), input="y\n")
    assert result.exit_code == 0, result.output
    assert "Release planner?" in result.output  # the bidi override is cleaned
    assert BIDI not in result.output
    assert "Example Ltd" in result.output
    assert "This identity is in 2 groups." in result.output
    assert "/.well-known/agentconnect.json" in result.output
    assert "Published https://directory.example.org/a/release-planner.json" in result.output
    (preview, publish) = fake.calls
    assert all(human for human, _, _ in fake.calls)
    assert preview[2] == {"directory": "directory.example.org", "card": CARD, "token": TOKEN}
    assert publish[2]["content_sha256"] == PREVIEW["content_sha256"]


def test_publish_declined_publishes_nothing(fake: Fake) -> None:
    result = fake.run(*PUBLISH, *fake.files(), "--owner-domain", "example.com", input="n\n")
    assert result.exit_code == 3
    assert [k for _, k, _ in fake.calls] == ["POST /v0/listing/preview"]
    assert fake.calls[0][2]["owner_domain"] == "example.com"


def test_publish_json_shape(fake: Fake) -> None:
    result = fake.run(*PUBLISH, *fake.files(), "--yes", "--json")
    assert result.exit_code == 0
    out = json.loads(result.stdout.splitlines()[-1])
    assert conforms(out, SCHEMAS["listing publish"])
    assert out["identity"] == "ac:v0:me"
    assert fake.run(*PUBLISH, *fake.files(), "--json").exit_code == 2  # needs --yes


def test_publish_reads_the_files_named_in_the_config(fake: Fake, tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        f'[listing]\ncard_file = "{fake.card}"\ntoken_file = "{fake.token}"\n', encoding="utf-8"
    )
    assert fake.run(*PUBLISH, "--config", str(config), "--yes").exit_code == 0
    assert fake.calls[0][2]["card"] == CARD


@pytest.mark.parametrize("content", [None, "not json", "[1]"])
def test_unreadable_files_are_usage_errors(fake: Fake, content: str | None) -> None:
    if content is None:
        fake.card.unlink()
    else:
        fake.card.write_text(content, encoding="utf-8")
    result = fake.run(*PUBLISH, *fake.files(), "--yes")
    assert result.exit_code == 2
    assert fake.calls == []


def test_a_directory_that_doesnt_answer_is_a_failure_that_retries(fake: Fake) -> None:
    fake.routes["POST /v0/listing/publish"] = PUBLISHED | {"retrying": True, "state": "publishing"}
    result = fake.run(*PUBLISH, *fake.files(), "--yes", "--json")
    assert result.exit_code == 1
    assert json.loads(result.stdout)["error"]["code"] == "publish_retrying"


@pytest.mark.parametrize(
    ("code", "status", "exit_code"),
    [
        ("human_only", 403, 3),
        ("unknown_directory", 400, 2),
        ("bad_card", 400, 2),
        ("bad_token", 400, 2),
        ("token_not_for_identity", 403, 3),
        ("unknown_key", 403, 3),
        ("token_invalid", 403, 1),
        ("name_held", 409, 1),
        ("listing_exists", 409, 1),
        ("relay", 502, 1),
    ],
)
def test_refusals_map_to_exit_codes(fake: Fake, code: str, status: int, exit_code: int) -> None:
    fake.routes["POST /v0/listing/preview"] = ApiClientError(status, code, "refused")
    assert fake.run(*PUBLISH, *fake.files(), "--yes").exit_code == exit_code


def test_withdraw_confirms_and_uses_the_agent_token(fake: Fake) -> None:
    result = fake.run("listing", "withdraw", input="y\n")
    assert result.exit_code == 0, result.output
    assert "Withdrew release-planner" in result.output
    assert not any(human for human, _, _ in fake.calls)
    assert fake.run("listing", "withdraw", input="n\n").exit_code == 3
    result = fake.run("listing", "withdraw", "--yes", "--json")
    assert conforms(json.loads(result.stdout), SCHEMAS["listing withdraw"])


def test_withdraw_still_pending_and_nothing_to_withdraw(fake: Fake) -> None:
    fake.routes["POST /v0/listing/withdraw"] = WITHDRAWN | {
        "state": "withdrawing",
        "doors_close_pending": 1,
    }
    result = fake.run("listing", "withdraw", "--yes", "--json")
    assert result.exit_code == 1
    assert json.loads(result.stdout)["error"]["code"] == "withdraw_pending"
    fake.routes["POST /v0/listing/withdraw"] = WITHDRAWN | {"doors_close_pending": 1}
    result = fake.run("listing", "withdraw", "--yes")
    assert "hasn't confirmed every door" in result.output
    fake.routes["GET /v0/listing"] = {"listing": STATUS | {"state": "withdrawn"}}
    assert fake.run("listing", "withdraw", "--yes").exit_code == 1
    # A refused publish may still be listed: it can be withdrawn.
    fake.routes["GET /v0/listing"] = {"listing": STATUS | {"state": "refused"}}
    fake.routes["POST /v0/listing/withdraw"] = WITHDRAWN
    assert fake.run("listing", "withdraw", "--yes").exit_code == 0
    fake.routes["GET /v0/listing"] = {"listing": None}
    assert fake.run("listing", "withdraw", "--yes").exit_code == 1


def test_status(fake: Fake) -> None:
    result = fake.run("listing", "status")
    assert result.exit_code == 0
    for text in (
        "published (seq 7)",
        "open until",
        "renews",
        "example.com (verified",
        "unreachable",
    ):
        assert text in result.output
    result = fake.run("listing", "status", "--json")
    assert conforms(json.loads(result.stdout), SCHEMAS["listing status"])
    fake.routes["GET /v0/listing"] = {
        "listing": STATUS
        | {"door": None, "owner_domain": None, "last_error": None, "state": "stale"}
    }
    result = fake.run("listing", "status")
    assert "none open" in result.output
    fake.routes["GET /v0/listing"] = {
        "listing": STATUS
        | {
            "door": {"expires_at": 1_790_600_000, "renews_at": None, "expiring": True},
            "retrying": {"since": 1_790_000_000, "code": None},
        }
    }
    output = fake.run("listing", "status").output
    assert "expires within a day" in output
    assert "retrying     since" in output
    assert "not renewing" in fake.run("listing", "status").output
    fake.routes["GET /v0/listing"] = {"listing": None}
    assert "No listing" in fake.run("listing", "status").output


def test_force_uses_the_human_token_and_says_what_it_does(fake: Fake) -> None:
    fake.routes["GET /v0/listing"] = {"listing": STATUS | {"state": "withdraw_failed"}}
    fake.routes["POST /v0/listing/withdraw"] = WITHDRAWN | {
        "state": "withdrawn_locally",
        "forced": True,
    }
    result = fake.run("listing", "withdraw", "--force", input="y\n")
    assert result.exit_code == 0, result.output
    assert "without the directory's answer" in result.output
    assert "may still list it" in result.output
    assert "Withdrew" not in result.output
    assert all(human for human, _, _ in fake.calls)
    assert fake.calls[-1][2] == {"force": True}


@pytest.mark.parametrize(
    "path", ["POST /v0/listing/preview", "POST /v0/listing/publish", "POST /v0/listing/withdraw"]
)
def test_a_directory_that_doesnt_list_our_relay_is_not_an_invite_problem(
    fake: Fake, path: str
) -> None:
    fake.routes[path] = ApiClientError(400, "wrong_relay", "the directory refused it")
    args = [*PUBLISH, *fake.files()] if "withdraw" not in path else ["listing", "withdraw"]
    result = fake.run(*args, "--yes")
    assert result.exit_code == 3
    assert "directory doesn't list this daemon's relay" in result.output
    assert "invite" not in result.output
