"""The webhook signature helper: valid, tampered, replayed and skewed."""

from __future__ import annotations

import secrets

import pytest

from agentconnect_sdk import (
    ReplayError,
    SignatureError,
    SkewError,
    WebhookVerifier,
    sign,
    verify,
)

NOW = 1_750_000_000


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def request(secret: str, body: bytes, at: int = NOW) -> dict[str, str]:
    stamp = str(at)
    return {
        "X-AgentConnect-Timestamp": stamp,
        "X-AgentConnect-Signature": sign(secret, stamp, body),
    }


def test_valid_request_verifies(secret: str) -> None:
    body = b'{"event":"message"}'
    headers = request(secret, body)
    verify(
        secret,
        headers["X-AgentConnect-Timestamp"],
        headers["X-AgentConnect-Signature"],
        body,
        now=NOW,
    )
    WebhookVerifier(secret, clock=Clock(NOW)).verify(headers, body)


def test_signature_is_hmac_sha256_over_timestamp_dot_body(secret: str) -> None:
    sig = sign(secret, "1", b"x")
    assert sig.startswith("v0=")
    assert len(sig) == 3 + 64
    assert sig != sign(secret, "1", b"y")
    assert sig != sign(secret, "2", b"x")
    assert sig != sign(secrets.token_hex(16), "1", b"x")


def test_header_names_are_case_insensitive(secret: str) -> None:
    body = b"{}"
    headers = {k.lower(): v for k, v in request(secret, body).items()}
    WebhookVerifier(secret, clock=Clock(NOW)).verify(headers, body)


@pytest.mark.parametrize("tamper", ["body", "timestamp", "signature", "secret"])
def test_tampered_request_is_refused(secret: str, tamper: str) -> None:
    body = b'{"event":"message","a2a":{"text":"hi"}}'
    headers = request(secret, body)
    verifier_secret = secret
    if tamper == "body":
        body = body.replace(b"hi", b"ho")
    elif tamper == "timestamp":
        headers["X-AgentConnect-Timestamp"] = str(NOW + 1)
    elif tamper == "signature":
        sig = headers["X-AgentConnect-Signature"]
        headers["X-AgentConnect-Signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    else:
        verifier_secret = secrets.token_hex(16)
    with pytest.raises(SignatureError) as info:
        WebhookVerifier(verifier_secret, clock=Clock(NOW)).verify(headers, body)
    assert not isinstance(info.value, (SkewError, ReplayError))


@pytest.mark.parametrize("missing", ["X-AgentConnect-Timestamp", "X-AgentConnect-Signature"])
def test_missing_headers_are_refused(secret: str, missing: str) -> None:
    headers = request(secret, b"{}")
    del headers[missing]
    with pytest.raises(SignatureError):
        WebhookVerifier(secret, clock=Clock(NOW)).verify(headers, b"{}")


def test_non_numeric_timestamp_is_refused(secret: str) -> None:
    headers = {
        "X-AgentConnect-Timestamp": "soon",
        "X-AgentConnect-Signature": sign(secret, "soon", b""),
    }
    with pytest.raises(SignatureError):
        WebhookVerifier(secret, clock=Clock(NOW)).verify(headers, b"")


@pytest.mark.parametrize("offset", [-301, 301, -3600, 86_400])
def test_skewed_request_is_refused_even_when_genuine(secret: str, offset: int) -> None:
    headers = request(secret, b"{}", at=NOW + offset)
    with pytest.raises(SkewError):
        WebhookVerifier(secret, clock=Clock(NOW)).verify(headers, b"{}")


@pytest.mark.parametrize("offset", [-300, 0, 300])
def test_requests_inside_the_window_pass(secret: str, offset: int) -> None:
    headers = request(secret, b"{}", at=NOW + offset)
    WebhookVerifier(secret, clock=Clock(NOW)).verify(headers, b"{}")


def test_replayed_request_is_refused(secret: str) -> None:
    clock = Clock(NOW)
    verifier = WebhookVerifier(secret, clock=clock)
    headers = request(secret, b"{}")
    verifier.verify(headers, b"{}")
    with pytest.raises(ReplayError):
        verifier.verify(headers, b"{}")
    clock.now += 10
    with pytest.raises(ReplayError):
        verifier.verify(headers, b"{}")


def test_replay_after_the_window_is_a_skew_error(secret: str) -> None:
    clock = Clock(NOW)
    verifier = WebhookVerifier(secret, clock=clock)
    headers = request(secret, b"{}")
    verifier.verify(headers, b"{}")
    clock.now += 301
    with pytest.raises(SkewError):
        verifier.verify(headers, b"{}")


def test_a_fresh_signature_for_the_same_body_is_not_a_replay(secret: str) -> None:
    """The daemon signs every attempt afresh, so a retry is accepted."""
    clock = Clock(NOW)
    verifier = WebhookVerifier(secret, clock=clock)
    verifier.verify(request(secret, b"{}", at=NOW), b"{}")
    clock.now += 1
    verifier.verify(request(secret, b"{}", at=NOW + 1), b"{}")


def test_replay_memory_is_bounded(secret: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentconnect_sdk.signature.MAX_REMEMBERED", 3)
    clock = Clock(NOW)
    verifier = WebhookVerifier(secret, clock=clock)
    for i in range(10):
        clock.now = NOW + i
        verifier.verify(request(secret, str(i).encode(), at=NOW + i), str(i).encode())
    assert len(verifier._seen) <= 3


@pytest.mark.parametrize(
    "stamp",
    [f"+{NOW}", f" {NOW}", f"{NOW} ", f"{NOW}.0", f"0{NOW}", "\u0663" * 10, "1" * 40, "-1", ""],
)
def test_the_timestamp_must_be_plain_ascii_unix_seconds(secret: str, stamp: str) -> None:
    headers = {
        "X-AgentConnect-Timestamp": stamp,
        "X-AgentConnect-Signature": sign(secret, stamp, b"{}"),
    }
    with pytest.raises(SignatureError) as info:
        WebhookVerifier(secret, clock=Clock(NOW)).verify(headers, b"{}")
    assert not isinstance(info.value, SkewError)


def test_the_signature_must_match_exactly(secret: str) -> None:
    headers = request(secret, b"{}")
    good = headers["X-AgentConnect-Signature"]
    for bad in (good.upper(), good[3:], "v1=" + good[3:], good + " ", "\u00e9" + good):
        with pytest.raises(SignatureError):
            WebhookVerifier(secret, clock=Clock(NOW)).verify(
                {**headers, "X-AgentConnect-Signature": bad}, b"{}"
            )


def test_the_body_is_signed_as_received_bytes(secret: str) -> None:
    """A re-serialised body (other key order or spacing) does not verify."""
    raw = b'{"b":1,"a":2}'
    headers = request(secret, raw)
    WebhookVerifier(secret, clock=Clock(NOW)).verify(headers, raw)
    with pytest.raises(SignatureError):
        WebhookVerifier(secret, clock=Clock(NOW)).verify(headers, b'{"a":2,"b":1}')
    with pytest.raises(SignatureError):
        WebhookVerifier(secret, clock=Clock(NOW)).verify(headers, b'{"b": 1, "a": 2}')
