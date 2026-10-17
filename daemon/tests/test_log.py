"""Logs never carry local variables or message content (AGENTS.md)."""

from __future__ import annotations

import json
import logging

import pytest
import structlog

from agentconnect import log

MARKER = "PLAINTEXT-MARKER-in-a-local"


def fail_with_secret_locals() -> None:
    envelope = {"ct": MARKER, "inner": {"text": MARKER}}
    secret = MARKER.encode()
    msg = f"failed after {len(secret)} bytes"
    raise RuntimeError(msg + str(len(envelope)))


def test_a_forced_exception_logs_no_locals(capsys: pytest.CaptureFixture[str]) -> None:
    # Even if the embedding application configured structlog's console
    # renderer, which prints locals with every traceback.
    structlog.configure(processors=[structlog.dev.ConsoleRenderer()])
    try:
        logger = log.get("test")
        try:
            fail_with_secret_locals()
        except RuntimeError:
            logger.exception("inbound_failed", t="deliver")
        logger.info("redacted", body={"text": MARKER}, env=MARKER, url=MARKER, kept="ok")
    finally:
        structlog.reset_defaults()
    err = capsys.readouterr().err
    assert MARKER not in err
    lines = [json.loads(line) for line in err.splitlines()]
    failed, redacted = lines
    assert failed["event"] == "inbound_failed"
    assert failed["level"] == "error"
    assert "fail_with_secret_locals" in failed["exception"]  # a traceback
    assert "RuntimeError" in failed["exception"]
    assert redacted["body"] == redacted["env"] == redacted["url"] == "[redacted]"
    assert redacted["kept"] == "ok"
    assert redacted["logger"] == "test"


def test_levels_filter(capsys: pytest.CaptureFixture[str]) -> None:
    logger = log.get("test")
    log.configure(logging.WARNING)
    try:
        logger.info("hidden")
        logger.warning("shown", exc_info=RuntimeError("boom"))
        logger.error("also", exc_info=False)
    finally:
        log.configure(logging.INFO)
    lines = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert [x["event"] for x in lines] == ["shown", "also"]
    assert "boom" in lines[0]["exception"]
    assert "exception" not in lines[1]
