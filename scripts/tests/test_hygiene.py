import importlib.util
import sys
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "hygiene", Path(__file__).resolve().parents[1] / "hygiene.py"
)
assert _spec is not None
assert _spec.loader is not None
hygiene = importlib.util.module_from_spec(_spec)
sys.modules["hygiene"] = hygiene
_spec.loader.exec_module(hygiene)

# Forbidden words are assembled at runtime so this file doesn't trip the
# pre-commit scan of itself.
AI = "clau" + "de"
VENDOR = "anthro" + "pic"
PLAN = "back" + "log"
DOCS = "cont" + "ext7"
GEN = "Gener" + "ated"


@pytest.mark.parametrize(
    "text",
    [
        f"feat: thing\n\n{AI.capitalize()}-Session: https://{AI}.ai/code/session_x",
        f"fix: x\n\nCo-Authored-By: {AI.capitalize()} <noreply@{VENDOR}.com>",
        f"{GEN} with {AI.capitalize()} Code",
        f"docs: written in {AI.capitalize()} Code",
        "docs: thanks \U0001f916",
        f"chore: close {PLAN} task 12",
        f"# written with {AI} help",
        f"see {VENDOR} docs",
        f"checked via {DOCS}",
        f"{GEN} by an AI assistant",
    ],
)
def test_rejects(text: str) -> None:
    assert hygiene.scan(text, "t")


@pytest.mark.parametrize(
    "text",
    [
        "feat(sdk): add Claude Agent SDK example",
        "uv run --with claude-agent-sdk python examples/claude-agent-sdk/agent.py",
        'sdk = importlib.import_module("claude_agent_sdk")',
        "MCP / Claude Code Channels adapters are deferred.",
        "MCP and Claude Code support is coming later.",
        "claude mcp add --transport stdio agentconnect -- agentconnect mcp --agent a",
        "`claude mcp add` registers the server; everything after `--` is the",
        "### Claude Code",
        "for agent tools that speak MCP, such as Claude Code, Gemini CLI and Cursor.",
        "Co-authored-by: Jane Doe <jane@example.com>",
        "fix(relay): handle epoch conflicts",
        "Session: started",
    ],
)
def test_allows(text: str) -> None:
    assert hygiene.scan(text, "t") == []


def test_commit_message_ignores_git_comments(tmp_path: Path) -> None:
    msg = tmp_path / "MSG"
    msg.write_text(f"feat: ok\n# {AI} comment stripped by git\n", encoding="utf-8")
    assert hygiene.main(["msg", str(msg)]) == 0


def test_files_mode_reports_and_fails(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text(f"x = 1  # thanks {AI}\n", encoding="utf-8")
    good = tmp_path / "good.py"
    good.write_text("x = 1\n", encoding="utf-8")
    assert hygiene.main(["files", str(good)]) == 0
    assert hygiene.main(["files", str(good), str(bad)]) == 1


def test_bad_usage() -> None:
    assert hygiene.main([]) == 2
    assert hygiene.main(["nope"]) == 2
