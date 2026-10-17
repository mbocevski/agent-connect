"""Reject AI-tool attribution and internal tooling references.

Commits, PR text, code comments and docs must not mention the assistants or
planning tools used to produce them. Product names we integrate with (for
example an agent SDK) are allowed through ALLOWED_PHRASES.

usage:
    hygiene.py files PATH...      scan files (pre-commit)
    hygiene.py msg FILE           scan a commit message file (commit-msg)
    hygiene.py range BASE         scan commit messages in BASE..HEAD (CI)
    hygiene.py text               scan stdin (PR title/body)
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Integration targets that legitimately contain a forbidden word. Matched
# case-insensitively and blanked out before the forbidden patterns run.
ALLOWED_PHRASES: tuple[str, ...] = (
    "Claude Agent SDK",
    "Claude Code Channels",
)

# Character classes like `cl[a]ude` keep this file from matching itself.
FORBIDDEN: tuple[tuple[str, str], ...] = (
    (r"\bcl[a]ude\b", "AI assistant name"),
    (r"\banthr[o]pic\b", "AI vendor name"),
    (r"\b(cl[a]ude|chatgpt|copilot|gemini|cursor)[\w.-]*\.(ai|com)\b", "AI tool URL"),
    (r"^\s*co-authored-by:.*\b(ai|bot|noreply@|gpt|copilot|gemini)\b", "AI co-author trailer"),
    (r"^\s*[\w-]*session:\s*https?://", "session-link trailer"),
    (r"\bgenerat[e]d (with|by)\b.*\b(ai|gpt|copilot|gemini|assistant|llm)\b", "AI notice"),
    (r"\U0001f916", "robot emoji attribution"),
    (r"\bb[a]cklog\b", "planning-tool reference"),
    (r"\bc[o]ntext7\b", "docs-tool reference"),
)

_ALLOWED = [re.compile(re.escape(p), re.IGNORECASE) for p in ALLOWED_PHRASES]
_FORBIDDEN = [(re.compile(p, re.IGNORECASE | re.MULTILINE), why) for p, why in FORBIDDEN]


@dataclass(frozen=True)
class Finding:
    where: str
    line: int
    reason: str
    text: str


def scan(text: str, where: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw
        for allowed in _ALLOWED:
            line = allowed.sub(" ", line)
        for pattern, why in _FORBIDDEN:
            if pattern.search(line):
                findings.append(Finding(where, lineno, why, raw.strip()))
                break
    return findings


def _commit_message_body(text: str) -> str:
    # git strips comment lines from commit messages; don't flag them.
    return "\n".join(line for line in text.splitlines() if not line.startswith("#"))


def _scan_files(paths: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for p in paths:
        try:
            text = Path(p).read_text(encoding="utf-8")
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue
        findings += scan(text, p)
    return findings


def _scan_range(base: str) -> list[Finding]:
    out = subprocess.run(  # noqa: S603
        ["git", "log", "--format=%H%x00%B%x1e", f"{base}..HEAD"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    findings: list[Finding] = []
    for record in filter(None, (r.strip() for r in out.split("\x1e"))):
        sha, _, body = record.partition("\x00")
        findings += scan(body, f"commit {sha[:12]}")
    return findings


def main(argv: list[str]) -> int:
    if len(argv) < 1:
        print(__doc__, file=sys.stderr)
        return 2
    mode, args = argv[0], argv[1:]
    if mode == "files":
        findings = _scan_files(args)
    elif mode == "msg" and len(args) == 1:
        text = Path(args[0]).read_text(encoding="utf-8")
        findings = scan(_commit_message_body(text), "commit message")
    elif mode == "range" and len(args) == 1:
        findings = _scan_range(args[0])
    elif mode == "text":
        findings = scan(sys.stdin.read(), "text")
    else:
        print(__doc__, file=sys.stderr)
        return 2

    for f in findings:
        print(f"{f.where}:{f.line}: {f.reason}: {f.text}", file=sys.stderr)
    if findings:
        print(
            "error: remove AI-tool attribution / internal tooling references (see AGENTS.md).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
