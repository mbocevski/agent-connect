"""Coverage ratchet: fail if coverage drops more than a tolerance below baseline.

Reports are named `component=path`. Two JSON shapes are understood:

* cargo-llvm-cov (`--json`): line coverage from `data[0].totals.lines.percent`.
* coverage.py (`--cov-report=json`): `totals.percent_covered` (lines + branches).

usage:
    cov_ratchet.py check  [--baseline FILE] [--tolerance PP] NAME=REPORT...
    cov_ratchet.py update [--baseline FILE] NAME=REPORT...

`check` only compares the components it is given. `update` rewrites just those
components in the baseline file and leaves the others untouched.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

DEFAULT_BASELINE = Path(__file__).resolve().parent.parent / "coverage-baseline.json"
DEFAULT_TOLERANCE = 0.5


def read_percent(report: Path) -> float:
    """Extract the headline coverage percentage from a coverage report."""
    data: Any = json.loads(report.read_text(encoding="utf-8"))
    if "data" in data:
        return float(data["data"][0]["totals"]["lines"]["percent"])
    return float(data["totals"]["percent_covered"])


def parse_reports(specs: list[str]) -> dict[str, float]:
    result: dict[str, float] = {}
    for spec in specs:
        name, sep, path = spec.partition("=")
        if not sep or not name or not path:
            msg = f"expected NAME=REPORT, got {spec!r}"
            raise ValueError(msg)
        result[name] = read_percent(Path(path))
    return result


def load_baseline(path: Path) -> dict[str, float]:
    data: Any = json.loads(path.read_text(encoding="utf-8"))
    return {name: float(value) for name, value in data["components"].items()}


def compare(current: dict[str, float], baseline: dict[str, float], tolerance: float) -> list[str]:
    """Return one message per component that regressed beyond `tolerance`."""
    problems: list[str] = []
    for name, value in sorted(current.items()):
        if name not in baseline:
            problems.append(f"{name}: no baseline (run `just cov-baseline`)")
        elif value < baseline[name] - tolerance:
            problems.append(
                f"{name}: {value:.2f}% is more than {tolerance}pp below baseline "
                f"{baseline[name]:.2f}%"
            )
    return problems


def write_baseline(path: Path, updates: dict[str, float]) -> None:
    components = load_baseline(path) if path.exists() else {}
    components.update({name: round(value, 2) for name, value in updates.items()})
    payload = {"components": dict(sorted(components.items()))}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("command", choices=["check", "update"])
    parser.add_argument("reports", nargs="+", metavar="NAME=REPORT")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE)
    args = parser.parse_args(argv)

    try:
        current = parse_reports(args.reports)
    except (ValueError, OSError, KeyError, IndexError, json.JSONDecodeError) as exc:
        print(f"cov_ratchet: cannot read reports: {exc!r}", file=sys.stderr)
        return 2

    if args.command == "update":
        write_baseline(args.baseline, current)
        for name, value in sorted(current.items()):
            print(f"cov_ratchet: baseline {name} = {value:.2f}%")
        return 0

    try:
        baseline = load_baseline(args.baseline)
    except (OSError, KeyError, ValueError) as exc:
        print(f"cov_ratchet: cannot read baseline: {exc!r}", file=sys.stderr)
        return 2
    for name, value in sorted(current.items()):
        base = baseline.get(name)
        shown = "none" if base is None else f"{base:.2f}%"
        print(f"cov_ratchet: {name} {value:.2f}% (baseline {shown})")
    problems = compare(current, baseline, args.tolerance)
    for problem in problems:
        print(f"cov_ratchet: FAIL {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
