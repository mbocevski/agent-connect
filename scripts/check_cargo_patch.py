"""Guard the temporary OpenMLS provider patch (ADR-001 §2).

The root `Cargo.toml` patches the OpenMLS provider crates to one upstream
commit (RUSTSEC-2026-0329, -0330, -0331). `check` fails when:

* a Cargo workspace in the tree (a `Cargo.toml` with a `[workspace]` table,
  such as the fuzz workspaces) lacks the root's `[patch.crates-io]` table, or
  has a different one;
* a git entry in any `[patch]` table isn't pinned by a full 40-hex commit
  SHA (cargo-deny's `required-git-spec = "rev"` also accepts short revs and
  refs such as `refs/heads/main`), or names a branch or tag;
* a `Cargo.lock` holds `libcrux-kem` < 0.0.10 or `libcrux-hmac-drbg` < 0.0.2,
  or a git source that isn't `?rev=<sha>#<same sha>` with a full SHA.

`upstream` (nightly, needs the network) fails when crates.io has an
`openmls_libcrux_crypto` release on the fixed libcrux crates that works with
the `openmls` release the workspace pins. That is the condition for removing
the patch, so the nightly failure issue tells someone.

usage: check_cargo_patch.py check [ROOT]    (default: the repository root)
       check_cargo_patch.py upstream [ROOT]
"""

from __future__ import annotations

import json
import os
import re
import sys
import tomllib
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

_SKIP_DIRS = frozenset({".git", ".venv", "target", "node_modules", "__pycache__"})
_SHA = re.compile(r"[0-9a-f]{40}")
_LOCK_GIT = re.compile(r"git\+[^?#]+\?rev=([0-9a-f]{40})#([0-9a-f]{40})")

# The first fixed releases (RUSTSEC-2026-0330/-0331 and RUSTSEC-2026-0329).
FIXED = {"libcrux-kem": (0, 0, 10), "libcrux-hmac-drbg": (0, 0, 2)}
PROVIDER = "openmls_libcrux_crypto"
# The provider's dependencies that must resolve together with `openmls`.
SHARED = ("openmls_traits", "openmls_memory_storage")
USER_AGENT = "agent-connect-ci (+https://github.com/mbocevski/agent-connect)"
CRATES_IO = "https://crates.io/api/v1/crates"

Version = tuple[int, int, int, str]
_FULL = 3  # major.minor.patch
_MAJOR_MINOR = 2


def _files(root: Path, name: str) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        if name in filenames:
            yield Path(dirpath, name)


def _toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def parse_version(text: str) -> Version:
    core, _, pre = text.partition("+")[0].partition("-")
    parts = [int(p) for p in core.split(".")]
    major, minor, patch = [*parts, 0, 0, 0][:3]
    return (major, minor, patch, pre)


def _below(version: Version, fixed: tuple[int, int, int]) -> bool:
    # A pre-release of the fixed version is still below it.
    return version[:3] < fixed or (version[:3] == fixed and version[3] != "")


def _patch_problems(rel: str, manifest: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for registry, entries in manifest.get("patch", {}).items():
        for crate, spec in entries.items():
            if not isinstance(spec, dict) or "git" not in spec:
                continue
            where = f"{rel}: [patch.{registry}] {crate}"
            if "branch" in spec or "tag" in spec:
                problems.append(f"{where}: pin a git patch by rev, not by branch or tag")
            if not _SHA.fullmatch(str(spec.get("rev", ""))):
                problems.append(f"{where}: rev must be a full 40-hex commit SHA")
    return problems


def _lock_problems(rel: str, lock: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for package in lock.get("package", []):
        name, version = package.get("name"), package.get("version", "0")
        fixed = FIXED.get(name)
        if fixed is not None and _below(parse_version(version), fixed):
            want = ".".join(map(str, fixed))
            problems.append(f"{rel}: {name} {version} is affected (fixed in {want})")
        source = package.get("source", "")
        if source.startswith("git+"):
            m = _LOCK_GIT.fullmatch(source)
            if m is None or m.group(1) != m.group(2):
                problems.append(
                    f"{rel}: {name} {version} has git source {source!r}, not ?rev=<sha>#<sha>"
                )
    return problems


def check(root: Path) -> list[str]:
    """Return a list of problems (empty when the patch is consistent)."""
    root_patch = _toml(root / "Cargo.toml").get("patch", {}).get("crates-io")
    problems: list[str] = []
    for path in _files(root, "Cargo.toml"):
        rel = path.relative_to(root).as_posix()
        manifest = _toml(path)
        problems.extend(_patch_problems(rel, manifest))
        is_workspace = "workspace" in manifest and path.parent != root
        own = manifest.get("patch", {}).get("crates-io")
        if root_patch and is_workspace and own != root_patch:
            problems.append(
                f"{rel}: its [patch.crates-io] table must be identical to the root Cargo.toml's"
            )
    for path in _files(root, "Cargo.lock"):
        problems.extend(_lock_problems(path.relative_to(root).as_posix(), _toml(path)))
    return problems


# --- upstream: is there a crates.io release that makes the patch removable? ---


def _bounds(req: str) -> list[tuple[str, Version]]:
    """Cargo version requirement as (op, version) comparators."""
    out: list[tuple[str, Version]] = []
    for part in (p.strip() for p in req.split(",")):
        if part in ("", "*"):
            continue
        m = re.fullmatch(r"(\^|~|=|>=|<=|>|<)?\s*(\d+(?:\.\d+){0,2})(-[0-9A-Za-z.-]+)?", part)
        if m is None:
            raise ValueError(f"unsupported version requirement {req!r}")
        op, nums, pre = m.group(1) or "^", m.group(2), (m.group(3) or "")[1:]
        given = nums.count(".") + 1
        low = parse_version(nums)
        low = (low[0], low[1], low[2], pre)
        if op in ("^", "~", "="):
            if op == "=" and given == _FULL:
                out.append(("=", low))
                continue
            major, minor, patch = low[:3]
            if op in {"~", "="}:
                high = (major + 1, 0, 0) if given == 1 else (major, minor + 1, 0)
            elif major > 0 or given == 1:
                high = (major + 1, 0, 0)
            elif minor > 0 or given == _MAJOR_MINOR:
                high = (0, minor + 1, 0)
            else:
                high = (0, 0, patch + 1)
            out.append((">=", low))
            out.append(("<", (*high, "")))
        else:
            out.append((op, low))
    return out


def _key(v: Version) -> tuple[int, int, int, int, str]:
    # A release sorts above its pre-releases.
    return (v[0], v[1], v[2], 0 if v[3] else 1, v[3])


def matches(req: str, version: str) -> bool:
    """Whether a release `version` satisfies the Cargo requirement `req`."""
    v = parse_version(version)
    ops: dict[str, Callable[[Version], bool]] = {
        "=": lambda b: _key(v) == _key(b),
        ">=": lambda b: _key(v) >= _key(b),
        ">": lambda b: _key(v) > _key(b),
        "<=": lambda b: _key(v) <= _key(b),
        "<": lambda b: _key(v) < _key(b),
    }
    return all(ops[op](bound) for op, bound in _bounds(req))


def lowest(req: str, versions: list[str]) -> str | None:
    """The lowest release in `versions` that satisfies `req`."""
    ok = [v for v in versions if matches(req, v)]
    return min(ok, key=lambda v: _key(parse_version(v))) if ok else None


class CratesIo:
    """Reads crate versions and dependencies from the crates.io API."""

    def __init__(self, fetch: Callable[[str], Any]) -> None:
        self._fetch = fetch

    def releases(self, crate: str) -> list[str]:
        data = self._fetch(f"{CRATES_IO}/{crate}/versions")
        return [v["num"] for v in data["versions"] if not v["yanked"] and "-" not in v["num"]]

    def deps(self, crate: str, version: str) -> dict[str, str]:
        data = self._fetch(f"{CRATES_IO}/{crate}/{version}/dependencies")
        return {d["crate_id"]: d["req"] for d in data["dependencies"] if d["kind"] == "normal"}


def _fixed_min(api: CratesIo, deps: dict[str, str], crate: str) -> bool:
    """Whether the lowest version of `crate` that `deps` allows is fixed."""
    req = deps.get(crate)
    if req is None:
        return False
    low = lowest(req, api.releases(crate))
    return low is not None and not _below(parse_version(low), FIXED[crate])


def _kem_fixed(api: CratesIo, deps: dict[str, str]) -> bool:
    if "libcrux-kem" in deps:
        return _fixed_min(api, deps, "libcrux-kem")
    req = deps.get("hpke-rs-libcrux")
    low = lowest(req, api.releases("hpke-rs-libcrux")) if req is not None else None
    return low is not None and _fixed_min(api, api.deps("hpke-rs-libcrux", low), "libcrux-kem")


def _shared_ok(api: CratesIo, provider: dict[str, str], openmls: dict[str, str]) -> bool:
    for crate in SHARED:
        a, b = provider.get(crate), openmls.get(crate)
        if a is None or b is None:
            return False
        if not any(matches(a, v) and matches(b, v) for v in api.releases(crate)):
            return False
    return True


def removable(api: CratesIo, openmls_version: str) -> list[str]:
    """Provider releases that are fixed and work with `openmls_version`."""
    openmls = api.deps("openmls", openmls_version)
    wanted = openmls.get(PROVIDER)
    found: list[str] = []
    for version in api.releases(PROVIDER):
        if wanted is None or not matches(wanted, version):
            continue
        deps = api.deps(PROVIDER, version)
        if (
            _fixed_min(api, deps, "libcrux-hmac-drbg")
            and _kem_fixed(api, deps)
            and _shared_ok(api, deps, openmls)
        ):
            found.append(version)
    return found


def pinned_openmls(root: Path) -> str:
    req = _toml(root / "Cargo.toml")["workspace"]["dependencies"]["openmls"]["version"]
    m = re.fullmatch(r"=\s*(\d+\.\d+\.\d+)", req)
    if m is None:
        raise ValueError(f"openmls must be pinned exactly, got {req!r}")
    return str(m.group(1))


def _fetch_json(url: str) -> Any:
    if not url.startswith(CRATES_IO + "/"):
        raise ValueError(f"refusing to fetch {url!r}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        return json.load(response)


def upstream(root: Path, fetch: Callable[[str], Any] = _fetch_json) -> list[str]:
    openmls = pinned_openmls(root)
    return [
        f"crates.io has {PROVIDER} {v} on the fixed libcrux crates, compatible with openmls "
        f"{openmls}: remove the [patch.crates-io] block (Cargo.toml, the fuzz workspaces, "
        "deny.toml allow-git) and move to it"
        for v in removable(CratesIo(fetch), openmls)
    ]


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("check", "upstream"):
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent
    problems = check(root) if argv[0] == "check" else upstream(root)
    for problem in problems:
        print(f"check_cargo_patch: {problem}", file=sys.stderr)
    if not problems:
        print(f"check_cargo_patch {argv[0]}: ok")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
