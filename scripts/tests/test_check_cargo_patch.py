import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_cargo_patch", Path(__file__).resolve().parents[1] / "check_cargo_patch.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_cargo_patch"] = module
    spec.loader.exec_module(module)
    return module


ccp = _load()
REPO = Path(__file__).resolve().parents[2]
SHA = "ab" * 20
URL = "https://github.com/openmls/openmls"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _patch(rev: str = SHA, extra: str = "") -> str:
    return (
        "[patch.crates-io]\n"
        f'openmls_traits = {{ git = "{URL}", rev = "{rev}"{extra} }}\n'
        f'openmls_libcrux_crypto = {{ git = "{URL}", rev = "{rev}" }}\n'
    )


def _lock(*packages: tuple[str, str, str]) -> str:
    out = "version = 4\n"
    for name, version, source in packages:
        out += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
        if source:
            out += f'source = "{source}"\n'
    return out


GOOD_LOCK = _lock(
    ("libcrux-kem", "0.0.10", "registry+https://github.com/rust-lang/crates.io-index"),
    ("libcrux-hmac-drbg", "0.0.2", "registry+https://github.com/rust-lang/crates.io-index"),
    ("openmls_traits", "0.6.0", f"git+{URL}?rev={SHA}#{SHA}"),
)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _write(tmp_path / "Cargo.toml", '[workspace]\nmembers = ["core"]\n\n' + _patch())
    _write(tmp_path / "Cargo.lock", GOOD_LOCK)
    _write(tmp_path / "core" / "Cargo.toml", '[package]\nname = "core"\n')
    _write(
        tmp_path / "core" / "fuzz" / "Cargo.toml",
        '[package]\nname = "f"\n\n[workspace]\n\n' + _patch(),
    )
    _write(tmp_path / "core" / "fuzz" / "Cargo.lock", GOOD_LOCK)
    return tmp_path


def test_consistent_tree_passes(repo: Path) -> None:
    assert ccp.check(repo) == []


def test_this_repository_passes() -> None:
    assert ccp.check(REPO) == []


def _git(repo: Path, *args: str) -> None:
    # Without GIT_*: git exports GIT_DIR and friends to the pre-push hook that
    # runs these tests, and they would point `init` and `add` at the real repository.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    subprocess.run(["git", "-C", str(repo), *args], env=env, check=True)


def _git_add(repo: Path) -> None:
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")


def _untracked_worktree(repo: Path) -> None:
    # A copy of the tree with an unpatched workspace and an affected lockfile,
    # like an agent worktree inside the checkout.
    _write(repo / "worktrees" / "wt" / "Cargo.toml", "[workspace]\n")
    _write(repo / "worktrees" / "wt" / "fuzz" / "Cargo.toml", "[workspace]\n")
    _write(
        repo / "worktrees" / "wt" / "Cargo.lock",
        _lock(("libcrux-kem", "0.0.9", "registry+https://github.com/rust-lang/crates.io-index")),
    )


def test_untracked_worktrees_are_not_scanned(repo: Path) -> None:
    _git_add(repo)
    _untracked_worktree(repo)
    assert ccp.check(repo) == []


def test_tracked_files_are_still_scanned_in_a_checkout(repo: Path) -> None:
    _git_add(repo)
    _write(repo / "relay" / "fuzz" / "Cargo.toml", '[package]\nname = "r"\n\n[workspace]\n')
    _git(repo, "add", "-A")
    assert any("relay/fuzz/Cargo.toml" in p for p in ccp.check(repo))


def test_without_git_every_directory_is_scanned(repo: Path) -> None:
    _untracked_worktree(repo)
    problems = ccp.check(repo)
    assert any("worktrees/wt/Cargo.lock" in p for p in problems)


def test_workspace_without_the_patch_fails(repo: Path) -> None:
    _write(repo / "relay" / "fuzz" / "Cargo.toml", '[package]\nname = "r"\n\n[workspace]\n')
    assert ccp.check(repo) == [
        "relay/fuzz/Cargo.toml: its [patch.crates-io] table must be identical"
        " to the root Cargo.toml's"
    ]


def test_workspace_with_another_rev_fails(repo: Path) -> None:
    _write(
        repo / "core" / "fuzz" / "Cargo.toml",
        '[package]\nname = "f"\n\n[workspace]\n\n' + _patch(rev="cd" * 20),
    )
    assert len(ccp.check(repo)) == 1


def test_member_crates_need_no_patch(repo: Path) -> None:
    # `core/Cargo.toml` has no [workspace] table and no patch.
    assert ccp.check(repo) == []


@pytest.mark.parametrize("rev", ["refs/heads/main", SHA[:7], SHA.upper(), SHA + "0"])
def test_rev_must_be_a_full_commit_sha(repo: Path, rev: str) -> None:
    _write(repo / "Cargo.toml", '[workspace]\nmembers = ["core"]\n\n' + _patch(rev=rev))
    problems = ccp.check(repo)
    assert (
        "Cargo.toml: [patch.crates-io] openmls_traits: rev must be a full 40-hex commit SHA"
        in problems
    )


def test_branch_is_refused(repo: Path) -> None:
    _write(repo / "Cargo.toml", "[workspace]\n\n" + _patch(extra=', branch = "main"'))
    assert (
        "Cargo.toml: [patch.crates-io] openmls_traits: pin a git patch by rev, not by branch or tag"
        in ccp.check(repo)
    )


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("libcrux-kem", "0.0.9"),
        ("libcrux-kem", "0.0.10-pre.1"),
        ("libcrux-hmac-drbg", "0.0.1"),
        ("libcrux-hmac-drbg", "0.0.2-pre.1"),
    ],
)
def test_affected_libcrux_in_any_lockfile_fails(repo: Path, name: str, version: str) -> None:
    _write(repo / "core" / "fuzz" / "Cargo.lock", _lock((name, version, "")))
    fixed = {"libcrux-kem": "0.0.10", "libcrux-hmac-drbg": "0.0.2"}[name]
    assert ccp.check(repo) == [
        f"core/fuzz/Cargo.lock: {name} {version} is affected (fixed in {fixed})"
    ]


def test_later_libcrux_versions_pass(repo: Path) -> None:
    _write(
        repo / "Cargo.lock", _lock(("libcrux-kem", "0.1.0", ""), ("libcrux-hmac-drbg", "0.0.3", ""))
    )
    assert ccp.check(repo) == []


@pytest.mark.parametrize(
    "source",
    [
        f"git+{URL}?branch=main#{SHA}",
        f"git+{URL}?rev=refs%2Fheads%2Fmain#{SHA}",
        f"git+{URL}?rev={SHA}#{'cd' * 20}",
        f"git+{URL}#{SHA}",
    ],
)
def test_lockfile_git_source_must_pin_a_full_rev(repo: Path, source: str) -> None:
    _write(repo / "Cargo.lock", _lock(("openmls_traits", "0.6.0", source)))
    assert len(ccp.check(repo)) == 1


@pytest.mark.parametrize(
    ("req", "version", "expected"),
    [
        ("^0.4.0", "0.4.1", True),
        ("^0.4.0", "0.5.0", False),
        ("0.4", "0.4.9", True),
        ("^0.0.2", "0.0.2", True),
        ("^0.0.2", "0.0.3", False),
        ("=0.0.10", "0.0.10", True),
        ("=0.0.10", "0.0.11", False),
        ("~0.8.1", "0.8.4", True),
        ("~0.8.1", "0.9.0", False),
        (">=0.30.1, <0.38.0", "0.37.0", True),
        (">=0.30.1, <0.38.0", "0.38.0", False),
        ("^1.2", "1.9.0", True),
        ("^1.2", "2.0.0", False),
        ("*", "3.0.0", True),
    ],
)
def test_requirement_matching(req: str, version: str, expected: bool) -> None:
    assert ccp.matches(req, version) is expected


def test_unsupported_requirement_is_an_error() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        ccp.matches("0.4 || 0.5", "0.4.0")


def _registry(provider: dict[str, dict[str, str]]) -> dict[str, Any]:
    releases = {
        "openmls_libcrux_crypto": list(provider),
        "libcrux-hmac-drbg": ["0.0.1", "0.0.2"],
        "libcrux-kem": ["0.0.9", "0.0.10"],
        "hpke-rs-libcrux": ["0.7.0", "0.8.0"],
        "openmls_traits": ["0.6.0", "0.7.0"],
        "openmls_memory_storage": ["0.6.0", "0.7.0"],
    }
    deps = {
        ("openmls", "0.9.1"): {
            "openmls_traits": "^0.6.0",
            "openmls_memory_storage": "^0.6.0",
            "openmls_libcrux_crypto": "^0.4.0",
        },
        ("hpke-rs-libcrux", "0.7.0"): {"libcrux-kem": "=0.0.9"},
        ("hpke-rs-libcrux", "0.8.0"): {"libcrux-kem": "=0.0.10"},
        **{("openmls_libcrux_crypto", v): d for v, d in provider.items()},
    }
    data: dict[str, Any] = {}
    for crate, nums in releases.items():
        versions = [{"num": n, "yanked": False} for n in nums]
        data[f"{ccp.CRATES_IO}/{crate}/versions"] = {"versions": versions}
    for (crate, version), reqs in deps.items():
        listed = [{"crate_id": c, "req": r, "kind": "normal"} for c, r in reqs.items()]
        listed.append({"crate_id": "dev-only", "req": "^1", "kind": "dev"})
        data[f"{ccp.CRATES_IO}/{crate}/{version}/dependencies"] = {"dependencies": listed}
    return data


SHARED_06 = {"openmls_traits": "^0.6.0", "openmls_memory_storage": "^0.6.0"}
VULNERABLE = {"libcrux-hmac-drbg": "^0.0.1", "hpke-rs-libcrux": "^0.7", **SHARED_06}
FIXED = {"libcrux-hmac-drbg": "^0.0.2", "hpke-rs-libcrux": "^0.8", **SHARED_06}


def _upstream(tmp_path: Path, provider: dict[str, dict[str, str]]) -> Any:
    _write(
        tmp_path / "Cargo.toml",
        '[workspace.dependencies]\nopenmls = { version = "=0.9.1" }\n',
    )
    return ccp.upstream(tmp_path, _registry(provider).__getitem__)


def test_upstream_quiet_while_only_the_vulnerable_release_exists(tmp_path: Path) -> None:
    assert _upstream(tmp_path, {"0.4.0": VULNERABLE}) == []


def test_upstream_flags_a_fixed_compatible_release(tmp_path: Path) -> None:
    problems = _upstream(tmp_path, {"0.4.0": VULNERABLE, "0.4.1": FIXED})
    assert len(problems) == 1
    assert "openmls_libcrux_crypto 0.4.1" in problems[0]
    assert "openmls 0.9.1" in problems[0]


def test_upstream_accepts_a_direct_libcrux_kem_dependency(tmp_path: Path) -> None:
    direct = {"libcrux-hmac-drbg": "^0.0.2", "libcrux-kem": "^0.0.10", **SHARED_06}
    assert len(_upstream(tmp_path, {"0.4.1": direct})) == 1


@pytest.mark.parametrize(
    "deps",
    [
        {**FIXED, "libcrux-hmac-drbg": "^0.0.1"},
        {**FIXED, "hpke-rs-libcrux": "^0.7"},
        {**FIXED, "openmls_traits": "^0.7.0"},
        {**FIXED, "openmls_memory_storage": "^0.7.0"},
    ],
)
def test_upstream_ignores_releases_that_are_unfixed_or_incompatible(
    tmp_path: Path, deps: dict[str, str]
) -> None:
    assert _upstream(tmp_path, {"0.4.1": deps}) == []


def test_upstream_ignores_releases_openmls_does_not_accept(tmp_path: Path) -> None:
    # openmls 0.9.1 asks for ^0.4.0, so a fixed 0.5.0 needs an openmls move.
    assert _upstream(tmp_path, {"0.5.0": FIXED}) == []


def test_openmls_must_be_pinned_exactly(tmp_path: Path) -> None:
    _write(tmp_path / "Cargo.toml", '[workspace.dependencies]\nopenmls = { version = "0.9.1" }\n')
    with pytest.raises(ValueError, match="pinned exactly"):
        ccp.pinned_openmls(tmp_path)


def test_main(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert ccp.main([]) == 2
    assert ccp.main(["check", str(repo)]) == 0
    assert "ok" in capsys.readouterr().out
    _write(repo / "Cargo.lock", _lock(("libcrux-kem", "0.0.9", "")))
    assert ccp.main(["check", str(repo)]) == 1
    assert "libcrux-kem 0.0.9 is affected" in capsys.readouterr().err
