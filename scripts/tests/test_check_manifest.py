import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_manifest", Path(__file__).resolve().parents[1] / "check_manifest.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_manifest"] = module
    spec.loader.exec_module(module)
    return module


check_manifest = _load()
REPO = Path(__file__).resolve().parents[2]


def _write(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _manifest(root: Path, files: dict[str, object]) -> None:
    _write(root / "testdata" / "MANIFEST.json", json.dumps({"version": 1, "files": files}))


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _write(tmp_path / "testdata" / "vec.json", "[]")
    _manifest(tmp_path, {"vec.json": {"suites": ["rust", "python"]}})
    _write(tmp_path / "core" / "tests" / "vec.rs", 'include_str!("../../testdata/vec.json");')
    _write(tmp_path / "daemon" / "tests" / "test_vec.py", "NAME = 'vec.json'")
    return tmp_path


def test_real_repository_is_consistent() -> None:
    assert check_manifest.check(REPO) == []


def test_consistent_repo_passes(repo: Path) -> None:
    assert check_manifest.check(repo) == []


def test_missing_manifest(tmp_path: Path) -> None:
    assert "is missing" in check_manifest.check(tmp_path)[0]


def test_malformed_manifest(repo: Path) -> None:
    _write(repo / "testdata" / "MANIFEST.json", "{not json")
    assert "malformed" in check_manifest.check(repo)[0]
    _write(repo / "testdata" / "MANIFEST.json", "[]")
    assert "malformed" in check_manifest.check(repo)[0]


def test_file_not_in_manifest(repo: Path) -> None:
    _write(repo / "testdata" / "sub" / "extra.json")
    assert check_manifest.check(repo) == [
        "sub/extra.json: in testdata/ but not listed in MANIFEST.json"
    ]


def test_manifest_entry_without_file(repo: Path) -> None:
    (repo / "testdata" / "vec.json").unlink()
    assert check_manifest.check(repo) == [
        "vec.json: listed in MANIFEST.json but missing from testdata/"
    ]


@pytest.mark.parametrize(
    ("suite", "path"),
    [("rust", "core/tests/vec.rs"), ("python", "daemon/tests/test_vec.py")],
)
def test_unreferenced_by_declared_suite(repo: Path, suite: str, path: str) -> None:
    _write(repo / path, "// nothing here")
    assert check_manifest.check(repo) == [f"vec.json: no {suite} test references it"]


def test_only_declared_suites_are_required(repo: Path) -> None:
    _manifest(repo, {"vec.json": {"suites": ["python"]}})
    (repo / "core" / "tests" / "vec.rs").unlink()
    assert check_manifest.check(repo) == []


def test_python_non_test_files_do_not_count(repo: Path) -> None:
    _write(repo / "daemon" / "tests" / "test_vec.py", "")
    _write(repo / "daemon" / "src" / "helper.py", "NAME = 'vec.json'")
    assert check_manifest.check(repo) == ["vec.json: no python test references it"]


def test_bad_suites_are_reported(repo: Path) -> None:
    _manifest(repo, {"vec.json": {"suites": []}})
    assert "non-empty list" in check_manifest.check(repo)[0]
    _manifest(repo, {"vec.json": {"suites": ["go"]}})
    assert "unknown suite 'go'" in check_manifest.check(repo)[0]


def test_build_dirs_are_ignored(repo: Path) -> None:
    (repo / "core" / "tests" / "vec.rs").unlink()
    _write(repo / "target" / "debug" / "x.rs", "vec.json")
    assert check_manifest.check(repo) == ["vec.json: no rust test references it"]


def test_main_exit_codes(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert check_manifest.main([str(repo)]) == 0
    assert "ok" in capsys.readouterr().out
    _write(repo / "testdata" / "extra.json")
    assert check_manifest.main([str(repo)]) == 1
    assert "extra.json" in capsys.readouterr().err
