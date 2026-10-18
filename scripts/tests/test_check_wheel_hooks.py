import importlib.util
import sys
import zipfile
from pathlib import Path
from types import ModuleType

import agentconnect_core as ac


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_wheel_hooks", Path(__file__).resolve().parents[1] / "check_wheel_hooks.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_wheel_hooks"] = module
    spec.loader.exec_module(module)
    return module


check = _load()


def _wheel(tmp: Path, name: str, native: bytes) -> Path:
    path = tmp / name
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("agentconnect_core/__init__.py", "")
        z.writestr("agentconnect_core/_native.abi3.so", native)
    return path


def test_a_wheel_without_hooks_passes(tmp_path: Path) -> None:
    clean = _wheel(tmp_path, "clean.whl", b"\x7fELF ... create_knock ... add_knock")
    assert check.hooks_in(clean) == []
    assert check.main([str(clean)]) == 0


def test_a_wheel_with_a_hook_fails(tmp_path: Path) -> None:
    hooked = _wheel(tmp_path, "hooked.whl", b"\x7fELF _add_knock_unchecked_for_testing")
    assert check.hooks_in(hooked) == ["_add_knock_unchecked_for_testing"]
    assert check.main([str(hooked)]) == 1
    assert check.main([]) == 2


def test_the_unchecked_commit_hook_fails_a_wheel(tmp_path: Path) -> None:
    hooked = _wheel(tmp_path, "commit.whl", b"\x7fELF _commit_unchecked_for_testing")
    assert check.hooks_in(hooked) == ["_commit_unchecked_for_testing"]
    assert check.main([str(hooked)]) == 1


def test_the_development_build_has_the_hooks() -> None:
    """The test environment (uv sync) builds the core with ``test-hooks``;
    the names the check looks for are the ones that build exports."""
    for hook in check.TEST_HOOKS:
        assert hasattr(ac.Client, hook.decode())
