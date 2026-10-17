import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "cov_ratchet", Path(__file__).resolve().parents[1] / "cov_ratchet.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["cov_ratchet"] = module
    spec.loader.exec_module(module)
    return module


cov_ratchet = _load()


def _llvm(path: Path, percent: float) -> str:
    path.write_text(json.dumps({"data": [{"totals": {"lines": {"percent": percent}}}]}))
    return str(path)


def _pycov(path: Path, percent: float) -> str:
    path.write_text(json.dumps({"totals": {"percent_covered": percent}}))
    return str(path)


def _baseline(path: Path, **components: float) -> str:
    path.write_text(json.dumps({"components": components}))
    return str(path)


def test_reads_both_report_shapes(tmp_path: Path) -> None:
    assert cov_ratchet.read_percent(Path(_llvm(tmp_path / "a.json", 91.5))) == 91.5
    assert cov_ratchet.read_percent(Path(_pycov(tmp_path / "b.json", 88.25))) == 88.25


def test_within_tolerance_passes() -> None:
    assert cov_ratchet.compare({"core": 96.6}, {"core": 97.0}, 0.5) == []
    assert cov_ratchet.compare({"core": 99.0}, {"core": 97.0}, 0.5) == []


def test_drop_beyond_tolerance_fails() -> None:
    problems = cov_ratchet.compare({"core": 96.4}, {"core": 97.0}, 0.5)
    assert len(problems) == 1
    assert "core" in problems[0]


def test_missing_baseline_fails() -> None:
    assert "no baseline" in cov_ratchet.compare({"relay": 80.0}, {}, 0.5)[0]


def test_check_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = _baseline(tmp_path / "base.json", core=97.0, python=90.0)
    ok = [_llvm(tmp_path / "c.json", 97.2), _pycov(tmp_path / "p.json", 89.6)]
    args = ["check", "--baseline", base, f"core={ok[0]}", f"python={ok[1]}"]
    assert cov_ratchet.main(args) == 0
    capsys.readouterr()

    low = _llvm(tmp_path / "low.json", 90.0)
    assert cov_ratchet.main(["check", "--baseline", base, f"core={low}"]) == 1
    assert "FAIL core" in capsys.readouterr().err


def test_check_only_compares_given_components(tmp_path: Path) -> None:
    base = _baseline(tmp_path / "base.json", core=97.0, python=90.0)
    report = _llvm(tmp_path / "c.json", 97.0)
    assert cov_ratchet.main(["check", "--baseline", base, f"core={report}"]) == 0


def test_update_merges_into_baseline(tmp_path: Path) -> None:
    base = Path(_baseline(tmp_path / "base.json", core=97.0, python=90.0))
    report = _llvm(tmp_path / "c.json", 98.123)
    assert cov_ratchet.main(["update", "--baseline", str(base), f"core={report}"]) == 0
    assert json.loads(base.read_text()) == {"components": {"core": 98.12, "python": 90.0}}
    assert base.read_text().endswith("\n")


def test_update_creates_missing_baseline(tmp_path: Path) -> None:
    base = tmp_path / "new.json"
    cov_ratchet.main(["update", "--baseline", str(base), f"relay={_llvm(tmp_path / 'r.json', 80)}"])
    assert json.loads(base.read_text()) == {"components": {"relay": 80.0}}


def test_bad_inputs_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = _baseline(tmp_path / "base.json", core=97.0)
    assert cov_ratchet.main(["check", "--baseline", base, "oops"]) == 2
    assert cov_ratchet.main(["check", "--baseline", base, f"core={tmp_path / 'none.json'}"]) == 2
    report = _llvm(tmp_path / "c.json", 97.0)
    assert (
        cov_ratchet.main(["check", "--baseline", str(tmp_path / "gone.json"), f"core={report}"])
        == 2
    )
    assert "cannot read" in capsys.readouterr().err
