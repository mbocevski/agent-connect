import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_licences", Path(__file__).resolve().parents[1] / "check_licences.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_licences"] = module
    spec.loader.exec_module(module)
    return module


check_licences = _load()
REPO = Path(__file__).resolve().parents[2]


def _policy(exceptions: dict[str, set[str]] | None = None) -> object:
    return check_licences.Policy({"MIT", "Apache-2.0", "BSD-3-Clause", "ISC"}, exceptions or {})


def _report(*entries: tuple[str, str]) -> list[dict[str, str]]:
    return [{"Name": n, "Version": "1.0", "License": lic} for n, lic in entries]


def test_allowed_spdx_and_classifier_names_pass() -> None:
    report = _report(
        ("a", "MIT"),
        ("b", "MIT License"),
        ("c", "ISC License (ISCL)"),
        ("d", "BSD License"),
        ("e", "Apache Software License"),
        ("f", "DFSG approved; MIT License"),
        ("g", "3-Clause BSD License"),
    )
    assert check_licences.check(report, _policy()) == []


def test_or_needs_one_allowed_alternative() -> None:
    assert check_licences.check(_report(("a", "GPL-3.0-only OR MIT")), _policy()) == []
    assert check_licences.check(_report(("a", "GPL-3.0-only OR AGPL-3.0-only")), _policy())


def test_and_needs_every_licence_allowed() -> None:
    assert check_licences.check(_report(("a", "MIT AND Apache-2.0")), _policy()) == []
    problems = check_licences.check(_report(("a", "MIT AND GPL-2.0-only")), _policy())
    assert len(problems) == 1
    assert "GPL-2.0-only" in problems[0]


@pytest.mark.parametrize("licence", ["UNKNOWN", "", "GPL-3.0-or-later", "LGPL-2.1", "AGPL-3.0"])
def test_unknown_and_copyleft_fail(licence: str) -> None:
    assert check_licences.check(_report(("a", licence)), _policy())


def test_exception_is_scoped_to_its_package() -> None:
    policy = _policy({"certifi": {"MPL-2.0"}})
    report = _report(("certifi", "MPL-2.0"), ("other", "MPL-2.0"))
    problems = check_licences.check(report, policy)
    assert len(problems) == 1
    assert problems[0].startswith("other ")


def test_exception_name_is_normalised() -> None:
    policy = _policy({"typing-extensions": {"PSF-2.0"}})
    assert check_licences.check(_report(("typing_extensions", "PSF-2.0")), policy) == []


def test_unused_exception_fails() -> None:
    problems = check_licences.check(_report(("a", "MIT")), _policy({"certifi": {"MPL-2.0"}}))
    assert problems == ["policy exception for 'certifi' is unused; remove it from licences-py.toml"]


def test_repo_policy_bans_copyleft_and_scopes_mpl() -> None:
    policy = check_licences.Policy.load(REPO / "licences-py.toml")
    assert not any("GPL" in lic or lic == "MPL-2.0" for lic in policy.allow)
    assert set(policy.exceptions) == {"certifi", "hypothesis"}
    assert all(allowed == {"MPL-2.0"} for allowed in policy.exceptions.values())


def test_main_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text('allow = ["MIT"]\n', encoding="utf-8")
    good = tmp_path / "good.json"
    good.write_text('[{"Name": "a", "Version": "1", "License": "MIT"}]', encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text('[{"Name": "a", "Version": "1", "License": "GPL-3.0-only"}]', encoding="utf-8")
    assert check_licences.main(["x", str(good), str(policy)]) == 0
    assert check_licences.main(["x", str(bad), str(policy)]) == 1
    assert "GPL-3.0-only" in capsys.readouterr().err
    assert check_licences.main(["x"]) == 2
