"""Tests for the shared root ``conftest.py`` (seed, fixtures, quarantine, profiles)."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import settings

ROOT = Path(__file__).resolve().parents[2]
CONFTEST = (ROOT / "conftest.py").read_text()


@pytest.fixture
def project(pytester: pytest.Pytester) -> pytest.Pytester:
    pytester.makeconftest(CONFTEST.replace('pytest_plugins = ["pytester"]', ""))
    return pytester


def test_header_shows_seed_from_env(
    project: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AC_TEST_SEED", "1234")
    project.makepyfile("def test_ok(): pass")
    result = project.runpytest_subprocess()
    result.stdout.fnmatch_lines(["AC_TEST_SEED=1234"])


def test_random_seed_when_unset(project: pytest.Pytester, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AC_TEST_SEED", raising=False)
    project.makepyfile("def test_ok(): pass")
    result = project.runpytest_subprocess()
    result.stdout.re_match_lines([r"AC_TEST_SEED=\d+"])


def test_invalid_seed_is_a_usage_error(
    project: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AC_TEST_SEED", "nope")
    project.makepyfile("def test_ok(): pass")
    result = project.runpytest_subprocess()
    assert result.ret != 0
    assert "AC_TEST_SEED must be an integer" in result.stderr.str() + result.stdout.str()


def test_seed_is_repeated_after_failure(
    project: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AC_TEST_SEED", "99")
    project.makepyfile("def test_bad(): assert False")
    result = project.runpytest_subprocess()
    result.stdout.fnmatch_lines(["*reproduce with*", "AC_TEST_SEED=99 pytest ..."])


def test_no_reproduce_hint_when_green(
    project: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AC_TEST_SEED", "99")
    project.makepyfile("def test_ok(): pass")
    result = project.runpytest_subprocess()
    assert "reproduce with" not in result.stdout.str()


def test_rng_is_reproducible_and_per_test(
    project: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AC_TEST_SEED", "7")
    project.makepyfile(
        """
        import random

        draws = {}

        def test_a(rng, test_seed):
            assert test_seed == 7
            expected = random.Random("7:test_rng_is_reproducible_and_per_test.py::test_a")
            first = rng.random()
            assert first == expected.random()
            draws["a"] = first

        def test_b(rng):
            assert rng.random() != draws["a"]
        """
    )
    project.runpytest_subprocess().assert_outcomes(passed=2)


def test_fake_clock_fixture_is_fresh_per_test(project: pytest.Pytester) -> None:
    project.makepyfile(
        """
        import datetime

        def test_a(fake_clock):
            fake_clock.advance(10)

        def test_b(fake_clock):
            assert fake_clock.now() == datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
        """
    )
    project.runpytest_subprocess().assert_outcomes(passed=2)


QUARANTINE_SRC = """
import pytest

@pytest.mark.quarantine
def test_flaky(): assert False

def test_stable(): pass
"""


def test_quarantined_tests_are_excluded_by_default(
    project: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AC_RUN_QUARANTINE", raising=False)
    project.makefile(".ini", pytest="[pytest]\nmarkers = quarantine\n")
    project.makepyfile(QUARANTINE_SRC)
    project.runpytest_subprocess().assert_outcomes(passed=1, deselected=1)


def test_quarantined_tests_run_when_enabled(
    project: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AC_RUN_QUARANTINE", "1")
    project.makefile(".ini", pytest="[pytest]\nmarkers = quarantine\n")
    project.makepyfile(QUARANTINE_SRC)
    project.runpytest_subprocess().assert_outcomes(passed=1, failed=1)


def test_hypothesis_profiles_are_registered() -> None:
    ci = settings.get_profile("ci")
    assert ci.derandomize is True
    assert ci.database is None
    assert settings.get_profile("dev").derandomize is False
    assert settings.get_profile("nightly").max_examples > ci.max_examples
