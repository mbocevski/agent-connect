"""Shared pytest configuration for every Python test directory.

Provides the deterministic-testing toolkit described in TESTING.md:

* ``AC_TEST_SEED``: one seed per run (random unless set), shown in the report
  header and repeated after any failure so the run can be reproduced.
* ``fake_clock``, ``test_seed`` and ``rng`` fixtures.
* Hypothesis profiles: ``dev`` (default), ``ci`` (derandomized) and ``nightly``.
* ``@pytest.mark.quarantine``: such tests are skipped unless
  ``AC_RUN_QUARANTINE=1`` (the nightly run sets it).
"""

from __future__ import annotations

import os
import random
import secrets
from collections.abc import Mapping

import pytest
from hypothesis import HealthCheck, settings

from agentconnect.clock import FakeClock

SEED_ENV = "AC_TEST_SEED"
QUARANTINE_ENV = "AC_RUN_QUARANTINE"
_SEED_KEY = pytest.StashKey[int]()


def resolve_seed(environ: Mapping[str, str]) -> int:
    """The run seed: ``AC_TEST_SEED`` if set, otherwise a fresh random one."""
    raw = environ.get(SEED_ENV, "").strip()
    if not raw:
        return secrets.randbits(32)
    try:
        return int(raw, 0)
    except ValueError:
        msg = f"{SEED_ENV} must be an integer, got {raw!r}"
        raise pytest.UsageError(msg) from None


def _register_hypothesis_profiles() -> None:
    # Explicit derandomize=False: under CI=true Hypothesis's built-in defaults
    # are deterministic, and profiles would otherwise inherit that.
    settings.register_profile("dev", derandomize=False)
    # Deterministic: same examples every run, no example database.
    settings.register_profile(
        "ci",
        derandomize=True,
        database=None,
        max_examples=100,
        print_blob=True,
        suppress_health_check=[HealthCheck.too_slow],
    )
    settings.register_profile(
        "nightly",
        derandomize=False,
        database=None,
        max_examples=2000,
        deadline=None,
        print_blob=True,
        suppress_health_check=[HealthCheck.too_slow],
    )
    default = "ci" if os.environ.get("CI", "") != "" else "dev"
    settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", default))


_register_hypothesis_profiles()


def pytest_configure(config: pytest.Config) -> None:
    config.stash[_SEED_KEY] = resolve_seed(os.environ)


def pytest_report_header(config: pytest.Config) -> str:
    return f"{SEED_ENV}={config.stash[_SEED_KEY]}"


def pytest_terminal_summary(
    terminalreporter: pytest.TerminalReporter, config: pytest.Config
) -> None:
    stats = terminalreporter.stats
    if len(stats.get("failed", [])) + len(stats.get("error", [])) > 0:
        seed = config.stash[_SEED_KEY]
        terminalreporter.write_sep("=", "reproduce with")
        terminalreporter.write_line(f"{SEED_ENV}={seed} pytest ...")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get(QUARANTINE_ENV) == "1":
        return
    kept: list[pytest.Item] = []
    deselected: list[pytest.Item] = []
    for item in items:
        (deselected if item.get_closest_marker("quarantine") else kept).append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = kept


@pytest.fixture
def fake_clock() -> FakeClock:
    """A fresh manually driven clock starting at 2025-01-01T00:00:00Z."""
    return FakeClock()


@pytest.fixture
def test_seed(request: pytest.FixtureRequest) -> int:
    """The run seed (``AC_TEST_SEED``), shared by every test in the run."""
    return request.config.stash[_SEED_KEY]


@pytest.fixture
def rng(test_seed: int, request: pytest.FixtureRequest) -> random.Random:
    """A ``random.Random`` seeded from the run seed and the test id.

    Stable for a given seed and test, independent of test ordering.
    """
    return random.Random(f"{test_seed}:{request.node.nodeid}")  # noqa: S311


pytest_plugins = ["pytester"]
