"""Fixtures of the integration suite (``just test-int``): the docker demos.

The suite drives the deployment in ``demo/compose.yaml`` with the demo
driver (``demo/run.py``), so the demos and their checks are the same code.
``just test-int`` builds the image first (``just demo-image``); a missing
image is built here.
"""

from __future__ import annotations

import base64
import importlib.util
import os
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]


def _load_driver() -> ModuleType:
    spec = importlib.util.spec_from_file_location("demo_run", REPO / "demo" / "run.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["demo_run"] = module
    spec.loader.exec_module(module)
    return module


driver = _load_driver()


@pytest.fixture(scope="session")
def image() -> str:
    found = subprocess.run(
        ["docker", "image", "inspect", driver.IMAGE], capture_output=True, check=False
    )
    if found.returncode != 0:
        driver.build_image()
    return str(driver.IMAGE)


def project(name: str) -> str:
    """A compose project name of this run's own, so runs never share one."""
    return f"acint-{os.getpid()}-{name}"


@pytest.fixture
def run_id(test_seed: int) -> str:
    """Markers for this test's message bodies, from the run seed."""
    return f"{test_seed & 0xFFFFFFFF:08x}"


@pytest.fixture(name="driver", scope="session")
def driver_fixture() -> ModuleType:
    """The demo driver, ``demo/run.py``."""
    return driver


@pytest.fixture
def one_to_one_deployment(image: str) -> Iterator[Any]:
    """The 1:1 deployment (hosts A and B), torn down afterwards."""
    with driver.deployment(project("one"), quiet=True) as dep:
        yield dep


@pytest.fixture
def group_deployment(image: str) -> Iterator[Any]:
    """The group deployment (hosts A, B and C), torn down afterwards."""
    with driver.deployment(project("group"), ("group",), quiet=True) as dep:
        yield dep


@pytest.fixture(scope="session")
def compose_project() -> Callable[[str], str]:
    return project


@pytest.fixture(name="encodings")
def encodings_fixture() -> Callable[[str], list[bytes]]:
    return marker_encodings


def marker_encodings(marker: str) -> list[bytes]:
    """``marker`` as it would appear in a capture if it were sent in the
    clear: raw, and base64 (standard and URL-safe) at each of the three
    alignments, without the partial characters at either end."""
    raw = marker.encode()
    out = [raw]
    for shift in range(3):
        padded = b"\0" * shift + raw
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            text = enc(padded).rstrip(b"=")
            start = (shift * 4 + 2) // 3
            stop = len(text) - (1 if (len(padded) % 3) else 0)
            if stop - start >= 8:
                out.append(text[start:stop])
    return out
