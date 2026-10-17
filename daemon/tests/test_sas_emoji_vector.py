"""Contract test: the shared SAS emoji table (`testdata/sas-emoji.json`).

The Rust suite loads the same file (`core/tests/sas_emoji_vector.rs`).
"""

import json
from pathlib import Path
from typing import Any

import pytest

VECTOR = Path(__file__).resolve().parents[2] / "testdata" / "sas-emoji.json"


@pytest.fixture(scope="module")
def entries() -> list[dict[str, Any]]:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_table_has_64_entries(entries: list[dict[str, Any]]) -> None:
    assert len(entries) == 64


def test_numbers_are_unique_and_cover_0_to_63(entries: list[dict[str, Any]]) -> None:
    assert sorted(e["number"] for e in entries) == list(range(64))


@pytest.mark.parametrize("field", ["emoji", "description"])
def test_field_is_non_empty_and_unique(entries: list[dict[str, Any]], field: str) -> None:
    values = [e[field] for e in entries]
    assert all(isinstance(v, str) and v.strip() for v in values)
    assert len(set(values)) == 64


def test_packaged_table_matches_the_vector(entries: list[dict[str, Any]]) -> None:
    from agentconnect.sas_emoji import SAS_EMOJI  # noqa: PLC0415

    expected = [(e["emoji"], e["description"]) for e in sorted(entries, key=lambda e: e["number"])]
    assert list(SAS_EMOJI) == expected
