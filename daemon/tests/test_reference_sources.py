"""The tables the reference docs are generated from stay complete."""

from __future__ import annotations

import dataclasses
import inspect
import re

from agentconnect import cli_json, cli_support, config
from agentconnect.runtime import api, errors
from agentconnect.shapes import Opt, conforms


def test_exit_codes_table_covers_every_constant() -> None:
    constants = {
        name: value
        for name, value in vars(cli_support).items()
        if re.fullmatch(r"EXIT_[A-Z]+", name) and isinstance(value, int)
    }
    assert {(code, name) for code, name, _ in cli_support.EXIT_CODES} == {
        (v, n) for n, v in constants.items()
    }
    for code, _name, meaning in cli_support.EXIT_CODES:
        assert meaning
        assert code in range(8)


def test_every_config_field_has_a_key_or_is_code_only() -> None:
    fields = {f.name for f in dataclasses.fields(config.Config)}
    keyed = [k.field for k in config.CONFIG_KEYS]
    # Only the keys of an array of tables share a field; they say their type.
    single = [k.field for k in config.CONFIG_KEYS if not k.kind]
    assert len(set(single)) == len(single)
    assert not set(single) & {k.field for k in config.CONFIG_KEYS if k.kind}
    assert set(keyed) <= fields
    assert fields - set(keyed) == config.CONFIG_FIELDS_WITHOUT_KEY


def test_config_keys_are_section_dot_name_and_documented() -> None:
    for key in config.CONFIG_KEYS:
        section, dot, name = key.key.partition(".")
        assert dot
        sections = {
            "relay",
            "daemon",
            "policy",
            "api",
            "webhook",
            "sse",
            "sdk",
            "a2a",
            "isolation",
            "directory",
            "listing",
            "knock",
            "groups",
        }
        assert section in sections
        assert name
        assert key.doc
        assert key.default


def test_config_env_overrides_are_read_by_the_loader() -> None:
    source = inspect.getsource(config.load_config)
    for key in config.CONFIG_KEYS:
        if key.env:
            assert f'"{key.env}"' in source
    for name, _doc in config.CONFIG_ENV_EXTRA:
        assert f'"{name}"' in source


def test_every_route_spec_has_a_handler_and_is_unique() -> None:
    seen = set()
    for spec in api.ROUTE_SPECS:
        assert callable(getattr(api.ApiServer, spec.handler))
        assert (spec.method, spec.path) not in seen
        seen.add((spec.method, spec.path))
        assert spec.summary
        assert spec.path.startswith("/v0/")


def test_error_table_lists_every_status_the_server_maps() -> None:
    documented = {(status, code) for status, code, _ in api.API_ERRORS}
    for code, status in errors.ERROR_STATUS.items():
        assert (status, code) in documented
    for status, code, meaning in api.API_ERRORS:
        assert meaning
        assert status in api.STATUS_TEXT, code


def test_json_notes_belong_to_a_schema() -> None:
    assert set(cli_json.NOTES) <= set(cli_json.SCHEMAS)


def test_shape_notation() -> None:
    assert conforms({"a": 1, "b": [None, "x"]}, {"a": "int", "b": [Opt("str")]})
    assert conforms({"a": 1}, {"a": "int", "b?": "str"})
    assert conforms({"a": "x"}, {"a": "int|str"})
    assert conforms({"a": {"anything": 1}}, {"a": "object"})
    assert conforms({"a": 1}, {"a": "any"})
    assert not conforms({"a": True}, {"a": "int"})
    assert not conforms({"a": 1, "extra": 1}, {"a": "int"})
    assert not conforms({}, {"a": "int"})
    assert not conforms([], {"a": "int"})
    assert not conforms({"a": "1"}, {"a": "int"})
    assert not conforms("x", ["str"])
    assert not conforms({"a": 1}, {"a": "nonsense"})
    assert not conforms(1, 5)
