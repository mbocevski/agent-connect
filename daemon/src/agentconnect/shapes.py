"""A tiny notation for JSON shapes, shared by the docs and the tests.

A shape is one of:

* a string naming a JSON type: ``str``, ``int``, ``bool``, ``null``, ``object``
  (any object) or ``any``; ``a|b`` allows either;
* a list holding one element shape (a list of that);
* a dict of key to shape; a key ending in ``?`` may be absent;
* :class:`Opt`, the inner shape or ``null``.

``scripts/gen_reference.py`` renders the shapes into the docs and the tests
check real output against the same objects (:func:`conforms`), so the docs
and the contract cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_TYPES: dict[str, type] = {"str": str, "bool": bool, "object": dict}


@dataclass(frozen=True)
class Opt:
    """The inner shape, or ``null``."""

    inner: Any


def _leaf(value: Any, name: str) -> bool:
    if name == "any":
        return True
    if name == "null":
        return value is None
    if name == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    kind = _TYPES.get(name)
    return kind is not None and isinstance(value, kind)


def conforms(value: Any, shape: Any) -> bool:
    """Whether ``value`` matches ``shape`` (objects must have exactly its keys)."""
    if isinstance(shape, Opt):
        return value is None or conforms(value, shape.inner)
    if isinstance(shape, str):
        return any(_leaf(value, name) for name in shape.split("|"))
    if isinstance(shape, list):
        return isinstance(value, list) and all(conforms(v, shape[0]) for v in value)
    if not isinstance(shape, dict) or not isinstance(value, dict):
        return False
    required = {k for k in shape if not k.endswith("?")}
    known = {k.removesuffix("?"): v for k, v in shape.items()}
    if not required <= set(value) or not set(value) <= set(known):
        return False
    return all(conforms(v, known[k]) for k, v in value.items())
