"""The runtime's adapters, by name.

Each group is bound to one adapter by name (the ``adapter`` column of the
groups table, ``daemon.default_adapter`` when the group was created). A
group whose adapter isn't registered delivers to the first one registered.
Registration closes when the runtime starts.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from typing import override

from agentconnect.adapter import Adapter


class AdapterRegistry(Mapping[str, Adapter]):
    def __init__(self, adapters: Iterable[Adapter] = ()) -> None:
        self._by_name: dict[str, Adapter] = {}
        self._closed = False
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: Adapter) -> None:
        """Add an adapter; only before the runtime starts."""
        if self._closed:
            msg = "adapters must be registered before the runtime starts"
            raise RuntimeError(msg)
        if adapter.name in self._by_name:
            msg = f"an adapter named {adapter.name!r} is already registered"
            raise ValueError(msg)
        self._by_name[adapter.name] = adapter

    def close(self) -> None:
        """No more registrations (the runtime is starting)."""
        self._closed = True

    def bound(self, name: str) -> Adapter | None:
        """The adapter for a group bound to ``name``: that one, else the
        first registered, else ``None``."""
        return self._by_name.get(name) or next(iter(self._by_name.values()), None)

    @override
    def __getitem__(self, name: str) -> Adapter:
        return self._by_name[name]

    @override
    def __iter__(self) -> Iterator[str]:
        return iter(self._by_name)

    @override
    def __len__(self) -> int:
        return len(self._by_name)
