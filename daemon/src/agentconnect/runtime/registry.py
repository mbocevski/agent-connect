"""The runtime's adapters, by name.

A group delivers to the adapters of its list, by name: the list the human
pinned (the ``adapters`` column of the groups table), else the config's
(``daemon.adapters``). A group none of whose adapters is registered delivers
to the first one registered (:meth:`AdapterRegistry.first`). Registration
closes when the runtime starts.
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

    def first(self) -> Adapter | None:
        """The first adapter registered, if any."""
        return next(iter(self._by_name.values()), None)

    @override
    def __getitem__(self, name: str) -> Adapter:
        return self._by_name[name]

    @override
    def __iter__(self) -> Iterator[str]:
        return iter(self._by_name)

    @override
    def __len__(self) -> int:
        return len(self._by_name)
