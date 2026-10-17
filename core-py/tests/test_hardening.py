"""The binding surface: no panic reaches Python, test-only knobs stay out of
the production constructors, and derived invite keys never leave the core.
"""

from __future__ import annotations

import random

import pytest

import agentconnect_core as ac


def make_client(rng: random.Random) -> ac.Client:
    identity = ac.Identity._generate_for_testing(rng.getrandbits(64))
    instance = identity._create_instance_for_testing(seed=rng.getrandbits(64))
    return ac.Client._for_testing(None, instance.to_secret_bytes(), rng.getrandbits(64))


def test_a_panic_is_a_core_error_and_the_client_recovers(rng: random.Random) -> None:
    client = make_client(rng)
    gid = client.create_group("g", "p")
    with pytest.raises(ac.CoreError, match="panicked") as caught:
        client._panic_for_testing()
    # An Exception (a daemon's `except Exception` sees it), not an
    # AgentConnectError and not PyO3's BaseException-derived PanicException.
    assert isinstance(caught.value, Exception)
    assert not isinstance(caught.value, ac.AgentConnectError)
    # The client is not poisoned: the group reloads from storage.
    assert client.epoch(gid) == 0
    assert len(client.members(gid)) == 1
    assert client.create_group("h", "p") != gid


def test_out_of_range_test_time_is_an_error_not_a_panic(rng: random.Random) -> None:
    # Before: 2**64 - 1 overflowed the clock and panicked, poisoning the client.
    client = make_client(rng)
    for bad in (2**64 - 1, 0):
        with pytest.raises(ac.AgentConnectError, match="time must be"):
            client._set_time_for_testing(bad)
    client.create_group("g", "p")
    identity = ac.Identity._generate_for_testing(rng.getrandbits(64))
    with pytest.raises(ac.AgentConnectError, match="time must be"):
        identity._create_instance_for_testing(now=2**64 - 1)


def test_production_constructors_take_no_seed() -> None:
    with pytest.raises(TypeError):
        ac.Identity.generate(seed=1)  # ty: ignore[unknown-argument]
    identity = ac.Identity.generate()
    with pytest.raises(TypeError):
        identity.create_instance(seed=1)  # ty: ignore[unknown-argument]
    instance = identity.create_instance()
    with pytest.raises(TypeError):
        ac.Client(None, instance.to_secret_bytes(), seed=1)  # ty: ignore[unknown-argument]
    client = ac.Client(None, instance.to_secret_bytes())
    assert client.identity == identity.id
    # Two production identities never collide (OS randomness).
    assert ac.Identity.generate().id != identity.id


def test_derived_invite_keys_are_not_exposed() -> None:
    for name in ("derive_join_key", "derive_welcome_key"):
        assert not hasattr(ac, name)
        assert not hasattr(ac._native, name)
