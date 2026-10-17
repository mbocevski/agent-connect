import agentconnect_core


def test_protocol_constants_match_spec() -> None:
    assert agentconnect_core.PROTOCOL_VERSION == 0
    assert agentconnect_core.CIPHERSUITE_V0 == "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"


def test_supports_only_v0() -> None:
    assert agentconnect_core.supports_protocol(0)
    assert not agentconnect_core.supports_protocol(1)
