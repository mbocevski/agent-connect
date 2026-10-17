import pytest


def test_harness_tests_get_the_larger_timeout(request: pytest.FixtureRequest) -> None:
    marker = request.node.get_closest_marker("timeout")
    assert marker is not None
    assert marker.args[0] == 30
