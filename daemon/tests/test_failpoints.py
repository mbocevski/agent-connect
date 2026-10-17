"""The daemon's test-only failpoints."""

import pytest

from agentconnect.failpoints import POINTS, FailpointError, Failpoints, SimulatedCrash


def test_points_fire_as_armed() -> None:
    f = Failpoints()
    f.hit("receive.after_core")  # inert when nothing is armed
    with pytest.raises(ValueError, match="unknown failpoint"):
        f.arm("receive.nowhere")
    f.arm("receive.after_core", times=2)
    f.hit("welcome.in_tx")
    for _ in range(2):
        with pytest.raises(FailpointError):
            f.hit("receive.after_core")
    f.hit("receive.after_core")
    f.arm("confirm.in_tx", "crash")
    with pytest.raises(SimulatedCrash):
        f.hit("confirm.in_tx")
    assert f.fired == ["receive.after_core", "receive.after_core", "confirm.in_tx"]
    f.arm("welcome.in_tx")
    f.clear()
    f.hit("welcome.in_tx")
    assert "invite.after_register" in POINTS
    assert not issubclass(SimulatedCrash, Exception)
