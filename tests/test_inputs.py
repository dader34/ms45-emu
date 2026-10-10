"""The pedal and throttle sensors (ms45emu/inputs.py)."""
import pytest

from ms45emu import inputs
from ms45emu.board import Board
from ms45emu.faults import Faults
from ms45emu.protections import Reactions

PEDAL_FAULTS = (69, 70, 71, 72, 73, 74, 75)     # supplies, pots, signal, brake/pedal plausibility
THROTTLE_FAULTS = (65, 66, 67, 68)


@pytest.mark.parametrize("percent", [0, 50])
def test_pedal(stock, percent):
    r = Reactions(Board(stock.pair)).scenario(rpm=800, seconds=0.3, settle=0.5, pedal=percent)
    assert inputs.pedal(r.board) == pytest.approx(percent, abs=1)
    assert not set(r.failed) & set(PEDAL_FAULTS), Faults(stock.pair).describe(min(set(r.failed) & set(PEDAL_FAULTS)))


def test_throttle(stock):
    r = Reactions(Board(stock.pair)).scenario(rpm=800, seconds=0.3, settle=0.5, throttle=10)
    assert inputs.throttle(r.board) == pytest.approx(10, abs=0.2)
    assert not set(r.failed) & set(THROTTLE_FAULTS)
