"""The whole program under Board: reset, OS, periodic tasks, EEPROM.

These take seconds each; the ignition-off round trip takes minutes and only
runs with MS45_SLOW=1.
"""
import os

import pytest

from ms45emu import dme
from ms45emu.board import Board

SCHEDULER_TASK = 0x3B38C
FRAME_0x316_BUILDER = 0x4B528
INIT_DONE = 0x3FEB26
FRAME = 400_000                  # instructions per 10 ms frame (one 0x316 build)


def run_frames(b, n):
    """Run until the tach hook has been entered n more times."""
    target = b.probe_counts["hook"] + n
    while b.probe_counts["hook"] < target:
        b.run(FRAME)


@pytest.fixture
def stock_board(stock):
    return Board(stock.pair)


@pytest.fixture
def patched_board(patched):
    return Board(patched.pair)


def test_stock_boot_reaches_the_periodic_tasks(stock_board):
    b = stock_board
    b.probe(SCHEDULER_TASK, "scheduler")
    b.probe(FRAME_0x316_BUILDER, "0x316")
    b.boot(max_insns=30_000_000)
    assert b.m.read8(INIT_DONE) == 1
    assert b.kl15
    assert b.probe_counts["scheduler"] > 10
    assert b.probe_counts["0x316"] > 10
    assert b.watchdog_bad == 0


def test_patched_boot_shows_map_1_at_power_up(patched_board):
    b = patched_board
    b.probe(dme.tach_hook_target(b.m), "hook")
    b.boot(max_insns=20_000_000)
    assert b.probe_counts["hook"] > 10
    assert b.m.sda16(dme.TACH_VAR) / 6.4 == 1000              # map 1, blank EEPROM
    assert b.m.read8(dme.RAM_FLAG) & 1 == 0


def _gesture_board(pair, image=None):
    b = Board(pair)
    if image:
        b.load_eeprom(image)
    m = b.m
    inputs = {"pedal": 0, "brake": False}

    def force(_):
        # The hook reads these right after; the sensors behind them are not modelled.
        m.set_sda8(dme.VAR_VS, 0)
        m.set_sda8(dme.VAR_PV, inputs["pedal"])
        m.set_sda8(dme.VAR_BRK_A, 1 if inputs["brake"] else 0)
        m.set_sda8(dme.VAR_BRK_B, 1 if inputs["brake"] else 0)

    b.probe(dme.tach_hook_target(m), "hook", on_hit=force)
    return b, inputs


def test_gesture_under_the_running_os(patched):
    b, inputs = _gesture_board(patched.pair)
    m = b.m
    b.boot(max_insns=20_000_000)
    run_frames(b, 320 - b.probe_counts["hook"])               # the 3 s indication passes
    assert m.sda16(dme.TACH_VAR) == 0
    inputs.update(pedal=0xFF, brake=True)
    run_frames(b, 498)
    assert m.read8(dme.RAM_FLAG) & 1 == 0, "toggled early"
    run_frames(b, 3)
    assert m.read8(dme.RAM_FLAG) & 1 == 1
    assert m.sda16(dme.TACH_VAR) / 6.4 == 2000
    run_frames(b, 50)
    assert m.sda8(dme.NV_SAVE_REQ) == 0, "the DME's NV task did not take the save"


@pytest.mark.skipif(not os.environ.get("MS45_SLOW"), reason="minutes; set MS45_SLOW=1")
def test_map_survives_ignition_off(patched):
    b, inputs = _gesture_board(patched.pair)
    b.boot(max_insns=20_000_000)
    run_frames(b, 320 - b.probe_counts["hook"])
    inputs.update(pedal=0xFF, brake=True)
    run_frames(b, 505)
    assert b.m.read8(dme.RAM_FLAG) & 1 == 1
    inputs.update(pedal=0, brake=False)
    b.ignition(False)
    for _ in range(600):                                      # up to a minute of after-run
        b.run(10 * FRAME)
        if b.powered_down:
            break
    assert b.powered_down
    assert b.qspi.eeprom.writes > 100

    b2, _ = _gesture_board(patched.pair, b.eeprom_image())
    b2.boot(max_insns=20_000_000)
    assert b2.m.read8(dme.RAM_FLAG) & 1 == 1
    assert b2.m.sda16(dme.TACH_VAR) / 6.4 == 2000
