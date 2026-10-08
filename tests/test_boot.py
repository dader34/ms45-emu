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


def test_patched_boot_comes_up_on_map_1(patched_board):
    b = patched_board
    b.probe(dme.tach_hook_target(b.m), "hook")
    b.boot(max_insns=20_000_000)
    assert b.probe_counts["hook"] > 10
    # a blank EEPROM: block 56 is initialised, not restored, so there is no
    # indication yet (the indication is the restore routine's); the tach
    # gets the real rpm, 0, and the map is map 1
    assert b.m.sda16(dme.TACH_VAR) == 0
    assert dme.selected(b.m) == 0


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
    assert dme.selected(m) == 0, "toggled early"
    run_frames(b, 3)
    assert dme.selected(m) == 1
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
    assert dme.selected(b.m) == 1
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
    assert dme.selected(b2.m) == 1
    assert b2.m.sda16(dme.TACH_VAR) / 6.4 == 2000


from unicorn.ppc_const import UC_PPC_REG_LR


def test_seven_maps_under_the_running_os(seven):
    """The DSC gesture walks the running program through all seven maps; on
    each, r2 is the map's own window and the OS reads the calibration there."""
    b = Board(seven.pair)
    m = b.m
    state = {"dsc": False}

    def force(_):
        m.set_sda8(dme.VAR_VS, 0)
        m.set_sda8(dme.VAR_DSC_STATE, dme.DSC_STATE_MASK if state["dsc"] else 0)

    b.probe(dme.tach_hook_target(m), "hook", on_hit=force)
    b.boot(max_insns=20_000_000)
    run_frames(b, 1100 - b.probe_counts["hook"])              # the 10 s start-up lockout passes
    assert dme.selected(m) == 0 and m.reg(2) == dme.map_r2(m, 0)

    def press(times):
        for _ in range(times):
            state["dsc"] = not state["dsc"]
            run_frames(b, 1)

    for expect in (1, 2, 3, 4, 5, 6, 0):
        press(4)
        run_frames(b, 2)
        assert dme.selected(m) == expect, f"the gesture did not reach map {expect + 1}"
        assert m.reg(2) == dme.map_r2(m, expect)
        assert m.sda16(dme.TACH_VAR) / 6.4 == 1000 * (expect + 1)
        # the program reads its single values from this map's window, and
        # from no other map's r2 blocks
        window = dme.map_r2(m, expect) - 0x7FF0
        others = [dme.map_r2(m, i) - 0x7FF0 for i in range(1, 7) if i != expect]
        reads = {"own": 0, "other": 0}

        def seen(_, is_write, addr, size, value):
            # every slot holds one map's block, so a read in another map's
            # r2 blocks cannot be the selected map's. The program's
            # background CRC walks the whole program area, maps included,
            # a byte at a time: not a calibration read
            if is_write or m.mu.reg_read(UC_PPC_REG_LR) == dme.FLASH_CRC_RETURN:
                return
            if any(base + blk * 0x400 <= addr < base + (blk + 1) * 0x400 for base in others for blk in dme.R2_BLOCKS):
                reads["other"] += 1
            elif any(window + blk * 0x400 <= addr < window + (blk + 1) * 0x400 for blk in dme.R2_BLOCKS):
                reads["own"] += 1

        h = m.hook_mem(seen, 0xFFFDD400, 0xFFFFFC00) if expect else None
        run_frames(b, 50)
        if h is not None:
            m.mu.hook_del(h)
            assert reads["own"] > 100, "the OS did not read through r2 from the selected map's window"
            assert reads["other"] == 0, "a read landed in another map's r2 blocks"
        run_frames(b, 300)                                   # the 3 s display, then quiet
