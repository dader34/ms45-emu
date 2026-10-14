"""The live-tune transport: our 0x6C service rides the stock 2C handler,
answers 7F 2C 12, and drives the overlay's descriptors from the K line —
so an edit sent as a define-packet reaches the lookup library."""
import os
import struct

import pytest
from unicorn.ppc_const import (UC_PPC_REG_0, UC_PPC_REG_PC, UC_PPC_REG_LR,
                               UC_PPC_REG_CTR, UC_PPC_REG_XER, UC_PPC_REG_CR,
                               UC_PPC_REG_MSR)

from ms45emu import dme, fold, overlay, transport
from ms45emu.board import Board
from ms45emu.image import IMAGES_DIR, Pair
from ms45emu.kwp import Tester

CURVE = 0x4395                    # the 16-entry byte curve the lookup tests use
SPECIAL = (UC_PPC_REG_PC, UC_PPC_REG_LR, UC_PPC_REG_CTR,
           UC_PPC_REG_XER, UC_PPC_REG_CR, UC_PPC_REG_MSR)


def _pair():
    # MS45_LIVETUNE_BASE=session1clean runs all of this on the stock program
    # (tools/livetune_build.py --stock --base-prefix) instead of the car's own
    base = os.environ.get("MS45_LIVETUNE_BASE", "session1")
    with open(os.path.join(IMAGES_DIR, f"{base}.flash.bin"), "rb") as f, \
         open(os.path.join(IMAGES_DIR, f"{base}.mpc.bin"), "rb") as m:
        return Pair(f.read(), m.read(), base)


@pytest.fixture(scope="module")
def board():
    b = Board(fold.build(transport.build(overlay.build(_pair()))))
    b.boot(max_insns=int(0.3 * b.ips))
    return b


@pytest.fixture(scope="module")
def t(board):
    return Tester(board)


def _read(board, index, at=CURVE):
    # m.call hijacks the CPU (emu_start to a sentinel) and parks it there, so
    # the task loop never resumes and the DME answers nothing afterwards —
    # snapshot the whole context and put it back around every call
    mu = board.m.mu
    snap = [mu.reg_read(UC_PPC_REG_0 + i) for i in range(32)]
    snap += [mu.reg_read(r) for r in SPECIAL]
    try:
        board.m.set_sda8(-0x283A, index)
        return board.m.call(dme.TABLE_READ_8, dme.CAL_BASE + at) & 0xFF
    finally:
        for i in range(32):
            mu.reg_write(UC_PPC_REG_0 + i, snap[i])
        for r, v in zip(SPECIAL, snap[32:]):
            mu.reg_write(r, v)
        mu.ctl_flush_tb()


def test_build_is_idempotent():
    p = transport.build(overlay.build(_pair()))
    assert transport.is_patched(p)
    again = transport.build(p)
    assert transport.is_patched(again)
    assert again.flash == p.flash


def test_stock_define_untouched(t):
    # the hook must not disturb the stock service: F0 defines, F1 is refused
    assert t.request([0x2C, 0xF0, 0x03, 0x01, 0x01, 0x3F, 0xCC, 0x04]) == bytes((0x6C, 0xF0))
    assert t.request([0x2C, 0xF1, 0x03, 0x01, 0x01, 0x3F, 0xCC, 0x04]) == transport.ACK


def test_state_initialises(t):
    st = transport.ping(t)
    assert st["status"] == transport.STATUS_OK
    assert st["count"] == 0
    assert st["version"] == transport.VERSION


def test_open_write_read(t, board):
    transport.close_all(t)
    slot, mirror = transport.open_table(t, CURVE, 16)
    assert slot == 0
    stock = board.m.read(dme.CAL_BASE + CURVE, 16)
    assert board.m.read(mirror, 16) == stock                 # seeded from cal
    assert transport.write_cell(t, slot, 7, [0xAA])
    assert board.m.read(mirror + 7, 1) == b"\xaa"
    for i in (0, 6, 8, 15):                                  # the rest still stock
        assert board.m.read(mirror + i, 1) == stock[i:i + 1]
    # the full loop: the library reads the edited cell through the overlay
    assert _read(board, 7) == 0xAA
    transport.close_all(t)
    assert _read(board, 7) == stock[7]                       # and stock again


def test_descriptor_matches_python_placement(t, board):
    transport.close_all(t)
    ((_, _, expect),) = overlay.placement([(CURVE, 16)])
    _, mirror = transport.open_table(t, CURVE, 16)
    assert mirror == expect
    words = struct.unpack(">3I", board.m.read(overlay.DESC + 4, 12))
    base = dme.CAL_BASE + CURVE
    assert words == (base, base + 16, (mirror - base) & 0xFFFFFFFF)
    transport.close_all(t)


def test_two_tables_two_slots(t, board):
    transport.close_all(t)
    s0, m0 = transport.open_table(t, CURVE, 16)
    s1, m1 = transport.open_table(t, CURVE + 0x100, 16)
    assert (s0, s1) == (0, 1) and m1 != m0
    assert transport.read_state(t)["count"] == 2
    transport.close_all(t)


def test_oversized_table_refused(t):
    transport.close_all(t)
    assert transport.open_table(t, 0x1000, 600) is None       # no pool fits it
    assert transport.read_state(t)["status"] == transport.STATUS_ROOM
    transport.close_all(t)


def test_out_of_cal_refused(t):
    transport.close_all(t)
    assert transport.open_table(t, 0x1CFFF, 0x20) is None     # past the cal
    assert transport.read_state(t)["status"] == transport.STATUS_RANGE
    transport.close_all(t)


def test_a_table_past_the_last_slot_refused(t):
    transport.close_all(t)
    for i in range(overlay.SLOTS):
        assert transport.open_table(t, CURVE + 16 * i, 16)
    assert transport.open_table(t, CURVE, 16) is None
    assert transport.read_state(t)["status"] == transport.STATUS_FULL
    assert len(transport.descriptors(t)) == overlay.SLOTS
    transport.close_all(t)


def test_full_ram_is_the_testers_to_see(t):
    transport.close_all(t)
    assert transport.open_table(t, 0x1000, 500)               # the one pool that fits it
    assert transport.open_table(t, 0x2000, 500) is None       # nothing asked of the DME
    assert transport.read_state(t)["count"] == 1
    transport.close_all(t)


def test_mirror_outside_the_pools_refused(t):
    transport.close_all(t)
    lo, hi = overlay.POOLS[1]
    for mirror in (lo - 2, hi - 8, 0x3FA0A0, 0x3F9A44, overlay.SHELF[0] - 2, overlay.SHELF[1] - 8, 0x4395):
        assert transport.place(t, 0, CURVE, 16, mirror) == transport.STATUS_ROOM, hex(mirror)
    assert transport.place(t, 1, CURVE, 16, lo) == transport.STATUS_SLOT     # slot 0 comes first
    assert transport.read_state(t)["count"] == 0
    transport.close_all(t)


def test_neighbours_in_the_same_block_read_stock(t, board):
    # the bitmap sends every lookup in the block to the descriptors; only
    # the opened range may move
    transport.close_all(t)
    slot, _ = transport.open_table(t, CURVE, 16)
    assert transport.write_cell(t, slot, 0, [0x11] * 16)
    assert _read(board, 0, CURVE - 1) == board.m.read8(dme.CAL_BASE + CURVE - 1)
    assert _read(board, 0, CURVE + 16) == board.m.read8(dme.CAL_BASE + CURVE + 16)
    assert _read(board, 0, CURVE + 0x400) == board.m.read8(dme.CAL_BASE + CURVE + 0x400)
    assert _read(board, 3) == 0x11
    transport.close_all(t)


def test_a_table_across_blocks(t, board):
    transport.close_all(t)
    at = 0x43F8                                               # 16 bytes over a 256-byte edge
    slot, _ = transport.open_table(t, at, 16)
    assert transport.write_cell(t, slot, 0, list(range(0x20, 0x30)))
    assert [_read(board, i, at) for i in (0, 7, 8, 15)] == [0x20, 0x27, 0x28, 0x2F]
    bitmap = board.m.read(overlay.BITMAP, overlay.BITMAP_SPACE)
    assert [b for b in range(overlay.BLOCKS) if bitmap[b >> 3] >> (b & 7) & 1] == [0x43, 0x44]
    transport.close_all(t)
    assert not any(board.m.read(overlay.BITMAP, overlay.BITMAP_SPACE))


def _shelf(board, at, n):
    return bytes(board.flash.image[fold.CAL_FILE + at:fold.CAL_FILE + at + n])


def test_park_on_the_shelf_and_back(t, board):
    """A mirror moves from RAM to blank flash and the lookup follows it; its
    RAM is free for the next table; placed in RAM again it brings the edit."""
    transport.close_all(t)
    board.flash.strict()
    shelf = overlay.SHELF[0]
    slot, ram = transport.open_table(t, CURVE, 16)
    edited = bytes(v ^ 0x55 for v in board.m.read(dme.CAL_BASE + CURVE, 16))
    assert transport.write_cell(t, slot, 0, list(edited))
    programs = board.flash.programs
    assert transport.park(t, slot, shelf) == transport.STATUS_OK
    assert board.flash.violations == [] and board.flash.erases == 0
    assert 0 < board.flash.programs - programs <= 8
    assert _shelf(board, shelf, 16) == edited
    assert transport.descriptors(t) == [(CURVE, 16, dme.CAL_BASE + shelf)]
    assert [_read(board, i) for i in (0, 7, 15)] == [edited[i] for i in (0, 7, 15)]
    assert not transport.write_cell(t, slot, 0, [1])          # flash is not written like RAM
    assert transport.read_state(t)["status"] == transport.STATUS_SHELVED
    assert _shelf(board, shelf, 16) == edited

    other, ram2 = transport.open_table(t, CURVE + 0x100, 16)  # the freed RAM, reused
    assert (other, ram2) == (1, ram)
    assert transport.write_cell(t, other, 0, [0x77] * 16)
    assert _read(board, 7) == edited[7] and _read(board, 7, CURVE + 0x100) == 0x77

    back = overlay.POOLS[1][0]
    assert transport.place(t, slot, CURVE, 16, back) == transport.STATUS_OK
    assert board.m.read(back, 16) == edited                   # seeded from the shelf
    assert transport.write_cell(t, slot, 7, [0x99])
    assert _read(board, 7) == 0x99 and _read(board, 6) == edited[6]
    assert transport.read_state(t)["count"] == 2
    transport.close_all(t)
    assert _read(board, 7) == board.m.read8(dme.CAL_BASE + CURVE + 7)


def test_shelf_refusals(t, board):
    transport.close_all(t)
    lo, hi = overlay.SHELF
    used = lo + 0x100
    assert transport.program(t, used, [0x12, 0x34]) == transport.STATUS_OK
    before = bytes(board.flash.image)
    assert transport.program(t, used, [0x00, 0x00]) == transport.STATUS_USED      # not blank
    assert transport.program(t, lo - 2, [1, 2]) == transport.STATUS_RANGE         # the calibration
    assert transport.program(t, hi - 2, [1, 2, 3, 4]) == transport.STATUS_RANGE   # the valid marks
    assert transport.program(t, CURVE & ~1, [1, 2]) == transport.STATUS_RANGE
    r = t.request([0x2C, 0x6C, 0x06, lo >> 16, (lo >> 8) & 0xFF, 0x41, 2, 1, 2])  # an odd address
    assert r == transport.ACK and transport.read_state(t)["status"] == transport.STATUS_RANGE
    assert bytes(board.flash.image) == before and board.flash.violations == []


def test_a_long_shelf_write(t, board):
    transport.close_all(t)
    at = overlay.SHELF[0] + 0x400
    data = bytes((7 * i + 1) & 0xFF for i in range(250)) + b"\xff\xff" + bytes(range(60))
    assert transport.program(t, at, data) == transport.STATUS_OK
    assert _shelf(board, at, len(data)) == data and board.flash.violations == []
    assert t.request([0x1A, 0x80]) is not None                # and the DME carries on


def test_bad_slot_and_range_refused(t):
    transport.close_all(t)
    assert transport.open_table(t, CURVE, 16)
    assert not transport.write_cell(t, 5, 0, [1])            # no such slot
    assert transport.read_state(t)["status"] == transport.STATUS_SLOT
    assert not transport.write_cell(t, 0, 16, [1])           # past the table
    assert transport.read_state(t)["status"] == transport.STATUS_RANGE
    transport.close_all(t)
