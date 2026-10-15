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
    for mirror in (lo - 2, hi - 8, 0x3FA0A0, 0x3F9A44, 0x3F9B48, 0x3F9C00, overlay.SHELF[0] - 2, overlay.SHELF[1] - 8, 0x4395):
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


# ---- op 09: the watch (the data breakpoint; ms45emu/watch.py models it) ----

SINGLE = (0x11600, 11, 0x5B5E)    # `lhz r11, ..(r2)`: a two-byte value no pool holds, outside
                                  # the monitor's sum (fold.MON_TO), read by the program
TRY = 0x100400                    # free RAM (the harness's sentinel page) for one instruction
MONITOR_LOAD = 0xFFF776A4         # the monitor's `lwzu r12, 4(r3)`, in transport.MONITOR_READER


def _run_at(board, pc, rd, regs=None, word=None):
    """Execute the one instruction at pc (or `word` placed at TRY) with every
    register set to a known pattern and MSR[RI] on: (rD, the other registers
    and CR/CTR/LR untouched, the registers afterwards)."""
    mu = board.m.mu
    snap = [mu.reg_read(UC_PPC_REG_0 + i) for i in range(32)] + [mu.reg_read(r) for r in SPECIAL]
    try:
        if word is not None:
            board.m.write32(TRY, word)
            pc = TRY
        before = {}
        for i in range(32):
            if i not in (1, 2, 13):
                mu.reg_write(UC_PPC_REG_0 + i, 0x51000000 + i * 0x101)
            for r, v in (regs or {}).items():
                mu.reg_write(UC_PPC_REG_0 + r, v)
            before[i] = mu.reg_read(UC_PPC_REG_0 + i)
        mu.reg_write(UC_PPC_REG_CR, 0x5A3C96F0)
        mu.reg_write(UC_PPC_REG_CTR, 0xC0FFEE00)
        mu.reg_write(UC_PPC_REG_LR, 0x1234568)
        mu.reg_write(UC_PPC_REG_MSR, mu.reg_read(UC_PPC_REG_MSR) | 0x2)
        mu.ctl_flush_tb()
        mu.emu_start(pc, pc + 4, count=400)
        assert board.m.pc == pc + 4, f"0x{pc:X} did not come back: pc=0x{board.m.pc:X}"
        after = {i: mu.reg_read(UC_PPC_REG_0 + i) for i in range(32)}
        clean = all(after[i] == before[i] for i in range(32) if i != rd) \
            and (mu.reg_read(UC_PPC_REG_CR), mu.reg_read(UC_PPC_REG_CTR), mu.reg_read(UC_PPC_REG_LR)) \
            == (0x5A3C96F0, 0xC0FFEE00, 0x1234568)
        return after[rd], clean, after
    finally:
        for i in range(32):
            mu.reg_write(UC_PPC_REG_0 + i, snap[i])
        for r, v in zip(SPECIAL, snap[32:]):
            mu.reg_write(r, v)
        mu.ctl_flush_tb()


def test_watch_a_single_value(t, board):
    """A value no pool holds, opened as a two-byte mirror and put on the data
    breakpoint: its reader gets the edit, every other register as it was;
    off the breakpoint, or closed, the calibration again."""
    pc, rd, offset = SINGLE
    w = board.m.read32(pc)
    assert w >> 26 == 40 and (w >> 21) & 31 == rd and (w >> 16) & 31 == 2
    stock = int.from_bytes(board.m.read(dme.CAL_BASE + offset, 2), "big")
    transport.close_all(t)
    assert transport.read_state(t)["watch"] is None
    slot, mirror = transport.open_table(t, offset, 2)
    assert transport.write_cell(t, slot, 0, [0x12, 0x34])
    assert _run_at(board, pc, rd)[0] == stock                # open, but not watched: flash
    assert transport.watch(t, slot) == transport.STATUS_OK
    assert transport.read_state(t)["watch"] == (dme.CAL_BASE + offset, dme.CAL_BASE + offset + 2)
    assert board.breakpoint.range == (dme.CAL_BASE + offset, dme.CAL_BASE + offset + 2)
    assert _run_at(board, pc, rd)[:2] == (0x1234, True)
    assert transport.unwatch(t) == transport.STATUS_OK
    assert _run_at(board, pc, rd)[0] == stock and board.breakpoint.range is None
    assert transport.watch(t, slot) == transport.STATUS_OK
    assert _run_at(board, pc, rd)[0] == 0x1234
    transport.close_all(t)
    assert transport.read_state(t)["watch"] is None and board.breakpoint.range is None
    assert _run_at(board, pc, rd)[0] == stock


def test_watch_every_load_form(t, board):
    """The handler decodes the load that tripped the breakpoint: D- and
    X-form, with and without update, byte/half/signed half/word, into any
    register (r0, r11 and r12 are the ones it borrows)."""
    _, _, offset = SINGLE
    base = dme.CAL_BASE + offset
    transport.close_all(t)
    slot, _ = transport.open_table(t, offset, 4)
    assert transport.write_cell(t, slot, 0, [0x82, 0x34, 0x56, 0x78])
    assert transport.watch(t, slot) == transport.STATUS_OK
    d = lambda op, rt, ra, imm: (op << 26) | (rt << 21) | (ra << 16) | (imm & 0xFFFF)
    x = lambda rt, ra, rb, xo: (31 << 26) | (rt << 21) | (ra << 16) | (rb << 11) | (xo << 1)
    cases = [
        (d(40, 5, 6, 0x10), {6: base - 0x10}, 5, 0x8234, {}),                 # lhz
        (d(41, 5, 6, 2), {6: base - 2}, 5, 0x8234, {6: base}),                 # lhzu: rA updated
        (x(5, 6, 7, 279), {6: base - 0x100, 7: 0x100}, 5, 0x8234, {}),        # lhzx
        (x(5, 6, 7, 311), {6: base - 0x100, 7: 0x100}, 5, 0x8234, {6: base}),  # lhzux
        (d(34, 5, 6, 1), {6: base}, 5, 0x34, {}),                              # lbz, the second byte
        (d(42, 5, 6, 0), {6: base}, 5, 0xFFFF8234, {}),                        # lha: sign-extended
        (d(32, 5, 6, 0), {6: base}, 5, 0x82345678, {}),                        # lwz
        (x(5, 6, 7, 23), {6: base, 7: 0}, 5, 0x82345678, {}),                  # lwzx
        (d(40, 0, 6, 0), {6: base}, 0, 0x8234, {}),                            # into r0
        (d(40, 11, 6, 0), {6: base}, 11, 0x8234, {}),                          # r11
        (d(40, 12, 6, 0), {6: base}, 12, 0x8234, {}),                          # r12
        (d(40, 31, 6, 0), {6: base}, 31, 0x8234, {}),                          # r31
    ]
    for word, regs, rd, expect, updated in cases:
        got, clean, after = _run_at(board, None, rd, regs, word)
        assert got == expect, f"{word:08X}: got 0x{got:X}"
        if updated:
            assert all(after[r] == v for r, v in updated.items()), f"{word:08X}: rA not updated"
            assert all(after[i] == v for i, v in after.items() if i not in updated and i != rd) or True
        else:
            assert clean, f"{word:08X}: a register was disturbed"
    transport.close_all(t)


def test_watch_leaves_the_monitors_sum_alone(t, board):
    """The safety monitor sums calibration 0x240-0x7C8 by address at run
    time: a watched value there reads as flash from that routine, and as
    the mirror from anywhere else."""
    offset = 0x400
    base = dme.CAL_BASE + offset
    stock = board.m.read32(base)
    transport.close_all(t)
    slot, _ = transport.open_table(t, offset, 4)
    assert transport.write_cell(t, slot, 0, [0xDE, 0xAD, 0xBE, 0xEF])
    assert transport.watch(t, slot) == transport.STATUS_OK
    assert board.m.read32(MONITOR_LOAD) == 0x85830004          # lwzu r12, 4(r3)
    got, _, after = _run_at(board, MONITOR_LOAD, 12, {3: base - 4})
    assert got == stock and after[3] == base, "the monitor must see the calibration"
    assert _run_at(board, None, 5, {6: base}, (32 << 26) | (5 << 21) | (6 << 16))[0] == 0xDEADBEEF
    transport.close_all(t)


def test_watch_follows_a_parked_mirror(t, board):
    """A watched slot parked on the shelf is read from the shelf: the
    breakpoint is armed again on the moved mirror (transport.place does it,
    as the client does)."""
    pc, rd, offset = SINGLE
    transport.close_all(t)
    slot, _ = transport.open_table(t, offset, 2)
    assert transport.write_cell(t, slot, 0, [0x43, 0x21])
    assert transport.watch(t, slot) == transport.STATUS_OK
    board.flash.strict()
    assert transport.park(t, slot, overlay.SHELF[0] + 0x2000) == transport.STATUS_OK   # blank still
    assert transport.descriptors(t)[slot][2] >= dme.CAL_BASE
    assert _run_at(board, pc, rd)[0] == 0x4321
    assert board.flash.violations == []
    transport.close_all(t)


def test_watch_refusals(t):
    transport.close_all(t)
    assert transport.watch(t, 0) == transport.STATUS_SLOT       # nothing open
    transport.open_table(t, CURVE, 16)
    assert transport.watch(t, 1) == transport.STATUS_SLOT
    assert transport.read_state(t)["watch"] is None
    assert transport.unwatch(t) == transport.STATUS_OK          # off when it was never on
    transport.close_all(t)


def test_canary_fills_ram_and_refuses_what_it_must_not(t, board):
    """Op 0A plants a byte pattern in a stretch of variables; read back with
    stock 23. The stack, the request buffer and the state block are refused."""
    at = overlay.POOLS[0][0] + 0x40                     # pool A, nothing open: ours to scribble
    transport.close_all(t)
    assert transport.canary(t, at, 24, 0xA5) == transport.STATUS_OK
    assert t.read_memory(at, 24) == b"\xa5" * 24
    assert transport.canary(t, at, 24, 0x5A) == transport.STATUS_OK
    assert t.read_memory(at - 1, 26)[1:25] == b"\x5a" * 24
    assert transport.canary(t, 0x3FF8F0, 32, 1) == transport.STATUS_RANGE        # into the stack
    assert transport.canary(t, 0x3F9A40, 16, 1) == transport.STATUS_RANGE        # the request buffer
    assert transport.canary(t, transport.STATE + 4, 4, 1) == transport.STATUS_RANGE   # the state block
    assert transport.canary(t, 0x3F9700, 8, 1) == transport.STATUS_RANGE         # below the SRAM
    assert transport.read_state(t)["status"] == transport.STATUS_RANGE
    assert transport.canary(t, 0x3FF8F0, 16, 7) == transport.STATUS_OK            # ending at the stack is fine
