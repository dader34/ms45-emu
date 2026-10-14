"""Live single values (ms45emu/singles.py): every instruction that reads a
constant straight from the calibration is re-pointed at RAM or turned into a
trap, and each one still loads exactly what the instruction it replaced
did -- and the mirror's value once the tester has opened one over it."""
import os
import struct

import pytest
from unicorn.ppc_const import (UC_PPC_REG_0, UC_PPC_REG_CR, UC_PPC_REG_CTR, UC_PPC_REG_LR,
                               UC_PPC_REG_MSR, UC_PPC_REG_PC, UC_PPC_REG_XER)

from ms45emu import dme, fold, overlay, singles, transport
from ms45emu.board import Board
from ms45emu.checksums import crc32_mpeg2
from ms45emu.e46 import Peers
from ms45emu.image import IMAGES_DIR, Pair
from ms45emu.inputs import set_pedal
from ms45emu.kwp import Tester

CAL = fold.CAL_FILE
SPECIAL = (UC_PPC_REG_PC, UC_PPC_REG_LR, UC_PPC_REG_CTR, UC_PPC_REG_XER, UC_PPC_REG_CR, UC_PPC_REG_MSR)
KEPT = (UC_PPC_REG_LR, UC_PPC_REG_CTR, UC_PPC_REG_XER, UC_PPC_REG_CR, UC_PPC_REG_MSR)


def _pair():
    # MS45_LIVETUNE_BASE=session1clean runs all of this on the stock program
    # (tools/livetune_build.py --stock --base-prefix) instead of the car's own
    base = os.environ.get("MS45_LIVETUNE_BASE", "session1")
    with open(os.path.join(IMAGES_DIR, f"{base}.flash.bin"), "rb") as f, \
         open(os.path.join(IMAGES_DIR, f"{base}.mpc.bin"), "rb") as m:
        return Pair(f.read(), m.read(), base)


@pytest.fixture(scope="module")
def stock():
    return _pair()


@pytest.fixture(scope="module")
def layers(stock):
    return fold.build(transport.build(overlay.build(stock)))


@pytest.fixture(scope="module")
def built(layers):
    # the trap tier is tested here although no image ships it any more:
    # it resets the car's DME at 3 krpm (singles.py's module doc)
    return singles.build(layers, traps=True)


def test_default_build_has_no_traps(stock, layers, planned):
    """What ships: the pool re-pointed, every other load untouched, the
    program exception vector left alone, the table saying nothing outside
    the pool is live."""
    plain = singles.build(layers)
    twi = lambda pair, image, span: sum(1 for at in range(*span, 4)   # noqa: E731
                                        if struct.unpack_from(">I", getattr(pair, image), at)[0] >> 26 == singles.TWI)
    for image, span in (("mpc", singles.MPC_CODE), ("flash", singles.EXT_CODE)):
        assert twi(plain, image, span) == twi(stock, image, span), image
    assert struct.unpack_from(">I", plain.mpc, singles.VECTOR)[0] == struct.unpack_from(">I", layers.mpc, singles.VECTOR)[0]
    t = singles.parse_table(plain.flash[singles.TABLE:singles.TABLE + 0x2800])
    assert t["runs"] == [] and len(t["pool"]) == len(planned.pool)
    in_pool = lambda s: any(lo <= s.offset < lo + n for lo, (n, _) in planned.pool.items())   # noqa: E731
    def word(pair, site):
        image, at = singles._file(site.pc)
        return struct.unpack_from(">I", pair.mpc if image == 0 else pair.flash, at)[0]
    for s in planned.sites:
        if in_pool(s):
            assert (word(plain, s) >> 16) & 31 == 13, hex(s.pc)      # re-pointed to the pool
        else:
            assert word(plain, s) == word(layers, s), hex(s.pc)      # left as it was
    assert singles.build(plain) is plain


@pytest.fixture(scope="module")
def planned(layers):
    return singles.plan(layers)


@pytest.fixture(scope="module")
def board(built):
    b = Board(built)
    b.boot(max_insns=int(0.3 * b.ips), reset_vector=True)
    return b


def _expected(image, site):
    """What the original instruction leaves in rD, from the calibration `image`."""
    n = singles.SIZES[site.op]
    v = int.from_bytes(image[CAL + site.offset:CAL + site.offset + n], "big")
    if site.op == 42 and v & 0x8000:                         # lha sign-extends
        v |= 0xFFFF0000
    return v


def _run_site(b, site, seed=0):
    """Execute the patched instruction at a site with every register set to a
    known pattern; (rD, whether everything else came through untouched)."""
    mu = b.m.mu
    snap = [mu.reg_read(UC_PPC_REG_0 + i) for i in range(32)] + [mu.reg_read(r) for r in SPECIAL]
    try:
        before = {}
        for i in range(32):
            if i not in (1, 2, 13):
                mu.reg_write(UC_PPC_REG_0 + i, (0x51000000 + seed * 0x10000 + i * 0x101) & 0xFFFFFFFF)
            before[i] = mu.reg_read(UC_PPC_REG_0 + i)
        mu.reg_write(UC_PPC_REG_CR, 0x5A3C96F0 ^ seed)
        mu.reg_write(UC_PPC_REG_CTR, 0xC0FFEE00 + seed)
        mu.reg_write(UC_PPC_REG_LR, 0x1234568 + 4 * seed)
        kept = [mu.reg_read(r) for r in KEPT]
        mu.ctl_flush_tb()            # a block translated earlier would run past the stop address
        mu.emu_start(site.pc, site.pc + 4, count=400)
        assert b.m.pc == site.pc + 4, f"0x{site.pc:X} did not come back: pc=0x{b.m.pc:X}"
        clean = all(mu.reg_read(UC_PPC_REG_0 + i) == before[i] for i in range(32) if i != site.rd) \
            and [mu.reg_read(r) for r in KEPT] == kept
        return mu.reg_read(UC_PPC_REG_0 + site.rd), clean
    finally:
        for i in range(32):
            mu.reg_write(UC_PPC_REG_0 + i, snap[i])
        for r, v in zip(SPECIAL, snap[32:]):
            mu.reg_write(r, v)
        mu.ctl_flush_tb()


def test_build(stock, layers, built, planned):
    assert singles.is_patched(built) and overlay.is_patched(built) and fold.is_patched(built)
    assert singles.build(built) is built                      # a second build leaves it alone
    assert len(planned.sites) > 4000 and len(planned.skipped) < 100
    assert {s.op for s in planned.sites} == set(singles.KINDS)
    t = singles.parse_table(built.flash[singles.TABLE:singles.CODE])
    assert t["pool"] == {lo: (n, singles.POOL[0] + at) for lo, (n, at) in planned.pool.items()}
    assert t["runs"] == planned.runs
    assert max(a + n for n, a in t["pool"].values()) <= singles.POOL[1]
    # nothing but the sites, the table, the code, the two hooks and the signature moved
    words = {s.pc for s in planned.sites}
    changed = [at for at in range(0, len(stock.mpc), 4) if layers.mpc[at:at + 4] != built.mpc[at:at + 4]]
    assert set(changed) - words - {singles.VECTOR} <= set(range(0x6FFE0, 0x70000, 4))
    # the golden calibration and the calibration itself are as they were
    assert built.flash[CAL:CAL + 0x20000] == layers.flash[CAL:CAL + 0x20000]
    assert fold.golden(built) == fold.golden(layers)


def test_boot_fills_the_pool_and_takes_it_from_the_heap(board, built):
    t = singles.parse_table(built.flash[singles.TABLE:singles.CODE])
    for offset, (n, at) in t["pool"].items():
        assert board.m.read(at, n) == built.flash[CAL + offset:CAL + offset + n]
    assert board.m.read32(singles.R13 + dme.HEAP_TOP) == singles.POOL[0]
    assert board.m.read32(singles.R13 + dme.HEAP_BOTTOM) <= singles.POOL[0]
    assert board.traps > 100 and not board.other_exceptions


def test_every_site_loads_what_it_did(board, built, planned):
    """All of them: the re-pointed ones and the traps, three register
    patterns over the run."""
    wrong, dirty = [], []
    traps = board.traps
    for i, site in enumerate(planned.sites):
        got, clean = _run_site(board, site, i % 3)
        if got != _expected(built.flash, site):
            wrong.append(hex(site.pc))
        if not clean:
            dirty.append(hex(site.pc))
    assert not wrong and not dirty, (wrong[:10], dirty[:10])
    pooled = sum(1 for s in planned.sites
                 if any(lo <= s.offset < lo + n for lo, (n, _) in planned.pool.items()))
    assert 500 < pooled < len(planned.sites)
    assert board.traps - traps == len(planned.sites) - pooled    # each of the others trapped once


def test_every_destination_register_and_load(board, built):
    # the handler writes rD through a table of 32 entries and picks one of
    # four loads: every pair, on a trap word of our own making in RAM, at a
    # halfword whose top bit is set (so lha and lhz differ)
    offset = next(o for o in range(0x300, 0x1B00) if built.flash[CAL + o] & 0x80)
    at = 0x3FA200
    keep = board.m.read(at, 4)
    try:
        for op in singles.KINDS:
            for rd in range(32):
                if rd in (1, 2, 13):
                    continue
                site = singles.Site(at, op, rd, offset)
                board.m.write32(at, singles.trap_word(site))
                board.m.mu.ctl_flush_tb()
                for seed in range(2):
                    got, clean = _run_site(board, site, seed)
                    assert got == _expected(built.flash, site) and clean, (op, rd)
    finally:
        board.m.write(at, keep)


def test_other_program_exceptions_reach_the_program(board, built, layers):
    # a trap that is not ours (TO below 28) goes on to the program's own
    # handler, every register as the exception found it
    stock = struct.unpack_from(">I", layers.mpc, singles.VECTOR)[0] & 0x03FFFFFC | 0xFC000000
    at = 0x3FA200
    keep = board.m.read(at, 4)
    mu = board.m.mu
    snap = [mu.reg_read(UC_PPC_REG_0 + i) for i in range(32)] + [mu.reg_read(r) for r in SPECIAL]
    try:
        board.m.write32(at, (3 << 26) | (4 << 21) | (3 << 16) | 0x7FFF)    # twi 4 (eq), r3, 0x7FFF
        mu.ctl_flush_tb()
        mu.reg_write(UC_PPC_REG_0 + 3, 0x7FFF)
        for i in (0, 11, 12):
            mu.reg_write(UC_PPC_REG_0 + i, 0xA0A00000 + i)
        mu.reg_write(UC_PPC_REG_CR, 0x13579BDF)
        mu.emu_start(at, stock, count=400)
        assert board.m.pc == stock
        assert [board.m.reg(i) for i in (0, 11, 12)] == [0xA0A00000 + i for i in (0, 11, 12)]
        assert mu.reg_read(UC_PPC_REG_CR) == 0x13579BDF
    finally:
        board.m.write(at, keep)
        for i in range(32):
            mu.reg_write(UC_PPC_REG_0 + i, snap[i])
        for r, v in zip(SPECIAL, snap[32:]):
            mu.reg_write(r, v)
        mu.ctl_flush_tb()


def test_engine_runs_on_the_patched_program(built):
    b = Board(built)
    b.boot(max_insns=int(0.2 * b.ips))
    peers = Peers(b, automatic=True)
    set_pedal(b, 15)
    b.crank.rpm = 900
    peers.run(int(0.5 * b.ips))
    traps = b.traps
    peers.run(int(1.0 * b.ips))
    assert b.m.sda16(dme.VAR_N) == 900 and not b.other_exceptions
    assert 200 < b.traps - traps < 6000                       # the quiet tier: ~2,000 a second


def _sites_of(planned, offset):
    return [s for s in planned.sites if s.offset == offset]


def test_live_edit_of_a_trapped_value(board, built, planned):
    """A value outside the pool: opened as a two-byte mirror like a table,
    every reader sees the edit; closed, the calibration again."""
    t = Tester(board)
    transport.close_all(t)
    site = next(s for s in planned.sites if s.op == 40 and s.offset not in planned.pool
                and len(_sites_of(planned, s.offset)) > 1)
    readers = _sites_of(planned, site.offset)
    slot, mirror = transport.open_table(t, site.offset, 2)
    assert mirror < dme.CAL_BASE
    assert transport.write_cell(t, slot, 0, [0x12, 0x34])
    assert [_run_site(board, s)[0] for s in readers] == [0x1234] * len(readers)
    # its neighbours in the same block still read the calibration
    other = next(s for s in planned.sites if s.offset not in planned.pool
                 and s.offset >> 8 == site.offset >> 8 and abs(s.offset - site.offset) > 4)
    assert _run_site(board, other)[0] == _expected(built.flash, other)
    # parked on the shelf it is read from flash
    board.flash.strict()
    assert transport.park(t, slot, overlay.SHELF[0] + 0x800) == transport.STATUS_OK
    assert [_run_site(board, s)[0] for s in readers] == [0x1234] * len(readers)
    assert board.flash.violations == []
    transport.close_all(t)
    assert _run_site(board, site)[0] == _expected(built.flash, site)


def test_live_edit_of_a_pool_value(board, built, planned):
    """A value with RAM of its own: the mirror is placed on those bytes, so
    the write is what the program reads; close-all puts the calibration back."""
    t = Tester(board)
    transport.close_all(t)
    table = singles.parse_table(built.flash[singles.TABLE:singles.CODE])
    offset = next(o for o, (n, _) in sorted(table["pool"].items()) if n == 1 and len(_sites_of(planned, o)) > 1)
    n, at = table["pool"][offset]
    readers = _sites_of(planned, offset)
    stock_value = built.flash[CAL + offset]
    assert transport.place(t, 0, offset, n, at) == transport.STATUS_OK
    assert board.m.read8(at) == stock_value                   # seeded with what it held
    assert transport.write_cell(t, 0, 0, [stock_value ^ 0x5A])
    assert [_run_site(board, s)[0] for s in readers] == [stock_value ^ 0x5A] * len(readers)
    assert transport.descriptors(t) == [(offset, n, at)]
    transport.close_all(t)
    assert board.m.read8(at) == stock_value
    assert [_run_site(board, s)[0] for s in readers] == [stock_value] * len(readers)
    assert t.request([0x1A, 0x80]) is not None                # and the DME carries on


def test_mirror_outside_the_pools_still_refused(board):
    t = Tester(board)
    transport.close_all(t)
    for mirror in (singles.POOL[0] - 2, singles.POOL[1] - 1, 0x3FFA00):
        assert transport.place(t, 0, 0x1944, 2, mirror) == transport.STATUS_ROOM, hex(mirror)
    transport.close_all(t)


def test_save_folds_both_kinds(built, planned):
    b = Board(built)
    b.boot(max_insns=int(0.3 * b.ips), reset_vector=True)
    t = Tester(b)
    table = singles.parse_table(built.flash[singles.TABLE:singles.CODE])
    pooled = next(o for o, (n, _) in sorted(table["pool"].items()) if n == 1)
    trapped = next(s.offset for s in planned.sites if s.op == 34 and s.offset not in planned.pool)
    n, at = table["pool"][pooled]
    assert transport.place(t, 0, pooled, n, at) == transport.STATUS_OK
    assert transport.write_cell(t, 0, 0, [built.flash[CAL + pooled] ^ 0x11])
    slot, _ = transport.open_table(t, trapped, 1)
    assert transport.write_cell(t, slot, 0, [built.flash[CAL + trapped] ^ 0x22])
    b.flash.strict()
    assert transport.save(t) is True
    for _ in range(300):
        if b.m.pc == fold.DONE:
            break
        b.run(b.ips // 100)
    assert b.m.pc == fold.DONE and b.flash.violations == []
    want = bytearray(built.flash)
    want[CAL + pooled] ^= 0x11
    want[CAL + trapped] ^= 0x22
    want[CAL + fold.MON_AT:CAL + fold.MON_AT + 8] = fold.monitor_sum(want[CAL:CAL + fold.SECTOR])
    struct.pack_into(">I", want, CAL + fold.CRC_AT, crc32_mpeg2(bytes(want[CAL + fold.CRC_FROM:CAL + fold.CRC_TO])))
    assert bytes(b.flash.image) == bytes(want)
    # the DME it resets into reads both from the calibration: pool refilled, no mirrors
    b2 = b.reset()
    b2.boot(max_insns=40_000_000, reset_vector=True)
    assert b2.m.read8(at) == want[CAL + pooled]
    for s in [s for s in planned.sites if s.offset in (pooled, trapped)]:
        assert _run_site(b2, s)[0] == _expected(want, s)
