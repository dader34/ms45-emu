"""The diagnostic patch (ms45emu/diagpatch.py), built onto the stock pair
and run: faster K-line logging, the log frame on CAN, the per-segment
capture buffer.

The full flash of the patched program through the DME's own boot loader
takes minutes and only runs with MS45_SLOW=1.
"""
import os
import struct
from collections import Counter

import pytest

from ms45emu import Machine, checksums, diagpatch, dme, e46
from ms45emu.board import Board
from ms45emu.kwp import Tester
from ms45emu.machine import R13

FRAME = e46.FRAME_INSTRUCTIONS
MS = FRAME // 10
SECOND = 100 * FRAME
PACKET = [(R13 + dme.VAR_N, 2), (R13 + dme.VAR_PV, 1), (dme.KL15_FLAG, 1)] + [(0x3FA100 + 2 * i, 2) for i in range(13)]


@pytest.fixture
def diag(stock):
    return diagpatch.build(stock.pair)


def _running(pair):
    b = Board(pair)
    b.boot(max_insns=20_000_000)
    return b


def _timing(b):
    return tuple(b.m.read(R13 + dme.KWP_P2MIN, 2))


def _log_frames(b, layout):
    return [layout.frame(f.data) for f in b.can_a.tx_log if f.id == layout.can_id]


def _cycle_ms(b, t, reads=40):
    """Mean time for one read of the defined packet, in ms of DME time."""
    start = b.instructions
    for _ in range(reads):
        assert t.read_packet() is not None
    return (b.instructions - start) / reads / MS


# ---- the images ---------------------------------------------------------------
def test_signing_reproduces_the_stock_signature(stock):
    flash, mpc = stock.pair.flash, stock.pair.mpc
    assert checksums.program_signature(flash, mpc) == flash[0x60074:0x60074 + 64]


def test_only_the_two_calls_and_the_free_area_change(stock, diag):
    pair, layout = diag
    mpc_changes = {i & ~3 for i in range(len(pair.mpc)) if pair.mpc[i] != stock.pair.mpc[i]}
    assert mpc_changes == {dme.FRAME_TASK_BUILDER_CALL, dme.SEGMENT_TASK_LAST_CALL}
    allowed = (list(range(0x60000, 0x60004)) + list(range(0x60074, 0x600B4)) + list(range(0x60340, 0x60344)) +
               list(range(diagpatch.CODE_START, layout.code_end - diagpatch.EXT)))
    flash_changes = {i for i in range(len(pair.flash)) if pair.flash[i] != stock.pair.flash[i]}
    assert flash_changes <= set(allowed)
    assert diagpatch.is_patched(pair) and not diagpatch.is_patched(stock.pair)


def test_sums_and_signature_are_brought_up_to_date(diag):
    pair, _ = diag
    m = Machine(pair)
    assert dme.romtest_sum_native(m) == dme.romtest_sum_stored(m)
    crc = checksums.image_program_crc(pair.flash, pair.mpc)
    assert all(struct.unpack_from(">I", pair.flash, at)[0] == crc for at in checksums.PROGRAM_CRC_OFFSETS)
    assert pair.flash[0x60074:0x60074 + 64] == checksums.program_signature(pair.flash, pair.mpc)


def test_remove_gives_the_stock_pair_back(stock, diag):
    back = diagpatch.remove(diag[0])
    assert back.flash == stock.pair.flash and back.mpc == stock.pair.mpc


def test_rebuild_with_other_fields(diag):
    pair, layout = diagpatch.build(diag[0], can_id=None, capture_fields=(diagpatch.SEGMENT, diagpatch.SEGMENT_TIME))
    assert layout.can_id is None and [f.name for f in layout.capture_fields] == ["segment", "segment_time"]
    b = _running(pair)
    assert not [f for f in b.can_a.tx_log if f.id == diagpatch.CAN_ID]
    assert b.m.read16(layout.block) == diagpatch.MAGIC


def test_fields_that_would_not_fit_are_refused(stock):
    with pytest.raises(ValueError):
        diagpatch.build(stock.pair, can_fields=(diagpatch.N,))            # 16 bit at an odd offset
    with pytest.raises(ValueError):
        diagpatch.build(stock.pair, capture_fields=(diagpatch.SEGMENT,) * 8)


# ---- the program still runs -----------------------------------------------------
def test_program_runs_as_before(diag):
    pair, layout = diag
    b = _running(pair)
    b.can_a.tx_log.clear()
    b.run(SECOND)
    counts = Counter(f.id for f in b.can_a.tx_log)
    for ident in (e46.DME1, e46.DME2, e46.DME4, layout.can_id):
        assert 95 <= counts[ident] <= 105, (hex(ident), counts[ident])
    assert b.watchdog_bad == 0
    assert b.kl15


def test_log_frame_counts_and_carries_the_variables(diag):
    pair, layout = diag
    b = _running(pair)
    b.crank.rpm = 2000
    b.can_a.tx_log.clear()
    b.run(SECOND)
    frames = _log_frames(b, layout)
    counters = [f["counter"] for f in frames]
    assert all((b_ - a) & 0xFF == 1 for a, b_ in zip(counters, counters[1:]))
    assert abs(frames[-1]["n"] - 2000) <= 5
    assert frames[-1]["kl15"] == 1
    assert b.m.read8(layout.block + 2) == counters[-1]


# ---- K line -----------------------------------------------------------------------
def test_timing_stays_stock_until_a_tester_asks(diag):
    b = _running(diag[0])
    t = Tester(b)
    stock_timing = _timing(b)
    assert stock_timing == (25, 25)
    assert t.ident() is not None and t.define_packet(PACKET) and t.read_packet() is not None
    assert _timing(b) == stock_timing


def test_logging_mode_on_the_stock_program(stock):
    """What needs no patch: 115200 baud and the default session's limits."""
    b = _running(stock.pair)
    t = Tester(b)
    assert t.define_packet(PACKET)
    assert t.logging_mode()
    assert _timing(b) == dme.KWP_FAST_TIMING
    assert len(t.read_packet()) == 30
    assert 17 <= _cycle_ms(b, t) <= 23                         # 50 Hz


def test_logging_mode_with_the_patch_is_twice_as_fast(diag):
    b = _running(diag[0])
    t = Tester(b)
    assert t.define_packet(PACKET)
    assert t.logging_mode(patched=True)
    assert _timing(b) == (diagpatch.FAST_P2MIN, diagpatch.FAST_P3MIN)
    assert len(t.read_packet()) == 30
    assert 8 <= _cycle_ms(b, t) <= 11                          # 100 Hz
    # Back in the default session the DME is as it was (it restores its
    # answer delay only after the answer has gone out).
    assert t.default_mode()
    b.run(2 * FRAME)
    assert _timing(b) == (25, 25)
    assert t.ident() is not None


# ---- the capture buffer -------------------------------------------------------------
def _truth(b, layout):
    """What the program's variables were each time the segment task got to
    its end, taken by a probe on the stub's first instruction."""
    seen = []
    b.probe(layout.segment_stub, "segment end",
            on_hit=lambda b: seen.append(tuple(int.from_bytes(b.m.read(f.address, f.size), "big") for f in layout.capture_fields)))
    return seen


@pytest.mark.parametrize("rpm", [900, 3000, 6500])
def test_every_segment_is_captured(diag, rpm):
    """Read over the K line while the engine turns, the ring gives every
    run of the segment task, in order, with the values it had. (Above
    about 4000 rpm the emulated DME, which has no cam signal, keeps
    restarting its crank search, so the values themselves are irregular
    there; the capture has to show exactly that.)"""
    pair, layout = diag
    b = _running(pair)
    truth = _truth(b, layout)
    t = Tester(b)
    assert t.logging_mode(patched=True)
    b.crank.rpm = rpm
    b.run(SECOND)                                             # synchronise, fill the ring

    capture = diagpatch.Capture(layout)
    records = capture.feed(t.read_memory(layout.block, layout.block_size))
    assert len(records) == diagpatch.SLOTS - 1
    for _ in range(25):
        records += capture.feed(t.read_memory(layout.block, layout.block_size))
    assert capture.lost == 0
    assert len(records) > diagpatch.SLOTS - 1 + rpm / 20 * 0.5       # three segments a revolution, 25 reads take 0.7 s

    seqs = [r["seq"] for r in records]
    assert all(b_ - a == 1 or (a, b_) == (255, 1) for a, b_ in zip(seqs, seqs[1:]))
    got = [tuple(r[f.name] for f in layout.capture_fields) for r in records]
    # The n-th run of the task writes sequence number (n - 1) % 255 + 1, so
    # the last record says which run it was: a few before the newest, which
    # happened while the last answer was on the line.
    last = max(n for n in range(1, len(truth) + 1) if (n - 1) % 255 + 1 == seqs[-1])
    assert len(truth) - last <= rpm / 20 * 0.04 + 1
    assert got == truth[last - len(got):last]


def test_records_carry_segment_time_and_speed(diag):
    pair, layout = diag
    b = _running(pair)
    b.crank.rpm = 3000
    b.run(SECOND)
    records = layout.records(b.m.read(layout.block, layout.block_size))
    assert len(records) == diagpatch.SLOTS - 1
    segments = [r["segment"] for r in records]
    assert all((b_ - a) % 6 == 1 for a, b_ in zip(segments, segments[1:]))
    assert all(abs(r["n"] - 3000) <= 5 for r in records)
    assert all(abs(5_000_000 / r["segment_time"] - r["n"]) <= 5 for r in records)     # 4 us a count


def test_nothing_is_captured_with_the_engine_stopped(diag):
    pair, layout = diag
    b = _running(pair)
    b.run(SECOND // 2)
    block = b.m.read(layout.block, layout.block_size)
    assert layout.header(block)[0]
    assert layout.records(block) == []
    assert block[diagpatch.HEADER:] == bytes(diagpatch.SLOTS * diagpatch.RECORD)


def test_block_is_left_alone_when_the_heap_reaches_it(diag):
    pair, layout = diag
    b = _running(pair)
    assert b.m.read32(R13 + dme.HEAP_BOTTOM) <= layout.block
    assert b.m.read32(R13 + dme.HEAP_TOP) >= layout.block + layout.block_size
    b.crank.rpm = 3000
    b.run(SECOND // 2)

    for pointer, value in ((dme.HEAP_BOTTOM, layout.block + 4), (dme.HEAP_TOP, layout.block + layout.block_size - 4)):
        old = b.m.read32(R13 + pointer)
        b.m.write32(R13 + pointer, value)
        b.run(2 * FRAME)
        before = b.m.read(layout.block, layout.block_size)
        b.can_a.tx_log.clear()
        b.run(SECOND // 4)
        assert b.m.read(layout.block, layout.block_size) == before
        assert not _log_frames(b, layout)
        assert Counter(f.id for f in b.can_a.tx_log)[e46.DME1] >= 20      # the program itself carries on
        b.m.write32(R13 + pointer, old)
        b.run(SECOND // 4)
        assert b.m.read(layout.block, layout.block_size) != before


# ---- with the map switch --------------------------------------------------------------
def _dme1(pair, layout=None):
    """The 0x316 frames of the first second and a half, and the log frames."""
    b = Board(pair)
    dme1, log = [], []
    b.can_a.on_tx = lambda f: dme1.append(f.data) if f.id == e46.DME1 else log.append(f) if layout and f.id == layout.can_id else None
    b.boot(max_insns=60_000_000)
    return dme1, log


def test_goes_on_top_of_the_map_switch(patched):
    pair, layout = diagpatch.build(patched.pair)
    assert pair.mpc[0x6E550:] == patched.pair.mpc[0x6E550:]      # the map switch's code, as its builder checks it
    assert dme.tach_hook_target(Machine(pair)) == dme.tach_hook_target(patched)
    # The cluster is told the same with and without the patch, map indication included.
    before, _ = _dme1(patched.pair)
    after, log = _dme1(pair, layout)
    assert len(before) > 100 and after == before
    assert len(log) == len(after) and layout.frame(log[-1].data)["map"] & dme.FLAG_INDEX_MASK == 0
    assert diagpatch.remove(pair).mpc == patched.pair.mpc


# ---- flashed the way the car gets it ----------------------------------------------------
@pytest.mark.skipif(not os.environ.get("MS45_SLOW"), reason="minutes; set MS45_SLOW=1")
def test_patched_program_passes_the_boot_loader(stock, diag):
    pair, layout = diag
    program, program_end, calibration, calibration_end = 0x60000, 0xFFF40, 0x40000, 0x5D000
    b = _running(stock.pair)
    t = Tester(b)
    assert t.authenticate() and t.programming_mode()
    assert t.erase(0x02000000 + program, 0xA0000)
    assert t.write(0x02000000 + program, pair.flash[program:program_end])
    assert t.write(0x06000000, pair.mpc)
    assert t.erase(0x02000000 + calibration, 0x20000)
    assert t.write(0x02000000 + calibration, pair.flash[calibration:calibration_end])
    assert t.default_mode()
    assert t.check_signature("program")                          # the DME's own CRC and RSA check
    assert t.check_signature("data")
    assert t.programming_status() == 1
    assert t.reset()

    b = b.reset()
    b.boot(max_insns=40_000_000, reset_vector=True)
    assert len(_log_frames(b, layout)) > 10
    t = Tester(b)
    assert t.logging_mode(patched=True)
    assert _timing(b) == (diagpatch.FAST_P2MIN, diagpatch.FAST_P3MIN)
