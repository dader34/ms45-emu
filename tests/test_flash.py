"""Flashing the emulated DME over the K line, the way the flasher does it.

The tester only talks KWP2000*; everything else is the DME's own code: its
boot loader erases and programs the external flash chip and the MPC555's
internal flash through their models, checks its checksums and RSA
signatures, marks the parts valid, and after a reset starts the program
it was given. The image flashed is the stock pair itself: a dump of a DME
carries checksums and signatures the DME accepts.

A calibration takes half a minute; the whole program (640 KB external,
448 KB internal, then the calibration) several, and only runs with
MS45_SLOW=1.
"""
import os

import pytest

from ms45emu.board import Board, VALID_MARKS
from ms45emu.kwp import Tester

SCHEDULER_TASK = 0x3B38C
INIT_DONE = 0x3FEB26
PROGRAM, PROGRAM_END = 0x60000, 0xFFF40          # what the flasher sends of each part
CALIBRATION, CALIBRATION_END = 0x40000, 0x5D000
EXTERNAL, INTERNAL = 0x02000000, 0x06000000      # the address windows of the flash jobs
BLANK = b"\xff" * 4


def _programming_session(pair):
    b = Board(pair)
    b.boot(max_insns=20_000_000)
    t = Tester(b)
    assert t.authenticate()
    assert t.programming_mode()
    return b, t


def _marks(b):
    return [bytes(b.flash.image[at:at + 4]) for at, _ in VALID_MARKS]


def _boots_program(b):
    b.probe(SCHEDULER_TASK, "scheduler")
    b.boot(max_insns=40_000_000, reset_vector=True)
    return b.m.read8(INIT_DONE) == 1 and b.probe_counts["scheduler"] > 10


def test_calibration_flash(stock):
    flash = stock.pair.flash
    b, t = _programming_session(stock.pair)

    assert t.erase(EXTERNAL + CALIBRATION, 0x20000)
    assert bytes(b.flash.image[CALIBRATION:PROGRAM]) == b"\xff" * 0x20000
    assert bytes(b.flash.image[PROGRAM:PROGRAM_END]) == flash[PROGRAM:PROGRAM_END], "erased more than the calibration"

    # A DME reset now has nothing valid to run and stays in the loader.
    stuck = b.reset()
    assert not stuck.program_valid()
    assert not _boots_program(stuck)

    assert t.write(EXTERNAL + CALIBRATION, flash[CALIBRATION:CALIBRATION_END])
    assert bytes(b.flash.image[CALIBRATION:CALIBRATION_END]) == flash[CALIBRATION:CALIBRATION_END]
    assert b.m.read(0xFFE00000 + CALIBRATION, 0x100) == flash[CALIBRATION:CALIBRATION + 0x100]

    assert t.default_mode()
    assert _marks(b)[2:] == [BLANK, BLANK]
    assert t.check_signature("data")
    assert _marks(b) == [mark.to_bytes(4, "big") for _, mark in VALID_MARKS]
    assert t.reset()

    assert _boots_program(b.reset())


def test_wrong_checksum_is_refused(stock):
    """The DME's own checks are what decides: a calibration whose stored
    checksum does not match is not marked valid."""
    cal = bytearray(stock.pair.flash[CALIBRATION:CALIBRATION + 0x2000])
    cal[0x1000] ^= 0x01
    b, t = _programming_session(stock.pair)
    assert t.erase(EXTERNAL + CALIBRATION, 0x20000)
    assert t.write(EXTERNAL + CALIBRATION, bytes(cal))
    assert t.default_mode()
    assert not t.check_signature("data")
    assert not b.program_valid()


def test_calibration_flash_skips_blank_blocks(stock):
    """BMWeb leaves the all-0xFF blocks of an erased sector unsent, one
    download per run of the others. The loader takes the sub-ranges and its
    own signature check accepts the result: the stock calibration's last
    125 blocks are blank."""
    flash = stock.pair.flash
    cal = flash[CALIBRATION:CALIBRATION_END]
    runs = Tester.blank_runs(cal)
    assert [(at, len(d)) for at, d in runs] == [(0, 345 * 253)]
    b, t = _programming_session(stock.pair)
    assert t.erase(EXTERNAL + CALIBRATION, 0x20000)
    ok, sent = t.write_sparse(EXTERNAL + CALIBRATION, cal)
    assert ok and sent == 345
    assert bytes(b.flash.image[CALIBRATION:CALIBRATION_END]) == cal
    assert t.default_mode()
    assert t.check_signature("data")
    assert _marks(b) == [mark.to_bytes(4, "big") for _, mark in VALID_MARKS]
    assert t.reset()
    assert _boots_program(b.reset())


def test_sparse_download_edge_cases(stock):
    """The loader takes a download at an odd address, one-block runs, a
    non-blank partial last block and a lone byte in a blank block; the chip
    ends up as the image says. (A changed calibration fails the signature,
    so this checks contents only.) It does NOT refuse a range that leaves
    the erased sector, which is why the runs are cut from the image itself."""
    S = 253
    cal = bytearray(stock.pair.flash[CALIBRATION:CALIBRATION_END])
    def blank(*blocks):
        for i in blocks:
            cal[i * S:(i + 1) * S] = b"\xff" * len(cal[i * S:(i + 1) * S])
    blank(0, 1, 2)                                   # leading: first run starts at +0x2F7
    blank(10, 11, 12, 100)                           # interior gaps, a one-block gap
    blank(*range(20, 40, 2))                         # ten one-block runs
    blank(199, 200, 201); cal[200 * S + 77] = 0x5A   # a lone byte keeps its block
    cal[469 * S:] = bytes(range(127))                # the partial last block, non-blank
    cal = bytes(cal)
    runs = Tester.blank_runs(cal)
    assert runs[0][0] == 3 * S and runs[0][0] & 1
    assert all(at + len(d) <= len(cal) for at, d in runs)
    assert sum(-(-len(d) // S) for at, d in runs) == 470 - 3 - 4 - 10 - 2 - 124
    b, t = _programming_session(stock.pair)
    assert t.erase(EXTERNAL + CALIBRATION, 0x20000)
    ok, sent = t.write_sparse(EXTERNAL + CALIBRATION, cal)
    assert ok
    assert bytes(b.flash.image[CALIBRATION:CALIBRATION_END]) == cal

    # the hazard: a range across the sector end is taken and programmed
    ok = t.write(EXTERNAL + CALIBRATION_END - S, b"\x11" * (2 * S))
    assert ok
    assert bytes(b.flash.image[CALIBRATION_END:CALIBRATION_END + S]) != stock.pair.flash[CALIBRATION_END:CALIBRATION_END + S]


def test_programming_gap_is_exactly_12_ms(stock):
    """The loader's access timing: P3min 12 ms is both its limit and the
    only value it accepts; a block sent sooner is ignored and only taken on
    the retransmit. BMWeb's TRANSFER_GAP_MS rests on this."""
    b, t = _programming_session(stock.pair)
    assert t.request([0x83, 0x00]) == bytes.fromhex("c300007818f000")
    for p3 in (0x17, 0x10, 0x00, 0x32):
        assert t.request([0x83, 0x03, 0x00, 0x78, p3, 0xF0, 0x00]) == bytes.fromhex("7f8322")
    assert t.request([0x83, 0x03, 0x00, 0x78, 0x18, 0xF0, 0x00]) == bytes.fromhex("c303")
    data = stock.pair.flash[CALIBRATION:CALIBRATION + 3 * 253]
    assert t.erase(EXTERNAL + CALIBRATION, 0x20000)
    t.gap = b.ips * 11 // 1000                       # 11 ms after the answer: too soon
    t.step = b.ips // 4000
    assert t.write(EXTERNAL + CALIBRATION, data)
    ignored = sum(1 for req, rep in t.log if req and req[0] == 0x36 and not rep)
    assert ignored == 3, "every block was dropped once and taken on the retry"
    t.gap = b.ips * 12 // 1000
    assert t.write(EXTERNAL + CALIBRATION + 3 * 253, data)
    assert not any(not rep for req, rep in t.log[-4:] if req[0] == 0x36)


STOCK_0PA = os.path.expanduser("~/Desktop/e46bins/MS45-DME/sp-daten/MDS451/7561382A.0PA")


@pytest.mark.skipif(not os.environ.get("MS45_SLOW"), reason="minutes; set MS45_SLOW=1")
@pytest.mark.skipif(not os.path.isfile(STOCK_0PA), reason="needs the stock program's .0PA from SP-Daten")
def test_0pa_program_flash_skips_blank_blocks(stock):
    """BMW's own .0PA of the stock program, written sparsely: no calibration,
    no boot area and a header gap, so 13% of its blocks are blank. The stock
    calibration stays valid, so the loader's checks and the boot judge it."""
    from ms45emu.daten import records, _write, PROGRAM as PROG, EXTERNAL as WINDOW, MPC_SIZE
    from ms45emu.machine import FLASH_SIZE
    flash, mpc = bytearray(b"\xff" * FLASH_SIZE), bytearray(b"\xff" * MPC_SIZE)
    recs = list(records(STOCK_0PA))
    assert _write(mpc, 0, MPC_SIZE, 0, recs) and _write(flash, PROG[0], PROG[1], WINDOW, recs)
    ext, mpc = bytes(flash[PROGRAM:PROGRAM_END]), bytes(mpc)
    assert len(Tester.blank_runs(ext)) == 4 and len(Tester.blank_runs(mpc)) == 1

    b, t = _programming_session(stock.pair)
    assert t.erase(EXTERNAL + PROGRAM, 0xA0000)
    ok, sent = t.write_sparse(EXTERNAL + PROGRAM, ext)
    assert ok and sent == 2055
    ok, sent = t.write_sparse(INTERNAL, mpc)
    assert ok and sent == 1787
    assert bytes(b.flash.image[PROGRAM:PROGRAM_END]) == ext
    assert bytes(b.cmf.image) == mpc
    assert t.default_mode()
    assert t.programming_status() == 5
    assert t.check_signature("program")
    assert t.programming_status() == 1
    assert _marks(b) == [mark.to_bytes(4, "big") for _, mark in VALID_MARKS]
    assert t.reset()
    assert _boots_program(b.reset())


@pytest.mark.skipif(not os.environ.get("MS45_SLOW"), reason="minutes; set MS45_SLOW=1")
def test_full_program_flash(stock):
    flash, mpc = stock.pair.flash, stock.pair.mpc
    b, t = _programming_session(stock.pair)

    # One erase job takes the program's three sectors and the internal flash.
    assert t.erase(EXTERNAL + PROGRAM, 0xA0000)
    assert bytes(b.flash.image[PROGRAM:]) == b"\xff" * 0xA0000
    assert bytes(b.cmf.image) == b"\xff" * len(mpc)
    assert bytes(b.flash.image[:PROGRAM]) == flash[:CALIBRATION] + bytes(b.flash.image[CALIBRATION:PROGRAM])

    assert t.write(EXTERNAL + PROGRAM, flash[PROGRAM:PROGRAM_END])
    assert t.write(INTERNAL, mpc)
    assert t.erase(EXTERNAL + CALIBRATION, 0x20000)
    assert t.write(EXTERNAL + CALIBRATION, flash[CALIBRATION:CALIBRATION_END])
    assert bytes(b.flash.image[PROGRAM:PROGRAM_END]) == flash[PROGRAM:PROGRAM_END]
    assert bytes(b.cmf.image) == mpc

    assert t.default_mode()
    assert t.programming_status() == 5              # program signature not checked
    assert t.check_signature("program")
    assert t.programming_status() == 6              # data signature not checked
    assert t.check_signature("data")
    assert t.programming_status() == 1
    assert t.reset()

    assert _boots_program(b.reset())
