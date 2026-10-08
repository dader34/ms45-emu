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
