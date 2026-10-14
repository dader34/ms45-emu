"""The save (docs/livetune-design.md, milestone 4): fold the open live-tune
tables into the calibration sector itself, as often as wanted.

The flash allows no second rewritable calibration (one sector holds nothing
but calibration, the part is single-bank and SRAM is 26 KB against a 116 KB
calibration), so a save keeps only the *difference* across the erase:

- `build` puts a golden copy of the calibration at ext 0xE0000 (where the
  old generation kept its map 2), never rewritten afterwards;
- a save, engine stopped: (1) the current tune -- the calibration sector with
  the open mirrors laid over it -- is compared with the golden copy and the
  differing words written to RAM as runs; (2) the calibration sector is
  erased; (3) it is programmed back from the golden copy with the runs laid
  over it; (4) the safety monitor's sum, the calibration CRC and then the
  loader's two valid marks are programmed, and the DME resets.

After that the calibration *is* the tune: nothing is consumed, there is no
manifest and no boot redirect. A power loss between (2) and (4) leaves a
calibration without its valid marks, so the loader keeps the DME in
programming mode until it is flashed again; no recovery is built in.

Everything that touches the chip runs from the MPC's internal flash with
interrupts masked: the part answers every read with status while it programs
or erases, so no instruction may be fetched from it then. The driver is our
own (the loader's lives in the chip and is meant for a RAM copy): the AMD
sequences, a poll for the written data with the DQ5 time-out and an
iteration bound, and the watchdog serviced in every wait, as the loader's
does. Burst mode goes off first, by the loader's own sequence.

Two ways in, both through `ENTRY` with the return address in CTR:

- transport op 05, from the K line with the engine stopped;
- the after-run: the power-down routine's last call before it releases the
  main relay is displaced through `KEYOFF`, so edits still open at key-off
  are saved without a tester -- when a save was asked for beforehand
  (transport op 08 sets `overlay.SAVE_ARMED`); otherwise they are dropped
  with the power.

`ENTRY` returns (r12 = 0 nothing to save, 1 engine turning, 2 the tune is
further from golden than RAM holds) with every other register as it found
it, or it does not return at all: once RAM is given over to the runs the
only way on is the reset at the end.
"""
import struct

from . import dme, overlay
from .checksums import crc32_mpeg2, fix_program
from .image import Pair
from .ppc import (BEQ, BNE, BLT, BGT, BGE, BDNZ, ISYNC, BLR, BCTR, BEQLR, R13, Asm,
                  _branch, _branch_target, _d, _li, _lis, _ori, _addi, _addis, _andi, _lwz, _lhz,
                  _lbz, _stw, _sth, _cmpwi, _cmplwi, _cmplw, _add, _or, _xor, _mr, _addc, _addze,
                  _srw, _mflr, _mtlr, _mfctr, _mtctr, _mfmsr, _mtmsr, _mfbbcmcr, _mtbbcmcr,
                  _rlwinm, _slwi, _srwi)

CHIP = 0xFFE00000                       # the external chip's first window
CAL = dme.CAL_BASE                      # 0xFFE40000, the calibration sector
CAL_FILE, SECTOR = 0x40000, 0x20000
GOLD_FILE = 0xE0000                     # the golden copy, CAL + 0xA0000
LENGTH = 0x18000                        # what a save rewrites: the calibration's data ends
WORDS = LENGTH // 2                     # at 0x1548C and the golden room at 0xF8000
CRC_AT = 0x100                          # the stored CRC, over cal 0x200-0x1CFFF
CRC_FROM, CRC_TO = 0x200, dme.CAL_LENGTH
MARKS = ((0x1FF80, 0x48249042), (0x1FFC0, 0x90482442))   # the loader's "calibration valid"
# The program's safety monitor keeps a sum of its own: the 32-bit words of
# calibration 0x240-0x7C8 added into 64 bits from a seed, against the eight
# bytes at 0x57DC (its code at 0xFFF77850, the range from the table at program
# file 0x60620). It reads the range by address, so a mirror does not disturb
# it, but an edit saved into the range must take the stored sum with it.
MON_FROM, MON_TO, MON_AT = 0x240, 0x7C8, 0x57DC
MON_SEED = 0x0123456789ABCDEF
MON_TABLE = (0x60620, (dme.CAL_BASE + MON_FROM, dme.CAL_BASE + MON_TO, 0xFFFFFFFF))

CODE, CODE_END = overlay.CODE_END, 0x70000   # the rest of the internal flash's blank tail
RUNS, RUNS_END = 0x3FA0A0, overlay.SINGLES_POOL[0]   # RAM above the overlay's mirrors and
                                        # below the single-value pool (a mirror may be
                                        # there), ours once the save is past its checks
KEYOFF_SITE = 0xFFF979BC                # the power-down routine: `bl 0xFFFC8FB0`, its last
KEYOFF_STOCK = 0xFFFC8FB0               # call before the relay bit (MPIO 0x306100 & 0x40) drops
SWSR, BR0 = 0x2FC00E, 0x2FC100
SIU = 0x300000                          # both are reached from here (lis 0x30)
VAR_N = R13 + dme.VAR_N                 # engine speed: 0 with the engine stopped

STATUS_NOTHING, STATUS_TURNING, STATUS_BIG = 0, 1, 2
SHELF_OK, SHELF_RANGE, SHELF_FLASH, SHELF_USED = 0, 1, 2, 3   # what `SHELF` leaves in r12
SHELF_MAX = 32                          # bytes one shelf request may program: the chip is
                                        # unreadable and interrupts are off for that long
                                        # (9 us a word typically), with the engine running
REQUEST = 0x3F9A47                      # the shelf request's arguments (transport op 06):
                                        # calibration offset (3), byte count, the bytes
FRAME = 0x30
SHELF_FRAME = 0x40


def _watchdog(e, base, scratch=0):
    """The service sequence, `base` holding 0x300000."""
    e(_li(scratch, 0x556C), _sth(scratch, SWSR - SIU, base),
      _li(scratch, 0xAA39 - 0x10000), _sth(scratch, SWSR - SIU, base))


def _command(e, *cycles):
    """AMD command cycles through r0: (value, offset from the chip base in r20)."""
    for value, at in cycles:
        e(_li(0, value), _sth(0, at, 20))


def _current_byte(a, tag):
    """r0 = the byte the program reads at the calibration address in r11: the
    mirror's if an open descriptor covers it (the overlay's own scan, inline,
    its block bitmap first; r11 moves to the mirror, r12 is scratch)."""
    e = a.emit
    e(_lwz(0, overlay.DESC - R13, 13), _srwi(0, 0, 16),
      _cmplwi(0, overlay.MAGIC >> 16), a.bc(BNE, f"read{tag}"),
      _addis(12, 11, -(CAL >> 16) & 0xFFFF), _srwi(12, 12, overlay.BLOCK_SHIFT),
      _rlwinm(0, 12, 0, 29, 31), _srwi(12, 12, 3), _add(12, 12, 13),
      _lbz(12, overlay.BITMAP - R13, 12), _srw(12, 12, 0),
      _andi(0, 12, 1), a.bc(BEQ, f"read{tag}"),
      _addi(12, 13, overlay.DESC + 4 - R13))
    a.label(f"scan{tag}")
    e(_lwz(0, 0, 12), _cmpwi(0, 0), a.bc(BEQ, f"read{tag}"),
      _cmplw(11, 0), a.bc(BLT, f"next{tag}"),
      _lwz(0, 4, 12), _cmplw(11, 0), a.bc(BGE, f"next{tag}"),
      _lwz(0, 8, 12), _add(11, 11, 0), a.b(f"read{tag}"))
    a.label(f"next{tag}")
    e(_addi(12, 12, 12), a.b(f"scan{tag}"))
    a.label(f"read{tag}")
    e(_lbz(0, 0, 11))


def _burst_off(a, tag, br0, bbcmcr):
    """Burst mode off, the loader's sequence (its routine at 0xFFE14BC4):
    r20 the chip, r22 the SIU. The registers named keep BR0 and BBCMCR as
    they were, for `_burst_on`; with burst already inhibited nothing changes."""
    e = a.emit
    e(ISYNC, _li(0, 0xF0), _sth(0, 0xAAA, 20),
      _lwz(br0, BR0 - SIU, 22), _andi(0, br0, 2), a.bc(BNE, f"plain{tag}"),
      _mfbbcmcr(bbcmcr), _rlwinm(0, bbcmcr, 0, 19, 17), _mtbbcmcr(0), ISYNC)
    _command(e, (0xAA, 0xAAA), (0x55, 0x554), (0xC0, 0xAAA), (0x00, 0xAAA))
    e(_ori(0, br0, 2), _rlwinm(0, 0, 0, 29, 27),
      _stw(0, BR0 - SIU, 22), ISYNC)
    a.label(f"plain{tag}")


def _burst_on(a, tag, br0, bbcmcr):
    """And back on, in the order the program's own start-up uses (its routine
    at 0xFFF71864): the chip select, the part, then the burst buffer."""
    e = a.emit
    e(_andi(0, br0, 2), a.bc(BNE, f"bursting{tag}"),
      _stw(br0, BR0 - SIU, 22))
    _command(e, (0xAA, 0xAAA), (0x55, 0x554), (0xC0, 0xAAA), (0x01, 0xAAA))
    e(_mtbbcmcr(bbcmcr), ISYNC, ISYNC)
    a.label(f"bursting{tag}")


def _code(base):
    """The whole of it, assembled at `base`: (bytes, labels)."""
    a = Asm(base)
    e = a.emit

    # ---- the after-run's way in: our return is the displaced call ---------
    # Only when a save was asked for (transport op 08): a tune being tried
    # out is not kept just because the key was turned.
    a.label("keyoff")
    e(_lbz(12, overlay.SAVE_ARMED - R13, 13), _cmpwi(12, overlay.SAVE_ASKED), a.bc(BNE, "keyoff_ret"),
      a.lis_lbl(12, "keyoff_ret"), a.ori_lbl(12, "keyoff_ret"), _mtctr(12), a.b("entry"))
    a.label("keyoff_ret")
    a.far(KEYOFF_STOCK)                     # LR is still the power-down routine's

    # ---- program one word: r3 = address, r4 = the word, r20 the chip, r22
    # the SIU. r0 = 0 when the chip holds it, 1 when it gave up (and is back
    # in read mode). Takes CTR.
    a.label("program_try")
    _command(e, (0xAA, 0xAAA), (0x55, 0x554), (0xA0, 0xAAA))
    e(_sth(4, 0, 3), _lis(0, 2), _mtctr(0))                  # 0x20000 polls at most
    a.label("program_poll")
    _watchdog(e, 22)
    e(_lhz(0, 0, 3), _cmplw(0, 4), a.bc(BEQ, "program_done"),
      _andi(0, 0, 0x20), a.bc(BEQ, "program_wait"),          # DQ5: the chip gave up;
      _lhz(0, 0, 3), _cmplw(0, 4), a.bc(BEQ, "program_done"),  # unless it finished meanwhile
      a.b("program_bad"))
    a.label("program_wait")
    e(a.bc(BDNZ, "program_poll"))
    a.label("program_bad")
    e(_li(0, 0xF0), _sth(0, 0, 20), _li(0, 1), BLR)
    a.label("program_done")
    e(_li(0, 0), BLR)

    # ---- the save's: the same, and no way back from a failure (r23 is free
    # once the save is past its checks)
    a.label("program")
    e(_mflr(23))
    a.bl("program_try")
    e(_mtlr(23), _cmpwi(0, 0), BEQLR, a.b("fail"))

    # ---- the shelf (transport op 06): program a few words of the blank end
    # of the calibration sector with the engine running. Entered like the
    # save, return address in CTR, interrupts already masked by the caller;
    # r12 = SHELF_* on the way out and every other register as it was. The
    # chip answers nothing but status while a word goes in, so between burst
    # off and burst on nothing is read from it but the word being polled.
    a.label("shelf")
    e(_d(37, 1, 1, -SHELF_FRAME))                            # stwu r1, -SHELF_FRAME(r1)
    for i, r in enumerate(range(3, 11)):
        e(_stw(r, 8 + 4 * i, 1))
    e(_mfctr(0), _stw(0, 0x28, 1), _mflr(0), _stw(0, 0x2C, 1),
      _stw(20, 0x30, 1), _stw(21, 0x34, 1), _stw(22, 0x38, 1))
    req = REQUEST - R13
    e(_lbz(5, req, 13), _slwi(5, 5, 16), _lhz(0, req + 1, 13), _or(5, 5, 0),   # r5 = offset
      _lbz(6, req + 3, 13))                                  # r6 = byte count
    e(_li(12, SHELF_RANGE),
      _cmpwi(6, 0), a.bc(BEQ, "shelf_out"),
      _cmplwi(6, SHELF_MAX), a.bc(BGT, "shelf_out"),
      _or(0, 5, 6), _andi(0, 0, 1), a.bc(BNE, "shelf_out"),  # whole words only
      _lis(0, overlay.SHELF[0] >> 16), _ori(0, 0, overlay.SHELF[0] & 0xFFFF),
      _cmplw(5, 0), a.bc(BLT, "shelf_out"),
      _add(7, 5, 6), _lis(0, overlay.SHELF[1] >> 16), _ori(0, 0, overlay.SHELF[1] & 0xFFFF),
      _cmplw(7, 0), a.bc(BGT, "shelf_out"))
    e(_addis(21, 5, CAL >> 16),                              # r21 = where it goes
      _addi(9, 13, req + 4))                                 # r9 = the bytes
    e(_li(12, SHELF_USED), _li(7, 0))                        # only blank flash is written
    a.label("shelf_blank")
    e(_add(3, 21, 7), _lhz(0, 0, 3), _cmplwi(0, 0xFFFF), a.bc(BNE, "shelf_out"),
      _addi(7, 7, 2), _cmplw(7, 6), a.bc(BLT, "shelf_blank"))
    e(_lis(20, CHIP >> 16), _lis(22, SIU >> 16))
    _burst_off(a, "_shelf", 8, 10)
    e(_li(7, 0), _li(5, 0))                                  # r5: a word failed
    a.label("shelf_word")
    e(_add(3, 9, 7), _lhz(4, 0, 3), _cmplwi(4, 0xFFFF), a.bc(BEQ, "shelf_next"),
      _add(3, 21, 7))
    a.bl("program_try")
    e(_cmpwi(0, 0), a.bc(BEQ, "shelf_next"), _li(5, 1), a.b("shelf_back"))
    a.label("shelf_next")
    e(_addi(7, 7, 2), _cmplw(7, 6), a.bc(BLT, "shelf_word"))
    a.label("shelf_back")
    _burst_on(a, "_shelf", 8, 10)
    e(_li(12, SHELF_FLASH), _cmpwi(5, 0), a.bc(BNE, "shelf_out"), _li(7, 0))
    a.label("shelf_check")                                   # read back what the program will read
    e(_add(3, 9, 7), _lhz(4, 0, 3), _add(3, 21, 7), _lhz(0, 0, 3),
      _cmplw(0, 4), a.bc(BNE, "shelf_out"),
      _addi(7, 7, 2), _cmplw(7, 6), a.bc(BLT, "shelf_check"))
    e(_li(12, SHELF_OK))
    a.label("shelf_out")
    e(_lwz(0, 0x28, 1), _mtctr(0), _lwz(0, 0x2C, 1), _mtlr(0),
      _lwz(20, 0x30, 1), _lwz(21, 0x34, 1), _lwz(22, 0x38, 1))
    for i, r in enumerate(range(3, 11)):
        e(_lwz(r, 8 + 4 * i, 1))
    e(_addi(1, 1, SHELF_FRAME), BCTR)

    # ---- the way in. Nothing is disturbed until the checks have passed -----
    a.label("entry")
    e(_d(37, 1, 1, -FRAME))                                  # stwu r1, -FRAME(r1)
    for i, r in enumerate(range(3, 11)):
        e(_stw(r, 8 + 4 * i, 1))
    e(_mfmsr(11), _stw(11, 0x28, 1),
      _rlwinm(0, 11, 0, 17, 15), _mtmsr(0), ISYNC)           # EE off
    e(_li(12, STATUS_TURNING),
      _lhz(0, VAR_N - R13, 13), _cmpwi(0, 0), a.bc(BNE, "return"))
    e(_li(7, 0))                                             # first pass: measure only

    # One pass over the calibration: r3 word index, r4 where the next run
    # byte goes, r5 the open run's header (0 = none), r6 its length, r7
    # whether to store, r8 the current word, r9 the golden one, r10 whether
    # anything differs from the sector as it is.
    a.label("pass")
    e(_li(3, 0), _lis(4, RUNS >> 16), _ori(4, 4, RUNS & 0xFFFF), _li(5, 0), _li(10, 0))
    a.label("word")
    e(_andi(0, 3, 0x3F), a.bc(BNE, "word_go"), _lis(11, SIU >> 16))
    _watchdog(e, 11)
    a.label("word_go")
    e(_slwi(11, 3, 1), _addis(11, 11, CAL >> 16))
    _current_byte(a, "_hi")
    e(_slwi(8, 0, 8),
      _slwi(11, 3, 1), _addis(11, 11, CAL >> 16), _addi(11, 11, 1))
    _current_byte(a, "_lo")
    e(_or(8, 8, 0))
    e(_slwi(11, 3, 1), _addis(11, 11, CAL >> 16),
      _lhz(9, 0, 11), _cmplw(9, 8), a.bc(BEQ, "unchanged"), _li(10, 1))
    a.label("unchanged")
    e(_addis(11, 11, (GOLD_FILE - CAL_FILE) >> 16),
      _lhz(9, 0, 11), _cmplw(9, 8), a.bc(BEQ, "same"))
    e(_cmpwi(5, 0), a.bc(BNE, "in_run"),                     # a run opens: its header
      _mr(5, 4), _cmpwi(7, 0), a.bc(BEQ, "opened"), _sth(3, 0, 4))
    a.label("opened")
    e(_addi(4, 4, 4), _li(6, 0))
    a.label("in_run")
    e(_addi(6, 6, 1), _cmpwi(7, 0), a.bc(BEQ, "counted"),
      _sth(8, 0, 4), _sth(6, 2, 5))
    a.label("counted")
    e(_addi(4, 4, 2), a.b("word_next"))
    a.label("same")
    e(_li(5, 0))
    a.label("word_next")
    e(_addi(3, 3, 1), _cmplwi(3, WORDS), a.bc(BLT, "word"))
    e(_cmpwi(7, 0), a.bc(BEQ, "ended"), _li(0, -1), _sth(0, 0, 4))   # the terminator
    a.label("ended")
    e(_addi(4, 4, 2), _cmpwi(7, 0), a.bc(BNE, "go"))

    e(_li(12, STATUS_NOTHING), _cmpwi(10, 0), a.bc(BEQ, "return"))
    e(_li(12, STATUS_BIG), _lis(0, RUNS_END >> 16), _ori(0, 0, RUNS_END & 0xFFFF),
      _cmplw(4, 0), a.bc(BGT, "return"))
    e(_li(7, 1), a.b("pass"))                                # RAM is ours from here

    a.label("return")
    e(_lwz(0, 0x28, 1), _mtmsr(0), ISYNC)
    for i, r in enumerate(range(3, 11)):
        e(_lwz(r, 8 + 4 * i, 1))
    e(_addi(1, 1, FRAME), BCTR)

    # ---- no way back: r20 chip, r21 calibration, r22 the SIU ---------------
    a.label("go")
    e(_lis(20, CHIP >> 16), _lis(21, CAL >> 16), _lis(22, SIU >> 16))
    _burst_off(a, "", 9, 3)

    # erase the calibration sector
    _command(e, (0xAA, 0xAAA), (0x55, 0x554), (0x80, 0xAAA), (0xAA, 0xAAA), (0x55, 0x554))
    e(_li(0, 0x30), _sth(0, 0, 21), _lis(0, 0x1000), _mtctr(0))
    a.label("erase_poll")
    _watchdog(e, 22)
    e(_lhz(0, 0, 21), _andi(5, 0, 0x80), a.bc(BNE, "erased"),
      _andi(5, 0, 0x20), a.bc(BEQ, "erase_wait"),
      _lhz(0, 0, 21), _andi(5, 0, 0x80), a.bc(BNE, "erased"), a.b("fail"))
    a.label("erase_wait")
    e(a.bc(BDNZ, "erase_poll"), a.b("fail"))
    a.label("erased")
    e(_li(0, 0xF0), _sth(0, 0, 20))

    # program it back: golden, with the runs laid over. r14 word index, r15
    # the run cursor, r16 the next run's first word, r17 words left in a run.
    e(_li(14, 0), _lis(15, RUNS >> 16), _ori(15, 15, RUNS & 0xFFFF),
      _lhz(16, 0, 15), _li(17, 0))
    a.label("put")
    e(_cmpwi(17, 0), a.bc(BNE, "from_run"), _cmplw(14, 16), a.bc(BNE, "from_gold"),
      _lhz(17, 2, 15), _addi(15, 15, 4))
    a.label("from_run")
    e(_lhz(4, 0, 15), _addi(15, 15, 2), _addi(17, 17, -1),
      _cmpwi(17, 0), a.bc(BNE, "have"), _lhz(16, 0, 15), a.b("have"))
    a.label("from_gold")
    e(_slwi(3, 14, 1), _addis(3, 3, (CHIP + GOLD_FILE) >> 16), _lhz(4, 0, 3))
    a.label("have")
    e(_cmplwi(14, CRC_AT // 2), a.bc(BEQ, "put_next"),       # the CRC goes in last
      _cmplwi(14, CRC_AT // 2 + 1), a.bc(BEQ, "put_next"),
      _addi(0, 14, -(MON_AT // 2)), _cmplwi(0, 4), a.bc(BLT, "put_next"),   # and the monitor's sum
      _cmplwi(4, 0xFFFF), a.bc(BEQ, "put_next"),             # blank stays blank
      _slwi(3, 14, 1), _add(3, 3, 21))
    a.bl("program")
    a.label("put_next")
    e(_addi(14, 14, 1), _cmplwi(14, WORDS), a.bc(BLT, "put"))

    # the safety monitor's sum over the new sector, before the CRC that covers it
    e(_lis(6, MON_SEED >> 48), _ori(6, 6, (MON_SEED >> 32) & 0xFFFF),
      _lis(7, (MON_SEED >> 16) & 0xFFFF), _ori(7, 7, MON_SEED & 0xFFFF),
      _addi(8, 21, MON_FROM), _addi(9, 21, MON_TO))
    a.label("mon_word")
    e(_lwz(0, 0, 8), _addc(7, 7, 0), _addze(6, 6), _addi(8, 8, 4), _cmplw(8, 9), a.bc(BLT, "mon_word"))
    for i, (reg, shift) in enumerate(((6, 16), (6, 0), (7, 16), (7, 0))):
        e(_srwi(4, reg, 16) if shift else _rlwinm(4, reg, 0, 16, 31),
          _cmplwi(4, 0xFFFF), a.bc(BEQ, f"mon_put{i}"), _addi(3, 21, MON_AT + 2 * i))
        a.bl("program")
        a.label(f"mon_put{i}")

    # the CRC the background walker checks: CRC-32/MPEG-2 over the new sector
    e(_li(6, -1), _lis(7, 0x04C1), _ori(7, 7, 0x1DB7),
      _addi(8, 21, CRC_FROM), _lis(9, (CAL + CRC_TO) >> 16), _ori(9, 9, (CAL + CRC_TO) & 0xFFFF))
    a.label("crc_byte")
    e(_andi(0, 8, 0xFF), a.bc(BNE, "crc_go"))
    _watchdog(e, 22)
    a.label("crc_go")
    e(_lbz(0, 0, 8), _slwi(0, 0, 24), _xor(6, 6, 0), _li(10, 8), _mtctr(10))
    a.label("crc_bit")
    e(_cmpwi(6, 0), _slwi(6, 6, 1), a.bc(BGE, "crc_next"), _xor(6, 6, 7))
    a.label("crc_next")
    e(a.bc(BDNZ, "crc_bit"), _addi(8, 8, 1), _cmplw(8, 9), a.bc(BLT, "crc_byte"))
    e(_srwi(4, 6, 16), _cmplwi(4, 0xFFFF), a.bc(BEQ, "crc_low"), _addi(3, 21, CRC_AT))
    a.bl("program")
    a.label("crc_low")
    e(_rlwinm(4, 6, 0, 16, 31), _cmplwi(4, 0xFFFF), a.bc(BEQ, "marks"), _addi(3, 21, CRC_AT + 2))
    a.bl("program")

    # the valid marks last: without them the loader does not start the program
    a.label("marks")
    for at, mark in MARKS:
        for half in (0, 2):
            e(_lis(3, (CAL + at + half + 0x8000) >> 16), _addi(3, 3, ((at + half + 0x8000) & 0xFFFF) - 0x8000),
              _li(4, 0), _ori(4, 4, (mark >> (16 - 8 * half)) & 0xFFFF))
            a.bl("program")
    e(_li(0, 0xF0), _sth(0, 0, 20))
    a.label("done")
    e(a.b("done"))                          # the watchdog resets into the new calibration

    a.label("fail")
    e(_li(0, 0xF0), _sth(0, 0, 20))
    a.label("failed")
    e(a.b("failed"))                        # no marks: the loader waits for a flash
    return a.bytes(), a.labels


_BYTES, _LABELS = _code(CODE)
KEYOFF, ENTRY, SHELF = _LABELS["keyoff"], _LABELS["entry"], _LABELS["shelf"]
DONE, FAILED = _LABELS["done"], _LABELS["failed"]


def monitor_sum(cal):
    """The safety monitor's 64-bit sum of a calibration, as eight bytes."""
    total = MON_SEED
    for (word,) in struct.iter_unpack(">I", cal[MON_FROM:MON_TO]):
        total = (total + word) & 0xFFFFFFFFFFFFFFFF
    return total.to_bytes(8, "big")


def is_patched(pair):
    w = struct.unpack_from(">I", pair.flash, KEYOFF_SITE - 0xFFF00000)[0]
    return w >> 26 == 18 and _branch_target(KEYOFF_SITE, w) == KEYOFF


def golden(pair):
    """The golden calibration of a built pair."""
    return pair.flash[GOLD_FILE:GOLD_FILE + LENGTH]


def tune_runs(pair_or_flash):
    """How far a flash image's calibration is from its golden copy, as the
    save counts it: (differing words, bytes of RAM the runs take)."""
    flash = getattr(pair_or_flash, "flash", pair_or_flash)
    words = size = 0
    run = False
    for at in range(0, LENGTH, 2):
        if flash[CAL_FILE + at:CAL_FILE + at + 2] != flash[GOLD_FILE + at:GOLD_FILE + at + 2]:
            size += 2 if run else 6
            words, run = words + 1, True
        else:
            run = False
    return words, size + 2


def build(pair):
    """The pair with the golden copy, the save in the internal flash's tail
    and the after-run hooked, re-signed. Composes after overlay.build and
    transport.build (whose op 05 enters at ENTRY). The golden copy is the
    pair's calibration as it stands, so a rebuild of a tuned read-out makes
    that tune the new base."""
    mpc, flash = bytearray(pair.mpc), bytearray(pair.flash)
    cal = bytes(flash[CAL_FILE:CAL_FILE + SECTOR])
    if cal[LENGTH:MARKS[0][0]].strip(b"\xff"):
        raise ValueError(f"the calibration has data past 0x{LENGTH:X}, which a save would not rewrite")
    if struct.unpack_from(">I", cal, CRC_AT)[0] != crc32_mpeg2(cal[CRC_FROM:CRC_TO]):
        raise ValueError("the calibration's stored CRC is not the one a save would write")
    at, table = MON_TABLE
    if struct.unpack_from(">3I", flash, at) != table:
        raise ValueError("the safety monitor does not sum the one range a save keeps in step")
    if cal[MON_AT:MON_AT + 8] != monitor_sum(cal):
        raise ValueError("the calibration's stored monitor sum is not the one a save would write")
    room = flash[GOLD_FILE:GOLD_FILE + LENGTH]
    if room.strip(b"\xff") and room[:0x40] != cal[:0x40]:
        raise ValueError(f"ext 0x{GOLD_FILE:X} holds neither a calibration copy nor nothing")
    site = KEYOFF_SITE - 0xFFF00000
    w = struct.unpack_from(">I", flash, site)[0]
    if is_patched(pair):
        mpc[CODE:CODE_END] = b"\xff" * (CODE_END - CODE)        # our own, rebuilt below
    elif w != _branch(KEYOFF_SITE, KEYOFF_STOCK, link=True):
        raise ValueError(f"the power-down routine's call is not the stock one: 0x{w:08X}")
    if mpc[CODE:CODE_END].strip(b"\xff"):
        raise ValueError(f"the internal flash is not blank from 0x{CODE:X}")
    if CODE + len(_BYTES) > CODE_END:
        raise ValueError("the save does not fit the internal flash's tail")

    flash[GOLD_FILE:GOLD_FILE + LENGTH] = cal[:LENGTH]
    mpc[CODE:CODE + len(_BYTES)] = _BYTES
    struct.pack_into(">I", flash, site, _branch(KEYOFF_SITE, KEYOFF, link=True))
    fix_program(flash, mpc)
    return Pair(bytes(flash), bytes(mpc), pair.name + "+save")
