"""The bootstrap install through the STOCK kernel, calibration untouched.

The question (2026-10-28): can the DME's own programming mode load our
flasher without a full program install -- erase and write only the few
sectors the install touches (the body at ext 0xFD26C+, the stored sums at
ext 0x60074, the hook word at MPC 0x8)?

No. tools/proofs/bootstrap_probe.py put the loader's own code on it:

- the erase job is CATEGORICAL and the range in it is ignored: any
  program-window erase (even "top 64K", even the internal window) wipes
  ALL external program sectors AND all 448 KB of internal flash. Only the
  calibration erase is separate. There is no partial erase to build a
  small install on.
- programming cannot avoid the erase either: flash only clears bits, so
  the stored sums at ext 0x60000-0x60640 (which cover the body AND the
  hook word) cannot be rewritten in place, and a body written into blank
  space without new sums leaves the stored ones stale -- the program's
  own self-test then reset-loops the DME.
- nothing executes tester data (no download-to-RAM kernel on this loader)
  and no service reads external flash (0x23 reads internal only, both
  sessions), so there is no transient loader and no self-contained
  read-back bootstrap either.

So the smallest install the stock kernel can carry is program + internal
-- the calibration rides through untouched, marks and all. That is what
this proof runs, end to end on the emulator, with the DME's own loader
doing the erasing, writing, CRC and RSA checking and marking:

  1. session1 (a stock pair: blank body range, stock hook at MPC 0x8)
     boots; the tester authenticates and enters programming mode;
  2. one program erase, then ext program + internal written from the
     builder's output (gate + body + hook, sums and signature fresh);
  3. the loader's own checks pass and it marks program AND data valid --
     the calibration was never touched, its check passes on the car's
     own bytes;
  4. a plain reset boots the gated program exactly as a stock boot;
  5. a break held across the reset takes the gate, the body relocates to
     SRAM, HELLO arrives, and one 4 KB READ over the wire returns the
     calibration byte-for-byte -- the installed flasher works.

Run from the ms45-emu root (about as long as the write takes, minutes):

    .venv/bin/python -m tools.proofs.bootstrap_install_test
"""
import struct
import sys
import time

from ms45emu.image import load_named
from ms45emu.board import Board, VALID_MARKS
from ms45emu.kwp import Tester
from tools.build.flasher_gate import build, ENTRY_CPU, STAMP_AT
from tools.build.flasher_body import SRAM_BASE, REPLY_OFF
from tools.proofs.flasher_session_test import Session, expect, fast_waits, frame

PROGRAM, PROGRAM_END = 0x60000, 0xFFF40          # what a program flash writes
CALIBRATION, CALIBRATION_END = 0x40000, 0x5D000
EXTERNAL, INTERNAL = 0x02000000, 0x06000000      # the address windows of the flash jobs
SCHEDULER_TASK = 0x3B38C
INIT_DONE = 0x3FEB26


def marks(b):
    return [bytes(b.flash.image[at:at + 4]) for at, _ in VALID_MARKS]


def valid_marks():
    return [mark.to_bytes(4, "big") for _, mark in VALID_MARKS]


def progress(done, total):
    if done % (253 * 256) < 253:                 # a line every ~64 KB
        print(f"    {done:#x}/{total:#x}", flush=True)


def main():
    t0 = time.time()
    stock = load_named("session1")               # the car's own read: a stock pair
    blank = stock.flash[0xFD26C:PROGRAM_END] == b"\xff" * (PROGRAM_END - 0xFD26C)
    hook = struct.unpack_from(">I", stock.mpc, 8)[0]
    assert blank and hook == 0x4BF717B6, "the base pair is not stock (body range/hook)"
    print(f"base: {stock.name}, body range blank, stock hook at MPC 0x8")

    target_f, target_m = build(stock.flash, stock.mpc)   # gate + body + hook, signed
    stamp = bytes(target_f[STAMP_AT:STAMP_AT + 16])
    print(f"target: built, stamp {stamp[:6].decode()} v{stamp[6]} flags {stamp[7]:#04x}")

    # ---- 1-2: the stock-kernel session ------------------------------------
    b = Board(stock)
    b.boot(max_insns=20_000_000)
    t = Tester(b)
    assert t.authenticate(), "authentication refused"
    assert t.programming_mode(), "programming mode refused"
    print(f"session: authenticated, programming mode ({time.time() - t0:.0f} s)")

    at = time.time()
    assert t.erase(EXTERNAL + PROGRAM, 0xA0000), "the program erase was refused"
    assert bytes(b.flash.image[PROGRAM:]) == b"\xff" * 0xA0000, "program area not blank"
    assert bytes(b.cmf.image) == b"\xff" * len(target_m), "internal not blank"
    assert bytes(b.flash.image[CALIBRATION:CALIBRATION_END]) == stock.flash[CALIBRATION:CALIBRATION_END], \
        "the program erase touched the calibration"
    print(f"erase: program area + internal ({time.time() - at:.0f} s), calibration untouched")

    at = time.time()
    assert t.write(EXTERNAL + PROGRAM, bytes(target_f[PROGRAM:PROGRAM_END]), progress), "ext write failed"
    print(f"write: external program, {PROGRAM_END - PROGRAM:#x} bytes ({time.time() - at:.0f} s)")
    at = time.time()
    assert t.write(INTERNAL, bytes(target_m), progress), "internal write failed"
    print(f"write: internal, {len(target_m):#x} bytes ({time.time() - at:.0f} s)")

    # ---- 3: the loader's own checks ---------------------------------------
    assert t.default_mode()
    assert t.programming_status() == 5, "status after the writes"
    assert t.check_signature("program"), "the loader refused the program signature"
    assert t.check_signature("data"), "the loader refused the calibration signature"
    assert t.programming_status() == 1, "status not normal"
    assert marks(b) == valid_marks(), f"marks not all valid: {marks(b).hex()}"
    assert t.reset()
    print(f"checks: program + calibration marked valid by the loader itself ({time.time() - t0:.0f} s)")

    f = bytes(b.flash.image)
    assert f[PROGRAM:PROGRAM_END] == bytes(target_f[PROGRAM:PROGRAM_END]), "ext content differs"
    assert bytes(b.cmf.image) == bytes(target_m), "internal content differs"
    assert f[CALIBRATION:CALIBRATION_END] == stock.flash[CALIBRATION:CALIBRATION_END], "calibration changed"
    diff = sum(1 for a, c in zip(f, stock.flash) if a != c)
    print(f"content: program + internal as built; calibration byte-identical "
          f"({diff} bytes differ from the stock image, all in the program area)")

    # ---- 4: a plain boot is a stock boot ----------------------------------
    b.set_waits(fast_waits())
    nb = b.reset()
    nb.probe(SCHEDULER_TASK, "scheduler")
    nb.boot(max_insns=40_000_000, reset_vector=True)
    assert not nb.in_loader and nb.m.read8(INIT_DONE) == 1 and nb.probe_counts["scheduler"] > 10, \
        "the gated program did not boot like stock"
    print("boot: the program runs as on a stock DME (scheduler ticking, init done)")

    # ---- 5: break entry -> the installed flasher works --------------------
    eb = b.reset()
    sci = eb.sci
    sci.line_hold = True                         # the app holds the break
    reached, why = eb.boot(max_insns=2_000_000, until=ENTRY_CPU + 4, reset_vector=True)
    assert reached, f"never reached the flasher entry: {why}"
    s = Session(eb)
    if not s.until(lambda: SRAM_BASE <= eb.m.pc < SRAM_BASE + REPLY_OFF, budget=2_000_000):
        raise SystemExit("FAIL: the body never reached SRAM")
    sci.line_hold = False
    if not s.until(lambda: len(sci.tx) >= 21, budget=10_000_000):
        raise SystemExit("FAIL: no HELLO after the break released")
    hello = bytes(sci.tx[:21])
    if hello != frame(0x40, stamp):
        raise SystemExit(f"FAIL: HELLO {hello.hex()}, want {frame(0x40, stamp).hex()}")
    eb.watchdog_window()
    eb.sci.model_overrun = True
    expect(s.xfer(0x00), 0x00, "HELLO (request form)")

    data = s.read(CALIBRATION, 4096)             # one wire READ of the untouched cal
    assert data == f[CALIBRATION:CALIBRATION + 4096], "READ differs from the image"
    print(f"  ok: READ {CALIBRATION:#x}+4096 over the wire (the cal the session rode through)")

    print(f"\nBOOTSTRAP INSTALL PROVEN ({time.time() - t0:.0f} s): the stock kernel carried "
          f"gate + body + hook with the calibration untouched, and the installed "
          f"flasher answers on the line.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
