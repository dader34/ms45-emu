"""The EEPROM dump proof (docs/EWS-ISN.md in BMWeb-Flasher, protections.md
"Next" 3): the v14 body's READ offset bit 30 stages the serial EEPROM's
bytes through the QSPI and streams them like any array.

Run from the ms45-emu root: .venv/bin/python -m tools.proofs.eeprom_dump_test

The part is seeded with a non-repeating pattern before boot (nothing in the
gate->body path reads it; task10's stored-data restore belongs to the stock
program, which this boot never starts). The whole 4 KB comes back
byte-exact through the window; the flash and MPC spaces read unchanged; a
read that would run past the part is refused; and the dump leaves the part
exactly as it found it -- content compared before and after, write counter
asserted flat. That last part is the whole safety case for pointing this at
the bench donor: READs only, ever.
"""
import struct
import sys
import time

from ms45emu.image import load_named, Pair
from ms45emu.board import Board
from ms45emu.checksums import crc32_mpeg2  # noqa: F401  (the session helpers use it)
from tools.build.flasher_gate import build, ENTRY_CPU, stamp_bytes
from tools.build.flasher_body import SRAM_BASE, REPLY_OFF, EE_WINDOW, EE_SIZE
from tools.proofs.flasher_session_test import Session, frame, expect, expect_nak, fast_waits

PAGE = 0x1000


def main():
    t0 = time.time()
    pair = load_named("session1.livetune6-notraps")
    f, m = build(pair.flash, pair.mpc)
    board = Board(Pair(bytes(f), bytes(m), "eedump", check_program=False),
                  waits=fast_waits() if "--fast-wait" in sys.argv else None)
    pattern = bytes((i * 13 + 0x5A) & 0xFF for i in range(EE_SIZE))
    board.load_eeprom(pattern + bytes(0x10000 - EE_SIZE))   # a 64 KB image: the
                                                            # part keeps its first 4 KB
    s = Session(board)

    # ---- boot into the body (the same contract as mpc_session_test) ----
    board.sci.line_hold = True
    reached, why = board.boot(max_insns=2_000_000, until=ENTRY_CPU + 4, reset_vector=True)
    assert reached, f"never reached the flasher entry: {why}"
    in_body = lambda: SRAM_BASE <= board.m.pc < SRAM_BASE + REPLY_OFF   # noqa: E731
    if not s.until(in_body, budget=2_000_000):
        raise SystemExit("FAIL: the body never reached SRAM")
    board.sci.line_hold = False
    if not s.until(lambda: len(board.sci.tx) >= 21):
        raise SystemExit("FAIL: no HELLO after the break released")
    hello = bytes(board.sci.tx[:21])
    if hello != frame(0x40, stamp_bytes(20, 0x1B)):
        raise SystemExit(f"FAIL: HELLO mismatch: {hello.hex()}")
    board.watchdog_window()                      # the body runs from here
    board.sci.model_overrun = True               # the real SCI drops, it does not wait
    board.cmf.watch_hv_reads()                   # silicon faults an array read mid-pulse

    reads0, writes0 = board.qspi.eeprom.reads, board.qspi.eeprom.writes
    untouched = board.eeprom_image()

    # ---- the dump: every page through the window, byte-exact -----------
    for at in range(0, EE_SIZE, PAGE):
        got = s.read(EE_WINDOW | at, PAGE)
        if got != pattern[at:at + PAGE]:
            bad = next(i for i in range(PAGE) if got[i] != pattern[at + i])
            raise SystemExit(f"FAIL: EEPROM page {at:#x} differs at +{bad:#x}: "
                             f"{got[bad]:#04x} not {pattern[at + bad]:#04x}")
    print("  ok: the whole 4 KB through the window, byte-exact")

    # small reads too: the queue tail path (n < 32 entries) and the very
    # last bytes of the part, where the address's high byte turns over
    for at, n in ((0x123, 1), (0xFFE, 2), (0x800, 0x1D), (0x2A0, 0x100)):
        if s.read(EE_WINDOW | at, n) != pattern[at:at + n]:
            raise SystemExit(f"FAIL: EEPROM {at:#x}+{n} differs")
    print("  ok: tail-path sizes (1, 2, 29, 256) and the part's last word")

    # ---- the other address spaces are untouched ------------------------
    img = bytes(board.flash.image)
    for off, n, want, what in ((0x40000, PAGE, img[0x40000:0x41000], "ext cal head"),
                               (0xFFFF0, 16, img[0xFFFF0:0x100000], "ext last bytes"),
                               (0x80000000 | 0x6F000, PAGE, bytes(m)[0x6F000:0x70000],
                                "the MPC window")):
        if s.read(off, n) != want:
            raise SystemExit(f"FAIL: READ {what} ({off:#x}+{n}) differs from the image")
    print("  ok: ext and MPC READs unchanged")

    # ---- the part is not written, and its bounds are policed -----------
    if board.eeprom_image() != untouched:
        raise SystemExit("FAIL: the EEPROM content changed during the dump")
    dw = board.qspi.eeprom.writes - writes0
    if dw:
        raise SystemExit(f"FAIL: {dw} EEPROM WRITE commands happened (READs only, ever)")
    dr = board.qspi.eeprom.reads - reads0
    if dr < 20:
        raise SystemExit(f"FAIL: only {dr} EEPROM READ commands for 20 requests")
    print(f"  ok: the part untouched: {dr} READ commands, 0 writes, content identical")

    expect_nak(s.xfer(10, struct.pack(">IH", EE_WINDOW | 0x001, PAGE)),
               10, 1, "EEPROM read past the part's end refused")
    expect_nak(s.xfer(10, struct.pack(">IH", EE_WINDOW | EE_SIZE, 1)),
               10, 1, "EEPROM read at 4 KB (a mirror on the car) refused")
    expect_nak(s.xfer(10, struct.pack(">IH", EE_WINDOW, 0)),
               10, 6, "EEPROM read of zero bytes refused (malformed)")
    # stray high bits ride along masked: bit 30 selects the window and only
    # the low 16 bits are the address (strictness would cost 8 body bytes
    # the DRV_SDA ceiling does not have; the read stays read-only anyway)
    if s.read(0x50000000, 4) != pattern[:4]:
        raise SystemExit("FAIL: 0x50000000+4 does not read EEPROM 0x0000")
    print("  ok: stray high bits masked: 0x50000000 reads EEPROM 0x0000")

    print(f"ALL OK -- {time.time() - t0:.0f}s wall")


if __name__ == "__main__":
    main()
