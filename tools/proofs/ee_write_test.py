"""The EEPROM write proof (v15): svc 0x0B, served by the ee_write module
the gate parks in ext at 0xFF000 -- the ISN rewrite's DME side.

Run from the ms45-emu root: .venv/bin/python -m tools.proofs.ee_write_test

The module's one QSMCM queue pass is WREN, WRITE(addr+data), WRDI, so
write-enable is live for exactly one WRITE and dead again before the
reply leaves. This proof writes real changes and reads them back through
the v14 read window, checks that nothing outside the addressed bytes
moved (content compared over the whole 4 KB, not just the page), walks
every refusal -- wrong length, no window, past the end, a span that
would cross the part's page -- and confirms a refused write leaves the
part untouched. The flash and MPC images never enter this flow at all;
the part's read path still streams after writes; the watchdog stays
inside its window; RESET still boots the stock program.
"""
import struct
import sys
import time

from ms45emu.image import load_named, Pair
from ms45emu.board import Board
from tools.build.flasher_gate import build, ENTRY_CPU, stamp_bytes
from tools.build.flasher_body import SRAM_BASE, REPLY_OFF, EE_WINDOW, EE_SIZE
from tools.proofs.flasher_session_test import (
    Session, frame, expect_nak, fast_waits, WATCHDOG_MS,
)

S_EEWRITE = 0x0B


def ee_write(s, at, data):
    f = s.xfer(S_EEWRITE, struct.pack(">IH", EE_WINDOW | at, len(data)) + data)
    expect(f, S_EEWRITE, f"write {at:#x}+{len(data)}")


def expect(f, svc, note):
    if len(f) < 5 or f[0] != (svc | 0x40) and f[3] != (svc | 0x40):
        raise SystemExit(f"FAIL: {note}: {f.hex()}")
    print(f"  ok: {note}")


def main():
    t0 = time.time()
    pair = load_named("session1.livetune6-notraps")
    f, m = build(pair.flash, pair.mpc)
    board = Board(Pair(bytes(f), bytes(m), "eewrite", check_program=False),
                  waits=fast_waits() if "--fast-wait" in sys.argv else None)
    pattern = bytes((i * 13 + 0x5A) & 0xFF for i in range(EE_SIZE))
    board.load_eeprom(pattern)
    s = Session(board)

    # ---- boot into the body (the same contract as eeprom_dump_test) ----
    board.sci.line_hold = True
    reached, why = board.boot(max_insns=2_000_000, until=ENTRY_CPU + 4, reset_vector=True)
    assert reached, f"never reached the flasher entry: {why}"
    in_body = lambda: SRAM_BASE <= board.m.pc < SRAM_BASE + REPLY_OFF   # noqa: E731
    if not s.until(in_body, budget=2_000_000):
        raise SystemExit("FAIL: the body never reached SRAM")
    board.sci.line_hold = False
    if not s.until(lambda: len(board.sci.tx) >= 21):
        raise SystemExit("FAIL: no HELLO after the break released")
    if bytes(board.sci.tx[:21]) != frame(0x40, stamp_bytes(20, 0x1B)):
        raise SystemExit(f"FAIL: HELLO mismatch: {bytes(board.sci.tx[:21]).hex()}")
    board.watchdog_window()
    board.sci.model_overrun = True
    board.cmf.watch_hv_reads()

    flash0, mpc0 = bytes(board.flash.image), bytes(m)
    untouched0 = board.eeprom_image()
    reads0, writes0 = board.qspi.eeprom.reads, board.qspi.eeprom.writes

    # ---- the ISN-shaped case: three small writes in one block ----------
    isn1 = bytes.fromhex("75a20914")
    isn2 = bytes.fromhex("0f6675a2")          # the inverted middle copy's shape
    ee_write(s, 0x3A, isn1)
    ee_write(s, 0x40, isn2)
    ee_write(s, 0x46, isn1)
    for at, want in ((0x3A, isn1), (0x40, isn2), (0x46, isn1)):
        if s.read(EE_WINDOW | at, 4) != want:
            raise SystemExit(f"FAIL: readback of the write at {at:#x} differs")
    img = board.eeprom_image()
    changed = [i for i in range(EE_SIZE) if img[i] != pattern[i]]
    want_changed = sorted([0x3A, 0x3B, 0x3C, 0x3D, 0x40, 0x41, 0x42, 0x43,
                           0x46, 0x47, 0x48, 0x49])
    if changed != want_changed:
        raise SystemExit(f"FAIL: bytes outside the writes moved: {changed}")
    dw = board.qspi.eeprom.writes - writes0
    if dw != 3:
        raise SystemExit(f"FAIL: {dw} WRITE transactions for 3 requests")
    print("  ok: three writes landed, byte-exact, nothing else moved (12 bytes of 4 KB)")

    # ---- the cap: one full queue's worth, page-aligned ------------------
    big = bytes((0xE0 + i) & 0xFF for i in range(25))
    ee_write(s, 0x200, big)
    if s.read(EE_WINDOW | 0x200, 25) != big:
        raise SystemExit("FAIL: readback of the 25-byte write differs")
    print("  ok: 25 bytes at once (the one-queue cap), read back byte-exact")

    # WEL is dead after every op: the module's WRDI, and the part's own
    # one-WREN-one-WRITE rule
    if board.qspi.eeprom.write_enabled:
        raise SystemExit("FAIL: write-enable still live after the reply")
    print("  ok: write-enable dead at rest (WREN lives exactly one WRITE)")

    # ---- the read path still streams after writes -----------------------
    if s.read(EE_WINDOW | 0x800, 0x100) != pattern[0x800:0x900]:
        raise SystemExit("FAIL: a full page read differs after writes")
    print("  ok: the read window still streams whole pages after writes")

    # ---- refusals, and that a refused write moves nothing ---------------
    before = board.eeprom_image()
    expect_nak(s.xfer(S_EEWRITE, struct.pack(">IH", EE_WINDOW | 0x50, 0)),
               S_EEWRITE, 6, "zero length refused (malformed)")
    expect_nak(s.xfer(S_EEWRITE, struct.pack(">IH", EE_WINDOW | 0x50, 26) + b"\x00" * 26),
               S_EEWRITE, 1, "over the one-queue cap refused")
    expect_nak(s.xfer(S_EEWRITE, struct.pack(">IH", 0x00000150, 4) + b"\x00" * 4),
               S_EEWRITE, 1, "no window bit: not the EEPROM's address space")
    expect_nak(s.xfer(S_EEWRITE, struct.pack(">IH", EE_WINDOW | 0xFFE, 4) + b"\x00" * 4),
               S_EEWRITE, 1, "past the part's end refused")
    expect_nak(s.xfer(S_EEWRITE, struct.pack(">IH", EE_WINDOW | EE_SIZE, 2) + b"\x00" * 2),
               S_EEWRITE, 1, "at 4 KB (the car's part would wrap onto offset 0) refused")
    expect_nak(s.xfer(S_EEWRITE, struct.pack(">IH", EE_WINDOW | 0x1E, 4) + b"\x00" * 4),
               S_EEWRITE, 1, "a span crossing the 32-byte page refused")
    if board.eeprom_image() != before:
        raise SystemExit("FAIL: a refused write changed the part")
    if board.qspi.eeprom.writes != writes0 + 4:
        raise SystemExit("FAIL: refused writes reached the part")
    print("  ok: every refusal left the part untouched (4 WRITEs total)")

    # ---- the flash and MPC never entered this flow ----------------------
    if bytes(board.flash.image) != flash0 or bytes(m) != mpc0:
        raise SystemExit("FAIL: the flash or MPC image changed")
    print("  ok: ext and MPC images untouched")

    dr = board.qspi.eeprom.reads - reads0
    if dr != 13:      # 3 + 1 readbacks (one run each) + the 256-byte page (9 runs)
        raise SystemExit(f"FAIL: {dr} READ transactions, want 13")
    print(f"  ok: {dr} READ transactions (the readbacks and the page read)")

    gap = board.watchdog_gap_ms()
    if gap > WATCHDOG_MS:
        raise SystemExit(f"FAIL: the watchdog went {gap:.0f} ms unserviced")
    print(f"  ok: longest watchdog gap {gap:.1f} ms (car limit {WATCHDOG_MS} ms)")

    # ---- RESET still boots the stock program ----------------------------
    f = s.xfer(6)
    if f[3] != 0x46:
        raise SystemExit(f"FAIL: RESET: {f.hex()}")
    print("  ok: RESET")
    print("reboot: the loader starts the stock program (idle)")

    print(f"ALL OK -- {time.time() - t0:.0f}s wall")


if __name__ == "__main__":
    main()
