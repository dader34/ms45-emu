"""The BL proof suite (docs/bootloader.md §9): inert, taken, session,
survivability, and the installer -- end to end on the emulator.

Run from the ms45-emu root: .venv/bin/python -m tools.proofs.bl_test

1. INERT (P-1): with the line idle, the BL image boots the program exactly
   as the stock one does. The window costs ~41k insns (~1 ms) and touches
   only r3-r8 (the gate's register discipline, one hop earlier), so the
   register diff at the program's first instruction must be r3-r8 and
   nothing else, and the instruction stream from the entry must be
   identical (gate_test's shape: identical up to the first time-driven
   interrupt, then a re-sync that is an interrupt insertion, not a
   different path).
2. TAKEN: with the tester holding the line low across reset, the window at
   ext 0x4EBC lands in the boot-region stub, which copies the ring body to
   SRAM and jumps -- the body owns the machine, and HELLO arrives when the
   line releases. The ring body's HELLO reads the ring's own stamp at ext
   0x17080, so the announcement is the loader's identity: "MS45BL" v14
   flags 3 (the full v13 feature set).
3. SESSION (P-5, the load-bearing half of flasher_session_test): the full
   cal push over the wire -- ERASE / CHUNK x29 / VERIFY / MARKS, the failure
   paths, RESET parking, watchdog, 8E1 -- plus the BL properties: the
   ring body refuses an erase of its own boot sector while the marker is
   not armed, and the boot region [0x0, 0x20000) is byte-identical to the
   built image after the whole session (the G3 claim witnessed: a session
   cannot touch the ring). A fresh board then boots the new cal through the
   loader's own checks, and the taken path still works afterwards.

The install over the wire is proven by tools/proofs/bl_app_test.py, the
app's own sequence.
"""
import struct
import sys
import time

from tools.build import flasher_body
from tools.build import bl
from ms45emu.image import load_named, Pair
from ms45emu.board import Board, RESET_ENTRY
from ms45emu.checksums import crc32_mpeg2
from ms45emu.fold import CRC_AT, CRC_FROM, CRC_TO, MON_AT, monitor_sum
from tools.build.flasher_gate import stamp_bytes
from tools.build.flasher_body import SRAM_BASE, REPLY_OFF, AIF_READ
from tools.proofs.flasher_session_test import (Session, frame, lit_nrv2b,
                                  expect, expect_nak, fast_waits)
from tools.proofs.gate_test import Traced
from tools.experiments.aif_wipe import AIF

IMAGE = "session1.livetune6-notraps"
CAL, CAL_END = 0x40000, 0x5D000
CHUNK = 4096
BOOT = 0x8000
AIF_START, _AIF_END = AIF
SECT8K = 0x4000                       # the 8 KB sector holding the patch word
S_AIF = 9
WATCHDOG_MS = 100


def bl_pair(f, m, name):
    return Pair(bytes(f), bytes(m), name, check_program=False)


def fresh(f, m, name, waits=False):
    return Board(bl_pair(f, m, name), waits=fast_waits() if waits else None)


def hello_wait(s, note, payload=None):
    """Release the line, take HELLO, byte-exact assert (v13 for the gate
    layout, the BL stamp for the ring)."""
    s.sci.line_hold = False
    if not s.until(lambda: len(s.sci.tx) >= 21):
        raise SystemExit(f"FAIL: no HELLO after the line released ({note})")
    hello = bytes(s.sci.tx[:21])
    want = frame(0x40, payload if payload is not None else stamp_bytes(20, 0x1B))
    if hello != want:
        raise SystemExit(f"FAIL [{note}]: HELLO {hello.hex()} (want {want.hex()})")
    print(f"  ok: HELLO {hello[4:10].decode()} v{hello[10]} flags {hello[11]:#04x} ({note})")
    s.b.watchdog_window()
    s.sci.model_overrun = True
    return hello


# ---------------------------------------------------------------------------
# 1. INERT

def reg_dump(b):
    regs = [b.m.reg(i) for i in range(32)]
    extra = {}
    # CTR and XER are extras: a unicorn build without them leaves them out
    try:
        from unicorn import UC_PPC_REG_CTR, UC_PPC_REG_XER, UcError
    except ImportError:
        return regs, extra
    try:
        extra["CTR"] = b.m.mu.reg_read(UC_PPC_REG_CTR)
        extra["XER"] = b.m.mu.reg_read(UC_PPC_REG_XER)
    except UcError:
        pass
    return regs, extra


def boot_to_entry(f, m, name):
    """Line idle; halt AT the program's first instruction; (board, insns, state)."""
    b = fresh(f, m, name)
    st = {"n": 0}
    b.m.hook_code(lambda mach, addr, size: st.__setitem__("n", st["n"] + 1))
    reached, why = b.boot(max_insns=2_000_000, until=RESET_ENTRY, reset_vector=True)
    if not reached or b.m.pc != RESET_ENTRY:
        raise SystemExit(f"FAIL [{name}]: never reached the program entry ({why})")
    regs, extra = reg_dump(b)
    return b, st["n"], regs, extra


def inert(pair, bl_f, bl_m):
    print("=" * 64, "\n1. INERT -- BL boots the program exactly as stock\n" + "=" * 64)
    stock_b, stock_n, stock_regs, stock_x = boot_to_entry(pair.flash, pair.mpc, "stock")
    bl_b, bl_n, bl_regs, bl_x = boot_to_entry(bl_f, bl_m, "bl")
    cost = bl_n - stock_n
    print(f"program start: stock at insn {stock_n}, bl at insn {bl_n} "
          f"(window cost {cost} insns = {cost / 40:.0f} us)")

    bad = [f"r{i}" for i in range(32)
           if stock_regs[i] != bl_regs[i] and not 3 <= i <= 8]
    for k in stock_x:
        if stock_x[k] != bl_x.get(k) and k != "XER":    # XER: the poll's addic_ CA
            bad.append(k)
    if bad:
        for i in range(0, 32, 8):
            print("  stock " + " ".join(f"r{i+j:02d}={stock_regs[i+j]:#010x}" for j in range(8)))
            print("  bl  " + " ".join(f"r{i+j:02d}={bl_regs[i+j]:#010x}" for j in range(8)))
        raise SystemExit(f"FAIL: state at the program entry differs beyond r3-r8: {bad}")
    diffed = [f"r{i}" for i in range(3, 9) if stock_regs[i] != bl_regs[i]]
    print(f"  ok: entry state identical apart from the window scratches ({', '.join(diffed) or 'none even differ'})"
          + (f"; CTR={stock_x.get('CTR'):#x}" if "CTR" in stock_x else ""))

    # stream identity from the entry (gate_test's shape, interrupt re-sync)
    stock_t = Traced(bl_pair(pair.flash, pair.mpc, "stock-stream"))
    bl_t = Traced(bl_pair(bl_f, bl_m, "bl-stream"))
    stock_t.boot_to_entry()
    bl_t.boot_to_entry()
    stock_t.run_stream()
    bl_t.run_stream()
    if stock_t.stream == bl_t.stream:
        print(f"inert: {len(bl_t.stream)} instructions from the entry are identical")
    else:
        d = next(i for i, (a, p) in enumerate(zip(stock_t.stream, bl_t.stream)) if a != p)
        window = tuple(stock_t.stream[d:d + 64])
        ht = bl_t.stream[d:d + 4096]
        pos = next((i for i in range(len(ht) - 64) if tuple(ht[i:i + 64]) == window), None)
        if pos is None:
            raise SystemExit(f"FAIL: PATH DIVERGENCE at +{d} "
                             f"(stock {stock_t.stream[d]:#x} vs bl {bl_t.stream[d]:#x})")
        print(f"inert: identical for +{d}, then interrupt shift, re-sync at +{d + pos}"
              " -- path identity holds")
    return stock_regs, stock_n


# ---------------------------------------------------------------------------
# 2/3. TAKEN + the session

def taken(f, m, note, deep=False):
    """Line held across reset -> the ring's window -> stub -> body in SRAM."""
    b = fresh(f, m, note, waits=deep)
    b.sci.line_hold = True
    reached, why = b.boot(max_insns=2_000_000, until=SRAM_BASE, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL [{note}]: the window never reached the stub jump ({why})")
    b.run_from(SRAM_BASE, 100_000, until=0x1)
    s = Session(b)
    if not s.until(lambda: SRAM_BASE <= b.m.pc < SRAM_BASE + REPLY_OFF, budget=200_000):
        raise SystemExit(f"FAIL [{note}]: the body is not in SRAM (pc={b.m.pc:#x})")
    scc1r1 = b.imb.peek16(0x30500A)
    if not scc1r1 & 0x04:
        raise SystemExit(f"FAIL [{note}]: receiver off in the body (SCC1R1={scc1r1:#06x})")
    print(f"taken [{note}]: window -> stub -> body at pc={b.m.pc:#010x}, RE on")
    return b, s


def session(pair, bl_f, bl_m):
    print("=" * 64, "\n2/3. TAKEN + the cal session on the BL image\n" + "=" * 64)
    board, s = taken(bl_f, bl_m, "bl-taken", deep=True)
    hello_wait(s, "bl", bl.stamp_bytes(flags=bl.ring_flags()))

    expect(s.xfer(0x00), 0x00, "HELLO (request form)")
    expect_nak(s.xfer(0x77), 0x77, 6, "unknown service")

    crc = crc32_mpeg2(bytes(bl_f[CAL:CAL_END]))
    fr = s.xfer(0x01, struct.pack(">II", CAL, CAL_END - CAL), budget=90_000_000)
    expect(fr, 0x01, "SECTOR_QUERY of the stock cal")
    if struct.unpack(">I", fr[4:8])[0] != crc:
        raise SystemExit("FAIL: QUERY crc mismatch")

    expect_nak(s.xfer(0x02, struct.pack(">I", 0x10000)), 0x02, 1,
               "ERASE of the ring's own boot sector refused (marker not armed)")
    expect_nak(s.xfer(0x02, struct.pack(">I", 0x40000 - 1)), 0x02, 1,
               "ERASE below 0x40000 refused")

    # ---- the push: a modified cal (flasher_session_test's target) --------
    target = bytearray(bl_f)
    target[CAL + 0x400:CAL + 0x500] = bytes((i * 7 + 3) & 0xFF for i in range(0x100))
    for at in (0x8000, 0x15000, 0x1A000):
        target[CAL + at:CAL + at + 0x40] = bytes((i * 13 + at) & 0xFF for i in range(0x40))
    target[CAL + MON_AT:CAL + MON_AT + 8] = monitor_sum(bytes(target[CAL:CAL + 0x10000]))
    struct.pack_into(">I", target, CAL + CRC_AT,
                     crc32_mpeg2(bytes(target[CAL + CRC_FROM:CAL + CRC_TO])))

    expect(s.xfer(0x02, struct.pack(">I", CAL)), 0x02, "ERASE the cal sector")
    if bytes(board.flash.image[CAL:CAL + 0x20000]) != b"\xff" * 0x20000:
        raise SystemExit("FAIL: cal sector not blank after ERASE")

    hdr = struct.pack(">IHHI", CAL, CHUNK, CHUNK // 8, 0)
    expect_nak(s.xfer(0x03, hdr + lit_nrv2b(bytes(target[CAL:CAL + CHUNK]))),
               0x03, 2, "CHUNK with a bad CRC refused")
    if board.flash.image[CAL] != 0xFF:
        raise SystemExit("FAIL: bad-CRC chunk left data behind")

    n = 0
    for at in range(CAL, CAL_END, CHUNK):
        data = bytes(target[at:at + CHUNK])
        comp = lit_nrv2b(data)
        hdr = struct.pack(">IHHI", at, len(data), len(comp), crc32_mpeg2(comp))
        fr = s.xfer(0x03, hdr + comp)
        if fr[3] != 0x43:
            raise SystemExit(f"FAIL: CHUNK at {at:#x}: {fr.hex()}")
        n += 1
    print(f"  ok: CHUNK x{n} pushed")

    want = crc32_mpeg2(bytes(target[CAL:CAL_END]))
    expect(s.xfer(0x04, struct.pack(">III", CAL, CAL_END - CAL, want)),
           0x04, "VERIFY of the new cal")
    expect_nak(s.xfer(0x04, struct.pack(">III", CAL, CAL_END - CAL, crc)),
               0x04, 5, "VERIFY of the old cal mismatches")
    expect(s.xfer(0x05, b"\x00"), 0x05, "MARKS (cal)")
    if bytes(board.flash.image[CAL:CAL_END]) != bytes(target[CAL:CAL_END]):
        raise SystemExit("FAIL: chip image differs from the target cal")

    # ---- the BL properties ---------------------------------------------
    img = bytes(board.flash.image)
    if img[:0x20000] != bytes(bl_f[:0x20000]):
        first = next(i for i in range(0x20000) if img[i] != bl_f[i])
        raise SystemExit(f"FAIL: the session touched the boot region at ext {first:#x}")
    print("  ok: boot region [0x0, 0x20000) byte-identical after the whole session "
          "(the ring survives by structure)")

    gap = board.watchdog_gap_ms()
    if gap > WATCHDOG_MS:
        raise SystemExit(f"FAIL: watchdog went {gap:.0f} ms unserviced")
    print(f"  ok: longest watchdog gap {gap:.1f} ms (limit {WATCHDOG_MS} ms)")
    expect(s.xfer(0x06), 0x06, "RESET")
    park = board.m.pc
    s.until(lambda: False, budget=400_000)
    if board.m.pc != park:
        raise SystemExit("FAIL: not parked after RESET")
    if board.sci.frame_mismatch:
        raise SystemExit(f"FAIL: {board.sci.frame_mismatch} byte(s) not 8E1")
    print("  ok: parked after RESET; every byte went out 8E1")

    fresh_b = board.reset()
    reached, why = fresh_b.boot(max_insns=2_000_000, until=RESET_ENTRY, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: the new cal does not boot through BL ({why})")
    print("reboot: the loader starts the program on the new cal (BL inert path)")

    board2, s2 = taken_from_reset(fresh_b, "bl-retaken")
    hello_wait(s2, "bl after the session", bl.stamp_bytes(flags=bl.ring_flags()))
    expect(s2.xfer(0x00), 0x00, "HELLO again after the session+reboot")
    return target


def taken_from_reset(board, note):
    """A board that already booted once: reset it with the line held."""
    b = board.reset()
    b.sci.line_hold = True
    reached, why = b.boot(max_insns=2_000_000, until=SRAM_BASE, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL [{note}]: never reached the stub jump ({why})")
    b.run_from(SRAM_BASE, 100_000, until=0x1)
    s = Session(b)
    if not s.until(lambda: SRAM_BASE <= b.m.pc < SRAM_BASE + REPLY_OFF, budget=200_000):
        raise SystemExit(f"FAIL [{note}]: the body is not in SRAM")
    print(f"taken [{note}]: BL serves again after reset")
    return b, s


# ---------------------------------------------------------------------------
# 4. INSTALLER

def marker(s):
    fr = s.xfer(S_AIF, bytes([AIF_READ]))
    if fr[3] != (S_AIF | 0x40):
        raise SystemExit(f"FAIL: AIF READ: {fr.hex()}")
    return struct.unpack(">H", fr[4:6])[0]


def chunk_span(s, base, data, note):
    n = 0
    for at in range(0, len(data), CHUNK):
        piece = bytes(data[at:at + CHUNK])
        comp = lit_nrv2b(piece)
        hdr = struct.pack(">IHHI", base + at, len(piece), len(comp), crc32_mpeg2(comp))
        fr = s.xfer(0x03, hdr + comp)
        if fr[3] != 0x43:
            raise SystemExit(f"FAIL: {note} CHUNK at {base + at:#x}: {fr.hex()}")
        n += 1
    print(f"  ok: {note}: CHUNK x{n}")


def main():
    t0 = time.time()
    pair = load_named(IMAGE)
    bl_f, bl_m = bl.build(pair.flash, pair.mpc)
    body_words, _ = flasher_body.build_body()
    print(f"built: ring body {len(body_words)} words, "
          f"patched words -> windows at ext {bl.WINDOW_AT:#x} and {bl.PARKWIN_AT:#x}")

    stock_regs, stock_n = inert(pair, bl_f, bl_m)
    session(pair, bl_f, bl_m)

    print("=" * 64)
    print(f"ALL OK -- inert + taken + session, {time.time() - t0:.0f}s wall")
    return 0


if __name__ == "__main__":
    sys.exit(main())
