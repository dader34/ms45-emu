"""The BL14 proof suite (docs/bootloader.md §9): inert, taken, session,
survivability, and the installer -- end to end on the emulator.

Run from the ms45-emu root: .venv/bin/python tools/bl14_test.py

1. INERT (P-1): with the line idle, the BL14 image boots the program exactly
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
   paths, RESET parking, watchdog, 8E1 -- plus the BL14 properties: the
   ring body refuses an erase of its own boot sector while the marker is
   not armed, and the boot region [0x0, 0x20000) is byte-identical to the
   built image after the whole session (the G3 claim witnessed: a session
   cannot touch the ring). A fresh board then boots the new cal through the
   loader's own checks, and the taken path still works afterwards.
4. INSTALLER (P-12): from a stock image carrying today's gate + v13 body,
   over the wire: arm the AIF marker, erase the 96 KB boot sector, stream
   the stock boot content back WITH the ring spliced in, erase the 8 KB
   sector at 0x4000 and rewrite it with the one patched handoff word,
   erase MPC block 0 and restore it stock (taking the v13 gate's MPC 0x8
   hook out), verify each piece, DONE. The result is byte-identical to
   tools/bl14.py's build, and the installed image passes the inert diff
   and the taken path -- stock -> BL14 without a soldering iron.

The installer body is a bench variant (PERM_LOW=0x4000, the 8 KB sector
opened below the boot sector); the ring it installs carries the shipped
narrow body (PERM_LOW=0x8000).
"""
import os
import struct
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import flasher_body                                             # noqa: E402
import bl14                                                     # noqa: E402

from ms45emu.image import load_named, Pair                      # noqa: E402
from ms45emu.board import Board, RESET_ENTRY                    # noqa: E402
from ms45emu.checksums import crc32_mpeg2                       # noqa: E402
from ms45emu.fold import CRC_AT, CRC_FROM, CRC_TO, MON_AT, monitor_sum  # noqa: E402
from flasher_gate import (build as gate_build, ENTRY_CPU,       # noqa: E402
                          stamp_bytes, hook_word)
from flasher_body import (SRAM_BASE, REPLY_OFF, MARK_ARMED,     # noqa: E402
                          AIF_READ, AIF_ARM, AIF_DONE, MPC_WINDOW)
from flasher_session_test import (Session, frame, lit_nrv2b,    # noqa: E402
                                  expect, expect_nak, fast_waits)
from mpc_session_test import push_chunks                        # noqa: E402
from gate_test import Traced                                     # noqa: E402
from aif_wipe import AIF                                         # noqa: E402

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
    layout, the BL14 stamp for the ring)."""
    s.sci.line_hold = False
    if not s.until(lambda: len(s.sci.tx) >= 21):
        raise SystemExit(f"FAIL: no HELLO after the line released ({note})")
    hello = bytes(s.sci.tx[:21])
    want = frame(0x40, payload if payload is not None else stamp_bytes(13, 3))
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
    try:
        from unicorn import UC_PPC_REG_CTR, UC_PPC_REG_XER
        extra["CTR"] = b.m.mu.reg_read(UC_PPC_REG_CTR)
        extra["XER"] = b.m.mu.reg_read(UC_PPC_REG_XER)
    except Exception:
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
    print("=" * 64, "\n1. INERT -- BL14 boots the program exactly as stock\n" + "=" * 64)
    stock_b, stock_n, stock_regs, stock_x = boot_to_entry(pair.flash, pair.mpc, "stock")
    bl_b, bl_n, bl_regs, bl_x = boot_to_entry(bl_f, bl_m, "bl14")
    cost = bl_n - stock_n
    print(f"program start: stock at insn {stock_n}, bl14 at insn {bl_n} "
          f"(window cost {cost} insns = {cost / 40:.0f} us)")

    bad = [f"r{i}" for i in range(32)
           if stock_regs[i] != bl_regs[i] and not 3 <= i <= 8]
    for k in stock_x:
        if stock_x[k] != bl_x.get(k) and k != "XER":    # XER: the poll's addic_ CA
            bad.append(k)
    if bad:
        for i in range(0, 32, 8):
            print("  stock " + " ".join(f"r{i+j:02d}={stock_regs[i+j]:#010x}" for j in range(8)))
            print("  bl14  " + " ".join(f"r{i+j:02d}={bl_regs[i+j]:#010x}" for j in range(8)))
        raise SystemExit(f"FAIL: state at the program entry differs beyond r3-r8: {bad}")
    diffed = [f"r{i}" for i in range(3, 9) if stock_regs[i] != bl_regs[i]]
    print(f"  ok: entry state identical apart from the window scratches ({', '.join(diffed) or 'none even differ'})"
          + (f"; CTR={stock_x.get('CTR'):#x}" if "CTR" in stock_x else ""))

    # stream identity from the entry (gate_test's shape, interrupt re-sync)
    stock_t = Traced(bl_pair(pair.flash, pair.mpc, "stock-stream"))
    bl_t = Traced(bl_pair(bl_f, bl_m, "bl14-stream"))
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
                             f"(stock {stock_t.stream[d]:#x} vs bl14 {bl_t.stream[d]:#x})")
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
    print("=" * 64, "\n2/3. TAKEN + the cal session on the BL14 image\n" + "=" * 64)
    board, s = taken(bl_f, bl_m, "bl14-taken", deep=True)
    hello_wait(s, "bl14", bl14.stamp_bytes())

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

    # ---- the BL14 properties ---------------------------------------------
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
        raise SystemExit(f"FAIL: the new cal does not boot through BL14 ({why})")
    print("reboot: the loader starts the program on the new cal (BL14 inert path)")

    board2, s2 = taken_from_reset(fresh_b, "bl14-retaken")
    hello_wait(s2, "bl14 after the session", bl14.stamp_bytes())
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
    print(f"taken [{note}]: BL14 serves again after reset")
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


def installer(pair, bl_f, bl_m, stock_regs, stock_n):
    print("=" * 64, "\n4. INSTALLER -- stock+gate image -> BL14, over the wire\n" + "=" * 64)
    flasher_body.PERM_LOW = 0x4000                     # the bench installer body
    inst_f, inst_m = gate_build(pair.flash, pair.mpc)
    flasher_body.PERM_LOW = 0x8000
    board = fresh(inst_f, inst_m, "bl14-install", waits=True)

    # entry through today's gate (MPC 0x8), exactly as the app does it
    board.sci.line_hold = True
    reached, why = board.boot(max_insns=2_000_000, until=ENTRY_CPU + 4, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: never reached the gate entry ({why})")
    s = Session(board)
    if not s.until(lambda: SRAM_BASE <= board.m.pc < SRAM_BASE + REPLY_OFF, budget=2_000_000):
        raise SystemExit("FAIL: the body never reached SRAM")
    hello_wait(s, "installer (gate image)")

    if marker(s) != 0xFFFF:
        raise SystemExit(f"FAIL: marker not fresh ({marker(s):#06x})")
    expect(s.xfer(S_AIF, bytes([AIF_ARM])), S_AIF, "AIF ARM")
    if marker(s) != MARK_ARMED:
        raise SystemExit("FAIL: marker not armed")

    # ---- the 96 KB boot sector: stock content + the ring ------------------
    expect(s.xfer(0x02, struct.pack(">I", BOOT)), 0x02, "ERASE the boot sector")
    fr = s.xfer(0x01, struct.pack(">II", BOOT, 0x20000 - BOOT), budget=90_000_000)
    expect(fr, 0x01, "SECTOR_QUERY of the erased boot sector")
    if struct.unpack(">I", fr[4:8])[0] != crc32_mpeg2(b"\xff" * (0x20000 - BOOT)):
        raise SystemExit("FAIL: boot sector not blank after ERASE")

    payload = bytearray(bl_f[BOOT:AIF_START])
    if len(payload) % 8:
        payload += b"\xff" * (8 - len(payload) % 8)
    chunk_span(s, BOOT, bytes(payload), "restore boot content + the BL14 ring")
    want = crc32_mpeg2(bytes(bl_f[BOOT:AIF_START]))
    expect(s.xfer(0x04, struct.pack(">III", BOOT, AIF_START - BOOT, want)),
           0x04, "VERIFY of the restored boot sector")

    # ---- the 8 KB sector: stock content + the one patched word ------------
    expect(s.xfer(0x02, struct.pack(">I", SECT8K)), 0x02,
           "ERASE the 8 KB sector at 0x4000 (bench window)")
    chunk_span(s, SECT8K, bytes(bl_f[SECT8K:SECT8K + 0x2000]),
               "rewrite it with the patched handoff word at 0x4EBC")
    want = crc32_mpeg2(bytes(bl_f[SECT8K:SECT8K + 0x2000]))
    expect(s.xfer(0x04, struct.pack(">III", SECT8K, 0x2000, want)),
           0x04, "VERIFY of the 8 KB sector")
    got = struct.unpack(">I", bytes(board.flash.image[bl14.PATCH_AT:bl14.PATCH_AT + 4]))[0]
    if got != hook_word(0xFFF00000 + bl14.WINDOW_AT):
        raise SystemExit(f"FAIL: the patch word is {got:#010x}")

    # ---- MPC block 0: stock content (the gate's 0x8 hook comes out) -------
    expect(s.xfer(0x02, struct.pack(">I", MPC_WINDOW)), 0x02, "ERASE MPC block 0")
    push_chunks(s, board, MPC_WINDOW, bytes(pair.mpc[:0x8000]), "MPC block 0 restored stock")
    want = crc32_mpeg2(bytes(pair.mpc[:0x8000]))
    expect(s.xfer(0x04, struct.pack(">III", MPC_WINDOW, 0x8000, want)),
           0x04, "VERIFY of MPC block 0")

    expect(s.xfer(S_AIF, bytes([AIF_DONE])), S_AIF, "AIF DONE")
    if marker(s) != 0xFFFF:
        raise SystemExit("FAIL: the next marker slot is not fresh after DONE")

    # ---- the result is exactly the built image ---------------------------
    img = bytes(board.flash.image)
    if img[:AIF_START] != bytes(bl_f[:AIF_START]):
        first = next(i for i in range(AIF_START) if img[i] != bl_f[i])
        raise SystemExit(f"FAIL: installed image differs from the build at ext {first:#x}")
    if img[AIF_START:0x20000] != b"\xff" * (0x20000 - AIF_START):
        raise SystemExit("FAIL: the AIF span is not blank (the wipe side effect)")
    if bytes(board.cmf.image) != bytes(pair.mpc):
        raise SystemExit("FAIL: the MPC image differs from stock")
    print("  ok: installed ext [0x0, 0x1FB34) == bl14.build, AIF blank, MPC == stock")

    expect(s.xfer(0x06), 0x06, "RESET")
    print("installed: BL14 is on the DME by wire alone")

    # ---- the installed image passes the same proofs -----------------------
    b, n, regs, _x = boot_to_entry(img, board.cmf.image, "installed-inert")
    if n - stock_n > 120_000:
        raise SystemExit(f"FAIL: installed window cost {n - stock_n} insns")
    bad = [f"r{i}" for i in range(32)
           if stock_regs[i] != regs[i] and not 3 <= i <= 8]
    if bad:
        raise SystemExit(f"FAIL: installed inert diff beyond r3-r8: {bad}")
    print(f"inert [installed]: entry at insn {n} (window {n - stock_n} insns), "
          "state identical apart from r3-r8")

    ib = board.reset()
    ib.sci.line_hold = True
    reached, why = ib.boot(max_insns=2_000_000, until=SRAM_BASE, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: the installed window never fired ({why})")
    ib.run_from(SRAM_BASE, 100_000, until=0x1)
    s2 = Session(ib)
    if not s2.until(lambda: SRAM_BASE <= ib.m.pc < SRAM_BASE + REPLY_OFF, budget=200_000):
        raise SystemExit("FAIL: the installed body is not in SRAM")
    hello_wait(s2, "installed", bl14.stamp_bytes())
    expect(s2.xfer(0x00), 0x00, "HELLO (request form) on the installed ring")
    print("taken [installed]: the ring serves the fast path -- end to end")


def main():
    t0 = time.time()
    pair = load_named(IMAGE)
    bl_f, bl_m = bl14.build(pair.flash, pair.mpc)
    body_words, _ = flasher_body.build_body()
    print(f"built: ring body {len(body_words)} words, "
          f"patch word -> window at ext {bl14.WINDOW_AT:#x}")

    stock_regs, stock_n = inert(pair, bl_f, bl_m)
    session(pair, bl_f, bl_m)
    installer(pair, bl_f, bl_m, stock_regs, stock_n)

    print("=" * 64)
    print(f"ALL OK -- inert + taken + session + installer, {time.time() - t0:.0f}s wall")
    return 0


if __name__ == "__main__":
    sys.exit(main())
