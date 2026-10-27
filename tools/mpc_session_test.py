"""The MPC session proof (docs/fast-flasher.md): the v2 window, end to end.

Run from the ms45-emu root: .venv/bin/python tools/mpc_session_test.py

Everything the app's "full fast flash" does to the CMF, over the emulated
wire: QUERY/ERASE/CHUNK/VERIFY through the 0x80000000 window, mid-page
chunk staging, the contract order (blocks 13..1 then 0, the ext check
block, MARKS 1, RESET), a fresh boot that starts the pushed stock program
through the loader's own checks, and the resume-without-reset path (HELLO
answered mid-push). The pushed MPC is the stock donor pair; the ext cal
and the flasher's own ext bytes stay as they are, exactly as a real full
flash would leave them.
"""
import os
import struct
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from ms45emu.image import load_named, Pair                         # noqa: E402
from ms45emu.board import Board, RESET_ENTRY                       # noqa: E402
from ms45emu.checksums import crc32_mpeg2                          # noqa: E402
from flasher_gate import build, ENTRY_CPU, STAMP_AT, stamp_bytes   # noqa: E402
from flasher_body import SRAM_BASE, REPLY_OFF, MPC_WINDOW, CRC_TABLE, STACK_TOP   # noqa: E402
from flasher_session_test import Session, frame, lit_nrv2b, expect, expect_nak, fast_waits

CHUNK = 4096
BLOCK = 0x8000
CHECK_AT = 0x60000                     # the ext sector carrying the program check


def cpu_view(board, off, ln):
    """What the body reads through the window (stubs and all)."""
    return bytes(board.m.mu.mem_read(off, ln))


def push_chunks(s, board, wire_base, data, note):
    """ERASE is the caller's; CHUNK the whole span in 4 KB pieces."""
    n = 0
    for at in range(0, len(data), CHUNK):
        piece = bytes(data[at:at + CHUNK])
        comp = lit_nrv2b(piece)
        hdr = struct.pack(">IHHI", wire_base + at, len(piece), len(comp),
                          crc32_mpeg2(comp))
        fr = s.xfer(0x03, hdr + comp)
        if fr[3] != 0x43:
            raise SystemExit(f"FAIL: {note} CHUNK at +{at:#x}: {fr.hex()}")
        n += 1
    print(f"  ok: {note}: CHUNK x{n}")


WATCHDOG_MS = 100        # the loader's SYPCR 0x07A17F87, write-once


def main():
    t0 = time.time()
    pair = load_named("session1.livetune6-notraps")
    f, m = build(pair.flash, pair.mpc)
    stock = Pair(open("/tmp/ms45-stock/flash.bin", "rb").read(),
                 open("/tmp/ms45-stock/mpc.bin", "rb").read(), "stock")
    board = Board(Pair(bytes(f), bytes(m), "quickflash1", check_program=False),
                  waits=fast_waits() if "--fast-wait" in sys.argv else None)
    s = Session(board)

    # ---- boot into the body --------------------------------------------
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
    if hello != frame(0x40, stamp_bytes(13, 3)):
        raise SystemExit(f"FAIL: HELLO mismatch: {hello.hex()}")
    print(f"hello: {hello[4:10].decode()} v{hello[10]} flags {hello[11]:#04x}")
    board.watchdog_window()                      # the body runs from here
    board.sci.model_overrun = True               # the real SCI drops, it does not wait
    board.cmf.watch_hv_reads()                   # silicon faults an array read mid-pulse
    # stack watermark: the room between the CRC table and the stack top
    WM_LO, WM_HI = CRC_TABLE + 0x400, STACK_TOP - 0x20
    board.m.mu.mem_write(WM_LO, b"\xa5" * (WM_HI - WM_LO))
    SCC1R0 = 0x305008

    # ---- SET_BAUD: switch, hold, and the silent fallback ---------------
    scbr = lambda: board.imb.peek16(SCC1R0) & 0x1FFF           # noqa: E731
    # a new rate, used but never confirmed: the body gives it up (v8 kept any
    # rate it could read telegrams at, and a one-way line stranded the car)
    expect(s.xfer(0x07, struct.pack(">H", 5)), 0x07, "SET_BAUD to SCBR 5 (250 kbaud)")
    if scbr() != 5:
        raise SystemExit(f"FAIL: SCBR after SET_BAUD is {scbr()}, want 5")
    expect(s.xfer(0x00), 0x00, "HELLO at 250 kbaud")
    expect(s.xfer(0x01, struct.pack(">II", 0x40000, 0x1000)), 0x01, "QUERY at 250 kbaud")
    if not s.until(lambda: scbr() == 11, budget=200_000_000):
        raise SystemExit(f"FAIL: unconfirmed, the body did not fall back to 115200 (SCBR {scbr()})")
    print("  ok: a rate used but never confirmed: the body fell back to 115200 by itself")
    expect(s.xfer(0x00), 0x00, "HELLO at 115200 after the fallback")
    # confirmed, it holds through silence; then back by request, confirmed
    expect(s.xfer(0x07, struct.pack(">H", 5)), 0x07, "SET_BAUD to SCBR 5 again")
    expect(s.xfer(0x00), 0x00, "HELLO at 250 kbaud")
    expect(s.xfer(0x07, struct.pack(">H", 5)), 0x07, "SET_BAUD 5 while on 5: confirmed")
    s.until(lambda: False, budget=150_000_000)
    if scbr() != 5:
        raise SystemExit(f"FAIL: confirmed rate did not hold (SCBR {scbr()})")
    print("  ok: confirmed, 250 kbaud held through 3.7 s of silence")
    expect(s.xfer(0x07, struct.pack(">H", 11)), 0x07, "SET_BAUD back to SCBR 11")
    expect(s.xfer(0x00), 0x00, "HELLO at 115200")
    expect(s.xfer(0x07, struct.pack(">H", 11)), 0x07, "confirmed at 115200")
    expect(s.xfer(0x07, struct.pack(">H", 4)), 0x07, "SET_BAUD to SCBR 4, then silence")
    if not s.until(lambda: scbr() == 11, budget=200_000_000):
        raise SystemExit(f"FAIL: silent after SET_BAUD, no fallback (SCBR {scbr()})")
    print("  ok: silent after SET_BAUD: the body fell back to 115200 by itself")
    expect(s.xfer(0x00), 0x00, "HELLO at 115200 after the fallback")
    expect_nak(s.xfer(0x07, struct.pack(">H", 0)), 0x07, 6, "SET_BAUD 0 refused")

    # ---- the window's permission edges ----------------------------------
    expect_nak(s.xfer(0x02, struct.pack(">I", MPC_WINDOW | 0x70000)), 0x02, 1,
               "ERASE past the window refused")
    expect_nak(s.xfer(0x01, struct.pack(">II", MPC_WINDOW | 0x6FFFE, 4)), 0x01, 1,
               "QUERY over the window end refused")

    # ---- QUERY sees the CPU's view of the CMF ---------------------------
    for off, ln in ((0x0, 0x8000), (0x68000, 0x8000), (0x30, 0x1234)):
        want = crc32_mpeg2(cpu_view(board, off, ln))
        fr = s.xfer(0x01, struct.pack(">II", MPC_WINDOW | off, ln))
        expect(fr, 0x01, f"QUERY of the window at {off:#x}")
        got = struct.unpack(">I", fr[4:8])[0]
        if got != want:
            raise SystemExit(f"FAIL: QUERY at {off:#x}: {got:#010x}, want {want:#010x}")

    # ---- a mid-page chunk exercises the staging paths -------------------
    expect(s.xfer(0x02, struct.pack(">I", MPC_WINDOW | 13 * BLOCK)), 0x02,
           "ERASE of MPC block 13")
    if board.cmf.image[13 * BLOCK:14 * BLOCK] != b"\xff" * BLOCK:
        raise SystemExit("FAIL: block 13 not blank in the CMF after ERASE")
    if cpu_view(board, 13 * BLOCK, BLOCK) != b"\xff" * BLOCK:
        raise SystemExit("FAIL: block 13 not blank in the CPU view after ERASE")

    # two spans inside the erased block: one mid-page (staging below and
    # above the span), one crossing a page boundary (cursor continuation).
    # Lengths are multiples of 8 -- the test's all-literal NRV2B form needs
    # whole groups; the real JS encoder has no such limit (byte-exact on all
    # 301 real chunks, tools/nrv2b_emu_test.py)
    for off, ln, note in ((0x18, 0x10, "CHUNK mid-page (span at +0x18)"),
                         (0x30, 0x60, "CHUNK across the page border (+0x30)")):
        span = bytes((i * 7 + 1) & 0xFF for i in range(ln))
        comp = lit_nrv2b(span)
        hdr = struct.pack(">IHHI", MPC_WINDOW | 13 * BLOCK + off, len(span),
                          len(comp), crc32_mpeg2(comp))
        expect(s.xfer(0x03, hdr + comp), 0x03, note)
        base13 = 13 * BLOCK
        if board.cmf.image[base13 + off:base13 + off + ln] != span:
            raise SystemExit(f"FAIL: {note}: wrong in the CMF image")
        if cpu_view(board, base13 + off, ln) != span:
            raise SystemExit(f"FAIL: {note}: wrong in the CPU view")
    if cpu_view(board, 13 * BLOCK + 0x08, 0x10) != b"\xff" * 0x10 or \
       cpu_view(board, 13 * BLOCK + 0x28, 0x08) != b"\xff" * 0x08 or \
       cpu_view(board, 13 * BLOCK + 0x90, 0x3F0) != b"\xff" * 0x3F0:
        raise SystemExit("FAIL: staging disturbed bytes outside the spans")

    # ---- the full push: blocks 13..1 as pagesets, block 0 last ---------
    block0_before = bytes(board.cmf.image[:BLOCK])
    expect_nak(s.xfer(0x02, struct.pack(">IH", MPC_WINDOW | BLOCK, 0x4002)), 0x02, 6,
               "ERASE with a block beyond 13 in the mask refused")
    t_par = board.instructions
    expect(s.xfer(0x02, struct.pack(">IH", MPC_WINDOW | BLOCK, 0x3FFE)), 0x02,
           "ERASE of MPC blocks 13..1 in one job")
    if board.cmf.image[BLOCK:14 * BLOCK] != b"\xff" * (13 * BLOCK):
        raise SystemExit("FAIL: blocks 13..1 not blank after the mask ERASE")
    if bytes(board.cmf.image[:BLOCK]) != block0_before:
        raise SystemExit("FAIL: the mask ERASE touched block 0")
    print(f"  ok: mask ERASE: {len({a for k, a, _ in board.cmf.log if k == 'erase'})} blocks, one job")
    MASK, PAGES = 0x3FFE, 4                      # 13 blocks x 4 pagesets x 64 = 3328 B
    blocks = [b for b in range(14) if MASK >> b & 1]
    bad = struct.pack(">HHHHIB3x", MASK, 0, 3328 - 64, 1, 0, PAGES)
    expect_nak(s.xfer(0x08, bad + b"\x00"), 0x08, 6, "CHUNK_SET with declen != pages x blocks x 64 refused")
    n = 0
    for off in range(0, BLOCK, PAGES * 64):
        plain = b"".join(stock.mpc[b * BLOCK + off + p * 64:b * BLOCK + off + p * 64 + 64]
                         for p in range(PAGES) for b in blocks)
        comp = lit_nrv2b(plain)
        hdr = struct.pack(">HHHHIB3x", MASK, off, len(plain), len(comp), crc32_mpeg2(comp), PAGES)
        fr = s.xfer(0x08, hdr + comp)
        if fr[3] != 0x48:
            raise SystemExit(f"FAIL: CHUNK_SET at offset {off:#x}: {fr.hex()}")
        n += 1
    print(f"  ok: blocks 13..1 as pagesets: CHUNK_SET x{n}")
    for blk in blocks:
        want = crc32_mpeg2(stock.mpc[blk * BLOCK:(blk + 1) * BLOCK])
        expect(s.xfer(0x04, struct.pack(">III", MPC_WINDOW | blk * BLOCK, BLOCK, want)), 0x04,
               f"VERIFY of block {blk}")
    par_ms = (board.instructions - t_par) * 1000 / board.ips
    t_seq = board.instructions
    expect(s.xfer(0x02, struct.pack(">I", MPC_WINDOW)), 0x02, "ERASE of MPC block 0")
    push_chunks(s, board, MPC_WINDOW, stock.mpc[:BLOCK], "block 0")
    seq_ms = (board.instructions - t_seq) * 1000 / board.ips
    print(f"  DME time (pulses instant, wire included): 13 blocks as pagesets {par_ms / 1000:.1f} s "
          f"= {par_ms / 13 / 1000:.2f} s/block; block 0 sequential {seq_ms / 1000:.2f} s")

    if board.cmf.image != stock.mpc:
        first = next(i for i in range(len(stock.mpc))
                     if board.cmf.image[i] != stock.mpc[i])
        raise SystemExit(f"FAIL: CMF image differs from stock at {first:#x}")
    if cpu_view(board, 0, 0x70000) != stock.mpc:
        first = next(i for i in range(0x70000)
                     if cpu_view(board, i, 1) != stock.mpc[i:i + 1])
        raise SystemExit(f"FAIL: CPU view differs from stock at {first:#x}")
    print("  ok: CMF image and CPU view == stock over all 448 KB")

    # the ext check block, over the target MPC
    expect(s.xfer(0x02, struct.pack(">I", CHECK_AT)), 0x02, "ERASE the check sector")
    push_chunks(s, board, CHECK_AT, stock.flash[CHECK_AT:CHECK_AT + BLOCK],
                "check sector")
    if board.flash.image[CHECK_AT:CHECK_AT + BLOCK] != stock.flash[CHECK_AT:CHECK_AT + BLOCK]:
        raise SystemExit("FAIL: check sector differs from stock")

    want = crc32_mpeg2(stock.mpc)
    expect(s.xfer(0x04, struct.pack(">III", MPC_WINDOW, 0x70000, want)), 0x04,
           "VERIFY of the whole window")
    expect_nak(s.xfer(0x04, struct.pack(">III", MPC_WINDOW, 0x70000, want ^ 1)), 0x04, 5,
               "VERIFY with a wrong CRC mismatches")

    expect(s.xfer(0x05, b"\x01"), 0x05, "MARKS (program)")
    for at, hi, lo in ((0xFFF80, 0x4290, 0x2448), (0xFFFC0, 0x4224, 0x4890)):
        got = struct.unpack_from(">HH", board.flash.image, at)
        if got != (hi, lo):
            raise SystemExit(f"FAIL: program mark at {at:#x}: {got:#x}")
    print("  ok: program marks burned")

    # ---- RESET, then the loader must start the stock program ------------
    sp = bytes(board.m.mu.mem_read(WM_LO, WM_HI - WM_LO))
    low = next((i for i, b in enumerate(sp) if b != 0xA5), None)
    depth = STACK_TOP - (WM_LO + low) if low is not None else 0
    if low is None or low < 0x40:
        raise SystemExit(f"FAIL: the stack reached within 64 B of the CRC table (depth {depth:#x})")
    print(f"  ok: stack depth {depth:#x} of the {STACK_TOP - WM_LO:#x} above the CRC table")
    if board.cmf.hv_reads:
        pc, addr = board.cmf.hv_reads[0]
        raise SystemExit(f"FAIL: {len(board.cmf.hv_reads)} CMF array read(s) while EHV was set "
                         f"(first: pc {pc:#x} reads {addr:#x}) -- a machine check on silicon")
    print("  ok: no CMF array read while EHV was set")
    gap = board.watchdog_gap_ms()                # RESET stops servicing on purpose
    if gap > WATCHDOG_MS:
        raise SystemExit(f"FAIL: the watchdog went {gap:.0f} ms unserviced "
                         f"(the car's loader resets the DME after {WATCHDOG_MS} ms)")
    print(f"  ok: longest watchdog gap {gap:.1f} ms (car limit {WATCHDOG_MS} ms)")
    expect(s.xfer(0x06), 0x06, "RESET")
    fresh = board.reset()
    reached, why = fresh.boot(max_insns=2_000_000, until=RESET_ENTRY + 4, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: the pushed stock MPC does not boot ({why})")
    print(f"reboot: the loader starts the stock program ({why})")

    # ---- resume without reset: HELLO answered mid-push ------------------
    board2 = Board(Pair(bytes(f), bytes(m), "quickflash1", check_program=False),
                   waits=board.waits)
    s2 = Session(board2)
    board2.sci.line_hold = True
    reached, why = board2.boot(max_insns=2_000_000, until=ENTRY_CPU + 4, reset_vector=True)
    assert reached, f"board 2 never reached the entry: {why}"
    if not s2.until(lambda: SRAM_BASE <= board2.m.pc < SRAM_BASE + REPLY_OFF,
                    budget=2_000_000):
        raise SystemExit("FAIL: board 2's body never reached SRAM")
    board2.sci.line_hold = False
    if not s2.until(lambda: len(board2.sci.tx) >= 21):
        raise SystemExit("FAIL: board 2 sent no HELLO")

    expect(s2.xfer(0x02, struct.pack(">I", MPC_WINDOW | 12 * BLOCK)), 0x02,
           "board 2: ERASE of MPC block 12")
    push_chunks(s2, board2, MPC_WINDOW | 12 * BLOCK,
                stock.mpc[12 * BLOCK:13 * BLOCK], "board 2: block 12 (partial push)")
    expect(s2.xfer(0x00), 0x00, "board 2: HELLO mid-push, no reset (resume)")
    fr = s2.xfer(0x01, struct.pack(">II", MPC_WINDOW | 12 * BLOCK, BLOCK))
    expect(fr, 0x01, "board 2: QUERY after the resume")
    if struct.unpack(">I", fr[4:8])[0] != crc32_mpeg2(stock.mpc[12 * BLOCK:13 * BLOCK]):
        raise SystemExit("FAIL: QUERY after resume does not reflect the pushed block")

    print(f"ALL OK -- {time.time() - t0:.0f}s wall")
    return 0


if __name__ == "__main__":
    sys.exit(main())
