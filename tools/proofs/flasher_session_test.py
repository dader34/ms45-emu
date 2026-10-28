"""The flasher session proof (docs/fast-flasher.md): a full calibration
push over the emulated wire, from break-held boot to reset.

Run from the ms45-emu root: .venv/bin/python -m tools.proofs.flasher_session_test

The session drives the DME exactly as the app will: break held across the
reset (line_hold), release, HELLO arrives, then SECTOR_QUERY / ERASE /
CHUNK x29 / VERIFY / MARKS / RESET, plus the failure paths (perm NAK,
unknown service, malformed frame, bad chunk CRC, verify mismatch). The
pushed cal is a modified copy of the car's; the compressed chunks are the
all-literal NRV2B form (one 0xFF control byte per 8 data bytes, closed by
the EOF marker) because the real encoder is JS -- the decoder itself is
already proven byte-exact on all 301 real chunks (tools/nrv2b_emu_test.py).
At the end the chip
image must equal the target, the cal marks must be burned, and a fresh
board must boot the new cal through the loader's own checks.
"""
import os
import struct
import sys
import time

from ms45emu.image import load_named, Pair
from ms45emu.board import Board, RESET_ENTRY
from ms45emu.checksums import crc32_mpeg2
from ms45emu.fold import CRC_AT, CRC_FROM, CRC_TO, MON_AT, monitor_sum
from tools.build.flasher_gate import build, ENTRY_CPU, STAMP_AT, stamp_bytes
from tools.build.flasher_body import SRAM_BASE, REPLY_OFF
from tools import ROOT

CAL, CAL_END = 0x40000, 0x5D000
CHUNK = 4096


def fast_waits():
    """The body's spins as Board.set_waits entries — the same list kline
    installs unless --no-fast-wait. Call after build() filled LABEL_ADDRS;
    pass --fast-wait to run the proof with the spins skipped (the wire then
    moves at the emulator's per-byte pace instead of the spin's)."""
    from tools.build import flasher_body
    la = flasher_body.LABEL_ADDRS
    return [(la["rx_wait"], 0xA09C0000, "rx", 3, 7),   # lhz r4,0(r28); 7 insns a pass
            (la["reply_gap"], 0xB2510000, "spin", 3, 4)]
    # (the CMF spins went with the body's own CMF sequence: the loader's
    # driver paces itself and the emulator's Cmf answers it at once)


def lit_nrv2b(data):
    """The all-literal NRV2B form: a 0xFF control byte (eight 1-bits) then 8
    bytes, closed by the encoder's EOF marker (match bit, offset code
    0x1000002, low byte 0xFF) so the decoder terminates cleanly at a fresh
    bit-buffer boundary. Byte-exact per both /tmp/nrv2b_ref.py and the PPC
    decoder."""
    out = bytearray()
    for i in range(0, len(data), 8):
        out.append(0xFF)
        out += data[i:i + 8]
    return bytes(out) + b"\x00\x00\x00\x00\x00\x04\x80\xff"


def frame(svc, payload=b""):
    span = 4 + len(payload)                      # tgt..cksum
    if span <= 255:
        f = bytes([span, 0x12, 0xF1, svc]) + payload
        body = f[1:]
    else:                                        # the u16 escape (CHUNK); the
        f = bytes([0, span >> 8, span & 0xFF, 0x12, 0xF1, svc]) + payload
        body = f[3:]                             # cksum covers tgt..data only,
    return f + bytes([sum(body) & 0xFF])         # never the length bytes


class Session:
    """The tester: run the board in slices, exchange telegrams."""

    def __init__(self, board):
        self.b = board
        self.sci = board.sci

    def until(self, pred, budget=60_000_000, slice=200_000):
        while budget > 0:
            self.b.run_from(self.b.m.pc, slice, until=0x1)
            budget -= slice
            if pred():
                return True
        return False

    def reply_at(self, mark):
        t = self.sci.tx
        if len(t) < mark + 5:
            return None
        n = t[mark]
        if n < 4 or len(t) < mark + n + 1:
            return None
        f = bytes(t[mark:mark + n + 1])
        return f if sum(f[1:n]) & 0xFF == f[n] else "badck"

    def read(self, off, n, budget=200_000_000):  # 4 KB at ~20k cycles a byte
        """v13 READ: the long reply's crc and data, checked against each other."""
        mark = len(self.sci.tx)
        self.sci.send(frame(10, struct.pack(">IH", off, n)))

        def whole():
            t = self.sci.tx
            if len(t) < mark + 3:
                return None
            if t[mark] != 0:                     # a short frame: a NAK
                return self.reply_at(mark)
            span = (t[mark + 1] << 8) | t[mark + 2]
            if len(t) < mark + 3 + span:
                return None
            return bytes(t[mark:mark + 3 + span])
        if not self.until(lambda: whole() is not None, budget):
            raise SystemExit(f"FAIL: no READ reply at {off:#x} (pc={self.b.m.pc:#x}, sent {len(self.sci.tx) - mark}: {bytes(self.sci.tx[mark:mark + 24]).hex()})")
        f = whole()
        if f[0] != 0:
            raise SystemExit(f"FAIL: READ {off:#x}+{n}: {f.hex()}")
        if sum(f[3:-1]) & 0xFF != f[-1]:
            raise SystemExit(f"FAIL: READ {off:#x}: bad frame checksum")
        if f[5] != 0x4A:
            raise SystemExit(f"FAIL: READ {off:#x}: reply svc {f[5]:#x}")
        crc, data = struct.unpack(">I", f[6:10])[0], f[10:-1]
        if len(data) != n or crc32_mpeg2(data) != crc:
            raise SystemExit(f"FAIL: READ {off:#x}: {len(data)} bytes, crc mismatch")
        return data

    def xfer(self, svc, payload=b"", budget=60_000_000):
        mark = len(self.sci.tx)
        self.sci.send(frame(svc, payload))
        if not self.until(lambda: self.reply_at(mark) is not None, budget):
            raise SystemExit(f"FAIL: no reply to svc {svc:#02x} (pc={self.b.m.pc:#x})")
        f = self.reply_at(mark)
        if f == "badck":
            raise SystemExit(f"FAIL: bad reply checksum for svc {svc:#02x}")
        return f


def expect(f, svc, note):
    want = svc | 0x40
    if f[3] != want:
        raise SystemExit(f"FAIL: {note}: reply svc {f[3]:#02x}, want {want:#02x} ({f.hex()})")
    print(f"  ok: {note}")


def expect_nak(f, svc, reason, note):
    if len(f) < 6 or f[3] != 0x7F or f[4] != svc or f[5] != reason:
        raise SystemExit(f"FAIL: {note}: {f.hex()} (want 7f {svc:02x} {reason:02x})")
    print(f"  ok: {note}")


WATCHDOG_MS = 100        # the loader's SYPCR 0x07A17F87, write-once


def main():
    t0 = time.time()
    pair = load_named("session1.livetune6-notraps")
    f, m = build(pair.flash, pair.mpc)
    board = Board(Pair(bytes(f), bytes(m), "quickflash1", check_program=False),
                  waits=fast_waits() if "--fast-wait" in sys.argv else None)
    sci = board.sci
    s = Session(board)

    sci.line_hold = True                         # the app holds the break
    reached, why = board.boot(max_insns=2_000_000, until=ENTRY_CPU + 4, reset_vector=True)
    assert reached, f"never reached the flasher entry: {why}"
    print(f"boot: gate taken ({why})")

    in_body = lambda: SRAM_BASE <= board.m.pc < SRAM_BASE + REPLY_OFF   # noqa: E731
    if not s.until(in_body, budget=2_000_000):
        raise SystemExit("FAIL: the body never reached SRAM")
    print("relocate: stub copied the body to SRAM and jumped")

    sci.line_hold = False                        # the app releases the line
    if not s.until(lambda: len(sci.tx) >= 21):
        raise SystemExit("FAIL: no HELLO after the break released")
    hello = bytes(sci.tx[:21])
    if hello != frame(0x40, stamp_bytes(13, 3)):
        raise SystemExit(f"FAIL: HELLO mismatch: {hello.hex()} "
                         f"(want {frame(0x40, stamp_bytes(13, 3)).hex()})")
    print(f"hello: {hello[4:10].decode()} v{hello[10]} flags {hello[11]:#04x}")
    board.watchdog_window()                      # the body runs from here
    board.sci.model_overrun = True               # the real SCI drops, it does not wait

    expect(s.xfer(0x00), 0x00, "HELLO (request form)")
    expect_nak(s.xfer(0x77), 0x77, 6, "unknown service")

    # v13 READ: anywhere on the chip (the boot block too) and the MPC
    img, mpc = bytes(board.flash.image), bytes(m)
    for off, n, want in ((0x40000, 4096, img[0x40000:0x41000]),
                         (0x7F00, 512, img[0x7F00:0x8100]),
                         (0xFFFF0, 16, img[0xFFFF0:0x100000]),
                         (0x80000000 | 0x6F000, 4096, mpc[0x6F000:0x70000])):
        if s.read(off, n) != want:
            raise SystemExit(f"FAIL: READ {off:#x}+{n} differs from the image")
    print("  ok: READ ext (cal, across 0x8000, the chip's last bytes) and the MPC")
    expect_nak(s.xfer(10, struct.pack(">IH", 0xFFFF0, 32)), 10, 1, "READ past the chip refused")
    expect_nak(s.xfer(10, struct.pack(">IH", 0x40000, 4097)), 10, 6, "READ over 4096 bytes refused")

    mark = len(sci.tx)                           # a corrupted checksum
    bad = bytearray(frame(0x00))
    bad[-1] ^= 0xFF
    sci.send(bytes(bad))
    if not s.until(lambda: s.reply_at(mark) is not None):
        raise SystemExit("FAIL: no NAK for a malformed frame")
    expect_nak(s.reply_at(mark), 0x00, 6, "malformed frame")

    crc = crc32_mpeg2(f[CAL:CAL_END])
    fr = s.xfer(0x01, struct.pack(">II", CAL, CAL_END - CAL), budget=90_000_000)
    expect(fr, 0x01, "SECTOR_QUERY of the stock cal")
    if struct.unpack(">I", fr[4:8])[0] != crc:
        raise SystemExit(f"FAIL: QUERY crc {struct.unpack('>I', fr[4:8])[0]:#010x}, "
                         f"want {crc:#010x}")

    expect_nak(s.xfer(0x02, struct.pack(">I", 0x10000)), 0x02, 1,
               "ERASE below 0x40000 refused")

    # ---- the push: a modified cal --------------------------------------
    target = bytearray(f)
    # the header (0x00-0x200: the doubled part-number string at 0x10/0x21 the
    # loader compares, the CRC slot at 0x100) stays stock apart from the CRC;
    # patch only data, starting inside the first chunk
    target[CAL + 0x400:CAL + 0x500] = bytes((i * 7 + 3) & 0xFF for i in range(0x100))
    for at in (0x8000, 0x15000, 0x1A000):        # touch the middle and tail too
        target[CAL + at:CAL + at + 0x40] = bytes((i * 13 + at) & 0xFF for i in range(0x40))
    # the loader only starts the program on a cal whose monitor sum and CRC
    # match (the fold flasher's scheme); fix both after the edits, monitor
    # first because its bytes sit inside the CRC's range
    target[CAL + MON_AT:CAL + MON_AT + 8] = monitor_sum(bytes(target[CAL:CAL + 0x10000]))
    struct.pack_into(">I", target, CAL + CRC_AT,
                     crc32_mpeg2(bytes(target[CAL + CRC_FROM:CAL + CRC_TO])))
    assert target != f

    expect(s.xfer(0x02, struct.pack(">I", CAL)), 0x02, "ERASE the cal sector")
    if bytes(board.flash.image[0x40000:0x60000]) != b"\xff" * 0x20000:
        raise SystemExit("FAIL: sector not blank after ERASE")

    hdr = struct.pack(">IHHI", CAL, CHUNK, CHUNK // 8, 0)   # CRC wrong on purpose
    expect_nak(s.xfer(0x03, hdr + lit_nrv2b(bytes(target[CAL:CAL + CHUNK]))),
               0x03, 2, "CHUNK with a bad CRC refused")
    if board.flash.image[CAL] != 0xFF:
        raise SystemExit("FAIL: bad-CRC chunk left data behind")

    t1 = time.time()
    n = 0
    for at in range(CAL, CAL_END, CHUNK):
        data = bytes(target[at:at + CHUNK])
        comp = lit_nrv2b(data)
        hdr = struct.pack(">IHHI", at, len(data), len(comp), crc32_mpeg2(comp))
        fr = s.xfer(0x03, hdr + comp)     # unconditional: `x if c else None`
        if fr[3] != 0x43:                 # skips the xfer itself for c false
            raise SystemExit(f"FAIL: CHUNK at {at:#x}: {fr.hex()}")
        if n < 2:
            print(f"  ok: CHUNK at {at:#x}")
        n += 1
    print(f"  ok: CHUNK x{n} pushed ({time.time() - t0:.0f}s wall)")

    want = crc32_mpeg2(bytes(target[CAL:CAL_END]))
    expect(s.xfer(0x04, struct.pack(">III", CAL, CAL_END - CAL, want)),
           0x04, "VERIFY of the new cal")
    expect_nak(s.xfer(0x04, struct.pack(">III", CAL, CAL_END - CAL, crc)),
               0x04, 5, "VERIFY of the old cal mismatches")

    expect(s.xfer(0x05, b"\x00"), 0x05, "MARKS (cal)")
    if bytes(board.flash.image[0x5FF80:0x5FF84]) != bytes.fromhex("48249042"):
        raise SystemExit("FAIL: cal mark 0x5FF80 not burned")
    if bytes(board.flash.image[0x5FFC0:0x5FFC4]) != bytes.fromhex("90482442"):
        raise SystemExit("FAIL: cal mark 0x5FFC0 not burned")

    if bytes(board.flash.image[CAL:CAL_END]) != bytes(target[CAL:CAL_END]):
        first = next(i for i in range(CAL, CAL_END)
                     if board.flash.image[i] != target[i])
        raise SystemExit(f"FAIL: image differs from target at ext {first:#x}")
    print("  ok: chip image == target over the whole cal")

    gap = board.watchdog_gap_ms()                # RESET stops servicing on purpose
    if gap > WATCHDOG_MS:
        raise SystemExit(f"FAIL: the watchdog went {gap:.0f} ms unserviced "
                         f"(the car's loader resets the DME after {WATCHDOG_MS} ms)")
    print(f"  ok: longest watchdog gap {gap:.1f} ms (car limit {WATCHDOG_MS} ms)")
    expect(s.xfer(0x06), 0x06, "RESET")
    park = board.m.pc
    s.until(lambda: False, budget=400_000)       # let it spin
    if board.m.pc != park:
        raise SystemExit(f"FAIL: not parked after RESET ({park:#x} -> {board.m.pc:#x})")
    print("  ok: parked after RESET (watchdog owns the real reset)")
    if board.sci.frame_mismatch:
        raise SystemExit(f"FAIL: {board.sci.frame_mismatch} byte(s) sent not 8E1 "
                         "(SCC1R1 lacks PE|M): a real tester reads them garbled")
    print("  ok: every byte went out 8E1, as the tester reads it")

    fresh = board.reset()                        # the DME after the session
    reached, why = fresh.boot(max_insns=2_000_000, until=RESET_ENTRY + 4, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: the new cal does not boot ({why})")
    print(f"reboot: the loader starts the program on the new cal ({why})")

    print(f"ALL OK -- {n} chunks, {time.time() - t0:.0f}s wall")
    return 0


if __name__ == "__main__":
    sys.exit(main())
