"""The AIF editor protocol, proven on the BL14 image (docs/bootloader.md).

Run from the ms45-emu root: .venv/bin/python -m tools.proofs.aif_editor_test

The programming log (AIF/UIF) is the tail of the boot sector: ext
0x1FB34-0x1FFFF = 0x4CC bytes = 19 full 64-byte slots + a 12-byte tail the
format cannot use. The editor is a CLIENT: every operation it needs already
exists in the v13/v14 body (READ anywhere, SECTOR_QUERY, and the AIF
arm/erase/restore ladder that aif_wipe_flasher.py proved).

1. READ + PARSE: the whole log over the wire, parsed into slots -- the
   layout decoded from the car's own log ('@' + 7-char part, opcode, two
   opaque fields, '!#', 5-char station, 7-char serial, the LL/LO + SWBA
   block) with the geometry proven: 19 slots, 12-byte tail.
2. DIRECT EDIT: a bit-clear-only change (a '4'->'0' station char, a byte
   cleared to 0x00) written by ARM -> CHUNK over the one slot -> VERIFY ->
   DONE -- no erase, the ring untouched. Then the AND-physics proof: a
   bit-SET change attempted the same way is NAKed by the body's read-back
   ("a page would not take"), which is exactly why the client must classify
   edits before choosing a path.
3. FULL REWRITE, fast path: the client's local file is only trusted after
   24 SECTOR_QUERY CRCs match the chip; then an arbitrary edit (a bit-set
   station char) plus a new synthesized entry: ARM -> ERASE the boot sector
   -> blank-check -> CHUNK x24 -> VERIFY -> DONE. The ring comes back
   byte-identical, the DME still boots, and the fast path still answers.
4. CLEAR ALL, the no-local-file fallback: the sector is rebuilt from 24
   wire READs alone, the AIF blanked in it, and the rewrite run from that.
   What the DME alone knows is enough to clear the log.
5. FILL TO THE MAX: 19 synthesized entries -- the walk stops there because
   the remaining 12 bytes cannot hold a slot -- read back over the wire and
   parsed. Ends with a clear, so the chip is left tidy.
"""
import os
import struct
import sys
import time

from tools.build import bl14
from ms45emu.image import load_named
from ms45emu.checksums import crc32_mpeg2
from tools.build.flasher_body import MARK_AT, MARK_DONE, AIF_ARM, AIF_DONE
from tools.proofs.flasher_session_test import (Session, frame, lit_nrv2b,
                                  expect, expect_nak, fast_waits)
from tools.proofs.bl14_test import (hello_wait, taken, marker,
                       taken_from_reset, BOOT, CHUNK, S_AIF)
from tools import ROOT

AIF_START, AIF_END = 0x1FB34, 0x20000
AIF_LEN = AIF_END - AIF_START                 # 0x4CC
SLOT = 64
MAX_SLOTS = AIF_LEN // SLOT                   # 19
TAIL = AIF_LEN % SLOT                         # 12 bytes no slot can use
AIF_OFF = AIF_START - BOOT                    # the log inside the sector
SECTOR_LEN = 0x20000 - BOOT                   # 0x18000 = 24 x 4096


# ---------------------------------------------------------------------------
# the slot model (the reference the app's aif.js mirrors)

def parse_slot(b):
    """One 64-byte slot as fields, from the car's own log layout."""
    a = lambda i, j: b[i:j].decode("ascii", "replace").rstrip("�")
    return {
        "part": a(1, 8),                       # '@' + 7 chars
        "opcode": b[9],                        # 0x03 factory first, 0x25/0x26 update
        "op2": (b[10], b[11]),                 # varies with the opcode
        "f1": b[12:18].hex(),                  # two opaque 6-byte fields
        "f2": b[18:24].hex(),
        "station": a(0x21, 0x26),              # '!' then 5 chars
        "serial": a(0x27, 0x2E),               # 0x00 then 7 chars
        "block": a(0x2E, 0x3D),                # LL/LO + '00SWBA' + version
        "raw": bytes(b),
    }


def parse_aif(data):
    """The used slots: the walk every reader does, stopping at 0xFF."""
    out = []
    for i in range(MAX_SLOTS):
        s = bytes(data[i * SLOT:(i + 1) * SLOT])
        if s[0] == 0xFF:
            break
        out.append(parse_slot(s))
    return out


def synth_entry(part, station, serial, block, opcode=0x26, op2=(0x10, 0x02)):
    """A slot in the app's own shape (the 'BMWEB' entries the car carries)."""
    b = bytearray(b"\xff" * SLOT)
    b[0] = ord("@")
    b[1:8] = part.encode()[:7].ljust(7, b"0")
    b[8] = ord(" ")
    b[9] = opcode
    b[10], b[11] = op2
    b[0x0C:0x12] = bytes.fromhex("000007561532")   # the counters the newest
    b[0x12:0x18] = bytes.fromhex("000007561533")   # entry on the car carries
    b[0x1E:0x20] = b"\x01\x23"
    b[0x20] = ord("!")
    b[0x21:0x26] = station.encode()[:5].ljust(5, b" ")
    b[0x26] = 0
    b[0x27:0x2E] = serial.encode()[:7].ljust(7, b"0")
    b[0x2E:0x3D] = block.encode()[:0xF].ljust(0xF, b"\xff")
    return bytes(b)


def bit_clear_only(new, old):
    """Whether `new` can be programmed over `old` without an erase."""
    return all(n & o == n for n, o in zip(new, old))


def cpu_view(board, data, base):
    """The file as the DME's CPU sees it. The emulator stubs some of the
    loader's interrupt-enable sites in the mapped view (keys in cpu.patched
    are absolute; the ext ones sit at 0xFFF0xxxx); the chip image is left
    honest and flash_pair restores the words. On real hardware the wire CRC
    and the file CRC are the same thing, so the local-verify fast path is
    proven against this view."""
    out = bytearray(data)
    for at in board.cpu.patched:
        if at < 0xFFF00000:
            continue                             # an MPC-array site
        off = at - 0xFFF00000
        if base <= off < base + len(out):
            out[off - base:off - base + 4] = struct.pack(">I", board.m.read32(at))
    return bytes(out)


# ---------------------------------------------------------------------------
# the wire client (the sequence the app's editor drives)

def chunk(s, off, data):
    comp = lit_nrv2b(data)
    hdr = struct.pack(">IHHI", off, len(data), len(comp), crc32_mpeg2(comp))
    fr = s.xfer(0x03, hdr + comp)
    if fr[3] != 0x43:
        raise SystemExit(f"FAIL: CHUNK at {off:#x}: {fr.hex()}")


def query_crc(s, off, ln):
    fr = s.xfer(0x01, struct.pack(">II", off, ln), budget=90_000_000)
    if fr[3] != 0x41:
        raise SystemExit(f"FAIL: QUERY {off:#x}+{ln:#x}: {fr.hex()}")
    return struct.unpack(">I", fr[4:8])[0]


def read_area(s, off, ln):
    out = b""
    while len(out) < ln:
        out += s.read(off + len(out), min(CHUNK, ln - len(out)))
    return out


def full_rewrite(s, board, sector, note):
    """ARM -> ERASE -> blank-check -> CHUNK x24 -> VERIFY -> DONE."""
    if len(sector) != SECTOR_LEN:
        raise SystemExit(f"FAIL: {note}: sector is {len(sector):#x} bytes")
    if marker(s) == MARK_DONE:
        raise SystemExit(f"FAIL: {note}: no marker slots left")
    expect(s.xfer(S_AIF, bytes([AIF_ARM])), S_AIF, f"{note}: AIF ARM")
    expect(s.xfer(0x02, struct.pack(">I", BOOT)), 0x02, f"{note}: ERASE the boot sector")
    if query_crc(s, BOOT, SECTOR_LEN) != crc32_mpeg2(b"\xff" * SECTOR_LEN):
        raise SystemExit(f"FAIL: {note}: sector not blank after ERASE")
    for at in range(0, SECTOR_LEN, CHUNK):
        chunk(s, BOOT + at, bytes(sector[at:at + CHUNK]))
    print(f"  ok: {note}: CHUNK x{SECTOR_LEN // CHUNK}")
    expect(s.xfer(0x04, struct.pack(">III", BOOT, SECTOR_LEN, crc32_mpeg2(bytes(sector)))),
           0x04, f"{note}: VERIFY the rewritten sector")
    expect(s.xfer(S_AIF, bytes([AIF_DONE])), S_AIF, f"{note}: AIF DONE")


# ---------------------------------------------------------------------------

def main():
    t0 = time.time()
    pair = load_named("session1.livetune6-notraps")
    bl_f, bl_m = bl14.build(pair.flash, pair.mpc)

    board, s = taken(bl_f, bl_m, "aif-editor", deep=True)
    hello_wait(s, "editor session", bl14.stamp_bytes())
    chip0 = bytes(board.flash.image)
    client_file = bytearray(bl_f)      # what the client holds, edits applied

    # ---- 1. READ + PARSE -------------------------------------------------
    print("=" * 64, "\n1. READ + PARSE -- the log over the wire\n" + "=" * 64)
    data = s.read(AIF_START, AIF_LEN)
    if data != bytes(bl_f[AIF_START:AIF_END]):
        raise SystemExit("FAIL: wire read of the AIF differs from the image")
    slots = parse_aif(data)
    print(f"  ok: READ {AIF_LEN:#x} bytes == image; geometry {MAX_SLOTS} slots "
          f"+ {TAIL}-byte tail, {len(slots)} used")
    for i, sl in enumerate(slots):
        print(f"    slot {i}: part {sl['part']} op {sl['opcode']:#04x} "
              f"station {sl['station']} serial {sl['serial']} block {sl['block']}")
    if len(slots) != 4 or slots[0]["opcode"] != 0x03:
        raise SystemExit("FAIL: the base log is not the expected four entries")
    if slots[-1]["station"] != "BMWEB":
        raise SystemExit("FAIL: the newest entry is not one of ours")

    # ---- 2. DIRECT EDIT + the AND-physics refusal ------------------------
    print("=" * 64, "\n2. DIRECT EDIT -- bit-clear only, no erase\n" + "=" * 64)
    old = slots[0]["raw"]
    new = bytearray(old)
    new[0x25] = old[0x25] & ~0x04                # station '4' -> '0' (a clear)
    new[0x0B] = 0x00                             # a byte fully cleared
    new = bytes(new)
    if not bit_clear_only(new, old):
        raise SystemExit("FAIL: the direct edit is not bit-clear")

    expect(s.xfer(S_AIF, bytes([AIF_ARM])), S_AIF, "AIF ARM")
    chunk(s, AIF_START, new)
    print("  ok: CHUNK over slot 0 (64 bytes, no erase)")
    expect(s.xfer(0x04, struct.pack(">III", AIF_START, SLOT, crc32_mpeg2(new))),
           0x04, "VERIFY slot 0")
    expect(s.xfer(S_AIF, bytes([AIF_DONE])), S_AIF, "AIF DONE")
    client_file[AIF_START:AIF_START + SLOT] = new   # the client knows what it wrote
    img = board.flash.image
    if bytes(img[AIF_START:AIF_START + SLOT]) != new:
        raise SystemExit("FAIL: slot 0 is not the edited bytes")
    stray = [i for i in range(len(img)) if img[i] != chip0[i]
             and not AIF_START <= i < AIF_START + SLOT
             and not MARK_AT <= i < MARK_AT + 2]   # the ladder slot this op burned
    if stray:
        raise SystemExit(f"FAIL: the direct edit touched ext {stray[0]:#x} "
                         f"({len(stray)} bytes beyond slot 0)")
    print("  ok: chip differs from the session start only inside slot 0")
    if bytes(img[MARK_AT:MARK_AT + 2]) != struct.pack(">H", MARK_DONE):
        raise SystemExit("FAIL: the marker slot did not burn to DONE")
    if marker(s) != 0xFFFF:
        raise SystemExit("FAIL: the next marker slot is not fresh")
    print("  ok: one marker slot spent; the ladder advanced")

    # a bit-SET change cannot take the direct path -- the body's read-back
    # refuses it (the physics the client's classifier exists for)
    bad = bytearray(new)
    bad[0x0B] = 0x10                             # a set bit over 0x00
    bad = bytes(bad)
    comp = lit_nrv2b(bad)
    hdr = struct.pack(">IHHI", AIF_START, len(bad), len(comp), crc32_mpeg2(comp))
    expect(s.xfer(S_AIF, bytes([AIF_ARM])), S_AIF, "AIF ARM (bit-set attempt)")
    expect_nak(s.xfer(0x03, hdr + comp), 0x03, 4, "bit-set CHUNK refused (would not take)")
    if bytes(board.flash.image[AIF_START:AIF_START + SLOT]) != new:
        raise SystemExit("FAIL: the refused chunk left data behind")
    print("  ok: the NAK changed nothing -- direct edits must classify first")
    expect(s.xfer(S_AIF, bytes([AIF_DONE])), S_AIF, "AIF DONE (attempt closed)")

    # ---- 3. FULL REWRITE, local-verify fast path --------------------------
    print("=" * 64, "\n3. FULL REWRITE -- arbitrary edit, ring restored\n" + "=" * 64)
    for i in range(SECTOR_LEN // CHUNK):
        got = query_crc(s, BOOT + i * CHUNK, CHUNK)
        view = cpu_view(board, client_file[BOOT + i * CHUNK:BOOT + (i + 1) * CHUNK],
                        BOOT + i * CHUNK)
        if got != crc32_mpeg2(view):
            raise SystemExit(f"FAIL: local file does not match the chip at chunk {i}")
    print(f"  ok: {SECTOR_LEN // CHUNK} QUERY CRCs -- the local file is the chip")

    sector = bytearray(client_file[BOOT:0x20000])
    slot1 = AIF_OFF + SLOT                       # the dealer entry, station 42324
    sector[slot1 + 0x21] = ord("5")              # '4' -> '5': a bit SET
    entry = synth_entry("NJ87379", "BMWEB", "0044570", "LO00SWBAET37495")
    at4 = AIF_OFF + 4 * SLOT
    sector[at4:at4 + SLOT] = entry               # a new entry in the first blank slot
    full_rewrite(s, board, bytes(sector), "rewrite")
    client_file[BOOT:0x20000] = sector

    img = board.flash.image
    if bytes(img[:BOOT]) != chip0[:BOOT]:
        raise SystemExit("FAIL: the rewrite touched below the boot sector")
    if bytes(img[BOOT:0x20000]) != bytes(sector):
        raise SystemExit("FAIL: the sector is not the edited image")
    if bytes(img[BOOT:AIF_START]) != bytes(bl_f[BOOT:AIF_START]):
        raise SystemExit("FAIL: the ring was not restored byte-identical")
    print("  ok: ring byte-identical, edits in place")
    now = parse_aif(bytes(img[AIF_START:AIF_END]))
    if len(now) != 5 or now[1]["station"] != "52324" or now[4]["station"] != "BMWEB":
        raise SystemExit(f"FAIL: parsed {len(now)} slots after the rewrite")
    print(f"  ok: {len(now)} entries parse; slot 1 station 52324, slot 4 is the new BMWEB")

    from ms45emu.board import RESET_ENTRY
    fresh_b = board.reset()
    reached, why = fresh_b.boot(max_insns=2_000_000, until=RESET_ENTRY, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: no boot through the rewritten sector ({why})")
    print("reboot: the loader starts the program on the rewritten sector")
    b2, s2 = taken_from_reset(fresh_b, "rewrite-retaken")
    hello_wait(s2, "after the rewrite", bl14.stamp_bytes())
    board, s = b2, s2

    # ---- 4. CLEAR ALL, the wire-READ fallback ------------------------------
    print("=" * 64, "\n4. CLEAR ALL -- rebuilt from the DME alone\n" + "=" * 64)
    sector = bytearray(read_area(s, BOOT, SECTOR_LEN))
    want = cpu_view(board, bytes(board.flash.image[BOOT:0x20000]), BOOT)
    if bytes(sector) != want:
        at = next(i for i in range(SECTOR_LEN) if sector[i] != want[i])
        raise SystemExit(f"FAIL: the wire READs disagree at ext {BOOT + at:#x}")
    # the emulator's loader stubs ride the view, not the chip; the client's
    # own file knows the true words there (on hardware this loop is a no-op)
    for at, orig in board.cpu.patched.items():
        if at >= 0xFFF00000 and BOOT <= at - 0xFFF00000 < 0x20000:
            struct.pack_into(">I", sector, at - 0xFFF00000 - BOOT, orig)
    print(f"  ok: {SECTOR_LEN:#x} bytes read back over the wire match the chip")
    sector[AIF_OFF:] = b"\xff" * (SECTOR_LEN - AIF_OFF)
    full_rewrite(s, board, bytes(sector), "clear")
    img = board.flash.image
    if bytes(img[AIF_START:AIF_END]) != b"\xff" * AIF_LEN:
        raise SystemExit("FAIL: the AIF is not blank after clear-all")
    if bytes(img[BOOT:AIF_START]) != bytes(bl_f[BOOT:AIF_START]):
        raise SystemExit("FAIL: clear-all disturbed the ring")
    print("  ok: AIF blank, ring intact -- the log cleared with no local file")

    # ---- 5. FILL TO THE MAX -------------------------------------------------
    print("=" * 64, "\n5. FILL TO THE MAX -- 19 entries, the walk's end\n" + "=" * 64)
    sector = bytearray(bl_f[BOOT:0x20000])
    for i in range(MAX_SLOTS):
        e = synth_entry("NJ87379", "BMWEB", f"{700000 + i:07d}", "LO00SWBAET37495")
        sector[AIF_OFF + i * SLOT:AIF_OFF + (i + 1) * SLOT] = e
    full_rewrite(s, board, bytes(sector), "fill")
    back = parse_aif(s.read(AIF_START, AIF_LEN))
    if len(back) != MAX_SLOTS:
        raise SystemExit(f"FAIL: {len(back)} slots parsed after the fill (want {MAX_SLOTS})")
    tail = bytes(board.flash.image[AIF_START + MAX_SLOTS * SLOT:AIF_END])
    if tail != b"\xff" * TAIL:
        raise SystemExit("FAIL: the 12-byte tail is not blank")
    print(f"  ok: {len(back)} entries read back and parsed; the {TAIL}-byte tail "
          "cannot hold a 20th -- 19 is the DME's max")

    full_rewrite(s, board, bytes(bl_f[BOOT:0x20000]), "tidy")
    if bytes(board.flash.image[BOOT:0x20000]) != bytes(bl_f[BOOT:0x20000]):
        raise SystemExit("FAIL: the tidy restore did not converge")
    print("  ok: log left as the session found it")

    if board.sci.frame_mismatch:
        raise SystemExit(f"FAIL: {board.sci.frame_mismatch} byte(s) not 8E1")
    print("=" * 64)
    print(f"ALL OK -- read/parse, direct edit, rewrite, clear, fill, {time.time() - t0:.0f}s wall")
    return 0


if __name__ == "__main__":
    sys.exit(main())
