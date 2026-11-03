"""Burn a new DME ISN into flash 0x1FB00 through the fast flash bootloader,
proven on the emulator the way BMWeb does it (core/flash/isn-flash.js +
bl.burnIsn): the app's JS computes the new boot sector from the DME's own
read, the Python bootloader session writes it through the AIF ladder, and
the DME is rebooted so its own vote routine reads the new ISN back.

Run from the ms45-emu root: .venv/bin/python -m tools.proofs.isn_burn_test

Steps, mirroring bl_app_test:
1. A DME on this build's bootloader (BL). Take a held line into the ring.
2. READ [0x0,0x8000) + [0x8000,0x20000) off it; hand the four areas to the
   app's isnFlash.spliceBoot(... newIsn) in node; get back the boot sector.
3. Check the splice touched ONLY the six ISN bytes (and left the boot CRC
   word as it was -- 0x1FB00 is above the CRC's range).
4. AIF ARM -> ERASE -> CHUNK x24 -> VERIFY -> DONE, then READ 0x1FB00 back
   and confirm the six bytes are the new triple.
5. RESET; boot the program; watch fn_FFFDB600's reader store the NEW ISN
   into the handshake RAM copy (0x3F9E06) -- the value the EWS would see.
"""
import json
import os
import struct
import subprocess
import sys
import time

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.ppc_const import UC_PPC_REG_PC

from tools.build import bl
from ms45emu.image import load_named
from ms45emu.board import Board, RESET_ENTRY
from ms45emu.checksums import image_boot_crc
from tools.proofs.flasher_session_test import expect
from tools.proofs.bl_test import fresh, hello_wait, marker, taken, S_AIF
from tools.proofs.bl_app_test import (BMWEB, BOOT, BOOT_LEN, LOW, LOW_LEN, MID, MID_LEN,
                                        SECT8K, SECT8K_LEN, read_area, read_outer, rewrite)
from tools.build.flasher_body import MARK_ARMED, AIF_ARM, AIF_DONE
from tools import ROOT

ISN_AT = 0x1FB00
NEW_ISN = 0x1E0B          # the car's original DME's ISN (pair a used DME to it)

SPLICE_JS = r"""
const fs = require('fs');
global.fastFlasher = { BODY_START: 0xfd26c, BODY_END: 0xfff40 };
const { isnFlash } = require(process.argv[1] + '/app/renderer/core/flash/isn-flash.js');
const low = new Uint8Array(fs.readFileSync(process.argv[3]));
const s8  = new Uint8Array(fs.readFileSync(process.argv[4]));
const mid = new Uint8Array(fs.readFileSync(process.argv[5]));
const boot = new Uint8Array(fs.readFileSync(process.argv[6]));
const r = isnFlash.spliceBoot(low, s8, mid, boot, parseInt(process.argv[2], 16));
fs.writeFileSync(process.argv[6] + '.out', r.boot);
console.log(JSON.stringify({ was: r.was, changed: r.changed }));
"""


def app_splice(isn, low, s8, mid, boot, tmp):
    paths = [os.path.join(tmp, n) for n in ("ilow.bin", "is8.bin", "imid.bin", "iboot.bin")]
    for p, d in zip(paths, (low, s8, mid, boot)):
        open(p, "wb").write(d)
    out = subprocess.run(["node", "-e", SPLICE_JS, BMWEB, f"{isn:x}", *paths],
                         check=True, capture_output=True, text=True).stdout
    return open(paths[3] + ".out", "rb").read(), json.loads(out)


def read_region(s, board):
    areas = [(bytearray(read_area(s, base, ln)), base, ln)
             for base, ln in ((LOW, LOW_LEN), (SECT8K, SECT8K_LEN), (MID, MID_LEN), (BOOT, BOOT_LEN))]
    for at, orig in board.cpu.patched.items():
        off = at - 0xFFF00000
        for area, base, ln in areas:
            if base <= off < base + ln:
                struct.pack_into(">I", area, off - base, orig)
    return tuple(bytes(a) for a, _, _ in areas)


def voted_isn(six):
    V = (six[4] << 8) | six[3]
    hi, lo = (V >> 8) & 0xFF, V & 0xFF
    ok = (six[0] == (~V >> 8) & 0xFF and six[1] == ~V & 0xFF
          and six[2] == ~hi & 0xFF and six[3] == lo
          and six[4] == hi and six[5] == ~lo & 0xFF)
    return V if ok else None


def main():
    t0 = time.time()
    tmp = os.environ.get("TMPDIR", "/tmp")
    pair = load_named(os.environ.get("BL_BASE", "session1.livetune7"))
    stock_f, mpc0 = bytes(pair.flash), bytes(pair.mpc)
    bl_f, _ = bl.build(stock_f, mpc0)
    old_isn = voted_isn(bl_f[ISN_AT:ISN_AT + 6])
    print(f"base DME ISN: {old_isn:04X} -> burning {NEW_ISN:04X}")
    if old_isn == NEW_ISN:
        raise SystemExit("FAIL: base already holds the target ISN; nothing to prove")

    board, s = taken(bl_f, mpc0, "BL", deep=True)
    low, s8, mid, boot = read_region(s, board)

    # the app's JS computes the new boot sector
    nb, ch = app_splice(NEW_ISN, low, s8, mid, boot, tmp)
    print(f"  ok: isnFlash.spliceBoot: was {ch['was']:#06x}, changed {ch['changed']}")
    if not ch["changed"] or ch["was"] != old_isn:
        raise SystemExit("FAIL: splice did not report the change we expect")
    # only the six ISN bytes differ, and the boot CRC word is unaffected
    diff = [i for i in range(len(nb)) if nb[i] != boot[i]]
    if diff != list(range(ISN_AT - BOOT, ISN_AT - BOOT + 6)):
        raise SystemExit(f"FAIL: splice changed {len(diff)} bytes, not only the ISN: {[hex(d) for d in diff[:10]]}")
    if image_boot_crc(bytearray(low + s8 + mid + nb)) != image_boot_crc(bytearray(low + s8 + mid + boot)):
        raise SystemExit("FAIL: the boot CRC changed (it must not -- 0x1FB00 is above its range)")
    print("  ok: only the six ISN bytes changed; boot CRC unaffected")

    # write it through the ladder, exactly bl.burnIsn's sequence
    if marker(s) != 0xFFFF:
        raise SystemExit("FAIL: marker not fresh")
    expect(s.xfer(S_AIF, bytes([AIF_ARM])), S_AIF, "AIF ARM")
    if marker(s) != MARK_ARMED:
        raise SystemExit("FAIL: marker not armed")
    rewrite(s, BOOT, nb, f"the boot sector (ISN {NEW_ISN:04X})")
    expect(s.xfer(S_AIF, bytes([AIF_DONE])), S_AIF, "AIF DONE")
    back = s.read(ISN_AT, 6)
    if voted_isn(back) != NEW_ISN:
        raise SystemExit(f"FAIL: read-back {back.hex(' ')} votes {voted_isn(back)}, not {NEW_ISN:04X}")
    print(f"  ok: read-back 0x1FB00 = {back.hex(' ')} votes {NEW_ISN:04X}")

    img = bytes(board.flash.image)
    stray = [i for i in range(len(img)) if img[i] != bl_f[i]
             and not (ISN_AT <= i < ISN_AT + 6)
             and not (0x387EC <= i < 0x387EC + 128)]   # the AIF/mark slots
    if stray:
        raise SystemExit(f"FAIL: ext {stray[0]:#x} changed outside the ISN ({len(stray)} bytes)")
    if bytes(board.cmf.image) != mpc0:
        raise SystemExit("FAIL: the MPC changed")
    print(f"  ok: {len(diff)} ISN bytes changed on the chip; ring, program, MPC untouched")
    expect(s.xfer(0x06), 0x06, "RESET")

    # boot the program and watch the handshake copy get the NEW ISN
    b2 = board.reset()
    got = []
    def wr(mu, access, addr, size, value, ud):
        pc = mu.reg_read(UC_PPC_REG_PC) & 0xFFFFFFFF
        if 0xFFFDBBB0 <= pc < 0xFFFDBBE0 and addr == 0x3F9E06 and size == 2:
            got.append(value & 0xFFFF)
    b2.m.mu.hook_add(UC_HOOK_MEM_WRITE, wr)
    from ms45emu.protections import Reactions
    r = Reactions(b2)
    r.scenario(rpm=800, seconds=0.5, settle=1.5)
    # the reader stores copy B raw (hi-inverted), i.e. (~hi)<<8 | lo for the NEW ISN
    hi, lo = (NEW_ISN >> 8) & 0xFF, NEW_ISN & 0xFF
    want_rawB = ((~hi & 0xFF) << 8) | lo
    if want_rawB not in got:
        raise SystemExit(f"FAIL: handshake RAM got {[hex(v) for v in got]}, not copy-B {want_rawB:#06x} of {NEW_ISN:04X}")
    print(f"  ok: after reboot the DME reads the new ISN -- handshake RAM copy = {want_rawB:#06x} (copy B of {NEW_ISN:04X})")
    print("=" * 64)
    print(f"ALL OK -- ISN burn {old_isn:04X} -> {NEW_ISN:04X}, {time.time() - t0:.0f}s wall")


if __name__ == "__main__":
    main()
