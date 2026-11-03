"""BMWeb's Restore stock bootloader (core/flash/bl.js toInstaller +
restore), proven on the emulator.

Run from the ms45-emu root: .venv/bin/python -m tools.proofs.bl_restore_test

On a BL DME a held line always lands in the ring (its handoff window runs
before MPC 0x8), and the ring's body may not write the 8 KB sector that
holds the two patched words. So the app takes BL off in two sessions,
both on the ring, and this runs them as the app does -- the new sector
contents computed by the APP'S OWN JS (bl.installerImage /
bl.restoreImages, in node) from what the wire READs returned:

0. BL itself refuses an ERASE of the 8 KB sector (why step 1 exists);
1. on BL: READ both sectors -> AIF ARM -> the 96 KB sector rewritten with
   the installer ring -> AIF DONE -> stamp reads flags 7 -> RESET;
2. line held across the reset lands in the installer ring (HELLO MS45BL
   v15 flags 7); READ both sectors -> AIF ARM -> the 8 KB sector with both
   words stock -> the 96 KB sector with the ring blanked -> AIF DONE ->
   stamp blank -> RESET.

Then the flash is byte-identical to the stock image the BL install
started from, apart from the two spent marker slots; the MPC is untouched;
line free boots the program; a held line and a parked loader (blank tune)
no longer reach any flasher.
"""
import json
import os
import struct
import subprocess
import sys
import time

from tools.build import flasher_body
from tools.build import bl
from ms45emu.image import load_named
from ms45emu.board import RESET_ENTRY
from tools.build.flasher_body import SRAM_BASE, MARK_ARMED, AIF_ARM, AIF_DONE
from tools.proofs.flasher_session_test import expect
from tools.proofs.bl_test import (fresh, hello_wait, marker, taken,
                       taken_from_reset, S_AIF)
from tools.proofs.bl_app_test import (BMWEB, BOOT, BOOT_LEN, SECT8K, SECT8K_LEN, read_area,
                                        read_outer, rewrite)
from tools import ROOT

# the app's composers, then its boot CRC word over the four areas as the
# sessions do it (bl.toInstaller / restore): argv = app root, which,
# boot, s8k, low, mid
IMAGES_JS = r"""
const fs = require('fs');
global.fastFlasher = { BODY_START: 0xfd26c, BODY_END: 0xfff40 };
const { bl } = require(process.argv[1] + '/app/renderer/core/flash/bl.js');
const boot = new Uint8Array(fs.readFileSync(process.argv[3]));
const s8 = new Uint8Array(fs.readFileSync(process.argv[4]));
const low = new Uint8Array(fs.readFileSync(process.argv[5]));
const mid = new Uint8Array(fs.readFileSync(process.argv[6]));
const survey = bl.survey(boot, s8);
if (process.argv[2] === 'installer') {
  const nb = bl.installerImage(boot, s8);
  fs.writeFileSync(process.argv[3] + '.out', bl.withBootCrc(low, s8, mid, nb || boot));
  fs.writeFileSync(process.argv[4] + '.out', s8);
  console.log(JSON.stringify({ survey, boot: !!nb, sect8k: false }));
} else {
  const r = bl.restoreImages(boot, s8);
  fs.writeFileSync(process.argv[3] + '.out', bl.withBootCrc(low, r.sect8k, mid, r.boot));
  fs.writeFileSync(process.argv[4] + '.out', r.sect8k);
  console.log(JSON.stringify({ survey, boot: r.bootChanged, sect8k: r.sect8kChanged }));
}
"""


def app_images(which, boot, s8, low, mid, tmp):
    bp, sp, lp, mp = (os.path.join(tmp, n) for n in ("rboot.bin", "rs8k.bin", "rlow.bin", "rmid.bin"))
    for path, data in ((bp, boot), (sp, s8), (lp, low), (mp, mid)):
        open(path, "wb").write(data)
    out = subprocess.run(["node", "-e", IMAGES_JS, BMWEB, which, bp, sp, lp, mp], check=True,
                         capture_output=True, text=True).stdout
    return open(bp + ".out", "rb").read(), open(sp + ".out", "rb").read(), json.loads(out)


def read_region(s, board):
    """Both sectors over the wire, with the emulator's stubbed loader words
    put back (on hardware the READ is the chip; see bl_app_test)."""
    s8 = bytearray(read_area(s, SECT8K, SECT8K_LEN))
    boot = bytearray(read_area(s, BOOT, BOOT_LEN))
    for at, orig in board.cpu.patched.items():
        off = at - 0xFFF00000
        if BOOT <= off < BOOT + BOOT_LEN:
            struct.pack_into(">I", boot, off - BOOT, orig)
        if SECT8K <= off < SECT8K + SECT8K_LEN:
            struct.pack_into(">I", s8, off - SECT8K, orig)
    chip = board.flash.image
    if bytes(boot) != bytes(chip[BOOT:BOOT + BOOT_LEN]) or bytes(s8) != bytes(chip[SECT8K:SECT8K + SECT8K_LEN]):
        raise SystemExit("FAIL: the wire READs disagree with the chip")
    return bytes(boot), bytes(s8)


def ladder(s, writes):
    if marker(s) != 0xFFFF:
        raise SystemExit("FAIL: marker not fresh")
    expect(s.xfer(S_AIF, bytes([AIF_ARM])), S_AIF, "AIF ARM")
    if marker(s) != MARK_ARMED:
        raise SystemExit("FAIL: marker not armed")
    for base, data, note in writes:
        rewrite(s, base, data, note)
    expect(s.xfer(S_AIF, bytes([AIF_DONE])), S_AIF, "AIF DONE")


def main():
    t0 = time.time()
    tmp = os.environ.get("TMPDIR", "/tmp")
    pair = load_named(os.environ.get("BL_BASE", "session1.livetune7"))
    stock_f, mpc0 = bytes(pair.flash), bytes(pair.mpc)
    bl_f, _ = bl.build(stock_f, mpc0)

    # ---- session 1, on BL ----------------------------------------------
    board, s = taken(bl_f, mpc0, "BL", deep=True)
    hello_wait(s, "BL", bl.stamp_bytes(flags=bl.RING_FLAGS))
    fr = s.xfer(0x02, struct.pack(">I", SECT8K))
    if fr[3] != 0x7F:
        raise SystemExit(f"FAIL: BL took an ERASE of the 8 KB sector ({fr.hex()})")
    print(f"  ok: BL refuses the 8 KB sector (7f {fr[4]:02x} {fr[5]:02x}): the installer ring is needed")
    boot, s8 = read_region(s, board)
    low, mid = read_outer(s, board)
    nb, ns, ch = app_images("installer", boot, s8, low, mid, tmp)
    print(f"  ok: bl.survey says {ch['survey']}")
    want = bytes(bl.build(stock_f, mpc0, installer=True)[0])
    if not ch["boot"] or ns != s8 or nb != want[BOOT:BOOT + BOOT_LEN]:
        raise SystemExit("FAIL: bl.installerImage differs from bl.build(installer=True)")
    print("  ok: bl.installerImage (the app's JS) == bl.build(installer=True)")
    ladder(s, [(BOOT, nb, "the 96 KB boot sector (installer ring)")])
    st = s.read(bl.STAMP_AT, 16)
    if st != bl.stamp_bytes(flags=bl.RING_FLAGS | 4):
        raise SystemExit(f"FAIL: stamp after the swap {st.hex()}")
    print(f"  ok: stamp {st[:6].decode()} v{st[6]} flags {st[7]:#04x} read back")
    if bytes(board.flash.image[SECT8K:SECT8K + SECT8K_LEN]) != s8:
        raise SystemExit("FAIL: session 1 touched the 8 KB sector")
    expect(s.xfer(0x06), 0x06, "RESET")

    # ---- session 2, on the installer ring --------------------------------
    b2 = board.reset()
    reached, why = b2.boot(max_insns=3_000_000, until=RESET_ENTRY, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: line free, the installer-ring DME did not reach its program ({why})")
    print("boot [installer ring, line free]: the program starts")
    b2, s2 = taken_from_reset(b2, "installer ring")
    hello_wait(s2, "the installer ring", bl.stamp_bytes(flags=bl.RING_FLAGS | 4))
    boot, s8 = read_region(s2, b2)
    low, mid = read_outer(s2, b2)
    nb, ns, ch = app_images("restore", boot, s8, low, mid, tmp)
    print(f"  ok: bl.survey says {ch['survey']}; rewrites {ch}")
    if not (ch["boot"] and ch["sect8k"]):
        raise SystemExit("FAIL: restoreImages would not rewrite both sectors")
    if nb != stock_f[BOOT:BOOT + BOOT_LEN] or ns != stock_f[SECT8K:SECT8K + SECT8K_LEN]:
        raise SystemExit("FAIL: bl.restoreImages differs from the stock boot region")
    print("  ok: bl.restoreImages (the app's JS) == the stock boot region")
    ladder(s2, [(SECT8K, ns, "the 8 KB sector (stock words, first)"),
                (BOOT, nb, "the 96 KB boot sector (ring blanked)")])
    st = s2.read(bl.STAMP_AT, 16)
    if st != b"\xff" * 16:
        raise SystemExit(f"FAIL: stamp after the restore {st.hex()}")
    print("  ok: the stamp reads blank")
    img = bytes(b2.flash.image)
    mark = range(flasher_body.MARK_AT, flasher_body.MARK_AT + 2 * flasher_body.MARK_SLOTS)
    stray = [i for i in range(len(img)) if img[i] != stock_f[i] and i not in mark]
    if stray:
        raise SystemExit(f"FAIL: ext {stray[0]:#x} differs from stock ({len(stray)} bytes)")
    if bytes(b2.cmf.image) != mpc0:
        raise SystemExit("FAIL: the MPC changed")
    print("  ok: the flash == the stock image but for the two spent marker slots; MPC untouched")
    expect(s2.xfer(0x06), 0x06, "RESET")

    # ---- the stock loader again ------------------------------------------
    b3 = b2.reset()
    reached, why = b3.boot(max_insns=3_000_000, until=RESET_ENTRY, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: line free, the restored DME did not reach its program ({why})")
    print("boot [restored, line free]: the program starts")
    b4 = fresh(img, mpc0, "restored-held")
    b4.sci.line_hold = True
    reached, _ = b4.boot(max_insns=3_000_000, until=SRAM_BASE, reset_vector=True)
    if reached:
        raise SystemExit("FAIL: a held line still reaches a flasher after the restore")
    print("boot [restored, line held]: no flasher")
    parked = bytearray(img)
    parked[0x40000:0x5D000] = b"\xff" * 0x1D000
    b5 = fresh(parked, mpc0, "restored-parked")
    parks = []
    h = b5.m.hook_code(lambda mach, addr, size: parks.append(addr) if addr == 0xFFF05228 else None)
    b5.sci.line_hold = True
    reached, _ = b5.boot(max_insns=3_000_000, until=SRAM_BASE, reset_vector=True)
    b5.m.mu.hook_del(h)
    if reached or not parks:
        raise SystemExit(f"FAIL: parked + held: flasher reached={reached}, park entered={bool(parks)}")
    print("boot [restored, tune blank, line held]: the stock park, no flasher")
    print("=" * 64)
    print(f"ALL OK -- the app's Restore stock bootloader, {time.time() - t0:.0f}s wall")


if __name__ == "__main__":
    main()
