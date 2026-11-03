"""BMWeb's bootloader update (core/flash/bl.js upgrade: the same Install
fast flash bootloader button on a DME that already carries an older BL),
proven on the emulator.

Run from the ms45-emu root:
    .venv/bin/python -m tools.proofs.bl_update_test [--old FLASH.bin]

A DME on an older BL -- the ring BMWeb installed from an earlier build,
say stamp MS45BL v15 flags 3, before the EEPROM read window -- is updated
in ONE session on that ring (a held line always lands in the ring, never in
a body in the program, so there is no installer stage): the park call and
both sectors READ -> the new boot sector computed by the APP'S OWN JS
(bl.splice, the app's put, in node) -> AIF ARM -> the 96 KB sector rewritten with
this build's ring -> AIF DONE -> stamp reads this build's flags (bl.RING_FLAGS) -> RESET. Then
the flash equals bl.build on the stock pair but for the spent marker
slots, the 8 KB sector and the MPC are untouched, a free line boots the
program and a held line lands in the new ring.

The old ring: --old (or BL_OLD_FLASH) names a flash image carrying one,
built by an earlier checkout of tools/build/bl.py on the same stock pair
(the faithful run: the old body serves the session). Without one, this
build's ring with its stamp flags set to 3 stands in: the app sees an older
ring either way, the wire is this body's.
"""
import json
import os
import struct
import subprocess
import sys
import time

from tools.build import bl
from tools.build import flasher_body
from ms45emu.image import load_named
from ms45emu.board import RESET_ENTRY
from tools.proofs.flasher_session_test import expect
from tools.proofs.bl_test import hello_wait, taken, taken_from_reset
from tools.proofs.bl_app_test import BMWEB, BOOT, BOOT_LEN, SECT8K, SECT8K_LEN, read_outer
from tools.proofs.bl_restore_test import read_region, ladder

GUARD_AT = 0x3828                        # the loader's park call the ring is built against

# the app's composer, then its boot CRC word over the four areas as the
# session does it (bl.put): argv = app root, boot, s8k, low, mid
IMAGES_JS = r"""
const fs = require('fs');
global.fastFlasher = { BODY_START: 0xfd26c, BODY_END: 0xfff40 };
const { bl } = require(process.argv[1] + '/app/renderer/core/flash/bl.js');
const boot = new Uint8Array(fs.readFileSync(process.argv[2]));
const s8 = new Uint8Array(fs.readFileSync(process.argv[3]));
const low = new Uint8Array(fs.readFileSync(process.argv[4]));
const mid = new Uint8Array(fs.readFileSync(process.argv[5]));
const guard = new Uint8Array(fs.readFileSync(process.argv[6]));
const survey = bl.survey(boot, s8);
const r = bl.splice(boot, s8, guard, process.argv[7] === 'force');
fs.writeFileSync(process.argv[2] + '.out', bl.withBootCrc(low, r.sect8k, mid, r.boot));
console.log(JSON.stringify({ survey, boot: r.bootChanged, sect8k: r.sect8kChanged,
                             current: bl.isCurrent(survey.stamp), version: bl.BODY_VERSION }));
"""


def app_image(boot, s8, low, mid, tmp, guard=None, force=False):
    """The app's put image for a region (bl.splice in node): the boot
    sector with this build's ring over whatever ring was there, the CRC
    word recomputed. `guard` = the 8 bytes at the park call (read off the
    DME), else taken from `low`. `force` = the app's Repair: the span is
    overwritten whatever it holds. Raises ValueError with the app's
    message when the splice refuses."""
    if guard is None:
        guard = low[GUARD_AT:GUARD_AT + 8]
    bp, sp, lp, mp, gp = (os.path.join(tmp, n) for n in ("uboot.bin", "us8k.bin", "ulow.bin", "umid.bin", "uguard.bin"))
    for path, data in ((bp, boot), (sp, s8), (lp, low), (mp, mid), (gp, guard)):
        open(path, "wb").write(data)
    r = subprocess.run(["node", "-e", IMAGES_JS, BMWEB, bp, sp, lp, mp, gp, "force" if force else ""],
                       capture_output=True, text=True)
    if r.returncode:
        msg = [l for l in r.stderr.splitlines() if l.startswith("Error:")]
        raise ValueError(msg[0] if msg else r.stderr.strip()[-300:])
    return open(bp + ".out", "rb").read(), json.loads(r.stdout)


def old_ring_flash(stock_f, mpc0):
    """(flash carrying an older ring, how it was got)."""
    path = os.environ.get("BL_OLD_FLASH")
    if "--old" in sys.argv:
        path = sys.argv[sys.argv.index("--old") + 1]
    if path:
        f = open(path, "rb").read()
        if len(f) != len(stock_f) or f[0x20000:] != stock_f[0x20000:]:
            raise SystemExit(f"FAIL: {path} is not an older BL on the {os.environ.get('BL_BASE', 'session1.livetune6-notraps')} pair")
        if f[bl.STAMP_AT:bl.STAMP_AT + 6] != b"MS45BL":
            raise SystemExit(f"FAIL: {path} carries no ring stamp")
        return bytearray(f), f"the image {path}"
    f = bytearray(bl.build(stock_f, mpc0)[0])
    f[bl.STAMP_AT + 7] = 3
    return f, "this build's ring with its stamp flags set to 3"


def main():
    t0 = time.time()
    tmp = os.environ.get("TMPDIR", "/tmp")
    pair = load_named(os.environ.get("BL_BASE", "session1.livetune6-notraps"))
    stock_f, mpc0 = bytes(pair.flash), bytes(pair.mpc)
    old_f, how = old_ring_flash(stock_f, mpc0)
    old_stamp = bytes(old_f[bl.STAMP_AT:bl.STAMP_AT + 16])
    new_f = bytes(bl.build(stock_f, mpc0)[0])
    new_stamp = new_f[bl.STAMP_AT:bl.STAMP_AT + 16]   # the ring's own stamp (flags incl. the read window)
    if old_f == new_f:
        raise SystemExit("FAIL: the old ring is this build's: nothing to update")
    print(f"the old ring: {how}; stamp {old_stamp[:6].decode()} v{old_stamp[6]} flags {old_stamp[7]:#04x}"
          f" -> this build v{new_stamp[6]} flags {new_stamp[7]:#04x}")

    # ---- the one session, on the old ring ---------------------------------
    board, s = taken(bytes(old_f), mpc0, "old BL", deep=True)
    hello_wait(s, "the old ring", old_stamp)
    guard = s.read(GUARD_AT, 8)
    if guard != stock_f[GUARD_AT:GUARD_AT + 8]:
        raise SystemExit(f"FAIL: the park call READ {guard.hex()}")
    boot, s8 = read_region(s, board)
    low, mid = read_outer(s, board)
    nb, ch = app_image(boot, s8, low, mid, tmp)
    print(f"  ok: bl.survey says {ch['survey']}; current {ch['current']}; this build v{ch['version']}")
    if ch["current"] or ch["survey"]["ring"] != "older" or not ch["boot"] or ch["sect8k"]:
        raise SystemExit("FAIL: the app does not see an older ring to put right (boot sector only)")
    if nb != new_f[BOOT:BOOT + BOOT_LEN]:
        raise SystemExit("FAIL: bl.splice (the app's put) differs from bl.build's boot sector")
    print("  ok: bl.splice (the app's put, in node) == bl.build's boot sector")
    ladder(s, [(BOOT, nb, "the 96 KB boot sector (the new ring)")])
    st = s.read(bl.STAMP_AT, 16)
    if st != new_stamp:
        raise SystemExit(f"FAIL: stamp after the update {st.hex()}")
    print(f"  ok: stamp {st[:6].decode()} v{st[6]} flags {st[7]:#04x} read back")
    if bytes(board.flash.image[SECT8K:SECT8K + SECT8K_LEN]) != s8:
        raise SystemExit("FAIL: the session touched the 8 KB sector")
    expect(s.xfer(0x06), 0x06, "RESET")

    # ---- the new ring ----------------------------------------------------------
    b2 = board.reset()
    reached, why = b2.boot(max_insns=3_000_000, until=RESET_ENTRY, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: line free, the updated DME did not reach its program ({why})")
    print("boot [updated, line free]: the program starts")
    b2, s2 = taken_from_reset(b2, "the new ring")
    hello_wait(s2, "the new ring", new_stamp)
    img = bytes(b2.flash.image)
    mark = range(flasher_body.MARK_AT, flasher_body.MARK_AT + 2 * flasher_body.MARK_SLOTS)
    stray = [i for i in range(len(img)) if img[i] != new_f[i] and i not in mark]
    if stray:
        raise SystemExit(f"FAIL: ext {stray[0]:#x} differs from bl.build ({len(stray)} bytes)")
    if bytes(b2.cmf.image) != mpc0:
        raise SystemExit("FAIL: the MPC changed")
    print("  ok: the flash == bl.build on the stock pair but for the spent marker slot; MPC untouched")
    expect(s2.xfer(0x06), 0x06, "RESET")
    print("=" * 64)
    print(f"ALL OK -- the app's bootloader update, {time.time() - t0:.0f}s wall")


if __name__ == "__main__":
    main()
