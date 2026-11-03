"""The boot overwrite (tools/build/bootwrite.py): the DME's boot region
written from a file, byte for byte, over the wire -- proven on the emulator,
with BL on loader build C along the way.

Run from the ms45-emu root: .venv/bin/python -m tools.proofs.bootwrite_test
Env: BL_BASE (the pair, default session1.livetune7), BOOTWRITE_FILE (a
read carrying the loader to put on, default images/loaderC.flash.bin: the
2002 325i M56 read, loader build C).

Two sessions each time, as the app runs them: on the ring that is there,
the 96 KB sector takes the SWAP ring (write window from ext 0x0); after a
reset with the line held, on the swap ring, the four sectors are written
from the file -- 16 KB (the reset vector's), 8 KB, 8 KB, 96 KB -- each
erase, blank-check, chunks, verify; DONE; RESET.

1. The raw file: BL on the base -> the file's boot region exactly. The
   chip's first 128 KB equal the file's, the rest is untouched, the line
   free boots the program through the file's loader, a held line reaches
   no flasher (the file carries none), a parked loader stays stock.
2. A boot file carrying BL on that loader: BL on the base -> it. The
   ring answers on loader C; a parked loader with the line held lands in
   it.
3. The way back from there: a boot file of BL on the base -> written
   over loader C's. The chip equals the base + BL but for the marker
   slots; the ring answers.
"""
import os
import struct
import time

from tools.build import bl, bootwrite, flasher_body
from ms45emu.image import load_named, IMAGES_DIR
from ms45emu.board import RESET_ENTRY
from tools.build.flasher_body import SRAM_BASE, MARK_ARMED, AIF_ARM, AIF_DONE
from tools.proofs.flasher_session_test import expect
from tools.proofs.bl_test import fresh, hello_wait, marker, taken, taken_from_reset, S_AIF
from tools.proofs.bl_app_test import rewrite

BOOT, BOOT_LEN = 0x8000, 0x18000
REGION = bootwrite.REGION_END
MARK = range(flasher_body.MARK_AT, flasher_body.MARK_AT + 2 * flasher_body.MARK_SLOTS)

# the app's own JS (core/flash/bl.js, node) against the Python builder: the
# sectors it would write from a file, and the swap ring its blob carries
BMWEB = os.path.normpath(os.path.join(IMAGES_DIR, "..", "..", "inpa-mac-bridge"))
PARITY_JS = r"""
const fs = require('fs');
global.fastFlasher = { BODY_START: 0xfd26c, BODY_END: 0xfff40 };
const { bl } = require(process.argv[1] + '/app/renderer/core/flash/bl.js');
const r = bl.bootRegionOf(new Uint8Array(fs.readFileSync(process.argv[2])));
fs.writeFileSync(process.argv[2] + '.out', Buffer.concat([r.low, r.sect8k, r.mid, r.boot].map((b) => Buffer.from(b))));
const blob = require(process.argv[1] + '/app/renderer/core/generated/bl-blob.js').blBlob;
const ring = Buffer.from(blob.swapRing.hex.join(''), 'hex');
fs.writeFileSync(process.argv[2] + '.ring', ring);
console.log(JSON.stringify({ at: blob.ring.at, site: r.site, crcOk: r.crcOk, ring: r.ring }));
"""


def js_parity(raw, swap_region):
    import json
    import subprocess
    tmp = os.path.join(os.environ.get("TMPDIR", "/tmp"), "bootwrite_parity.bin")
    open(tmp, "wb").write(raw)
    out = json.loads(subprocess.run(["node", "-e", PARITY_JS, BMWEB, tmp], check=True,
                                    capture_output=True, text=True).stdout)
    if open(tmp + ".out", "rb").read() != raw:
        raise SystemExit("FAIL: bl.bootRegionOf (the app's JS) differs from bootwrite.region")
    ring = open(tmp + ".ring", "rb").read()
    if swap_region[out["at"]:out["at"] + len(ring)] != ring:
        raise SystemExit("FAIL: the blob's swapRing differs from bl.build(swap=True)")
    if out["site"] != bl.park_call_site(raw) or out["ring"]:
        raise SystemExit(f"FAIL: bl.bootRegionOf facts {out}")
    print(f"  ok: the app's JS agrees: bootRegionOf == the file, swapRing == bl.build(swap=True), "
          f"park call at {out['site']:#x}, CRC {'ok' if out['crcOk'] else 'BAD'}")


def stray(a, b, lo=0, hi=None):
    hi = len(a) if hi is None else hi
    return [i for i in range(lo, hi) if a[i] != b[i] and i not in MARK]


def boots_free(f, m, note):
    b = fresh(f, m, note)
    reached, why = b.boot(max_insns=3_000_000, until=RESET_ENTRY, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL [{note}]: line free, the program was not reached ({why})")
    print(f"boot [{note}, line free]: the program starts")
    return b


def held(f, m, note, want_ring):
    b = fresh(f, m, note)
    b.sci.line_hold = True
    reached, _ = b.boot(max_insns=3_000_000, until=SRAM_BASE, reset_vector=True)
    if reached != want_ring:
        raise SystemExit(f"FAIL [{note}]: line held, flasher reached={reached}")
    print(f"boot [{note}, line held]: {'the ring' if reached else 'no flasher'}")


def parked(f, m, note, want_ring):
    p = bytearray(f)
    p[0x40000:0x5D000] = b"\xff" * 0x1D000
    b = fresh(p, m, note)
    parks = []
    h = b.m.hook_code(lambda mach, addr, size: parks.append(addr) if addr == 0xFFF05228 else None)
    b.sci.line_hold = True
    reached, _ = b.boot(max_insns=3_000_000, until=SRAM_BASE, reset_vector=True)
    b.m.mu.hook_del(h)
    if reached != want_ring or not parks:
        raise SystemExit(f"FAIL [{note}]: parked + held: ring={reached}, park entered={bool(parks)}")
    print(f"boot [{note}, tune blank, line held]: the park{' window -> the ring' if reached else ', no flasher'}")


def ladder(s, writes):
    if marker(s) != 0xFFFF:
        raise SystemExit("FAIL: marker not fresh")
    expect(s.xfer(S_AIF, bytes([AIF_ARM])), S_AIF, "AIF ARM")
    if marker(s) != MARK_ARMED:
        raise SystemExit("FAIL: marker not armed")
    for base, data, note in writes:
        rewrite(s, base, data, note)
    expect(s.xfer(S_AIF, bytes([AIF_DONE])), S_AIF, "AIF DONE")


def overwrite(board, s, note, swap_region, file_region):
    """On the ring: the swap ring in; on the swap ring: the file's four
    sectors. Returns the board after the second session's RESET."""
    hello_wait(s, note, bl.stamp_bytes(flags=bl.ring_flags()))
    ladder(s, [(BOOT, swap_region[BOOT:BOOT + BOOT_LEN], "the 96 KB sector (the swap ring)")])
    st = s.read(bl.STAMP_AT, 16)
    if st != bl.stamp_bytes(flags=bl.ring_flags(swap=True)):
        raise SystemExit(f"FAIL: stamp after the swap ring went in: {st.hex()}")
    print(f"  ok: stamp v{st[6]} flags {st[7]:#04x} (the swap ring) read back")
    expect(s.xfer(0x06), 0x06, "RESET")
    b2, s2 = taken_from_reset(board, "the swap ring")
    hello_wait(s2, "the swap ring", bl.stamp_bytes(flags=bl.ring_flags(swap=True)))
    for line in bootwrite.describe(file_region):
        print(f"  file: {line}")
    ladder(s2, [(lo, data, f"the {len(data) // 1024} KB sector at {lo:#x}")
                for lo, data in bootwrite.sectors(file_region)])
    chip = bytes(b2.flash.image)
    bad = stray(chip, file_region, 0, REGION)
    if bad:
        raise SystemExit(f"FAIL: ext {bad[0]:#x} differs from the file ({len(bad)} bytes)")
    print("  ok: the chip's boot region == the file's")
    expect(s2.xfer(0x06), 0x06, "RESET")
    return b2


def main():
    t0 = time.time()
    base = load_named(os.environ.get("BL_BASE", "session1.livetune7"))
    base_f, mpc0 = bytes(base.flash), bytes(base.mpc)
    src = open(os.environ.get("BOOTWRITE_FILE", os.path.join(IMAGES_DIR, "loaderC.flash.bin")), "rb").read()
    raw = bootwrite.region(src)
    hyb = bytearray(base_f)
    hyb[:REGION] = raw                               # the file's boot region on the base's rest
    bl_c, _ = bl.build(bytes(hyb), mpc0)
    bl_b, _ = bl.build(base_f, mpc0)
    swap_b, _ = bl.build(base_f, mpc0, swap=True)
    swap_c, _ = bl.build(bytes(hyb), mpc0, swap=True)
    bb, cb = bootwrite.loader_id(base_f)[0] or "?", bootwrite.loader_id(raw)[0] or "?"
    print(f"base: loader build {bb}; file: loader build {cb}")
    for reg, name in ((raw, "the raw file"), (bootwrite.region(bl_c), f"BL on loader {cb}"),
                      (bootwrite.region(bl_b), f"BL on loader {bb}")):
        if not bootwrite.crc_ok(reg):
            raise SystemExit(f"FAIL: {name}: the boot CRC word does not match its content")
    print("  ok: every boot file's CRC word matches its content")
    js_parity(raw, bootwrite.region(swap_b))

    # 1. the raw file
    b, s = taken(bl_b, mpc0, f"BL on loader {bb}", deep=True)
    b2 = overwrite(b, s, f"BL on loader {bb}", bootwrite.region(swap_b), raw)
    chip = bytes(b2.flash.image)
    if stray(chip, base_f, REGION):
        raise SystemExit("FAIL: the overwrite touched the flash above the boot region")
    if bytes(b2.cmf.image) != mpc0:
        raise SystemExit("FAIL: the MPC changed")
    print("  ok: above the boot region nothing changed; MPC untouched")
    boots_free(chip, mpc0, f"loader {cb}, raw")
    # the board the bench runs on after the DME's RESET (Board.reset) must
    # answer like a board booted from the chip: the emulator's site patches
    # from the old loader must not be put back into the new one
    from ms45emu.kwp import Tester
    def ident_of(b):
        b.boot(max_insns=30_000_000, until=0, reset_vector=True)
        return bytes(Tester(b).ident())
    i_reset, i_fresh = ident_of(b2.reset()), ident_of(fresh(chip, mpc0, "fresh"))
    if i_reset != i_fresh:
        raise SystemExit(f"FAIL: the reset board's identity {i_reset.hex()} != a fresh board's {i_fresh.hex()}")
    print(f"  ok: identity through the reset board == a fresh board's ({len(i_fresh)} bytes)")
    held(chip, mpc0, f"loader {cb}, raw", want_ring=False)
    parked(chip, mpc0, f"loader {cb}, raw", want_ring=False)

    # 2. a boot file carrying BL on loader C
    b, s = taken(bl_b, mpc0, f"BL on loader {bb}", deep=True)
    b2 = overwrite(b, s, f"BL on loader {bb}", bootwrite.region(swap_b), bootwrite.region(bl_c))
    chip = bytes(b2.flash.image)
    boots_free(chip, mpc0, f"BL on loader {cb}")
    held(chip, mpc0, f"BL on loader {cb}", want_ring=True)
    parked(chip, mpc0, f"BL on loader {cb}", want_ring=True)

    # 3. and back
    b3, s3 = taken_from_reset(b2, f"the ring on loader {cb}")
    b4 = overwrite(b3, s3, f"the ring on loader {cb}", bootwrite.region(swap_c), bootwrite.region(bl_b))
    chip = bytes(b4.flash.image)
    if stray(chip, bl_b):
        raise SystemExit("FAIL: the flash is not the base + BL again")
    print(f"  ok: the flash == BL on loader {bb} but for the marker slots")
    boots_free(chip, mpc0, f"BL on loader {bb} again")
    held(chip, mpc0, f"BL on loader {bb} again", want_ring=True)
    print("=" * 64)
    print(f"ALL OK -- the boot overwrite, and BL on loader {cb}, {time.time() - t0:.0f}s wall")


if __name__ == "__main__":
    main()
