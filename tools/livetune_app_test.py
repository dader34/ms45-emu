"""BMWeb's Install live tune (core/flash/livetune-patch.js), proven against
the Python build.

Run from the ms45-emu root: .venv/bin/python tools/livetune_app_test.py

For each starting pair the app's own JS splice runs in node, then the app's
own program-flash step (ms45Checksums.correctProgramChecksums +
signProgram, as fbFlashRun does), and the result must be byte-identical to
tools/livetune_build.py's layers built on the same tune:

  - the stock program (session1clean);
  - the same program under a different tune (the golden copy follows it);
  - live tune 6 and live tune 6 without traps, as flashed (an upgrade in
    place: the old build's bytes go, 7's come);
  - the stock program with the protections (session1cleanprot): the two
    compose, so the app may splice live tune over its own protection edit.

Then the refusals (nothing returned): another program's bytes in the
footprint, a tune with data past 0x18000. And the stock result boots on the
emulator to the program with live tune's state block seeded.
"""
import json
import os
import struct
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import livetune_js                                              # noqa: E402
from ms45emu.board import Board, RESET_ENTRY                    # noqa: E402
from ms45emu.image import Pair, load_named                      # noqa: E402

BMWEB = os.path.normpath(os.path.join(ROOT, "..", "inpa-mac-bridge"))
SPLICE_JS = r"""
const fs = require('fs');
// the browser build shares these as globals (as tools/verify/test_ms45_flash.js sets them)
global.Settings = { get: () => 'no' };
const F = require(process.argv[1] + '/app/renderer/core/flash/flasher.js');
global._md5 = F._md5;
global._modPow = F._modPow;
global._bytesLEToBigInt = (b) => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };
global._bigIntToBytesLE = (value, n) => { const o = new Uint8Array(n); let v = value; for (let i = 0; i < n; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
const { liveTunePatch } = require(process.argv[1] + '/app/renderer/core/flash/livetune-patch.js');
const CK = require(process.argv[1] + '/app/renderer/core/ms45/ms45.js').ms45Checksums;
const f = new Uint8Array(fs.readFileSync(process.argv[2]));
const m = new Uint8Array(fs.readFileSync(process.argv[3]));
const survey = liveTunePatch.survey(f, m);
try {
  const r = liveTunePatch.splice(f, m);
  const signed = CK.signProgram(CK.correctProgramChecksums(r.flash, r.mpc), r.mpc);
  fs.writeFileSync(process.argv[2] + '.out', signed);
  fs.writeFileSync(process.argv[3] + '.out', r.mpc);
  console.log(JSON.stringify({ survey, from: r.from }));
} catch (e) {
  console.log(JSON.stringify({ survey, refused: e.message }));
}
"""


def app(flash, mpc, tmp, tag):
    fp, mp = os.path.join(tmp, f"lt-{tag}.flash"), os.path.join(tmp, f"lt-{tag}.mpc")
    open(fp, "wb").write(flash)
    open(mp, "wb").write(mpc)
    p = subprocess.run(["node", "-e", SPLICE_JS, BMWEB, fp, mp], capture_output=True, text=True)
    if p.returncode:
        raise SystemExit(f"FAIL [{tag}]: node: {p.stderr.strip()[-800:]}")
    r = json.loads(p.stdout)
    if "refused" in r:
        return r, None, None
    return r, open(fp + ".out", "rb").read(), open(mp + ".out", "rb").read()


SIGN_CAL_JS = r"""
const fs = require('fs');
global.Settings = { get: () => 'no' };
const F = require(process.argv[1] + '/app/renderer/core/flash/flasher.js');
global._md5 = F._md5;
global._modPow = F._modPow;
global._bytesLEToBigInt = (b) => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };
global._bigIntToBytesLE = (value, n) => { const o = new Uint8Array(n); let v = value; for (let i = 0; i < n; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
const CK = require(process.argv[1] + '/app/renderer/core/ms45/ms45.js').ms45Checksums;
const f = new Uint8Array(fs.readFileSync(process.argv[2]));
f.set(CK.signParameters(CK.correctParameterChecksums(f.slice(0x40000, 0x5d000))), 0x40000);
fs.writeFileSync(process.argv[2], f);
"""


def signed_tune(pair, tmp):
    """The pair's calibration as the app flashes it (CRC and signature redone)."""
    fp = os.path.join(tmp, "lt-signcal.flash")
    open(fp, "wb").write(pair.flash)
    subprocess.run(["node", "-e", SIGN_CAL_JS, BMWEB, fp], check=True, capture_output=True)
    return Pair(open(fp, "rb").read(), pair.mpc, pair.name)


def first_diff(a, b):
    return next((i for i in range(len(a)) if a[i] != b[i]), None)


def same(tag, r, f, m, want):
    if f is None:
        raise SystemExit(f"FAIL [{tag}]: refused: {r['refused']}")
    df, dm = first_diff(f, want.flash), first_diff(m, want.mpc)
    if df is not None or dm is not None:
        raise SystemExit(f"FAIL [{tag}]: differs from the Python build "
                         f"(ext {df if df is None else hex(df)}, mpc {dm if dm is None else hex(dm)})")
    print(f"  ok [{tag}]: survey {r['survey']} -> the app's splice == livetune_build on the same tune")


def with_cal(program_flash, cal_from):
    f = bytearray(program_flash)
    f[0x40000:0x60000] = cal_from[0x40000:0x60000]
    return bytes(f)


def main():
    t0 = time.time()
    tmp = os.environ.get("TMPDIR", "/tmp")
    base = load_named("session1clean")

    r, f, m = app(base.flash, base.mpc, tmp, "stock")
    same("stock program", r, f, m, livetune_js.build_on(base))
    stock_out = (f, m)

    other = signed_tune(livetune_js.perturbed(base), tmp)
    r, f, m = app(other.flash, other.mpc, tmp, "tune")
    same("another tune", r, f, m, livetune_js.build_on(other))

    for name, img in livetune_js.OLDER.items():
        of, om = livetune_js.load_pair(img)
        r, f, m = app(of, om, tmp, name)
        want = livetune_js.build_on(Pair(with_cal(base.flash, of), base.mpc, name + "-tune"))
        if r.get("from") != name:
            raise SystemExit(f"FAIL [{name}]: surveyed as {r}")
        same(f"upgrade from {name}", r, f, m, want)

    prot = load_named("session1cleanprot")
    r, f, m = app(prot.flash, prot.mpc, tmp, "prot")
    same("stock + protections", r, f, m, livetune_js.build_on(prot))

    # ---- refusals ----------------------------------------------------------
    ext0 = int(open(livetune_js.OUT).read().split("ext: [", 1)[1].split("[0x", 1)[1].split(",", 1)[0], 16)
    badf = bytearray(base.flash)
    badf[ext0] ^= 0x01
    r, f, _ = app(bytes(badf), base.mpc, tmp, "foreign")
    if f is not None or r["survey"] is not None:
        raise SystemExit(f"FAIL: a foreign byte in the footprint was not refused ({r})")
    print(f"  ok: a foreign byte at ext {ext0:#x} is refused: {r['refused'][:60]}...")
    long_cal = bytearray(base.flash)
    long_cal[0x40000 + 0x18010] = 0x00
    struct.pack_into(">I", long_cal, 0x40100, 0)          # the app redoes the CRC anyway
    r, f, _ = app(bytes(long_cal), base.mpc, tmp, "longcal")
    if f is not None or "past" not in r["refused"]:
        raise SystemExit(f"FAIL: a tune with data past 0x18000 was not refused ({r})")
    print("  ok: a tune with data past 0x18000 is refused")

    # ---- the stock result boots ------------------------------------------
    b = Board(Pair(stock_out[0], stock_out[1], "lt-app", check_program=False))
    reached, why = b.boot(max_insns=3_000_000, until=RESET_ENTRY, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: the spliced pair does not reach its program ({why})")
    print("  ok: the spliced pair boots through the loader to its program")
    print("=" * 64)
    print(f"ALL OK -- the app's Install live tune splice, {time.time() - t0:.0f}s wall")


if __name__ == "__main__":
    main()
