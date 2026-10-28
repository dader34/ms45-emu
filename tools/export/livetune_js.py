"""Live tune for BMWeb: the patch as a generated JS blob, so the app can put
live tune on a DME from the pair it has loaded (Custom Options, Install live
tune) instead of a pair built here.

Run from the ms45-emu root: .venv/bin/python -m tools.export.livetune_js

Writes inpa-mac-bridge/app/renderer/core/generated/livetune-blob.js
(liveTuneBlob). Everything live tune adds is independent of the tune it
carries (tools/livetune_build.py's four layers on the stock program, checked
here by building on two different calibrations) except the fold's golden
copy, which the app takes from the loaded pair's own calibration. So the
blob holds:

  footprint  every byte any live tune build on the stock program touches
             (live tune 6, 6 without traps, 7), as runs over the external
             flash and the MPC, with live tune 7's bytes there -- stock
             where 7 leaves a byte alone, so laying them down also takes an
             older build out;
  known      the CRC-32 of a pair's bytes over the footprint for the stock
             program and each build: the app splices only into a pair that
             is one of these, which also refuses another program, or an
             edit of the app's own (a protection) that overlaps it;
  the fold's constants (golden copy, calibration checks).

The sums and the signature are not part of it: the app redoes the program
CRCs and the signature on every program flash, and the splice redoes the
safety monitor's ROM-test sum, which live tune's hooks fall inside.
"""
import datetime
import os
import subprocess
import struct
import sys
import zlib
from tools import ROOT

from tools.build import livetune_build as lb
from ms45emu import fold, overlay, singles, transport
from ms45emu.checksums import crc32_mpeg2
from ms45emu.image import IMAGES_DIR, Pair, load_named

OUT = os.path.normpath(os.path.join(
    ROOT, "..", "inpa-mac-bridge", "app", "renderer", "core", "generated", "livetune-blob.js"))
BASE = "session1clean"                     # the stock program under session1's tune
OLDER = {"livetune6": "session1.livetune6", "livetune6-notraps": "session1.livetune6-notraps"}
VERSION, NAME = 7, "livetune7"
GAP = 16                                   # runs closer than this are merged (the gap is
                                           # equal in every build, so it costs nothing)
LINE = 64


def outside(i):
    """External-flash offsets that are not the patch's: boot region, the
    calibration, the golden copy, the sums and signature, the trailer."""
    return (i < 0x60000 or fold.GOLD_FILE <= i < fold.GOLD_FILE + fold.LENGTH
            or 0x60000 <= i < 0x60004 or 0x60340 <= i < 0x60344
            or 0x60074 <= i < 0x600B4 or 0x60600 <= i < 0x60608 or i >= 0xFFF40)


def build_on(pair):
    _offsets, rates = lb.preferred_rates(pair, lb.prefer_path(pair))
    return singles.build(fold.build(transport.build(overlay.build(pair))), rates=rates)


def load_pair(name):
    return (open(os.path.join(IMAGES_DIR, name + ".flash.bin"), "rb").read(),
            open(os.path.join(IMAGES_DIR, name + ".mpc.bin"), "rb").read())


def diff(a, b, skip=lambda i: False):
    return {i for i in range(len(a)) if a[i] != b[i] and not skip(i)}


def runs(offsets):
    out = []
    for i in sorted(offsets):
        if out and i - (out[-1][0] + out[-1][1]) < GAP:
            out[-1][1] = i - out[-1][0] + 1
        else:
            out.append([i, 1])
    return [tuple(r) for r in out]


def take(img, rs):
    return b"".join(img[a:a + n] for a, n in rs)


def perturbed(base):
    """The same stock program under a different (valid) tune."""
    f = bytearray(base.flash)
    for k in range(0x41000, 0x57000, 97):
        if not (0x457D0 <= k < 0x457F0):                     # the monitor sum stays right
            f[k] ^= 0x5A
    struct.pack_into(">I", f, 0x40100, crc32_mpeg2(bytes(f[0x40200:0x5D000])))
    return Pair(bytes(f), base.mpc, base.name + "+othertune")


def main():
    base = load_named(BASE)
    lt = build_on(base)
    other = build_on(perturbed(base))
    ext7, mpc7 = diff(lt.flash, base.flash, outside), diff(lt.mpc, base.mpc)
    p2 = perturbed(base)
    if (ext7, mpc7) != (diff(other.flash, p2.flash, outside), diff(other.mpc, p2.mpc)) \
            or any(lt.flash[i] != other.flash[i] for i in ext7) \
            or any(lt.mpc[i] != other.mpc[i] for i in mpc7):
        raise SystemExit("live tune 7 depends on the tune beyond the golden copy: not a patch")
    shipped = load_pair("session1.livetune7")
    if any(shipped[0][i] != lt.flash[i] for i in ext7) or any(shipped[1][i] != lt.mpc[i] for i in mpc7):
        print("NOTE: images/session1.livetune7 differs from today's build over its footprint")

    gens = {"stock": (base.flash, base.mpc)}
    ext, mpc = set(ext7), set(mpc7)
    for name, img in OLDER.items():
        f, m = load_pair(img)
        gens[name] = (f, m)
        ext |= diff(f, base.flash, outside)
        mpc |= diff(m, base.mpc)
    gens[NAME] = (lt.flash, lt.mpc)
    ext_runs, mpc_runs = runs(ext), runs(mpc)
    if any(outside(i) for a, n in ext_runs for i in range(a, a + n)):
        raise SystemExit("a merged run reaches outside the program")
    known = {name: zlib.crc32(take(f, ext_runs) + take(m, mpc_runs)) for name, (f, m) in gens.items()}
    if len(set(known.values())) != len(known):
        raise SystemExit("two builds look the same over the footprint")

    now = datetime.date.today().isoformat()
    lines = [
        "// GENERATED by ms45-emu tools/livetune_js.py -- do not edit by hand.",
        "// Live tune 7 for the stock 0044570 program, as a patch over a loaded",
        "// pair (ms45-emu docs/livetune-design.md). BENCH ONLY.",
        f"// Built {now}. Re-run the tool when live tune changes.",
        "/* exported liveTuneBlob */",
        "",
        "const liveTuneBlob = {",
        f"  version: {VERSION},",
        f"  name: '{NAME}',",
        "  // the CRC-32 (zlib) of a pair's footprint bytes, ext then MPC, for the",
        "  // stock program and every live tune build the patch replaces",
        "  known: {",
        *[f"    {k if k.isidentifier() else repr(k)}: 0x{v:08x}," for k, v in known.items()],
        "  },",
        "  // the fold: the golden copy of the calibration, and what a save keeps",
        f"  goldAt: 0x{fold.GOLD_FILE:05x},",
        f"  goldLength: 0x{fold.LENGTH:05x},",
        f"  monitor: {{ from: 0x{fold.MON_FROM:x}, to: 0x{fold.MON_TO:x}, at: 0x{fold.MON_AT:x}, "
        f"table: 0x{fold.MON_TABLE[0]:05x} }},",
        "  // the footprint: [offset, live tune 7's bytes]",
    ]
    for key, rs, img in (("ext", ext_runs, lt.flash), ("mpc", mpc_runs, lt.mpc)):
        lines.append(f"  {key}: [")
        for a, n in rs:
            hx = img[a:a + n].hex()
            line = f"    [0x{a:05x}, '{hx}'],"
            if len(line) <= 80:
                lines.append(line)
            else:
                lines += ["    [", f"      0x{a:05x},",
                          *[f"      '{hx[i:i + LINE]}'" + (" +" if i + LINE < len(hx) else ",")
                            for i in range(0, len(hx), LINE)], "    ],"]
        lines.append("  ],")
    lines += [
        "};",
        "",
        "if (typeof window !== 'undefined') window.liveTuneBlob = liveTuneBlob;",
        "if (typeof module !== 'undefined' && module.exports)",
        "  module.exports = { liveTuneBlob };",
        "",
    ]
    with open(OUT, "w") as fh:
        fh.write("\n".join(lines))
    # in the app repo's own format (its deploy checks it): the long runs'
    # continuation lines are prettier's to lay out
    subprocess.run(["npx", "prettier", "--write", OUT], check=True, capture_output=True,
                   cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(OUT)))))
    print(f"wrote {OUT}: ext {sum(n for _, n in ext_runs)} B in {len(ext_runs)} runs, "
          f"mpc {sum(n for _, n in mpc_runs)} B in {len(mpc_runs)} runs; known "
          + ", ".join(f"{k} {v:08x}" for k, v in known.items()))


if __name__ == "__main__":
    main()
