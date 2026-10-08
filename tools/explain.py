#!/usr/bin/env python
"""Explain a routine (ms45emu/explain.py): the calibration items it reads by
their XDF names, the RAM variables it touches, what it calls.

    .venv/bin/python tools/explain.py dme1_builder
    .venv/bin/python tools/explain.py 0x53DE8                     # by address, anywhere inside the function
    .venv/bin/python tools/explain.py brake_throttle_plausibility --run 1 --rpm 800 --speed 30
    .venv/bin/python tools/explain.py fn_93B4 --callees             # the routines it calls, each explained too

The function comes from the function map (tools/funcmap.py), the names
from ms45emu/names/<program>.json and the XDF (MS45_XDF, or a *.xdf in
images/ whose name holds the program's short id, LO02S). The static scan
follows the registers that hold a calibration or RAM base; --run then
boots the pair and watches the function's own memory accesses for that
many seconds of DME time, which confirms the scan and catches what it
could not follow (pointers from callers, computed addresses). The run
hooks every RAM and calibration access of the program, so it takes
about a minute and a half of wall time per second of DME time.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu import load_pair                           # noqa: E402
from ms45emu.board import Board                         # noqa: E402
from ms45emu.e46 import Peers                           # noqa: E402
from ms45emu.image import Pair, ENV_NAMES               # noqa: E402
from ms45emu.funcmap import FunctionMap                 # noqa: E402
from ms45emu.explain import explain                     # noqa: E402
from ms45emu.xdf import Xdf                             # noqa: E402
from ms45emu.xref import parse_address                  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("function", nargs="+", help="a function name, or an address inside it")
    ap.add_argument("--pair", default="stock", choices=list(ENV_NAMES))
    ap.add_argument("--flash")
    ap.add_argument("--mpc")
    ap.add_argument("--xdf", default=None, help="the XDF to name calibration items with (default: MS45_XDF or images/*.xdf)")
    ap.add_argument("--callees", action="store_true", help="explain the routines it calls as well")
    ap.add_argument("--run", type=float, default=0, metavar="SECONDS", help="also watch the function run this long on the emulator")
    ap.add_argument("--settle", type=float, default=0.5, metavar="SECONDS")
    ap.add_argument("--rpm", type=float, default=0)
    ap.add_argument("--speed", type=float, default=0, metavar="KMH")
    ap.add_argument("--mips", type=int, default=40)
    args = ap.parse_args()

    if args.flash and args.mpc:
        with open(args.flash, "rb") as f, open(args.mpc, "rb") as m:
            name = os.path.basename(args.flash).rsplit(".", 1)[0].replace("_Flash", "")
            pair = Pair(f.read(), m.read(), name)
    else:
        pair = load_pair(args.pair)
    fm = FunctionMap(pair)
    xdf = Xdf(args.xdf) if args.xdf else Xdf.find(pair)
    if xdf is None:
        print("no XDF: calibration items are listed by offset only (set MS45_XDF or put the file in images/)")

    functions = []
    for text in args.function:
        f = fm.by_name(text)
        if f is None:
            f = fm.at(parse_address(text)[0])
        if f is None:
            sys.exit(f"{text}: no such function")
        functions.append(f)
    if args.callees:
        extra = []
        for f in functions:
            for target in explain(fm, f, xdf).calls:
                g = fm.at(target)
                if g is not None and g not in functions and g not in extra:
                    extra.append(g)
        functions += extra

    explanations = [explain(fm, f, xdf) for f in functions]
    if args.run:
        b = Board(pair, mips=args.mips)
        print(f"booting, {args.settle:g} s to settle...", flush=True)
        b.boot(max_insns=int(args.settle * b.ips))
        b.crank.rpm = args.rpm
        peers = Peers(b)
        if args.speed:
            peers.set_speed(args.speed)
        for e in explanations:
            print(f"watching {e.f.label} for {args.run:g} s...", flush=True)
            e.run(b, int(args.run * b.ips), run=peers.run)
    for e in explanations:
        print(e.report())
        print()


if __name__ == "__main__":
    main()
