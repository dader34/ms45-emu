#!/usr/bin/env python
"""The program's function map (ms45emu/funcmap.py): boundaries from a sweep
of the code, names from ms45emu/names/<program>.json, and what runs.

    .venv/bin/python tools/funcmap.py --pair stock                       # the sweep: how many, how many named
    .venv/bin/python tools/funcmap.py --at 0x4B6AC --at r13-0x4BEC       # which function (or variable) an address is in, its callers
    .venv/bin/python tools/funcmap.py --coverage 1 --rpm 800 --top 40     # what runs in a second with the crank turning
    .venv/bin/python tools/funcmap.py --coverage 1 --json images/stock_functions.json
    .venv/bin/python tools/funcmap.py --ghidra images/stock_symbols.txt   # for Ghidra's ImportSymbolsScript

Coverage boots the pair, lets it settle, then runs it with a block hook
(Python per basic block: about 15 s of wall time per second of DME time).
The hot unnamed functions it lists are the ones worth naming next; names
go in the JSON by hand.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu import load_pair                           # noqa: E402
from ms45emu.board import Board                         # noqa: E402
from ms45emu.e46 import Peers                           # noqa: E402
from ms45emu.image import Pair, ENV_NAMES               # noqa: E402
from ms45emu.funcmap import FunctionMap, names_path     # noqa: E402
from ms45emu.xref import parse_address, describe        # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair", default="stock", choices=list(ENV_NAMES))
    ap.add_argument("--flash")
    ap.add_argument("--mpc")
    ap.add_argument("--at", action="append", default=[], metavar="ADDR", help="say what is at this address (repeatable)")
    ap.add_argument("--coverage", type=float, default=0, metavar="SECONDS", help="run the program this long and count what runs")
    ap.add_argument("--settle", type=float, default=0.5, metavar="SECONDS", help="DME time to boot before coverage starts")
    ap.add_argument("--rpm", type=float, default=0)
    ap.add_argument("--mips", type=int, default=40)
    ap.add_argument("--top", type=int, default=30, help="functions to list by block hits (default 30)")
    ap.add_argument("--unnamed", action="store_true", help="list only unnamed functions under --top")
    ap.add_argument("--json", metavar="FILE", help="write the map (with coverage when run) as JSON")
    ap.add_argument("--ghidra", metavar="FILE", help="write symbols for Ghidra's ImportSymbolsScript")
    ap.add_argument("--ext-base", type=lambda s: int(s, 0), default=0xFFF00000,
                    help="where the Ghidra project has the external flash (default 0xFFF00000)")
    args = ap.parse_args()

    if args.flash and args.mpc:
        with open(args.flash, "rb") as f, open(args.mpc, "rb") as m:
            name = os.path.basename(args.flash).rsplit(".", 1)[0].replace("_Flash", "")
            pair = Pair(f.read(), m.read(), name)
    else:
        pair = load_pair(args.pair)

    fm = FunctionMap(pair)
    named = sum(1 for f in fm.functions if f.name)
    code = sum(f.size for f in fm.functions)
    print(f"{pair.name}: program {pair.program_id.decode('latin1')}: {len(fm.functions)} functions, "
          f"{named} named ({os.path.relpath(names_path(pair))}), {code // 1024} KB of code")

    for text in args.at:
        start, end = parse_address(text)
        f = fm.at(start)
        var = fm.variable(start)
        line = describe(start) + (f"  variable {var}" if var else "")
        if f is None:
            print(f"{line}: not in a function")
            continue
        print(f"{line}: {fm.label(start)}  ({f.label} 0x{f.start:X}-0x{f.end:X}, {f.size} bytes, found by {'/'.join(sorted(f.sources))})")
        if f.callers:
            callers = ", ".join(f"0x{c:X} in {fm.label(c)}" for c in f.callers[:12])
            print(f"    called from {len(f.callers)}: {callers}{', ...' if len(f.callers) > 12 else ''}")
        else:
            print("    no bl to it (entered through a table, a vector, or a computed branch)")

    if args.coverage:
        b = Board(pair, mips=args.mips)
        print(f"booting, {args.settle:g} s to settle...", flush=True)
        b.boot(max_insns=int(args.settle * b.ips))
        b.crank.rpm = args.rpm
        peers = Peers(b)
        print(f"covering {args.coverage:g} s" + (f" at {args.rpm:g} rpm" if args.rpm else "") + "...", flush=True)
        fm.cover(b, int(args.coverage * b.ips), run=peers.run)
        ran = fm.executed
        found = sum(1 for f in fm.functions if "coverage" in f.sources)
        print(f"{len(ran)} of {len(fm.functions)} functions ran ({sum(1 for f in ran if f.name)} named), "
              f"{sum(fm.blocks.values())} blocks" + (f"; {found} functions the sweep had missed" if found else "")
              + (f"; {sum(fm.stray.values())} blocks in RAM copies ({', '.join(f'0x{a:X}' for a, _ in fm.stray.most_common(3))})" if fm.stray else ""))
        top = sorted((f for f in ran if not (args.unnamed and f.name)), key=lambda f: -f.hits)[:args.top]
        print(f"{'hits':>9} {'entries':>8}  function")
        for f in top:
            print(f"{f.hits:9} {f.entries:8}  {f.label}  0x{f.start:X}-0x{f.end:X}" + (f"  callers {len(f.callers)}" if not f.name else ""))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(fm.to_json(), f, indent=1)
        print("wrote", args.json)
    if args.ghidra:
        with open(args.ghidra, "w") as f:
            f.write(fm.ghidra_symbols(args.ext_base))
        print("wrote", args.ghidra, "(Ghidra: Window > Script Manager > ImportSymbolsScript)")


if __name__ == "__main__":
    main()
