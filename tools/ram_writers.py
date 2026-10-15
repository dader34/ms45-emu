#!/usr/bin/env python
"""Which SRAM is free while the engine runs: the survey, cross-checked by
the program's own stores (ms45emu/ramwriters.py).

    .venv/bin/python tools/ram_writers.py [--pair session1clean] [--least 16]
                                          [--range 3FA386-3FA4DB ...] [--no-survey]

Without --range, the survey runs the board through boot, running (idle and
3000 rpm with a tester busy) and the after-run, with function coverage on
while running, and takes every stretch of `--least` bytes or more that the
running engine never touched (and is not ours, not a DME buffer, not the
stack). For each stretch: the stores the code can place there, with the
function, its phase (runtime / init / unknown) and its task; then a verdict.
Functions that store through computed pointers are listed once, by phase:
those reachable at run time could in principle write anything.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unicorn import UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_HOOK_CODE   # noqa: E402

from ms45emu import overlay, singles                   # noqa: E402
from ms45emu.board import Board                        # noqa: E402
from ms45emu.e46 import Peers                          # noqa: E402
from ms45emu.image import load_named                   # noqa: E402
from ms45emu.kwp import Tester                         # noqa: E402
from ms45emu.ramwriters import Writers                 # noqa: E402

LO, HI = 0x3F9800, 0x400000
STACK = 0x3FF900
OURS = [overlay.POOLS, ((overlay.DESC, overlay.DESC + overlay.DESC_SPACE),
                        (overlay.BITMAP, overlay.BITMAP + 64), overlay.SINGLES_POOL)]
DME_BUFFERS = ((0x3F9A44, 0x3F9C43), (0x3F9860, 0x3F98A0), (0x3F9DC0, 0x3F9E00), (0x3FA0A2, 0x3FA0BA))


def survey(pair, mips=20):
    """(touched per phase as bytearrays over LO..HI, the function starts that
    ran while running)."""
    phase = ["boot"]
    touched = {k: bytearray(HI - LO) for k in ("boot", "run", "after")}
    b = Board(pair, mips=mips)
    mu = b.m.mu

    def touch(uc, access, addr, size, value, data):
        t = touched[phase[0]]
        for i in range(size):
            if LO <= addr + i < HI:
                t[addr + i - LO] = 1
    mu.hook_add(UC_HOOK_MEM_WRITE, touch, begin=LO, end=HI)
    mu.hook_add(UC_HOOK_MEM_READ, touch, begin=LO, end=HI)
    mu.hook_add(UC_HOOK_CODE, lambda uc, a, s, d: phase.__setitem__(0, "run"), begin=singles.MAIN, end=singles.MAIN)
    b.boot(max_insns=int(0.3 * b.ips))
    peers = Peers(b, automatic=True)
    assert phase[0] == "run", "main was not reached in the boot"
    from ms45emu.funcmap import FunctionMap
    fm = FunctionMap(pair)
    from unicorn import UC_HOOK_BLOCK
    blocks = set()
    h = mu.hook_add(UC_HOOK_BLOCK, lambda uc, a, s, d: blocks.add(a))
    mu.ctl_flush_tb()
    b.crank.rpm = 800
    b.run(int(1.0 * b.ips))
    t = Tester(b)
    t.request([0x1A, 0x80])
    t.request([0x2C, 0xF0, 0x04])
    t.request([0x2C, 0xF0] + sum(([0x02, 1 + 2 * k, 0x02, 0x41, 0x04 + k, 0x01] for k in range(36)), []))
    for rpm in (800, 3000, 5000):
        b.crank.rpm = rpm
        for _ in range(10):
            t.request([0x21, 0xF0])
            b.run(int(0.15 * b.ips))
    t.request([0x18, 0x02, 0xFF, 0xFF])
    t.request([0x2C, 0xF0, 0x04])
    t.request([0x31, 0x30, 0, 0, 0])
    b.crank.rpm = 800
    b.run(int(1.0 * b.ips))
    mu.hook_del(h)
    executed = set()
    for a in blocks:
        f = fm.at(a)
        if f is not None:
            executed.add(f.start)
    phase[0] = "after"
    b.crank.rpm = 0
    b.ignition(False)
    b.run(int(4.0 * b.ips))
    del peers
    return touched, executed


def candidate_gaps(touched, least):
    run = touched["run"]
    skip = set()
    for group in OURS:
        for lo, hi in group:
            skip.update(range(lo, hi))
    for lo, hi in DME_BUFFERS:
        skip.update(range(lo, hi))

    def free(i):
        a = LO + i
        return not run[i] and a not in skip and a < STACK
    out, start = [], None
    for i in range(len(run) + 1):
        ok = i < len(run) and free(i)
        if ok and start is None:
            start = i
        if not ok and start is not None:
            if i - start >= least:
                out.append((LO + start, LO + i))
            start = None
    return sorted(out, key=lambda g: g[0] - g[1])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair", default="session1clean")
    ap.add_argument("--least", type=int, default=16, help="smallest stretch worth listing")
    ap.add_argument("--range", action="append", default=[], metavar="LO-HI", help="look at this stretch instead")
    ap.add_argument("--no-survey", action="store_true", help="static only: no coverage, --range required")
    ap.add_argument("--top", type=int, default=40, help="stretches to report")
    ap.add_argument("--survey-file", help="pickle the survey here, or load it from here when it exists")
    args = ap.parse_args()
    pair = load_named(args.pair)
    executed, touched = set(), None
    import pickle
    if args.survey_file and os.path.exists(args.survey_file):
        with open(args.survey_file, "rb") as f:
            touched, executed = pickle.load(f)
    elif not args.no_survey:
        print("surveying (boot, running, after-run; a few minutes)...", flush=True)
        touched, executed = survey(pair)
        if args.survey_file:
            with open(args.survey_file, "wb") as f:
                pickle.dump((touched, executed), f)
    if touched is not None:
        print(f"functions seen running: {len(executed)}")
    # a booted board's RAM places the stores made through pointers the boot set up
    b = Board(pair, mips=20)
    b.boot(max_insns=int(0.3 * b.ips))
    w = Writers(pair, executed, b.m.read32)
    n = {p: sum(1 for f in w.phase.values() if f == p) for p in ("runtime", "init", "unknown")}
    print(f"functions: {len(w.fm.functions)} ({n['runtime']} runtime, {n['init']} init-only, {n['unknown']} unknown); "
          f"placed stores: {len(w.stores)}; functions storing through pointers: {len(w.pointer_functions)}")
    if args.range:
        gaps = [tuple(int(x, 16) for x in r.split("-")) for r in args.range]
    elif touched is not None:
        gaps = candidate_gaps(touched, args.least)[:args.top]
    else:
        sys.exit("--no-survey needs --range")
    free_total = 0
    for lo, hi in gaps:
        kind = ""
        if touched is not None:
            kind = ("boot-only" if any(touched["boot"][a - LO] for a in range(lo, hi)) else
                    "after-run-only" if any(touched["after"][a - LO] for a in range(lo, hi)) else "untouched")
        v = w.verdict(lo, hi)
        sub = w.free_within(lo, hi, args.least)
        free_total += sum(b - a for a, b in sub)
        print(f"\n{lo:X}-{hi:X} {hi - lo:5} B  {kind:14s} {v}"
              + (f"; untouched by any placed run-time store: " + ", ".join(f"{a:X}-{b:X} ({b - a} B)" for a, b in sub) if sub else ""))
        for ws in w.of(lo, hi)[:12]:
            what = "indexed array, extent unknown" if ws.size == 0 else f"{abs(ws.size)} B" + (" via pointer" if ws.size < 0 else "")
            print(f"    {ws.phase:8s} {ws.pc:08X} {ws.function.label:28s} {ws.task or '':16s} {what}")
    risk = w.pointer_risk()
    print(f"\nbytes no placed run-time store reaches, in stretches of {args.least}+: {free_total} B in total "
          "(stores through computed pointers excepted: see below)")
    print(f"\nfunctions storing through computed pointers: runtime {len(risk['runtime'])}, "
          f"init {len(risk['init'])}, unknown {len(risk['unknown'])}. The run-time ones:")
    for f, k in sorted(risk["runtime"], key=lambda x: -x[1])[:25]:
        print(f"    {f.label:28s} {k:3} pointer stores  {task_label(w, f)}")


def task_label(w, f):
    from ms45emu.ramwriters import task_of
    return task_of(w.fm, f) or ""


if __name__ == "__main__":
    main()
