#!/usr/bin/env python
"""Recover the scaling of the XDF's single values from how the program uses
them: a constant compared with, added to, or stored into a RAM variable
whose scaling is known has that variable's scaling.

    .venv/bin/python -m tools.analysis.scaling_sweep [--pair session1clean]
        [--values ../inpa-mac-bridge/app/renderer/core/generated/ms45-value-map.js]
        [--cursor ../inpa-mac-bridge/app/renderer/core/generated/ms45-cursor-map.js]
        [--report FILE]

Known variables come from two generated maps: the DME's own measurement
table (values map: figure = a * raw + b, checked in the emulator) and the
variables that feed each table axis (cursor map), which carry the axis's
XDF units and equation. For every single-value read site the function is
walked forward from the load: the loaded register (and what is copied or
sign-extended from it) meeting a register loaded from a known variable in
a compare, an add/subtract, or being stored into one, is a vote. The
constant's majority vote is set against the XDF's equation.
"""
import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from ms45emu import singles
from ms45emu.funcmap import FunctionMap
from ms45emu.image import load_named
from ms45emu.ppc import R13
from ms45emu.xdf import Xdf
from tools import ROOT

BMWEB = os.path.join(ROOT, "..", "inpa-mac-bridge", "app", "renderer", "core", "generated")
WINDOW = 24                                             # instructions after the load that count


def linear(equation):
    """(a, b) of an XDF equation in X, or None when it is not linear."""
    e = (equation or "X").strip() or "X"
    try:
        f = lambda x: eval(e.replace("X", f"({x})"), {"__builtins__": {}}, {})   # noqa: S307
        b, a = float(f(0)), float(f(1)) - float(f(0))
        if abs(f(2) - (2 * a + b)) > 1e-6 * max(1, abs(a)):
            return None
        return a, b
    except Exception:
        return None


def known_variables(values_js, cursor_js, xdf):
    """{address: (a, b, units, source)}"""
    out = {}
    if os.path.exists(values_js):
        text = open(values_js).read()
        for m in re.finditer(r"0x([0-9a-f]+):\s*\[0x([0-9a-f]+),\s*(\d),\s*(\d),\s*([-\d.e]+),\s*([-\d.e]+)\]", text):
            ident, addr, size, _, a, b = m.groups()
            out[int(addr, 16)] = (float(a), float(b), "", f"value 0x{ident}", int(size))
    if os.path.exists(cursor_js):
        text = open(cursor_js).read()
        start = text.index("{", text.index("MS45_CURSOR_MAP"))
        doc = json.loads(text[start:text.index("};", start) + 1])
        axes = {}
        for i in xdf.items:
            if i.kind == "axis":
                axes.setdefault(i.offset, i)
        refs = dict(doc.get("axes", {}))
        for _, pairs in doc.get("tables", {}).items():
            for off, var in pairs:
                refs.setdefault(str(off), var)
        for off, var in refs.items():
            axis = axes.get(int(off))
            v = doc["vars"][var]
            if axis is None or v[0] in out:
                continue
            ab = linear(axis.equation)
            if ab:
                out[v[0]] = (ab[0], ab[1], axis.units, f"axis of {axis.table or axis.name}", v[1])
    return out


def _sext(v):
    return v - 0x10000 if v & 0x8000 else v


def sweep(fm, sites, known):
    """{cal offset: Counter((a, b, units, size_match) -> votes)} with the evidence."""
    votes = defaultdict(Counter)
    evidence = defaultdict(list)
    by_fn = defaultdict(list)
    for s in sites:
        f = fm.at(s.pc)
        if f is not None:
            by_fn[f].append(s)
    for f, fsites in by_fn.items():
        site_at = {s.pc: s for s in fsites}
        src = {}                                        # reg -> ('cal', offset, size) | ('var', addr)
        for pc in range(f.start, f.end, 4):
            w = fm.words.get(pc, 0)
            op, rt, ra, rb = w >> 26, (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31
            xo = (w >> 1) & 0x3FF
            s = site_at.get(pc)
            if s is not None:
                src[s.rd] = ("cal", s.offset, singles.SIZES[s.op], pc)
                continue
            if op in (32, 34, 40, 42) and ra == 13:         # a load from a RAM variable
                src[rt] = ("var", (R13 + _sext(w & 0xFFFF)) & 0xFFFFFFFF)
                continue
            if op in (36, 38, 44) and ra == 13:             # a store into one
                v = src.get(rt)
                if v and v[0] == "cal":
                    _vote(votes, evidence, v, (R13 + _sext(w & 0xFFFF)) & 0xFFFFFFFF, known, "stored", pc)
                continue
            if op == 31 and xo in (0, 32):                  # cmp / cmpl
                a_, b_ = src.get(ra), src.get(rb)
                if a_ and b_ and {a_[0], b_[0]} == {"cal", "var"}:
                    cal, var = (a_, b_) if a_[0] == "cal" else (b_, a_)
                    _vote(votes, evidence, cal, var[1], known, "compared", pc)
                continue
            if op == 31 and xo in (40, 266, 8, 10):          # subf, add, subfc, addc
                a_, b_ = src.get(ra), src.get(rb)
                if a_ and b_ and {a_[0], b_[0]} == {"cal", "var"}:
                    cal, var = (a_, b_) if a_[0] == "cal" else (b_, a_)
                    _vote(votes, evidence, cal, var[1], known, "added", pc)
                src[rt] = src.get(ra) if a_ and a_[0] == "cal" else None
                if src[rt] is None:
                    src.pop(rt, None)
                continue
            # copies keep the origin: extsh/extsb, mr (or rA,rS,rS), rlwinm with no shift, addi rX,rY,0
            copy = None                                     # (target, origin)
            if op == 31 and (xo in (922, 954) or (xo == 444 and rt == rb)):
                copy = (ra, rt)                             # extsh/extsb/mr: rS is the rt field
            elif op == 21 and rb == 0:                      # rlwinm with no shift: a mask
                copy = (ra, rt)
            elif op == 14 and ra and w & 0xFFFF == 0:       # addi rX, rY, 0
                copy = (rt, ra)
            if copy:
                target, origin = copy
                if origin in src:
                    src[target] = src[origin]
                else:
                    src.pop(target, None)
                continue
            if op in (16, 18) or w in (0x4E800020, 0x4E800420, 0x4E800421):   # a branch: the function's
                src = {}                                                       # straight line ends
                continue
            # any other definition of a register forgets it
            if op in (14, 15, 24, 25, 26, 27, 28, 29, 32, 33, 34, 35, 40, 41, 42, 43, 46):
                src.pop(rt, None)
            elif op == 31 and xo not in (0, 32):
                target = ra if xo in (24, 28, 60, 124, 284, 316, 412, 444, 476, 536, 792, 824, 922, 954) else rt
                src.pop(target, None)
            elif op in (20, 21, 23):
                src.pop(ra, None)
    return votes, evidence


def _vote(votes, evidence, cal, var_addr, known, how, pc):
    k = known.get(var_addr)
    if not k:
        return
    a, b, units, source, size = k
    votes[cal[1]][(round(a, 9), round(b, 6), units)] += 1
    evidence[cal[1]].append((how, var_addr, source, pc, size == cal[2]))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair", default="session1clean")
    ap.add_argument("--values", default=os.path.join(BMWEB, "ms45-value-map.js"))
    ap.add_argument("--cursor", default=os.path.join(BMWEB, "ms45-cursor-map.js"))
    ap.add_argument("--report", default=None)
    args = ap.parse_args()
    pair = load_named(args.pair)
    xdf = Xdf.find(pair)
    known = known_variables(args.values, args.cursor, xdf)
    fm = FunctionMap(pair)
    sites, _ = singles.scan(pair)
    print(f"known variables: {len(known)}; single-value read sites: {len(sites)}")
    votes, evidence = sweep(fm, sites, known)
    agree, disagree, identity_scaled, unknown_eq = [], [], [], []
    for offset, c in sorted(votes.items()):
        item = xdf.at(offset)
        if item is None or item.kind != "constant":
            continue
        (a, b, units), n = c.most_common(1)[0]
        total = sum(c.values())
        xab = linear(item.equation)
        row = (item.name, offset, item.equation or "X", item.units, a, b, units, n, total,
               sorted(set(e[2] for e in evidence[offset]))[:3])
        close = lambda p, q: abs(p - q) <= 0.025 * max(abs(p), abs(q), 1e-12)   # noqa: E731 (the XDF rounds to 6 places)
        if xab is None:
            unknown_eq.append(row)
        elif a == 0:
            unknown_eq.append(row)                       # the measurement map has no scale for that value
        elif close(xab[0], a) and abs(xab[1] - b) <= 0.5:
            agree.append(row)
        elif close(xab[0], a * 256) or close(xab[0] * 256, a):
            agree.append(row)                            # a byte constant against a word variable (<< 8)
        else:
            disagree.append(row)
            if xab == (1.0, 0.0) and (a, b) != (1.0, 0.0):
                identity_scaled.append(row)
    print(f"constants with evidence: {len(agree) + len(disagree) + len(unknown_eq)}; "
          f"XDF agrees: {len(agree)}; disagrees: {len(disagree)} (of which identity in the XDF but scaled "
          f"by the program: {len(identity_scaled)}); XDF equation not linear: {len(unknown_eq)}")
    lines = []
    for title, rows in (("XDF IDENTITY, PROGRAM SCALED", identity_scaled),
                        ("XDF DISAGREES WITH THE PROGRAM", [r for r in disagree if r not in identity_scaled])):
        lines.append(f"\n== {title} ({len(rows)}) ==")
        lines.append(f"{'constant':36s} {'XDF':26s} {'program':30s} votes  evidence")
        for name, off, eq, units, a, b, u, n, total, ev in sorted(rows, key=lambda r: -r[7]):
            prog = f"{a:g} * X" + (f" + {b:g}" if b else "") + (f" [{u}]" if u else "")
            lines.append(f"{name:36s} {eq[:22] + (' [' + units + ']' if units else ''):26s} {prog:30s} {n}/{total}  {', '.join(ev)}")
    text = "\n".join(lines)
    print(text[:6000])
    if args.report:
        with open(args.report, "w") as f:
            f.write(f"Scaling sweep of {xdf.path} against program {pair.program_id.decode('latin1')}\n")
            f.write(f"constants with evidence {len(agree) + len(disagree) + len(unknown_eq)}, agree {len(agree)}, "
                    f"disagree {len(disagree)}, identity-but-scaled {len(identity_scaled)}\n")
            f.write(text + "\n\n== AGREE ==\n")
            for name, off, eq, units, a, b, u, n, total, ev in agree:
                f.write(f"{name:36s} {eq} [{units}]  {n}/{total}\n")
        print("report:", args.report)


if __name__ == "__main__":
    main()
