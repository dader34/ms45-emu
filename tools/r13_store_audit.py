#!/usr/bin/env python3
"""The designed-extent audit of the live tune's RAM: every store in the
program that addresses through r13 (the small-data anchor over SRAM,
0x4017F0), so a pool can be checked against what the firmware can reach,
not just what a profile watched it write.

The 2C-F0 definition store (0x3F9B43-0x3F9C42, found 2026-10-13) was an
indexed store: `stbx r12, r30, r31` with r30 = r13-0x7CAD, a base below
the pool and an index bounded only by the telegram length.  So the audit
splits the stores in two:

- the D-form, `sth r12, -0x7dd2(r13)`: a fixed address.  The risk to a
  span is only a store that lands inside it.
- the X-form indexed, `stbx r12, r30, r31` where the base register was
  built from r13 (usually `addi r30, r13, -off` just before): a range.
  Every one whose base is below a span has to be bounded by hand, the
  way the 2C store was.

The boot loader (which cannot change) is swept with the program.  What
this cannot see: stores through pointers held in memory -- the receive
interrupt's byte writes and the response echo -- which the milestone-1
profile and the KWP writer map cover on the runtime side.

    .venv/bin/python tools/r13_store_audit.py [--flash ... --mpc ...]
"""
import argparse
import os
import re
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN  # noqa: E402

from ms45emu.image import Pair                            # noqa: E402
from ms45emu.funcmap import FunctionMap                   # noqa: E402
from ms45emu.dme import R13                               # noqa: E402

# r2 (0xFFE47FF0) anchors the external flash window: its stores cannot
# reach SRAM and are not collected.

# the live tune's RAM, as ms45emu/overlay.py lays it out
SPANS = {
    "bitmap+SAVE":   (0x3F9858, 0x3F9894),
    "pool D":        (0x3F9894, 0x3F98B0),
    "pool C":        (0x3F9E10, 0x3F9E74),
    "state block":   (0x3F9E74, 0x3F9E98),
    "pool A":        (0x3F9E98, 0x3FA0A0),
    "pool B":        (0x3F9B48, 0x3F9C40),      # inside the 2C-F0 store: the bug
    "descriptors":   (0x3F9C48, 0x3F9E00),
    "2C-F0 store":   (0x3F9B43, 0x3F9C42),      # stock's own, for reference
    "rx buffer":     (0x3F9A44, 0x3F9B42),
}

STORES = re.compile(r"^(stb|sth|stw|stbu|sthu|stwu|stbx|sthx|stwx|stbux|sthux|stwux|"
                    r"stfs|stfd|stfsu|stfdu|stfsx|stfdx|stswi|stswx|stmw|stve[i,x].*)$")
D_FORM = re.compile(r"(-?0x[0-9a-f]+)\(r13\)$")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flash", default="images/session1clean.flash.bin")
    ap.add_argument("--mpc", default="images/session1clean.mpc.bin")
    args = ap.parse_args()

    pair = Pair(open(args.flash, "rb").read(), open(args.mpc, "rb").read(), "audit")
    fm = FunctionMap(pair)
    md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)

    fixed, indexed = [], []
    # the last addi to each register before a pc, per function: how an indexed
    # store's base is usually built (the 2C-F0 store is `addi r30, r13, -0x7cad`
    # then `stbx r12, r30, r31` -- r13 appears nowhere in the store itself)
    INDEXED = re.compile(r"^(stbx|sthx|stwx|stbux|sthux|stwux|stfsx|stfdx|stswx|stve[i,x].*)$")
    for fn in fm.functions:
        last_addi = {}
        for pc in range(fn.start, fn.end, 4):
            w = fm.words.get(pc)
            if w is None:
                continue
            ins = list(md.disasm(struct.pack(">I", w), pc))
            if not ins:
                continue
            i = ins[0]
            if w >> 26 == 14 and ((w >> 16) & 31) == 13:          # addi rD, r13, simm
                rD, simm = (w >> 21) & 31, w & 0xFFFF
                if simm & 0x8000:
                    simm -= 0x10000
                last_addi[rD] = (pc, R13 + simm)
                continue
            # any other redefinition of a register drops what we knew of it
            if i.mnemonic.startswith("add") or i.mnemonic in ("li", "lis", "mr", "or",
                                                              "lwz", "lbz", "lhz", "la"):
                rD = i.op_str.split(",")[0].strip()
                if rD.startswith("r") and rD[1:].isdigit():
                    last_addi.pop(int(rD[1:]), None)
            if not STORES.match(i.mnemonic):
                continue
            m = D_FORM.search(i.op_str)
            if m:                                          # off(r13): a fixed address
                fixed.append((pc, fm.label(pc), i.mnemonic, i.op_str, int(m.group(1), 16)))
            elif INDEXED.match(i.mnemonic):
                ops = [o.strip() for o in i.op_str.split(",")]
                if len(ops) >= 3 and ops[1].startswith("r") and ops[1][1:].isdigit():
                    rA = int(ops[1][1:])
                    if rA in last_addi:
                        indexed.append((pc, fm.label(pc), i.mnemonic, i.op_str, *last_addi[rA]))

    print(f"{len(fixed)} fixed r13 stores, {len(indexed)} indexed stores with an r13-built base\n")

    print("== indexed stores whose base sits at or below the pools (index can climb into them) ==")
    for pc, label, mn, ops, apc, base in sorted(indexed, key=lambda h: h[5]):
        if base > 0x3FA0A0:
            continue
        note = "".join(f" {name}[{lo - base:+#x}..]" for name, (lo, hi) in SPANS.items()
                       if base <= hi and lo >= base - 0x800)
        print(f"  {pc:08X}  {label:36}  {mn} {ops}   base {base:#x} (addi at {apc:08X}){note}")

    print("\n== fixed stores into the live tune's spans ==")
    for name, (lo, hi) in SPANS.items():
        hits = [(pc, label, mn, ops, off) for pc, label, mn, ops, off in fixed
                if lo <= R13 + off < hi]
        print(f"  {name} {lo:#x}-{hi:#x}: {len(hits)}")
        for pc, label, mn, ops, off in hits:
            print(f"    {pc:08X}  {label:36}  {mn} {ops}")

    print("\n== fixed stores within 1 KB below each span (an indexed base can climb into it) ==")
    for name, (lo, hi) in SPANS.items():
        hits = [(pc, label, mn, ops, off) for pc, label, mn, ops, off in fixed
                if lo - 0x400 <= R13 + off < lo and off < 0]
        if hits:
            print(f"  below {name}:")
            for pc, label, mn, ops, off in hits:
                print(f"    {pc:08X}  {label:36}  {mn} {ops}  -> {R13 + off:#x}")
    return 0


def SIGNED(x):
    return f"{x:+#x}"


if __name__ == "__main__":
    sys.exit(main())
