#!/usr/bin/env python
"""Which RAM variable feeds each table's axes: the map behind the live cursor.

    .venv/bin/python tools/livetune_cursor.py [--flash F --mpc M] [--seconds 0.4]
        [--json FILE] [--js FILE] [--table 0x1FC3]

The tuning screen marks the cell the program is reading. Nothing has to be
added to the DME for that: every table lookup goes through the lookup library
(docs/livetune-design.md), which is handed the axis and the value to look up
in registers, and that value nearly always comes straight out of one RAM
variable. Read the variable over the K line, search the axis with it as the
library does, and the cell is known.

This runs the program in the emulator at a few operating points with a hook on
every library routine, and for each call:

  - takes the axis pointer(s) and the table pointer (out of the descriptor for
    the wrapper routines; for the two-step routines the table read is paired
    with the axis searches that set the library's saved index before it);
  - walks back from the call for where the looked-up register came from: a
    load from RAM, or a store of the same register to RAM on the way;
  - checks, at every call, that the variable holds exactly what the register
    does. A variable is kept only if it never differed, so it is the value the
    library consumes, after any clamp or filter.

The result (ms45emu/names/<program>.cursor.json) lists, per table (calibration
offset of its first cell), each axis (offset of its count and of its first
break point, the break point width) and its variable (address, size, signed).
An axis nobody could be found for carries the reason instead. "axes" lists
the axes that had the same variable at every table that used them: a table the
run never reached (most of them: its conditions were not met) can borrow its
cursor from there, as a guess.

--js writes the same thing packed for BMWeb (core/ms45-cursor-map.js).
"""
import argparse
import bisect
import json
import os
import re
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN   # noqa: E402
from unicorn import UC_HOOK_CODE                             # noqa: E402
from unicorn.ppc_const import UC_PPC_REG_0, UC_PPC_REG_LR    # noqa: E402

from ms45emu import dme                                     # noqa: E402
from ms45emu.board import Board                              # noqa: E402
from ms45emu.e46 import Peers                                # noqa: E402
from ms45emu.funcmap import FunctionMap                      # noqa: E402
from ms45emu.image import IMAGES_DIR, Pair                   # noqa: E402
from ms45emu.inputs import set_pedal                         # noqa: E402
from ms45emu.machine import R13                              # noqa: E402
from ms45emu.overlay import LOOKUP_WRAPPERS                  # noqa: E402

RAM_LO, RAM_HI = 0x3F9800, 0x400000
LIB_LO, LIB_HI = 0xCFC8, 0xF25C              # the lookup routines, short of the RTOS lookalikes

# The two-step routines. A search leaves an index and a fraction in the
# library's RAM; a read picks them up. There are two such sets: the first
# (index at r13-0x283A) is all a curve needs, a map uses both, the first for
# its rows. (routine: set it writes, bytes in the count and in a break point)
SEARCHES = {0xCFC8: (0, 1), 0xD0E4: (0, 2), 0xD210: (0, 1), 0xD2C0: (0, 2),
            0xD054: (1, 1), 0xD178: (1, 2), 0xD264: (1, 1), 0xD31C: (1, 2)}
READS = {0xD380: 1, 0xD38C: 1, 0xD3DC: 1, 0xD44C: 1,      # routine: axes it reads through
         0xD39C: 2, 0xD3B8: 2, 0xD4C0: 2, 0xD660: 2}

# How the engine is held while the calls are counted: (rpm, pedal %).
POINTS = ((900, 0), (2500, 20), (4500, 60))

LOADS = {"lbz": (1, False), "lhz": (2, False), "lha": (2, True)}
STORES = {"stb": 1, "sth": 2}
MOVES = ("clrlwi", "extsh", "extsb")
MEM = re.compile(r"(-?(?:0x)?[0-9a-f]+)\(r(\d+)\)")


def cal_offset(addr):
    """A CPU address as a calibration offset, or None."""
    o = (addr & 0xFFFFF) - 0x40000
    return o if addr >= 0xFFE00000 and 0 <= o < dme.CAL_LENGTH else None


class Slicer:
    """Where a register's value came from, walking back from a call."""

    def __init__(self, pair):
        self.images = ((0, pair.mpc), (0xFFF00000, pair.flash))
        self.md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)

    def insn(self, pc):
        for base, data in self.images:
            if base <= pc < base + len(data):
                for i in self.md.disasm(data[pc - base:pc - base + 4], pc):
                    return i.mnemonic, [a.strip() for a in i.op_str.split(",")]
        return None, []

    def constant(self, pc, reg, depth=24):
        """The value a `lis`/`addi` pair left in reg, or None."""
        add = 0
        while depth > 0:
            pc -= 4
            depth -= 1
            m, a = self.insn(pc)
            if m is None or m in ("bl", "blr", "b", "bctr", "bctrl"):
                return None
            if not a or a[0] != f"r{reg}" or m in STORES or m == "stw":
                continue
            if m == "lis":
                return ((int(a[1], 0) << 16) + add) & 0xFFFFFFFF
            if m == "addi" and a[1] == f"r{reg}":
                add += int(a[2], 0)
                continue
            if m == "addis" and a[1] == f"r{reg}":
                add += int(a[2], 0) << 16
                continue
            return None
        return None

    def source(self, pc, reg, depth=48):
        """(address, size, signed) of the RAM the register at the call before
        pc was loaded from or stored to, or (None, reason)."""
        extended = None                     # the last clrlwi/extsh on the way: it decides the sign
        while depth > 0:
            pc -= 4
            depth -= 1
            m, a = self.insn(pc)
            if m is None:
                return None, "not code"
            if m in ("bl", "bla", "bctrl", "blrl"):
                if reg in (0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12):
                    return None, "returned by a call" if reg == 3 else "lost across a call"
                continue
            if m in ("blr", "b", "ba", "bctr"):
                return None, "passed in by the caller"
            if not a or a[0] != f"r{reg}":
                continue
            if m in LOADS or m in STORES:
                mem = MEM.match(a[1])
                if not mem:
                    return None, f"{m} {', '.join(a)}"
                base = int(mem.group(2))
                if base == 13:
                    addr = R13 + int(mem.group(1), 0)
                elif base == 2:
                    return None, "a calibration value"
                else:
                    k = self.constant(pc, base)
                    if k is None:
                        return None, "read through a pointer"
                    addr = (k + int(mem.group(1), 0)) & 0xFFFFFFFF
                if m in STORES:
                    return (addr, STORES[m], False), None
                size, signed = LOADS[m]
                return (addr, size, signed if extended is None else extended), None
            if m == "mr" or m in MOVES or (m == "addi" and a[2] in ("0", "0x0")):
                if m in MOVES and extended is None:
                    extended = m != "clrlwi"
                reg = int(a[1][1:])
                continue
            if m == "li":
                return None, "a constant"
            return None, f"computed ({m})"
        return None, "too far back"


def wrappers(fmap):
    """The descriptor routines: start -> [(4 or 8, break point width)]."""
    out = {}
    slicer = Slicer(fmap.pair)
    for pc, reg, disp in LOOKUP_WRAPPERS:
        start = fmap.starts[bisect.bisect_right(fmap.starts, pc) - 1]
        width = 0
        for at in range(pc + 4, pc + 24, 4):                # the count, read through the pointer
            m, a = slicer.insn(at)
            if m in ("lbz", "lhz") and len(a) > 1 and a[1] == f"0(r{reg})":
                width = 1 if m == "lbz" else 2
                break
        assert width, f"no count read after {pc:#x}"
        out.setdefault(start, []).append((disp, width))
    return out


def write_js(path, doc):
    """The map as BMWeb loads it: the variables once, then per table the
    (first break point, variable) pairs that have one."""
    variables, index = [], {}

    def ref(row):
        key = (int(row["var"], 16), row["size"], row["signed"])
        if key not in index:
            index[key] = len(variables)
            variables.append([key[0], key[1], int(key[2]), row.get("name", "")])
        return index[key]

    tables = {}
    for t, rows in doc["tables"].items():
        pairs = [[int(r["first"], 16), ref(r)] for r in rows if "var" in r]
        if pairs:
            tables[str(int(t, 16))] = pairs
    axes = {str(int(first, 16)): ref(row) for first, row in doc["axes"].items()}
    packed = {"program": doc["program"], "vars": variables, "tables": tables, "axes": axes}
    with open(path, "w") as f:
        f.write("/**\n * @file Which RAM variable feeds each MS45 table axis, for the live cursor\n"
                " * (core/livetune-cursor.js). GENERATED by ms45-emu tools/livetune_cursor.py;\n"
                " * do not edit. vars: [address, bytes, signed, name]; tables: calibration\n"
                " * offset of the first cell -> [[offset of the axis's first break point,\n"
                " * index into vars]]; axes: the same per axis, for tables not listed.\n */\n"
                "/* exported MS45_CURSOR_MAP */\n"
                "const MS45_CURSOR_MAP = " + json.dumps(packed, separators=(",", ":")) + ";\n\n"
                "if (typeof module !== 'undefined' && module.exports) module.exports = { MS45_CURSOR_MAP };\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flash", help="external flash dump (default: images/session1.*)")
    ap.add_argument("--mpc", help="MPC dump")
    ap.add_argument("--seconds", type=float, default=0.4, help="DME time at each operating point")
    ap.add_argument("--json", metavar="FILE", help="write here instead of ms45emu/names/<program>.cursor.json")
    ap.add_argument("--js", metavar="FILE", help="also write the map as a script for BMWeb")
    ap.add_argument("--table", type=lambda s: int(s, 0), action="append", default=[],
                    metavar="OFFSET", help="print what was found for this table (repeatable)")
    args = ap.parse_args()

    flash = args.flash or os.path.join(IMAGES_DIR, "session1.flash.bin")
    mpc = args.mpc or os.path.join(IMAGES_DIR, "session1.mpc.bin")
    with open(flash, "rb") as f, open(mpc, "rb") as m:
        pair = Pair(f.read(), m.read(), os.path.basename(flash).split(".")[0])
    program = pair.program_id.decode("latin1")
    b = Board(pair)
    fmap = FunctionMap(pair)
    slicer = Slicer(pair)
    wraps = wrappers(fmap)
    mu = b.m.mu

    sites = {}              # (lr, register) -> [variable or None, reason, calls, calls that agreed]
    last = [None, None]     # the search that last wrote each index set: (axis, width, site)
    links = Counter()       # (table, axis, width, site) -> calls

    def looked_up(lr, reg, value):
        key = (lr, reg)
        s = sites.get(key)
        if s is None:
            var, why = slicer.source(lr - 4, reg)
            if var and not RAM_LO <= var[0] < RAM_HI:
                var, why = None, "not RAM"
            s = sites[key] = [var, why, 0, 0]
        s[2] += 1
        if s[0]:
            addr, size, signed = s[0]
            raw = int.from_bytes(mu.mem_read(addr, size), "big", signed=signed)
            s[3] += (raw & 0xFFFFFFFF) == value
        return key

    def on_call(_mu, pc, _size, _ud):
        lr = mu.reg_read(UC_PPC_REG_LR)
        r3 = mu.reg_read(UC_PPC_REG_0 + 3)
        if pc in SEARCHES:
            which, width = SEARCHES[pc]
            last[which] = (r3, width, looked_up(lr, 4, mu.reg_read(UC_PPC_REG_0 + 4)))
        elif pc in READS:
            for which in range(READS[pc]):
                if last[which]:
                    links[(r3,) + last[which]] += 1
        elif pc in wraps:
            table = struct.unpack(">I", mu.mem_read(r3, 4))[0]
            for (disp, width), reg in zip(wraps[pc], (4, 5)):
                axis = struct.unpack(">I", mu.mem_read(r3 + disp, 4))[0]
                site = looked_up(lr, reg, mu.reg_read(UC_PPC_REG_0 + reg))
                links[(table, axis, width, site)] += 1

    for start in list(SEARCHES) + list(READS) + list(wraps):
        mu.hook_add(UC_HOOK_CODE, on_call, begin=start, end=start)

    b.boot(max_insns=int(0.2 * b.ips))
    peers = Peers(b, automatic=True)
    for rpm, pedal in POINTS:
        set_pedal(b, pedal)
        b.crank.rpm = rpm
        peers.run(int(args.seconds * b.ips))
        print(f"{rpm} rpm, pedal {pedal} %: {len(sites)} call sites, {len(links)} table/axis pairs",
              flush=True)

    # ---- per table and axis, the one variable every site agrees on ----------
    tables = {}
    for (table, axis, width, site), calls in links.items():
        t, a = cal_offset(table), cal_offset(axis)
        if t is None or a is None:
            continue
        tables.setdefault(t, {}).setdefault((a, width), []).append((site, calls))

    out, pool, reasons = {}, Counter(), Counter()
    shared = {}             # first break point -> the variables seen for it (None: some table had none)
    n_axes = n_found = 0
    for t in sorted(tables):
        rows = []
        for (a, width), users in sorted(tables[t].items()):
            found, why = set(), Counter()
            for site, calls in users:
                var, reason, n, agreed = sites[site]
                if var and agreed == n:
                    found.add(var)
                else:
                    why[reason or "the variable is not what is looked up"] += 1
            row = {"axis": f"0x{a:04X}", "first": f"0x{a + width:04X}", "width": width,
                   "calls": sum(c for _, c in users)}
            n_axes += 1
            if len(found) == 1 and not why:
                addr, size, signed = next(iter(found))
                row.update(var=f"0x{addr:06X}", size=size, signed=signed)
                name = fmap.variable(addr)
                if name:
                    row["name"] = name
                pool[(addr, size)] += 1
                n_found += 1
                shared.setdefault(a + width, set()).add((addr, size, signed))
            else:
                shared.setdefault(a + width, set()).add(None)
                row["why"] = ("several variables" if len(found) > 1 else
                              why.most_common(1)[0][0] if not found else "some callers differ")
                reasons[row["why"]] += 1
            rows.append(row)
        out[f"0x{t:04X}"] = rows

    print(f"\n{len(out)} tables, {n_axes} axes: {n_found} with a variable "
          f"({len(pool)} distinct variables)", flush=True)
    for why, n in reasons.most_common():
        print(f"  {n:4d}  {why}")
    print("the busiest variables:")
    for (addr, size), n in pool.most_common(12):
        print(f"  0x{addr:06X} ({size} B) {fmap.variable(addr) or ''}: {n} axes")
    for t in args.table:
        print(f"table 0x{t:04X}: {json.dumps(out.get(f'0x{t:04X}'), indent=1)}")

    path = args.json or os.path.join(os.path.dirname(__file__), "..", "ms45emu", "names",
                                     f"{program}.cursor.json")
    doc = {"program": program,
           "source": "emulator, %s pair, %g s at each of %s (rpm, pedal %%); tools/livetune_cursor.py"
                     % (pair.name, args.seconds, ", ".join(map(str, POINTS))),
           "tables": out,
           "axes": {f"0x{first:04X}": {"var": f"0x{v[0]:06X}", "size": v[1], "signed": v[2]}
                    for first, found in sorted(shared.items()) if len(found) == 1
                    for v in found if v}}
    with open(path, "w") as f:
        f.write(json.dumps(doc, indent=0).replace("\n", " ").replace("], ", "],\n").replace("{ ", "{")
                + "\n")
    print(f"wrote {os.path.normpath(path)}")
    if args.js:
        write_js(args.js, doc)
        print(f"wrote {args.js}")


if __name__ == "__main__":
    main()
