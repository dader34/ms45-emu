#!/usr/bin/env python
"""Where the DME keeps each of its measurement values: the map behind the
tuning screen's gauges.

    .venv/bin/python tools/values_map.py --tables .../ms450ds0.tables.json.gz
        [--flash F --mpc M] [--js FILE] [--json FILE] [--no-check]

The MS45 answers a tester's "send me values 4111, 411F, ..." (2C F0 02 ...,
then 21 F0) out of a table in its program: one entry per identifier
0x4100..0x41FF, eight bytes each, read by the routine at 0x27B20:

    +0  the variable's address, or a routine's for a value that is computed
    +4  flags:  0x4000 the variable is a word (else a byte, taken << 8)
                0x8000 it is signed
                low 14 bits: a factor, in 1/256ths
    +6  an offset taken off before the factor (signed)

and the word it sends is ((raw - offset) * factor) >> 8. What that word means
is the SGBD's business: its table FUMWELTTEXTE gives every identifier a name,
a unit and a scale (figure = word * MUL_WORD + ADD).

Put together, a value that is a plain variable can be read straight out of RAM
and scaled to the same figure:  figure = a * raw + b.  That is what the tuning
screen wants: its gauges ride in the live cursor's packet, which is defined by
address, and a packet cannot mix addresses with identifiers.

--js writes the map packed for BMWeb (core/ms45-value-map.js). Unless
--no-check, the program is run in the emulator and every mapped value is read
both ways, by identifier and from RAM, and the two figures compared.
"""
import argparse
import gzip
import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu.board import Board                              # noqa: E402
from ms45emu.image import IMAGES_DIR, Pair                   # noqa: E402
from ms45emu.kwp import Tester                               # noqa: E402

TABLE = 0x4C4                      # in the MPC: the entry of identifier 0x4100
LOADS_TABLE = 0x27B2C              # li r12, 0x4C4 in the routine that reads it
LI_R12_TABLE = 0x398004C4
BIASED = 0x3148                    # four identifiers whose word has 0x8000 added
RAM_LO, RAM_HI = 0x3F9800, 0x400000
FIRST, COUNT = 0x4100, 0x100
PACKET = 40                        # identifiers defined at once when checking


def entries(mpc):
    if struct.unpack(">I", mpc[LOADS_TABLE:LOADS_TABLE + 4])[0] != LI_R12_TABLE:
        raise SystemExit("this program does not read its value table at 0x4C4: not the build this was traced on")
    biased = set(mpc[BIASED:BIASED + 4])
    out = {}
    for n in range(COUNT):
        address, flags, offset = struct.unpack(">IHh", mpc[TABLE + 8 * n:TABLE + 8 * n + 8])
        if not flags or not RAM_LO <= address < RAM_HI or n in biased:
            continue                                   # unused, computed by a routine, or biased
        out[FIRST + n] = dict(address=address, wide=bool(flags & 0x4000), signed=bool(flags & 0x8000),
                              factor=flags & 0x3FFF, offset=offset)
    return out


def scaled(table_row, e):
    """figure = a * raw + b for one entry, and the SGBD's own word scaling."""
    mul, add = float(table_row["MUL_WORD"]), float(table_row["ADD"])
    per_word = e["factor"] / 256.0
    a = per_word * mul * (1 if e["wide"] else 256)
    b = add - e["offset"] * per_word * mul
    return a, b, mul, add


def check(pair, values):
    """Read every value both ways on a running engine; the worst disagreement."""
    board = Board(pair)
    board.boot(max_insns=int(0.3 * board.ips))
    board.crank.rpm = 800
    board.run(int(2.0 * board.ips))
    t = Tester(board)
    ids = sorted(values)
    bad, steady = [], 0
    for at in range(0, len(ids), PACKET):
        batch = ids[at:at + PACKET]
        t.request([0x2C, 0xF0, 0x04])
        request = [0x2C, 0xF0]
        for k, i in enumerate(batch):
            request += [0x02, 1 + 2 * k, 0x02, i >> 8, i & 0xFF, 0x01]
        assert t.request(request) == bytes((0x6C, 0xF0)), "the DME would not take the packet"
        answer = t.request([0x21, 0xF0])
        assert answer and answer[0] == 0x61 and len(answer) == 2 + 2 * len(batch)
        for k, i in enumerate(batch):
            v = values[i]
            word = struct.unpack(">h" if v["word_signed"] else ">H", answer[2 + 2 * k:4 + 2 * k])[0]
            by_id = word * v["mul"] + v["add"]
            size = 2 if v["wide"] else 1
            raw = int.from_bytes(bytes(board.m.read(v["address"], size)), "big", signed=v["signed"])
            by_ram = v["a"] * raw + v["b"]
            # the word is the figure truncated to 1/256 of a factor step, and
            # the engine has turned a little between the two reads
            slack = abs(v["mul"]) * 256 * 2 + abs(v["a"]) * 2
            if abs(by_id - by_ram) > slack:
                bad.append((i, by_id, by_ram, v["text"]))
            else:
                steady += 1
    return steady, bad


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flash", default=os.path.join(IMAGES_DIR, "session1clean.flash.bin"))
    ap.add_argument("--mpc", default=os.path.join(IMAGES_DIR, "session1clean.mpc.bin"))
    ap.add_argument("--tables", required=True, help="the SGBD's tables (BMWeb data/ecu-src/ms450ds0.tables.json.gz)")
    ap.add_argument("--js")
    ap.add_argument("--json")
    ap.add_argument("--no-check", action="store_true")
    args = ap.parse_args()

    with open(args.flash, "rb") as f, open(args.mpc, "rb") as m:
        pair = Pair(f.read(), m.read(), "values")
    with gzip.open(args.tables) as f:
        tables = json.load(f)
    rows = {int(r["UWNR"], 16): r for r in tables.get("tables", tables)["FUMWELTTEXTE"]}

    program = pair.program_id.decode("ascii", "replace")
    values = {}
    for i, e in entries(pair.mpc).items():
        row = rows.get(i)
        if not row or "unbenutzt" in row["UWTEXT"]:
            continue
        a, b, mul, add = scaled(row, e)
        values[i] = dict(e, a=a, b=b, mul=mul, add=add, text=row["UWTEXT"], unit=row["UW_EINH"].strip(),
                         word_signed=row["UWTYP_DDLI"].startswith("signed"))
    print(f"{program}: {len(values)} of {COUNT} values are plain variables")

    if not args.no_check:
        steady, bad = check(pair, values)
        print(f"read both ways: {steady} agree, {len(bad)} do not")
        for i, by_id, by_ram, text in bad:
            print(f"  {i:04X} {text}: {by_id:g} by identifier, {by_ram:g} from RAM")
            del values[i]                              # not offered: its figure is not understood

    packed = {f"{i:04X}": [v["address"], 2 if v["wide"] else 1, 1 if v["signed"] else 0,
                           float(f"{v['a']:.9g}"), float(f"{v['b']:.9g}")]
              for i, v in sorted(values.items())}
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"program": program, "values": {k: dict(zip(("address", "size", "signed", "a", "b"), v))
                                                               for k, v in packed.items()}}, f, indent=1)
    if args.js:
        with open(args.js, "w") as f:
            f.write("/**\n * @file Where the MS45 keeps its measurement values, and how each one's raw\n"
                    " * bytes become the figure the SGBD shows: figure = a * raw + b.\n *\n"
                    " * GENERATED by ms45-emu's tools/values_map.py from the program's own value\n"
                    " * table and the SGBD's scaling, each value checked in the emulator against\n"
                    " * the same value read by its identifier. Do not edit by hand.\n"
                    " * One program only: the addresses are that build's.\n */\n"
                    "/* exported MS45_VALUE_MAP */\n\n"
                    "// prettier-ignore\nconst MS45_VALUE_MAP = {\n"
                    f"  program: '{program}',\n"
                    "  // identifier: [address, size, signed, a, b]\n  values: {\n")
            for k, v in packed.items():
                f.write(f"    0x{k.lower()}: [0x{v[0]:x}, {v[1]}, {v[2]}, {v[3]!r}, {v[4]!r}],\n")
            f.write("  },\n};\n\nif (typeof module !== 'undefined' && module.exports) {\n"
                    "  module.exports = { MS45_VALUE_MAP };\n}\n")
        print(f"wrote {args.js}")


if __name__ == "__main__":
    main()
