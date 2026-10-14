#!/usr/bin/env python
"""Milestone 2 of the live-tune build (docs/livetune-design.md): the overlay,
live. Boots the car's pair with the overlay hooks, runs the engine, installs
a mirror of the hottest table MID-RUN, then edits it and shows two things:

  - the lookup library's reads of that table move to the SRAM mirror
    (the readers are the same pcs that read it from flash before);
  - editing the mirror changes what the program computes: the small-data
    RAM of an edited run differs from an unedited one with everything
    else identical.

    .venv/bin/python tools/livetune_overlay.py [--seconds 0.15] [--table 0x52F9]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu import dme, overlay                         # noqa: E402
from ms45emu.board import Board                          # noqa: E402
from ms45emu.e46 import running                          # noqa: E402
from ms45emu.funcmap import FunctionMap                  # noqa: E402
from ms45emu.image import load_named                     # noqa: E402
from ms45emu.xref import Xref                            # noqa: E402

TABLE, LENGTH = 0x52F9, 0x208      # the hottest table of the milestone-1 profile
RAM_LO, RAM_LEN = 0x3F9800, 0x4800


def run(edit, table, length, pre, post):
    pair = load_named("session1")
    b = Board(overlay.build(pair))
    fmap = FunctionMap(pair)
    peers = running(b)
    flash_range = (dme.CAL_BASE + table, dme.CAL_BASE + table + length)
    ((_, _, mirror),) = overlay.placement([(table, length)])   # where install will put it
    x = Xref(b, [flash_range, (mirror, mirror + length)])
    peers.run(int(pre * b.ips))                      # before: reads from flash
    overlay.install(b.m, [(table, length)])
    if edit:
        data = bytearray(b.m.read(mirror, length))
        for i in range(len(data)):
            data[i] ^= 0x55
        b.m.write(mirror, bytes(data))
    peers.run(int(post * b.ips))                     # after: reads from the mirror

    readers = {fmap.label(pc): hit
               for pc, hit in x.touched(flash_range, (mirror, mirror + length)).items()}
    state = (b.m.sda16(dme.VAR_N), b.m.read8(0x3F9C43))
    return readers, b.m.read(RAM_LO, RAM_LEN), state


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seconds", type=float, default=0.15, metavar="POST",
                    help="seconds after the mirror is installed (default 0.15)")
    ap.add_argument("--table", type=lambda s: int(s, 0), default=TABLE, metavar="OFFSET",
                    help=f"calibration offset of the table to mirror (default 0x{TABLE:X})")
    args = ap.parse_args()
    table, length, pre = args.table, LENGTH, 0.1

    readers, ram, state = run(False, table, length, pre, args.seconds)
    print(f"unedited run: N={state[0]}, engine_state={state[1]:#04x}")
    print(f"table 0x{table:X} readers ({len(readers)} sites):")
    for label, (count, flash, mirror) in sorted(readers.items(), key=lambda kv: -kv[1][0]):
        print(f"  {label:44s} x{count:6d}  flash={'y' if flash else '-'} mirror={'y' if mirror else '-'}")

    readers2, ram2, state2 = run(True, table, length, pre, args.seconds)
    diffs = [i for i, (a, b) in enumerate(zip(ram, ram2)) if a != b]
    print(f"\nedited run (mirror XOR 0x55): N={state2[0]}, engine_state={state2[1]:#04x}")
    print(f"small-data RAM {RAM_LO:#x}+{RAM_LEN:#x}: {len(diffs)} differing bytes")
    for i in diffs[:10]:
        print(f"  {RAM_LO + i:#08x}: {ram[i]:02x} -> {ram2[i]:02x}")
    print("\nverdict:",
          "reads relocated and the edit changed the computation" if diffs and
          any(m for _, (_, _, m) in readers2.items()) else "INCOMPLETE")


if __name__ == "__main__":
    main()
