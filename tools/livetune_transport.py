#!/usr/bin/env python
"""Milestone 3 of the live-tune build (docs/livetune-design.md): the
transport, live. Boots the car's pair with overlay + transport patches,
runs the engine, then tunes the hottest table entirely over the emulated
K line with our 0x6C define-packets:

  - open the table (2C 6C 01 ...): the mirror seeds, the library's reads
    relocate — while the engine runs;
  - edit cells (2C 6C 02 ...): what the program computes changes;
  - close (2C 6C 03): reads return to flash.

    .venv/bin/python tools/livetune_transport.py [--seconds 0.2] [--table 0x52F9]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu import dme, overlay, transport                # noqa: E402
from ms45emu.board import Board                            # noqa: E402
from ms45emu.e46 import running                            # noqa: E402
from ms45emu.image import load_named                       # noqa: E402
from ms45emu.kwp import Tester                             # noqa: E402
from ms45emu.xref import Xref                              # noqa: E402

TABLE, LENGTH = 0x52F9, 0x208      # the hottest table of the milestone-1 profile


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seconds", type=float, default=0.2, metavar="RUN",
                    help="seconds of engine run per phase (default 0.2)")
    ap.add_argument("--table", type=lambda s: int(s, 0), default=TABLE, metavar="OFFSET",
                    help=f"calibration offset of the table to tune (default 0x{TABLE:X})")
    args = ap.parse_args()
    table, length = args.table, LENGTH

    b = Board(transport.build(overlay.build(load_named("session1"))))
    peers = running(b)
    t = Tester(b)

    flash_range = (dme.CAL_BASE + table, dme.CAL_BASE + table + length)
    ((_, _, mirror),) = overlay.placement([(table, length)])   # where open will put it
    x = Xref(b, [flash_range, (mirror, mirror + length)])

    print("engine at 900 rpm; tuning over the K line")
    peers.run(int(args.seconds * b.ips))
    slot, got = transport.open_table(t, table, length)
    assert got == mirror, (got, mirror)
    print(f"  2C 6C 01 opened cal 0x{table:X} as slot {slot} at 0x{mirror:X}")
    peers.run(int(args.seconds * b.ips))                       # reads relocate now

    # an edit a tuner might make: the whole table +0x10, clamped
    data = bytes(min(0xFF, v + 0x10) for v in b.m.read(mirror, length))
    for off in range(0, length, 0x40):                         # 64-byte write cells
        chunk = data[off:off + 0x40]
        assert transport.write_cell(t, slot, off, list(chunk))
    print(f"  2C 6C 02 wrote {length} bytes across {round(length / 0x40)} requests")
    peers.run(int(args.seconds * b.ips))

    readers = x.touched(flash_range, (mirror, mirror + length))
    relocated = sum(c for c, _, mir in readers.values() if mir)
    stayed = sum(c for c, hit, _ in readers.values() if hit)
    print(f"  readers of the table: {relocated} reads from the mirror, {stayed} from flash")

    n = b.m.sda16(dme.VAR_N)
    print(f"  engine still running: N={n}, engine_state={b.m.read8(0x3F9C43):#04x}")

    transport.close_all(t)
    peers.run(int(args.seconds * b.ips))
    after = len(x.touched((mirror, mirror + length)))
    print(f"  2C 6C 03 closed: {after} reads from the mirror since")
    print("\nverdict:", "live tuning over the K line works"
          if relocated and n else "INCOMPLETE")


if __name__ == "__main__":
    main()
