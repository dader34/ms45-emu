#!/usr/bin/env python
"""Who reads and writes an address: ask the running program (ms45emu/xref.py).

    .venv/bin/python tools/xref.py 0x3FA195                  # the map-switch flag byte
    .venv/bin/python tools/xref.py r13-0x4BEC --rpm 800      # engine speed, with the crank turning
    .venv/bin/python tools/xref.py 0xFFE40000:0x400 --pair stock   # the first calibration block
    .venv/bin/python tools/xref.py 0x3FD853 --key-off --seconds 3  # the KL15 flag through the after-run
    .venv/bin/python tools/xref.py 0x305xxx --boot --trace    # a register, from the first instruction

The pair is booted under Board, the OS left to settle, and then the address
is watched for a stretch of DME time with the E46's other modules on the
CAN bus. Every instruction that touched it is listed with how often, the
values it read or wrote, the function it sits in (a guess from the code
around it) and the LR at the time, which is where that function was
called from. --trace prints the accesses as they happen as well.

Addresses: CPU addresses, or r13/r2 relative as the disassembly shows them
(`r13-0x4BEC`, `r2+0x2C`), a range (`0x3FA195..0x3FA197`) or a length
(`0x3FA195:4`). Calibration addresses are watched in both flash windows.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu import load_pair                           # noqa: E402
from ms45emu.board import Board                         # noqa: E402
from ms45emu.e46 import Peers                           # noqa: E402
from ms45emu.image import Pair, ENV_NAMES               # noqa: E402
from ms45emu.xref import Xref, parse_address            # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("address", nargs="+", type=parse_address, help="what to watch (see above)")
    ap.add_argument("--pair", default="patched", choices=list(ENV_NAMES))
    ap.add_argument("--flash")
    ap.add_argument("--mpc")
    ap.add_argument("--program", default=None, metavar="FILE.0PA", help="one of BMW's program files, written onto the pair first")
    ap.add_argument("--calibration", default=None, metavar="FILE.0DA")
    ap.add_argument("--eeprom", default=None, help="EEPROM image to boot on (default: blank)")
    ap.add_argument("--mips", type=int, default=40)
    ap.add_argument("--settle", type=float, default=0.5, metavar="SECONDS",
                    help="DME time to run before watching starts (default 0.5: the OS is up and its tasks run)")
    ap.add_argument("--seconds", type=float, default=1.0, help="DME time to watch (default 1)")
    ap.add_argument("--boot", action="store_true", help="watch from the first instruction instead (no settling)")
    ap.add_argument("--rpm", type=float, default=0, help="turn the crank at this speed")
    ap.add_argument("--automatic", action="store_true", help="a gearbox on the bus too (EGS frames)")
    ap.add_argument("--speed", type=float, default=0, metavar="KMH", help="vehicle speed in the ASC frame")
    ap.add_argument("--key-off", action="store_true", help="switch the ignition off when watching starts (the after-run)")
    ap.add_argument("--trace", action="store_true", help="print each access as it happens")
    ap.add_argument("--limit", type=int, default=200, help="accesses to print with --trace (default 200)")
    args = ap.parse_args()

    if args.flash and args.mpc:
        with open(args.flash, "rb") as f, open(args.mpc, "rb") as m:
            name = os.path.basename(args.flash).rsplit(".", 1)[0].replace("_Flash", "")
            pair = Pair(f.read(), m.read(), name)
    elif args.program or args.calibration:
        from ms45emu import daten
        pair = daten.load(args.pair, args.program, args.calibration, say=lambda text: print(text, flush=True))
    else:
        pair = load_pair(args.pair)

    b = Board(pair, mips=args.mips)
    if args.eeprom and os.path.exists(args.eeprom):
        b.load_eeprom(open(args.eeprom, "rb").read())
    peers = Peers(b, automatic=args.automatic)
    if args.speed:
        peers.set_speed(args.speed)
    b.crank.rpm = args.rpm
    trace = (lambda text: print(text, flush=True)) if args.trace else None

    print(f"{pair.name}: program {pair.program_id.decode('latin1')}", flush=True)
    if args.boot:
        x = Xref(b, args.address, trace=trace, trace_limit=args.limit)
        print("watching from reset", flush=True)
        b.boot(max_insns=int(args.seconds * b.ips))
    else:
        print(f"booting, {args.settle:g} s to settle...", flush=True)
        b.boot(max_insns=int(args.settle * b.ips))
        x = Xref(b, args.address, trace=trace, trace_limit=args.limit)
        if args.key_off:
            b.ignition(False)
            print("ignition off", flush=True)
        print(f"watching for {args.seconds:g} s", flush=True)
        peers.run(int(args.seconds * b.ips))
    if args.trace and x.traced >= args.limit:
        print(f"... ({args.limit} printed; --limit for more)")
    print(x.report())
    if b.powered_down:
        print("(the DME powered down during the watch)")


if __name__ == "__main__":
    main()
