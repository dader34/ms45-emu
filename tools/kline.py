#!/usr/bin/env python
"""The emulated DME on a serial port, for INPA / EDIABAS / the flasher app.

    .venv/bin/python tools/kline.py [--pair patched] [--eeprom images/eeprom.bin]

Prints the pseudo-terminal to point the tester at (e.g. /dev/ttys012) and
then plays the K line: bytes the tester writes are echoed back (a K-line
cable hears its own transmission) and fed to the DME's SCI; bytes the DME
transmits go out to the tester. The DME runs with the ignition on until
the tester goes away or `q`.

The DME speaks KWP2000* (B8 12 F1 <len> <data> <xor>) through its own
diagnostic code, so anything EDIABAS can do with ms450ds0.prg works here
as far as the hardware behind it is modelled: identification, memory
reads, fault memory, and the flash jobs against the flash models.
"""
import argparse
import os
import select
import sys
import termios
import time
import tty

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu import load_pair                 # noqa: E402
from ms45emu.board import Board               # noqa: E402

SLICE = 100_000          # instructions between looks at the line: 2.5 ms of DME time


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair", default="patched", choices=["stock", "patched"])
    ap.add_argument("--eeprom", default="images/eeprom.bin")
    ap.add_argument("--link", default=None, help="also create this symlink to the pty (a stable name)")
    ap.add_argument("--trace", action="store_true", help="print every telegram")
    args = ap.parse_args()

    master, slave = os.openpty()
    tty.setraw(master)
    attrs = termios.tcgetattr(slave)
    attrs[3] &= ~termios.ECHO                 # the DME side does the echo, not the tty
    termios.tcsetattr(slave, termios.TCSANOW, attrs)
    name = os.ttyname(slave)
    if args.link:
        try:
            os.unlink(args.link)
        except FileNotFoundError:
            pass
        os.symlink(name, args.link)
    print(f"K line on {name}" + (f" (also {args.link})" if args.link else ""), flush=True)

    board = Board(load_pair(args.pair))
    if os.path.exists(args.eeprom):
        board.load_eeprom(open(args.eeprom, "rb").read())
    out = bytearray()
    board.sci.on_tx = out.append
    print("booting...", flush=True)
    board.boot(max_insns=20_000_000)
    print("DME running (ignition on); q to quit", flush=True)

    rx_line = bytearray()
    tx_line = bytearray()
    last = time.time()
    try:
        while True:
            r, _, _ = select.select([master, sys.stdin], [], [], 0)
            if master in r:
                data = os.read(master, 4096)
                if data:
                    os.write(master, data)                    # the cable's echo
                    board.sci.send(data)
                    rx_line += data
            if sys.stdin in r and sys.stdin.readline().strip() == "q":
                break
            board.run(SLICE)
            if out:
                os.write(master, bytes(out))
                tx_line += out
                out.clear()
            if args.trace and time.time() - last > 0.3 and (rx_line or tx_line):
                print(f"tester> {rx_line.hex()}\n   dme> {tx_line.hex()}", flush=True)
                rx_line.clear(); tx_line.clear(); last = time.time()
    finally:
        os.makedirs(os.path.dirname(args.eeprom) or ".", exist_ok=True)
        open(args.eeprom, "wb").write(board.eeprom_image())
        if args.trace and board.flash_writes:
            print(f"{len(board.flash_writes)} flash writes; first 80:")
            for a, size, v, pc in board.flash_writes[:80]:
                print(f"  {a:08X}/{size} <- {v:0{2 * size}X}  pc={pc:X}")
        if args.link:
            try:
                os.unlink(args.link)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    main()
