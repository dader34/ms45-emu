#!/usr/bin/env python
"""Put the emulated DME on a real CAN bus.

    .venv/bin/pip install python-can
    .venv/bin/python tools/bench.py --interface slcan --channel /dev/tty.usbmodemXXXX --bitrate 500000
    .venv/bin/python tools/bench.py --interface gs_usb                   # candleLight firmware (CANable clones)
    .venv/bin/python tools/bench.py --interface socketcan --channel can0
    .venv/bin/python tools/bench.py --virtual              # no adapter: print what the DME sends

A CANable with slcan firmware is a serial port and needs nothing else.
With candleLight (gs_usb) firmware on macOS: `brew install libusb` and
`pip install pyusb`, then --interface gs_usb (channel defaults to the
first device; pass --channel 0/1 for a second one).

Frames the DME transmits on module A go out on the adapter as they are
built; frames seen on the adapter are fed to the DME's receive buffers.
The emulator runs slower than real time (about 4x), so the DME's 10 ms
frames arrive every 40 ms or so of wall time, which a cluster tolerates.

Keys while running: `2` press pedal+brake (the gesture), `0` release,
`k` ignition off (after-run, then the EEPROM image is saved), `q` quit.
"""
import argparse
import os
import select
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu import load_pair, dme           # noqa: E402
from ms45emu.board import Board              # noqa: E402
from ms45emu.e46 import FRAME_INSTRUCTIONS   # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair", default="patched", choices=["stock", "patched"])
    ap.add_argument("--interface", default=None, help="python-can interface (slcan, socketcan, pcan, ...)")
    ap.add_argument("--channel", default=None)
    ap.add_argument("--bitrate", type=int, default=500000)
    ap.add_argument("--virtual", action="store_true", help="no adapter; print the DME's frames")
    ap.add_argument("--eeprom", default="images/eeprom.bin", help="EEPROM image to load and save")
    args = ap.parse_args()

    bus = None
    if not args.virtual:
        import can
        if args.interface is None:
            ap.error("--interface is required unless --virtual")
        kwargs = {"bitrate": args.bitrate}
        if args.interface == "gs_usb":
            kwargs.update(channel=int(args.channel or 0), index=int(args.channel or 0))
        else:
            kwargs["channel"] = args.channel
        bus = can.Bus(interface=args.interface, **kwargs)

    board = Board(load_pair(args.pair))
    if os.path.exists(args.eeprom):
        board.load_eeprom(open(args.eeprom, "rb").read())
        print(f"EEPROM loaded from {args.eeprom}")

    sent = [0]

    def on_tx(frame):
        sent[0] += 1
        if bus is not None:
            import can
            bus.send(can.Message(arbitration_id=frame.id, data=frame.data, is_extended_id=frame.extended))
        elif frame.id == 0x316:
            rpm = (frame.data[2] | frame.data[3] << 8) / 6.4
            print(f"\r0x316 rpm={rpm:6.0f} data={frame.data.hex()}  sent={sent[0]}", end="", flush=True)

    board.can_a.on_tx = on_tx

    inputs = {"pedal": 0, "brake": False}
    m = board.m
    hook = dme.tach_hook_target(m)
    if hook is not None:
        def force(_):
            m.set_sda8(dme.VAR_PV, inputs["pedal"])
            m.set_sda8(dme.VAR_BRK_A, 1 if inputs["brake"] else 0)
            m.set_sda8(dme.VAR_BRK_B, 1 if inputs["brake"] else 0)
        board.probe(hook, "hook", on_hit=force)

    print("booting...", flush=True)
    board.boot(max_insns=20_000_000)
    print("running; keys: 2 gesture, 0 release, k ignition off, q quit", flush=True)
    t0 = time.time()
    try:
        while True:
            if bus is not None:
                while True:
                    msg = bus.recv(timeout=0)
                    if msg is None:
                        break
                    board.can_a.receive(msg.arbitration_id, bytes(msg.data), msg.is_extended_id)
            board.run(FRAME_INSTRUCTIONS)
            if select.select([sys.stdin], [], [], 0)[0]:
                key = sys.stdin.readline().strip()
                if key == "2":
                    inputs.update(pedal=0xFF, brake=True); print("\npedal+brake held")
                elif key == "0":
                    inputs.update(pedal=0, brake=False); print("\nreleased")
                elif key == "k":
                    board.ignition(False); print("\nignition off")
                elif key == "q":
                    break
            if board.powered_down:
                print(f"\npowered down after {time.time() - t0:.0f}s; EEPROM writes={board.qspi.eeprom.writes}")
                break
    finally:
        os.makedirs(os.path.dirname(args.eeprom) or ".", exist_ok=True)
        open(args.eeprom, "wb").write(board.eeprom_image())
        print(f"EEPROM saved to {args.eeprom}")
        if bus is not None:
            bus.shutdown()


if __name__ == "__main__":
    main()
