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

The DME follows the car's key like the real one: it is powered by KL15,
which the bridge infers from the bus (the DSC sends 0x153 only with the
ignition on). Key on: boot on the saved EEPROM image and run. Key off
(no 0x153 for a second): after-run, EEPROM written and saved, DME off
and silent until the next key-on. In the accessory position a real DME
is off, and so is this one. Without --follow-bus (and in --virtual mode)
the ignition is on until you press `k`.

Keys while running: `2` press pedal+brake (the gesture), `0` release,
`k` ignition off, `i` ignition on, `q` quit.
"""
import argparse
import os
import select
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu import load_pair, dme           # noqa: E402
from ms45emu.board import Board              # noqa: E402
from ms45emu.e46 import FRAME_INSTRUCTIONS, ASC1   # noqa: E402

KL15_TIMEOUT = 1.0                           # seconds without 0x153 = ignition off


class Dme:
    """One key cycle of the DME: boot, run, after-run, off."""

    def __init__(self, pair, eeprom_path, on_tx, inputs):
        self.pair = pair
        self.eeprom_path = eeprom_path
        self.on_tx = on_tx
        self.inputs = inputs
        self.board = None

    @property
    def on(self):
        return self.board is not None

    def key_on(self):
        b = Board(load_pair(self.pair))
        if os.path.exists(self.eeprom_path):
            b.load_eeprom(open(self.eeprom_path, "rb").read())
        b.can_a.on_tx = self.on_tx
        m = b.m
        hook = dme.tach_hook_target(m)
        if hook is not None:
            inputs = self.inputs

            def force(_):            # the sensors behind these are not modelled
                m.set_sda8(dme.VAR_PV, inputs["pedal"])
                m.set_sda8(dme.VAR_BRK_A, 1 if inputs["brake"] else 0)
                m.set_sda8(dme.VAR_BRK_B, 1 if inputs["brake"] else 0)
            b.probe(hook, "hook", on_hit=force)
        print("key on: booting...", flush=True)
        b.boot(max_insns=20_000_000)
        self.board = b
        print("DME running", flush=True)

    def key_off(self):
        if self.board is not None and self.board.kl15:
            self.board.ignition(False)
            print("key off: after-run...", flush=True)

    def run(self, instructions):
        b = self.board
        b.run(instructions)
        if b.powered_down:
            os.makedirs(os.path.dirname(self.eeprom_path) or ".", exist_ok=True)
            open(self.eeprom_path, "wb").write(b.eeprom_image())
            print(f"DME off; EEPROM writes={b.qspi.eeprom.writes}, image saved to {self.eeprom_path}", flush=True)
            self.board = None

    def receive(self, ident, data, extended=False):
        if self.board is not None:
            self.board.can_a.receive(ident, data, extended)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair", default="patched", choices=["stock", "patched"])
    ap.add_argument("--interface", default=None, help="python-can interface (slcan, gs_usb, socketcan, pcan, ...)")
    ap.add_argument("--channel", default=None)
    ap.add_argument("--bitrate", type=int, default=500000)
    ap.add_argument("--virtual", action="store_true", help="no adapter; print the DME's frames")
    ap.add_argument("--eeprom", default="images/eeprom.bin", help="EEPROM image to load and save")
    ap.add_argument("--follow-bus", action="store_true", help="take KL15 from the bus (0x153 present)")
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

    sent = [0]

    def on_tx(frame):
        sent[0] += 1
        if bus is not None:
            import can
            bus.send(can.Message(arbitration_id=frame.id, data=frame.data, is_extended_id=frame.extended))
        elif frame.id == 0x316:
            rpm = (frame.data[2] | frame.data[3] << 8) / 6.4
            print(f"\r0x316 rpm={rpm:6.0f} data={frame.data.hex()}  sent={sent[0]}", end="", flush=True)

    inputs = {"pedal": 0, "brake": False}
    dme_unit = Dme(args.pair, args.eeprom, on_tx, inputs)
    follow = args.follow_bus and bus is not None
    last_asc1 = None
    if not follow:
        dme_unit.key_on()
    else:
        print("waiting for the ignition (0x153 on the bus)...", flush=True)
    print("keys: 2 gesture, 0 release, k ignition off, i ignition on, q quit", flush=True)

    try:
        while True:
            if bus is not None:
                while True:
                    msg = bus.recv(timeout=0)
                    if msg is None:
                        break
                    if msg.arbitration_id == ASC1:
                        last_asc1 = time.time()
                    dme_unit.receive(msg.arbitration_id, bytes(msg.data), msg.is_extended_id)
            if follow:
                kl15 = last_asc1 is not None and time.time() - last_asc1 < KL15_TIMEOUT
                if kl15 and not dme_unit.on:
                    dme_unit.key_on()
                elif not kl15:
                    dme_unit.key_off()
            if dme_unit.on:
                dme_unit.run(FRAME_INSTRUCTIONS)
            else:
                time.sleep(0.05)
            if select.select([sys.stdin], [], [], 0)[0]:
                key = sys.stdin.readline().strip()
                if key == "2":
                    inputs.update(pedal=0xFF, brake=True); print("\npedal+brake held")
                elif key == "0":
                    inputs.update(pedal=0, brake=False); print("\nreleased")
                elif key == "k":
                    dme_unit.key_off()
                elif key == "i" and not dme_unit.on:
                    dme_unit.key_on()
                elif key == "q":
                    break
    finally:
        if dme_unit.on:
            os.makedirs(os.path.dirname(args.eeprom) or ".", exist_ok=True)
            open(args.eeprom, "wb").write(dme_unit.board.eeprom_image())
            print(f"\nEEPROM saved to {args.eeprom}")
        if bus is not None:
            bus.shutdown()


if __name__ == "__main__":
    main()
