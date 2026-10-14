#!/usr/bin/env/python3
"""Runtime half of the pool audit: does anything write the live tune's
RAM while the DME runs the way it runs on the car -- engine turning,
E46 peers on the bus, and a diagnostic session with logging going.

The static half (tools/r13_store_audit.py) found 139 fixed r13 stores
inside pool A (0x3F9E98-0x3FA0A0) and 6 inside the bitmap span, all in
boot-loader code (ext < 0x40000: fault stubs that hang, counters, the
diag timing handler's neighbourhood).  Static sites are not executions:
this watches the spans under unicorn hooks for the whole run and lists
every site that actually wrote, with the values.

    .venv/bin/python tools/pool_a_runtime_check.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu.image import Pair                            # noqa: E402
from ms45emu.board import Board                           # noqa: E402
from ms45emu.e46 import Peers                             # noqa: E402
from ms45emu.kwp import Tester                            # noqa: E402
from ms45emu.xref import Xref                             # noqa: E402

RANGES = [                                   # the live tune's RAM, per overlay.py
    (0x3F9858, 0x3F9894),                    # bitmap + SAVE_ARMED
    (0x3F9894, 0x3F98B0),                    # pool D
    (0x3F9B43, 0x3F9C42),                    # the 2C-F0 store (stock's own -- for contrast)
    (0x3F9C48, 0x3F9E00),                    # descriptors
    (0x3F9E10, 0x3F9E74),                    # pool C
    (0x3F9E74, 0x3F9E98),                    # state block
    (0x3F9E98, 0x3FA0A0),                    # pool A
]


def main():
    pair = Pair(open("images/session1clean.flash.bin", "rb").read(),
                open("images/session1clean.mpc.bin", "rb").read(), "session1clean")
    b = Board(pair, mips=40)
    b.boot(max_insns=int(0.5 * b.ips))
    peers = Peers(b)
    t = Tester(b)

    x = Xref(b, RANGES)
    b.crank.rpm = 900                       # engine turning before the watchers? no: hooks are on
    print("watching", ", ".join(f"{lo:#x}-{hi:#x}" for lo, hi in RANGES))

    # the run: idle with the engine turning, then a logging session with a
    # define and packet reads -- the KWP paths the loader serves
    b.run(int(2.0 * b.ips))
    peers.run(int(2.0 * b.ips))
    ok = t.logging_mode()
    print("logging session:", ok)
    req, position = [0x2C, 0xF0], 1
    for _ in range(36):
        req += [0x03, position, 1, 0x3F, 0xA0, 0x00]
        position += 1
    print("define:", t.request(req) and "ok")
    for _ in range(20):
        t.read_packet()
    t.read_memory(0x3F9C48, 64)
    b.run(int(1.0 * b.ips))
    peers.run(int(1.0 * b.ips))

    print(f"\n{x.reads} reads, {x.writes} writes")
    print(x.report())
    x.detach()
    return 0


if __name__ == "__main__":
    sys.exit(main())
