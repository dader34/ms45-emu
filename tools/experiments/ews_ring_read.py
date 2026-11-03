"""Round-trip the zero-install ISN read against the real flash ring.

Offline, the ring at ext 0x1FB00 of the car's own image decodes with
voted_isn() (tools/proofs/isn_burn_test.py).  Here the same image runs
under the emulator and the stock KWP service answers, so the live
frames execute for real:

    23 01 FB 00 02 18   SPEICHER_LESEN FLASH window -> the ring bytes -> ISN
                        (selector 00 at 0x1FB00 hits MPC internal code, not
                        the external chip -- falsified 2026-10-30)
    23 3F C9 B0 00 10   the RAM slots (~isn / isn)
    23 3F 9E 06 00 04   the EWS handshake copy (the value the EWS sees)

at three stimulus levels -- idle boot, ignition on, crank-to-idle --
answering the open detail: does anything but the ring ever carry the
ISN before a real terminal-50 crank?

    .venv/bin/python -m tools.experiments.ews_ring_read
"""
import sys

from ms45emu.image import load_named
from ms45emu.board import Board
from ms45emu.kwp import Tester

RING, RAM_ISN, HANDSHAKE = 0x1FB00, 0x3FC9B0, 0x3F9E06


def voted_isn(six):
    V = (six[4] << 8) | six[3]
    hi, lo = (V >> 8) & 0xFF, V & 0xFF
    ok = (six[0] == (~V >> 8) & 0xFF and six[1] == ~V & 0xFF
          and six[2] == ~hi & 0xFF and six[3] == lo
          and six[4] == hi and six[5] == ~lo & 0xFF)
    return V if ok else None


def read(t, addr, n, sel=0x00):
    return t.request([0x23] + list(addr.to_bytes(3, "big")) + [sel, n])


def stage(t, b, label):
    print(f"\n== {label} ==")
    r = read(t, RING, 0x18, sel=0x02)
    body = bytes(r[1:]) if r and r[0] != 0x7F else b""
    v = voted_isn(body[:6]) if len(body) >= 6 else None
    print(f"  ring 23 01 FB 00 02 18 -> {body[:6].hex(' ')}"
          f"  votes {f'{v:04X}' if v else 'no vote'}")
    r = read(t, RAM_ISN, 16)
    body = bytes(r[1:]) if r and r[0] != 0x7F else b""
    notisn = int.from_bytes(body[0:4], "big") if len(body) >= 16 else None
    isn = int.from_bytes(body[12:16], "big") if len(body) >= 16 else None
    print(f"  RAM  23 3F C9 B0 00 10 -> ~isn={notisn:08X} isn={isn:08X}"
          if isn is not None else f"  RAM -> {r.hex() if r else 'no answer'}")
    r = read(t, HANDSHAKE, 4)
    body = bytes(r[1:]) if r and r[0] != 0x7F else b""
    print(f"  hs   23 3F 9E 06 00 04 -> {body.hex(' ')}")
    # ground truth straight out of CPU memory, independent of KWP
    gt = bytes(b.m.read8(a) for a in range(RAM_ISN, RAM_ISN + 16))
    hgt = bytes(b.m.read8(a) for a in range(HANDSHAKE, HANDSHAKE + 4))
    print(f"  (memory: ~isn={int.from_bytes(gt[0:4], 'big'):08X}"
          f" isn={int.from_bytes(gt[12:16], 'big'):08X}  hs={hgt.hex(' ')})")


def main():
    pair = load_named("session1")
    ring = bytes(pair.flash[RING:RING + 6])
    v = voted_isn(ring)
    print(f"image ring @0x1FB00: {ring.hex(' ')}  -> offline decode "
          f"{f'{v:04X}' if v else 'NO VOTE'}")

    b = Board(pair)
    b.boot(max_insns=20_000_000)
    t = Tester(b)
    stage(t, b, "idle boot")

    b.ignition(True)
    b.run(200_000_000)
    stage(t, b, "ignition on, 5 s")

    from ms45emu import e46
    e46.running(b)                       # crank straight to idle
    b.run(200_000_000)
    stage(t, b, "engine running, 5 s idle")
    return 0


if __name__ == "__main__":
    sys.exit(main())
