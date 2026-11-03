"""EWS_STARTWERT on real firmware: what the stock DME does with the
alignment jobs INPA's "EWS-Startwertabgleich MS45" screen sends.

The SGBD decode (ms450ds0.prg, sgbd_survey BEST2 walk):
    EWS_STARTWERT == STEUERN_SYNC_MODE -> 31 83 00 / 31 83 01
    EWS_EMPFANG    == STATUS_SYNC_MODE -> 21 06
    STATUS_EWS_LOCK                   -> 21 49
    AUTHENTISIERUNG_ZUFALLSZAHL_LESEN  -> 31 07 00 (level 0; the flasher
    uses 31 07 03 <uid> + 31 08 <rsa key>)

This asks the running program, not the disassembly: does the job answer
without security access, what does it answer, what moves in RAM (the
matcher's slots, the sync-mode state), and does anything ever reach the
flash ring at 0x1FB00 or the EEPROM. Run from the ms45-emu root:

.venv/bin/python -m tools.experiments.ews_startwert
"""
import sys

from ms45emu.image import load_named
from ms45emu.board import Board
from ms45emu.kwp import Tester, auth_key

RING = 0x1FB00                          # external flash: the ISN ring

# absolute RAM addresses (r13 = 0x4017F0), from the firmware trace
WATCH = [
    ("isn        0x3FC9BC", 0x3FC9BC, 2),
    ("~isn       0x3FC9B0", 0x3FC9B0, 2),
    ("accepted   0x3FC9AC", 0x3FC9AC, 2),
    ("gate       0x3FDC79", 0x3FDC79, 1),
    ("sync state 0x3FDC6E", 0x3FDC6E, 1),
    ("ews flag   0x3FDC7A", 0x3FDC7A, 1),
    ("reject     0x3FEFAC", 0x3FEFAC, 2),
]


def state(b):
    return {name: bytes(b.m.read8(at) for _ in range(at, at + size)).hex()
            for name, at, size in WATCH}


def show(b, baseline=None):
    now = state(b)
    for name in now:
        mark = "" if baseline is None or now[name] == baseline[name] else "   <-- CHANGED"
        print(f"    {name}: {now[name]}{mark}")
    return now


def flash_diff(before, after):
    runs, at = [], None
    for i in range(len(before)):
        if before[i] != after[i]:
            if at is None:
                at = i
        elif at is not None:
            runs.append((at, i))
            at = None
    if at is not None:
        runs.append((at, len(before)))
    return runs


def say(t, label, data):
    r = t.request(list(data))
    if r is None:
        print(f"  {label:34s} > {data.hex()}  < no answer")
    elif r and r[0] == 0x7F:
        print(f"  {label:34s} > {data.hex()}  < NRC {r.hex()}  ({NRC.get(r[2], '?')})")
    else:
        print(f"  {label:34s} > {data.hex()}  < {bytes(r).hex()}")
    return r


NRC = {0x11: "service not supported", 0x12: "sub not supported",
       0x21: "busy", 0x22: "conditions not correct", 0x31: "request out of range",
       0x33: "security access denied", 0x35: "invalid key", 0x36: "exceeded attempts"}


def main():
    b = Board(load_named("session1"))
    print("booting ...")
    b.boot(max_insns=20_000_000)
    t = Tester(b)
    t.trace = "-v" in sys.argv

    flash0 = bytes(b.flash.image)
    ee0 = b.eeprom_image()

    ident = t.ident()
    print(f"IDENT: {bytes(ident or b'').hex()[:24]} ...")
    assert ident and ident[0] == 0x5A

    print("\n== baseline (no auth) ==")
    base = show(b)
    say(t, "EWS_EMPFANG 21 06", bytes([0x21, 0x06]))
    say(t, "STATUS_EWS_LOCK 21 49", bytes([0x21, 0x49]))

    print("\n== the alignment job, unauthenticated ==")
    for arg in (0x00, 0x01):
        say(t, f"EWS_STARTWERT 31 83 {arg:02x}", bytes([0x31, 0x83, arg]))
    base = show(b, base)

    print("\n== security access: SGBD form 31 07 00 vs flasher's 31 07 03 ==")
    seed0 = say(t, "seed level 0", bytes([0x31, 0x07, 0x00]))
    serial = t.serial()
    seed3 = say(t, "seed level 3", bytes([0x31, 0x07, 0x03, 0x9B, 0x8E, 0xDA, 0xAE]))

    print("\n== authenticate (flasher's RSA), then the alignment job again ==")
    if not t.authenticate():
        print("  authenticate() failed")
    else:
        print("  authenticate() OK")
    base = show(b, base)
    for arg in (0x00, 0x01):
        say(t, f"EWS_STARTWERT 31 83 {arg:02x}", bytes([0x31, 0x83, arg]))
    show(b, base)
    say(t, "EWS_EMPFANG 21 06 (after)", bytes([0x21, 0x06]))
    say(t, "STATUS_EWS_LOCK 21 49 (after)", bytes([0x21, 0x49]))

    print("\n== what moved in the flash chip? ==")
    runs = flash_diff(flash0, bytes(b.flash.image))
    if not runs:
        print("  nothing (ring at 0x1FB00 untouched)")
    for at, end in runs:
        print(f"  {at:#08x}-{end:#08x}: {bytes(b.flash.image[at:end])[:24].hex()}")

    print("\n== key off: after-run, then the EEPROM ==")
    b.ignition(False)
    b.run(200_000_000)
    print("  powered down:", b.powered_down)
    diff = flash_diff(ee0, b.eeprom_image())
    if not diff:
        print("  EEPROM unchanged")
    for at, end in diff:
        print(f"  EEPROM {at:#06x}-{end:#06x}: was {ee0[at:at+16].hex()} now {b.eeprom_image()[at:at+16].hex()}")
    print("\n  (ring bytes now:", bytes(b.flash.image[RING:RING + 0x18]).hex(), ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
