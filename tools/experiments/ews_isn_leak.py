"""Can the car's ISN be read over plain KWP diagnostics -- no fast-flasher
push, nothing installed, stock firmware only?

Two candidates on the running DME:
  0x23 ReadMemoryByAddress  -- straight at the RAM slots (isn 0x3FC9BC,
      ~isn 0x3FC9B0, workA 0x3FD538), plus the flash ring 0x1FB00 as a
      control for range rules
  0x21 ReadDataByLocalIdentifier -- sweep every LID and grep the answers
      for the EWS identity bytes; a status block that formats those slots
      is a stock RAM leak

The emu never fills the EWS slots (no terminal-50 stimulus), so the live
car values are dropped in by hand first; any job that answers with them
is reading exactly that RAM.

    .venv/bin/python -m tools.experiments.ews_isn_leak
"""
import sys

from ms45emu.image import load_named
from ms45emu.board import Board
from ms45emu.kwp import Tester

WORKA, WORKB = 0x3FD538, 0x3FDC70
ISN, NOTISN, ACCEPTED = 0x3FC9BC, 0x3FC9B0, 0x3FC9AC
RING = 0x1FB00

NEEDLES = {
    b"\xa3\x56": "isn A356",
    b"\x5c\xa9": "~isn 5CA9",
    b"\xff\xff\x5c\xa9": "~isn word",
    b"\x00\xff\x5c\x56": "workA telegram",
    b"\x89\xab\xcd\xef": "workB marker",
}
NRC = {0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
       0x22: "conditionsNotCorrect", 0x31: "requestOutOfRange",
       0x33: "securityAccessDenied", 0x72: "generalProgrammingFailure"}


def show(r):
    if r is None:
        return "no answer"
    if len(r) >= 3 and r[0] == 0x7F:
        return f"NEG {NRC.get(r[2], hex(r[2]))} ({r.hex()})"
    return f"OK  {r.hex()}"


def try_memory(t, addr, size, sel):
    """The factory SPEICHER_LESEN encoding (ms450ds0): 0x23 with a 3-byte
    segment-relative address, a SEGMENT selector (LAR=00, FLASH=06), and
    the count -- no ISO format byte."""
    return t.request([0x23] + list(addr.to_bytes(3, "big")) + [sel, size])


def main():
    b = Board(load_named("session1"))
    b.boot(max_insns=20_000_000)
    t = Tester(b)

    b.m.write32(ISN, 0x0000A356)
    b.m.write32(NOTISN, 0xFFFF5CA9)
    b.m.write32(ACCEPTED, 0x0000A356)
    b.m.write32(WORKA, 0x00FF5C56)
    b.m.write32(WORKB, 0x89ABCDEF)

    print("== 0x23 factory dialect: segment sweep at offset 0 ==")
    for sel in range(0x100):
        r = try_memory(t, 0, 8, sel)
        if r and r[0] != 0x7F:
            print(f"  sel {sel:02X}: {r.hex()}")
        if sel > 0x20 and r and len(r) >= 3 and r[0] == 0x7F:
            # keep sweeping but stay quiet about negatives
            pass

    print("\n== aim the live selectors at the ISN slots ==")
    # planted: accepted@C9AC=0000A356  ~isn@C9B0=FFFF5CA9  isn@C9BC=0000A356
    #          workA@D538=00FF5C56     workB@DC70=89ABCDEF
    for sel in (0x00, 0x02, 0x06, 0x07):
        for where, addr in (("abs 0x3FC9B0", 0x3FC9B0), ("sram off 0x31B0", 0x31B0),
                            ("sram off 0x3D38", 0x3D38)):
            r = try_memory(t, addr, 16, sel)
            tag = ""
            if r and r[0] != 0x7F:
                body = bytes(r[1:])
                for needle, name in ((b"\xa3\x56", "A356"), (b"\x5c\xa9", "5CA9"),
                                     (b"\x00\xff\x5c\x56", "workA"), (b"\x89\xab\xcd\xef", "workB")):
                    if needle in body:
                        tag = f"  <-- {name} at +{body.index(needle) - 1}"
                        break
            print(f"  sel {sel:02X} {where:14s}: {show(r)}{tag}")

    print("\n== sweep 0x21 LIDs, grep for the identity bytes ==")
    hits, pos = [], 0
    for lid in range(0x100):
        r = t.request([0x21, lid])
        if r is None or (len(r) >= 3 and r[0] == 0x7F):
            continue
        pos += 1
        for needle, tag in NEEDLES.items():
            if needle in r:
                off = r.index(needle)
                hits.append((lid, tag, off, r))
                break
    print(f"  {pos} of 256 LIDs answered positive")
    for lid, tag, off, r in hits:
        print(f"\n  LID {lid:02X}  contains {tag} at +{off}:")
        print(f"    {r.hex()}")
    if not hits:
        print("  none of the LID answers carry the ISN bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
