"""What the stock loader's erase job does with a sub-range of the program
area -- the fact that decides the minimal bootstrap install.

The full flash erases (0x02060000, 0xA0000): the loader then wipes the
three external program sectors AND all of the internal flash (docs/
flashing.md, test_flash.py). A bootstrap that installs only gate+body
(ext top 64K), the signature sector (ext 0x60000) and the hook word
(MPC 0x8) wants to know:

  1. does a small program-window erase take just the named sectors,
     or does it wipe the whole program area?
  2. does it still wipe the internal flash?
  3. does the loader even accept an erase range it never sees from
     WinKFP (a NAK is 7F 31 <code>)?

Run from the ms45-emu root:

    .venv/bin/python -m tools.proofs.bootstrap_probe [flash.bin mpc.bin]
"""
import os
import sys

from ms45emu.image import Pair
from ms45emu.board import Board, VALID_MARKS
from ms45emu.kwp import Tester

DONOR = os.path.expanduser("~/Downloads/new_reads")


def wiped_runs(before, after):
    """The (start, end) runs the erase turned to 0xFF."""
    runs, run = [], None
    for i, (a, b) in enumerate(zip(before, after)):
        if b == 0xFF and a != 0xFF:
            run = [i, i] if run is None else [run[0], i]
        elif run is not None:
            runs.append(tuple(run))
            run = None
    if run is not None:
        runs.append(tuple(run))
    return runs


def probe(pair, name, start, length):
    b = Board(pair)
    b.boot(max_insns=20_000_000)
    t = Tester(b)
    assert t.authenticate(), "auth"
    assert t.programming_mode(), "programming mode"
    f0, m0 = bytes(b.flash.image), bytes(b.cmf.image)
    r = t.request([0x31, 0x02] + t._region(start, length), timeout_frames=240)
    print(f"\n== {name}: erase({start:#010x}, {length:#x})")
    print(f"   answer: {r.hex() if r else 'NONE'}"
          f"  ({'taken' if r and r[0] == 0x71 and r[2] == 1 else 'refused' if r else 'silent'})")
    if not (r and r[0] == 0x71):
        return
    f1, m1 = bytes(b.flash.image), bytes(b.cmf.image)
    runs = wiped_runs(f0, f1)
    total = sum(e - s + 1 for s, e in runs)
    print(f"   external wiped: {total:#x} bytes in {len(runs)} runs:")
    for s, e in runs:
        print(f"      {s:#08x} .. {e:#08x}  ({e - s + 1:#x})")
    mi = sum(1 for a, c in zip(m0, m1) if c == 0xFF and a != 0xFF)
    print(f"   internal newly-FF: {mi:#x} of {len(m1):#x}"
          f"{'  (ALL internal wiped)' if mi == m1.count(0xFF) - m0.count(0xFF) and mi > 0x60000 else ''}")
    marks = [f"{at:#x}={bytes(f1[at:at + 4]).hex()}" for at, _ in VALID_MARKS]
    print(f"   marks: {' '.join(marks)}")


def read_probe(pair):
    """Which windows 0x23 (readMemoryByAddress) answers, and in which mode:
    the running program (default session) and the loader (programming)."""
    b = Board(pair)
    b.boot(max_insns=20_000_000)
    t = Tester(b)
    windows = [("internal low (CPU 0x8)", 0x00000008), ("internal window", 0x06000000),
               ("ext program 0x60000", 0x02060000), ("ext top 0xF0000", 0x020F0000),
               ("ext boot 0x0", 0x02000000), ("ext cal 0x40000", 0x02040000),
               ("RAM 0x3F9800", 0x003F9800)]
    print("\n== reads in the DEFAULT session (the running program answers)")
    for name, addr in windows:
        r = t.read_memory(addr, 16)
        print(f"   {name:24s} -> {r.hex() if r else 'refused'}")
    assert t.authenticate() and t.programming_mode()
    print("== reads in PROGRAMMING mode (the loader answers)")
    for name, addr in windows:
        r = t.read_memory(addr, 16)
        print(f"   {name:24s} -> {r.hex() if r else 'refused'}")


def main():
    flash = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DONOR, "NJ87379_0044570_Flash_new.bin")
    mpc = sys.argv[2] if len(sys.argv) > 2 else os.path.join(DONOR, "NJ87379_0044570_MPC_new.bin")
    pair = Pair(open(flash, "rb").read(), open(mpc, "rb").read(), "donor")
    blank = pair.flash[0xFD26C:0xFFF40]
    print(f"donor pair: body range blank = {blank == b'\xff' * len(blank)}, "
          f"hook word = {pair.mpc[8:12].hex()} (stock 4bf717b6)")

    probe(pair, "top 64K of the program area", 0x020F0000, 0x10000)
    probe(pair, "first 64K of the program area", 0x02060000, 0x10000)
    probe(pair, "the internal window", 0x06000000, 0x10000)
    read_probe(pair)


if __name__ == "__main__":
    main()
