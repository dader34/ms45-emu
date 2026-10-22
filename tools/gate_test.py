"""The gate's proof suite (docs/fast-flasher.md, failure discipline).

Run from the ms45-emu root: .venv/bin/python tools/gate_test.py

1. Inert: with the line idle, the hooked image boots the program exactly
   as the stock one does. Raw stream equality holds until the first
   time-driven interrupt; the gate's ~600 us delay shifts where that
   lands, so the proof is path identity: identical up to the divergence,
   then stock's window re-syncs inside the hooked stream (verified to be
   an interrupt-handler insertion, not a different path).
2. Taken: with the tester holding the line low across reset, the gate
   lands in the entry stub, which copies the body to SRAM and jumps --
   proven by the body owning the machine (PC inside it, receiver on).
3. Misfire: a STOCK image booted with the line held -- the app asserting
   a break on a DME without the gate must not derail its boot.

One code hook per board, installed before the first run: unicorn only
delivers hooks added before the first emu_start.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from ms45emu.image import load_named, Pair                         # noqa: E402
from ms45emu.board import Board, RESET_ENTRY                       # noqa: E402
from flasher_gate import build, ENTRY_CPU                          # noqa: E402
from flasher_body import SRAM_BASE, REPLY_OFF                      # noqa: E402

STREAM_INSNS = 500_000


class Traced:
    """A board whose hook counts to the program entry, then records PCs."""

    def __init__(self, pair):
        self.b = Board(Pair(pair.flash, pair.mpc, pair.name, check_program=False))
        self.entry_at = None                     # insn count when the program started
        self.stream = []
        self.mode = "waiting"                    # waiting -> recording -> done
        self.n = 0
        self.b.m.hook_code(self._hook)

    def _hook(self, machine, addr, size):
        self.n += 1
        if self.mode == "waiting":
            if addr == RESET_ENTRY:
                self.entry_at = self.n
                self.mode = "recording"
        elif self.mode == "recording":
            if len(self.stream) >= STREAM_INSNS:
                self.mode = "done"
            else:
                self.stream.append(addr)

    def boot_to_entry(self):
        # stop one instruction past the entry: run() halts before executing
        # `until`, and the hook must see the entry itself execute
        reached, why = self.b.boot(max_insns=2_000_000, until=RESET_ENTRY + 4, reset_vector=True)
        assert reached, f"never started the program: {why}"
        assert self.entry_at is not None, "boot stopped past the entry without the hook seeing it"
        return self.entry_at

    def run_stream(self):
        return self.b.run_from(self.b.m.pc, STREAM_INSNS + 10_000, until=0x1)


def make(hooked, hold):
    pair = load_named("session1.livetune6-notraps")
    if hooked:
        f, m = build(pair.flash, pair.mpc)
        pair = Pair(bytes(f), bytes(m), "quickflash1", check_program=False)
    t = Traced(pair)
    t.b.sci.line_hold = hold
    return t


def main():
    fails = 0

    stock, hooked = make(False, False), make(True, False)
    gate_cost = hooked.boot_to_entry() - stock.boot_to_entry()
    print(f"program start: stock at insn {stock.entry_at}, hooked at {hooked.entry_at} "
          f"(gate cost {gate_cost} insns = {gate_cost / 40:.0f} us)")

    hooked.run_stream()
    stock.run_stream()
    if stock.stream == hooked.stream:
        print(f"inert: {len(hooked.stream)} instructions from the program entry are identical")
    else:
        d = next(i for i, (a, p) in enumerate(zip(stock.stream, hooked.stream)) if a != p)
        window = tuple(stock.stream[d:d + 64])
        ht = hooked.stream[d:d + 4096]
        pos = next((i for i in range(len(ht) - 64) if tuple(ht[i:i + 64]) == window), None)
        if pos is None:
            print(f"inert: FAIL -- PATH DIVERGENCE at +{d} "
                  f"(stock {stock.stream[d]:#x} vs hooked {hooked.stream[d]:#x})")
            fails += 1
        else:
            print(f"inert: identical for +{d}, then interrupt shift, "
                  f"re-sync at +{d + pos} -- path identity holds")

    held = make(True, True)
    reached, why = held.b.boot(max_insns=2_000_000, until=ENTRY_CPU, reset_vector=True)
    # the stub copies the body to SRAM and jumps; with the line still held
    # the body settles into its polled loops, all inside its own footprint
    held.b.run_from(ENTRY_CPU, 100_000, until=0x1)
    pc = held.b.m.pc
    scc1r1 = held.b.imb.peek16(0x30500A)
    in_body = SRAM_BASE <= pc < SRAM_BASE + REPLY_OFF
    ok = reached and in_body and scc1r1 & 0x04
    print(f"taken: entry={reached} ({why}); pc={pc:#010x} "
          f"({'the body in SRAM' if in_body else 'NOT in the body'}); "
          f"SCC1R1={scc1r1:#06x} (RE={bool(scc1r1 & 4)})")
    fails += 0 if ok else 1

    misfire = make(False, True)
    misfire.boot_to_entry()
    misfire.run_stream()
    same = misfire.stream == stock.stream
    print("misfire (stock image, line held): "
          + ("boot stream identical to a clean boot" if same else "STREAM DIFFERS -- FAIL"))
    fails += 0 if same else 1

    print("ALL OK" if not fails else f"{fails} FAILURES")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
