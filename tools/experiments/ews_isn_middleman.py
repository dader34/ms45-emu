"""The DME as ISN middleman: the EWS's telegram, learned into RAM, read
back over stock KWP.

The exploit-shaped observation this proves: the EWS transmits its ISN
(invertible mangled form) to the DME at every exchange, the DME's validator
stores what it heard in `accepted` 0x3FC9AC, and the factory 0x23
ReadMemoryByAddress reads ANY RAM in the default session with no auth.
Compose the three and the EWS has handed its ISN to the diagnostic port.

Decode (validator semantics fn_FFFDB734/80C, re-confirmed here):
    MATCH:  ~isn == mangA(workA) or mangB(workB)  -> accepted = 0000A356
    LEARN:  workA == ~workB (foreign, consistent) -> accepted = ~mangA
The ISN is the LOW 16 bits of accepted in BOTH branches:
    telegram 8B 8F 42 09 -> mangA = 74 8F 42 F6 -> ~mangA = 8B 70 BD 09
    and the sniff arithmetic gives ISN = ~(42<<8 | 09^FF) = BD09 -- the same
    low half, because mangA never touches the ISN's byte positions.

Part 1 (scheduler healthy) reads the exact live frame against the values
the exchange leaves behind.  Part 2 then plants each telegram and runs the
REAL validator to show it produces exactly those values -- the raw call
breaks the KWP scheduler, so it must come last.

Any image works: the MATCH case is derived from that image's own ring
(the married telegram for ISN V is 00 FF + the ring's B word), the LEARN
case is a fixed foreign pair -- so session1 tests A356, a PL48740 image
tests 2086, neither value is special.

    .venv/bin/python -m tools.experiments.ews_isn_middleman                 # session1
    .venv/bin/python -m tools.experiments.ews_isn_middleman <flash> <mpc>   # any pair
"""
import os
import sys

from ms45emu.image import load_named, Pair
from ms45emu.board import Board
from ms45emu.kwp import Tester
from ms45emu.machine import R13, RETURN_SENTINEL
from unicorn.ppc_const import UC_PPC_REG_LR

WORKA, WORKB, ACCEPTED, ISN, NOTISN = 0x3FD538, 0x3FDC70, 0x3FC9AC, 0x3FC9BC, 0x3FC9B0
VALIDATOR = 0xFFFDB734
RING = 0x1FB00


def voted_isn(six):
    V = (six[4] << 8) | six[3]
    hi, lo = (V >> 8) & 0xFF, V & 0xFF
    ok = (six[0] == (~V >> 8) & 0xFF and six[1] == ~V & 0xFF
          and six[2] == ~hi & 0xFF and six[3] == lo
          and six[4] == hi and six[5] == ~lo & 0xFF)
    return V if ok else None


def cases_for(flash):
    """MATCH derived from this image's own ring; LEARN = a fixed foreign pair."""
    V = voted_isn(flash[RING:RING + 6])
    b_word = (flash[RING + 2] << 8) | flash[RING + 3]          # [~hi, lo]
    telegram = 0x00FF0000 | b_word   # 00 FF + B word (0x00FF00 would eat the B word's high byte)
    return V, [
        (f"MATCH: this image's married telegram (ring {V:04X})",
         telegram, telegram ^ 0xFFFFFFFF, V, V),
        ("LEARN: foreign self-consistent (donor-2 pair)",
         0x8B8F4209, 0x7470BDF6, 0x8B70BD09, 0xBD09),
    ]


def isn_from_accepted(word):
    return word & 0xFFFF               # the low half, in both branches


def rd32(b, at):
    return int.from_bytes(bytes(b.m.read8(a) for a in range(at, at + 4)), "big")


def part1_kwp(b, t, cases):
    """The live frame against the post-exchange state, scheduler healthy."""
    ok = True
    for label, worka, workb, accepted, ews_isn in cases:
        b.m.write32(ACCEPTED, accepted)
        b.m.write32(NOTISN, (accepted ^ 0xFFFFFFFF) & 0xFFFF0000 | (ews_isn ^ 0xFFFF))
        b.m.write32(ISN, ews_isn)
        r = t.request([0x23, 0x3F, 0xC9, 0xAC, 0x00, 0x10])
        if not r or r[0] == 0x7F:
            print(f"  {label}: 0x23 refused ({r.hex() if r else 'no answer'})  FAIL")
            ok = False
            continue
        body = bytes(r[1:])
        got = isn_from_accepted(int.from_bytes(body[0:4], "big"))
        good = got == ews_isn
        ok &= good
        print(f"  {label}: 23 3F C9 AC 00 10 -> {body.hex(' ')}"
              f" -> accepted&FFFF = {got:04X} (expected {ews_isn:04X})  {'OK' if good else 'FAIL'}")
    return ok


def part2_validator(b, cases, ring_isn):
    """Plant the FULL slot state per case (the exchange leaves no stale
    slots), run the real validator, check accepted's low half."""
    ok = True
    trace = os.environ.get("MM_TRACE") == "1"
    hook = h = None
    if trace:
        from unicorn import UC_HOOK_MEM_WRITE
        from unicorn.ppc_const import UC_PPC_REG_PC
        watch = {WORKA, WORKB, ISN, NOTISN, ACCEPTED, 0x3F9E04, 0x3F9E08}

        def hook(mu, access, address, size, value, user):
            if any(a in watch for a in range(address, address + size)):
                print(f"    write {address:08X} <- {value & 0xFFFFFFFF:08X}"
                      f" ({size}) pc={mu.reg_read(UC_PPC_REG_PC):08X}")
        h = b.m.mu.hook_add(UC_HOOK_MEM_WRITE, hook)
    for label, worka, workb, accepted, ews_isn in cases:
        plants = [(WORKA, worka), (WORKB, workb),
                  (ISN, ring_isn), (NOTISN, (~ring_isn) & 0xFFFFFFFF)]
        for at, val in plants:
            b.m.write32(at, val)
        m = b.m
        back = [rd32(b, at) for at, _ in plants]
        want = [val for _, val in plants]
        if trace or back != want:
            print(f"    readback workA/workB/isn/~isn:"
                  f" {' '.join(f'{v:08X}' for v in back)}"
                  f"{'' if back == want else '  <- PLANT MISMATCH, want ' + ' '.join(f'{v:08X}' for v in want)}")
        assert m.reg(13) == R13
        m.mu.reg_write(UC_PPC_REG_LR, RETURN_SENTINEL)
        m.mu.emu_start(VALIDATOR, RETURN_SENTINEL, count=5_000_000)
        got_accepted = rd32(b, ACCEPTED)
        got = isn_from_accepted(got_accepted)
        good = got == ews_isn and got_accepted == accepted
        ok &= good
        if trace or not good:
            print(f"    post: accepted={got_accepted:08X} workA={rd32(b, WORKA):08X}"
                  f" workB={rd32(b, WORKB):08X} isn={rd32(b, ISN):08X} ~isn={rd32(b, NOTISN):08X}")
        print(f"  {label}: validator -> accepted={got_accepted:08X}"
              f" (want {accepted:08X}) -> ISN {got:04X}  {'OK' if good else 'FAIL'}")
    if h:
        b.m.mu.hook_del(h)
    return ok


def main():
    if len(sys.argv) > 1:
        flash = open(sys.argv[1], "rb").read()
        mpc = open(sys.argv[2], "rb").read()
        pair = Pair(flash=flash, mpc=mpc, name=os.path.basename(sys.argv[1]))
    else:
        pair = load_named("session1")
    print(f"image: {pair.name}  program {pair.program_id.decode(errors='replace')}")
    ring_isn, cases = cases_for(bytes(pair.flash))
    b = Board(pair)
    b.boot(max_insns=20_000_000)
    t = Tester(b)
    print("== part 1: the stock live frame reads the post-exchange state ==")
    ok1 = part1_kwp(b, t, cases)
    print("\n== part 2: the real validator produces exactly that state ==")
    ok2 = part2_validator(b, cases, ring_isn)
    print()
    if ok1 and ok2:
        print("ALL OK -- either branch of the exchange leaves the EWS's ISN in the")
        print("low half of accepted@0x3FC9AC, and stock 0x23 reads it: no auth, no loader.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
