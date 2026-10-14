#!/usr/bin/env python3
"""Where the stock 2C-F0 define-packet handler stores the definition.

The handler (entry 0xFFF6FC60) ends in a copy loop at 0xFFF7002C-48: the
whole received telegram, byte for byte, to 0x3F9B43 = r13-0x7CAD upward,
with no bound of its own -- the loop runs until it has written the
received length (the halfword at 0x3F9A1E = r13-0x7DD2; the handler's
own guard at 0xFFF6FFDC refuses anything over 0xFF with NRC 0x53).  This
checks that on the emulator, on the car's own clean pair, with the shape
of telegram a logger sends: 36 pieces of 6 bytes, 218 bytes in all, which
lands verbatim over 213 of mirror pool B's 248 bytes.  The store only
runs for a define the handler accepts: `2C F0 04` clears without storing,
a define while one is active is refused `7F 2C 50` and stores nothing,
and the live tune's own `2C 6C` ops exit on the local-id check before
any of it (checked by hand, not here).

    .venv/bin/python tools/twoc_store_check.py
"""
import sys

from ms45emu.image import Pair
from ms45emu.board import Board
from ms45emu.e46 import Peers
from ms45emu.kwp import Tester

STORE = 0x3F9B43                    # r13-0x7CAD, the definition store
POOL_B = (0x3F9B48, 0x3F9C40)       # the overlay's mirror pool B
DESC = 0x3F9C48                     # the overlay's descriptor table


def pieces(n, address=0x3FA000, size=1):
    req, position = [0x2C, 0xF0], 1
    for _ in range(n):
        req += [0x03, position, size,
                (address >> 16) & 0xFF, (address >> 8) & 0xFF, address & 0xFF]
        position += size
    return req


def main():
    pair = Pair(open("images/session1clean.flash.bin", "rb").read(),
                open("images/session1clean.mpc.bin", "rb").read(), "session1clean")
    b = Board(pair, mips=40)
    b.boot(max_insns=int(0.5 * b.ips))
    peers = Peers(b)
    t = Tester(b)
    assert t.logging_mode(), "no logging session"

    def region(first, last):
        """A read of the span, 250 bytes a request."""
        out = b""
        while first + len(out) <= last:
            n = min(250, last - (first + len(out)) + 1)
            chunk = t.read_memory(first + len(out), n)
            assert chunk and len(chunk) == n, f"read at {first + len(out):#x} failed"
            out += chunk
        return out

    BEFORE = (STORE - 16, DESC + 8)          # 0x3F9B33-0x3F9C4F
    before = region(*BEFORE)
    print("store before:", before[:32].hex())

    for n in (36,):
        req = pieces(n)
        r = t.request(req)
        print(f"\n{n} pieces ({len(req)} bytes): answer {bytes(r).hex() if r else 'NONE'}")
        after = region(*BEFORE)
        landed = after[16:]
        same = sum(1 for i in range(len(req)) if landed[i] == req[i])
        print(f"  store head: {landed[:16].hex()}  telegram head: {bytes(req[:16]).hex()}")
        print(f"  {same}/{len(req)} telegram bytes found verbatim at {STORE:#x}+")
        end = STORE + len(req) - 1
        in_pool = end >= POOL_B[0]
        print(f"  telegram ends {end:#x}: "
              f"{'INSIDE pool B' if in_pool and end <= POOL_B[1] else 'past pool B' if in_pool else 'below pool B'}"
              f" ({POOL_B[0]:#x}-{POOL_B[1]:#x});  descriptors at {DESC:#x} "
              f"{'UNTOUCHED' if after[16 + (DESC - STORE):16 + (DESC - STORE) + 8] == before[16 + (DESC - STORE):16 + (DESC - STORE) + 8] else 'TOUCHED'}")
        # what is left of pool B after this store
        print(f"  bytes of pool B overlapped: {max(0, min(end, POOL_B[1]) - POOL_B[0] + 1)}"
              f" of {POOL_B[1] - POOL_B[0] + 1}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
