"""BL15: BL14 + the park-path hook -- the flasher ring also catches the
loader's "no valid program" park (docs/bootloader.md).

BL14's window hangs off the stock handoff at ext 0x4EBC, which executes
only when the loader's own validity checks pass. A power cut mid-cal-push
leaves the cal content unverifiable, so the loader never hands off: it
calls its park function (the factory-dialect KWP server) and the BL14
window never runs -- the fast path cannot re-enter, which is exactly the
state an interruptible flash has to survive (flash_resume_test case C).

Where the park is entered (traced on session1.livetune6-notraps,
2026-10-27): the checks fail -> a ~13k-insn delay loop at 0x3D9C ->
the call block at 0x3828-0x383C builds the park function's address
(lis+addi, the only reference in the whole boot region) and `blrl`s it
with r3 = the handler table. The function at 0x5228 never returns during
a park. Valid boots never execute that call block (traced: 0 hits).

BL15 patches ONE more word, chosen so the installer never touches the
reset-vector sector:

    ext 0x5228   the park function's head `stwu r1,-0x18(r1)` (the same
                 8 KB sector as the 0x4EBC patch) -> `ba 0xFFF17080`
    ext 0x17080  the park window: our frame with r3-r8 saved (r3 is the
                 handler-table argument -- LIVE, unlike at the handoff),
                 then the same inert RAF poll as the handoff window.
                 Line free -> SCC1R1 restored, r3-r8 restored, frame
                 popped, the replaced `stwu` re-executed verbatim, and
                 the stock prologue continues at 0x522C: the factory
                 park behaves exactly as stock. Line held -> the stub.

The ring layout shifts up to fit the park window (stamp 0x17140,
stub 0x17180, body 0x17200); the MPC image stays untouched.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bl14                                                        # noqa: E402
import flasher_body                                                # noqa: E402
from flasher_gate import GateAsm, hook_word, SCC1R1, SC1SR, RE, RAF  # noqa: E402
from flasher_body import EXT, SRAM_BASE, build_body, pack          # noqa: E402

CPU = 0xFFF00000
PARK_CALL_AT = 0x3828                     # the lis+addi pair that builds the
PARK_HOOK_AT = 0x5228                     # the park function's head, 8 KB sector
STOCK_PARK_HEAD = 0x9421FFE8              # `stwu r1, -0x18(r1)`
PARK_CALL = (0x3D60FFF0, 0x396B5228)      # the lis+addi pair at 0x3828 -- the
                                          # guard that THIS loader parks by call
WINDOW_AT, PARKWIN_AT = 0x17000, 0x17080
STAMP_AT, STUB_AT, BODY_AT = 0x17140, 0x17180, 0x17200
SPAN_END = 0x1F700
VERSION = 15


def build_parkwin(stub_cpu):
    """The park window as (word, note) list.

    Entered by the patched head word, before the prologue: the stack is
    stock and r3 carries the handler table. Saves r3-r8 above a 0x20
    frame, runs the handoff window's poll verbatim, then either puts
    everything back and re-executes the replaced `stwu` (stock park,
    byte for byte) or drops into the stub with the stack stock.
    """
    a = GateAsm()
    a.raw(0x9421FFE0, "stwu   r1, -0x20(r1)          # our frame")
    for r in range(3, 9):
        a.stw(r, 8 + 4 * (r - 3), 1)               # r3-r8 above the new r1
    a.li32(3, SCC1R1)
    a.li32(4, SC1SR)
    a.lhz(5, 0, 3)                                 # save the loader's SCC1R1
    a.ori_rd(6, 5, RE)
    a.sth(6, 0, 3)                                 # receiver on
    a.li(7, bl14.WINDOW_POLLS)
    a.label("poll")
    a.li(8, 1000)                                  # ~50 us: 1000 x 2-cycle loop
    a.label("wait")
    a.addic_(8, -1)
    a.bne("wait")
    a.lhz(8, 0, 4)                                 # SC1SR
    a.andi_(8, 8, RAF)
    a.bne("flasher")
    a.addic_(7, -1)
    a.bne("poll")
    a.sth(5, 0, 3)                                 # SCC1R1 back, exactly as found
    for r in range(3, 9):
        a.lwz(r, 8 + 4 * (r - 3), 1)               # r3-r8 back (r3 = the table)
    a.addi(1, 1, 0x20)                             # frame popped
    a.raw(STOCK_PARK_HEAD, "stwu   r1, -0x18(r1)    # the replaced word, verbatim")
    a.ba(CPU + PARK_HOOK_AT + 4)                   # the stock prologue at 0x522C
    a.label("flasher")
    a.addi(1, 1, 0x20)                             # stack stock; SCC1R1 left with
    a.ba(stub_cpu)                                 #  RE on, the taken discipline
    a.resolve(0)
    return a.words


def ring(installer=False):
    """{ext offset: bytes} of the ring: windows, stamp, stub and body."""
    was = flasher_body.STAMP_SRC, flasher_body.PERM_LOW
    flasher_body.STAMP_SRC = STAMP_AT
    if installer:
        flasher_body.PERM_LOW = 0x4000
    try:
        body_words, _notes = build_body()
    finally:
        flasher_body.STAMP_SRC, flasher_body.PERM_LOW = was
    end = BODY_AT + 4 * len(body_words)
    if end > SPAN_END:
        raise ValueError(f"body spans to {end:#x}, past the span end {SPAN_END:#x}")
    return {WINDOW_AT: pack(bl14.build_window(CPU + STUB_AT)),
            PARKWIN_AT: pack(build_parkwin(CPU + STUB_AT)),
            STAMP_AT: stamp_bytes(flags=7 if installer else 3),
            STUB_AT: pack(bl14.build_stub(len(body_words), BODY_AT)),
            BODY_AT: pack(body_words)}


def stamp_bytes(version=VERSION, flags=3):
    return (b"MS45BL" + bytes([version, flags])
            + struct.pack(">II", CPU + WINDOW_AT, CPU + STUB_AT))


def build(flash, mpc, installer=False):
    """The stock pair -> the same pair carrying the BL15 ring. MPC unchanged.

    installer=True builds the ring's INSTALLER variant: the same windows,
    stub and layout, but the body's write window opened down to 0x4000
    (flasher_body.PERM_LOW) and the stamp's flags bit 2 set. It is the only
    flasher a held line can reach on a BL15 DME that may rewrite the 8 KB
    sector holding the two patched words -- the way back to the stock
    loader (BMWeb's Restore stock bootloader). Either variant may stand
    where the other is: the ring check accepts both."""
    callsite = struct.unpack_from(">II", flash, PARK_CALL_AT)
    if callsite != PARK_CALL:
        raise ValueError(f"ext {PARK_CALL_AT:#x} holds {callsite[0]:#010x},{callsite[1]:#010x}: "
                         "not this loader's park call")
    head = struct.unpack_from(">I", flash, PARK_HOOK_AT)[0]
    if head not in (STOCK_PARK_HEAD, hook_word(CPU + PARKWIN_AT)):
        raise ValueError(f"ext {PARK_HOOK_AT:#x} holds {head:#010x}, not the park head")
    handoff = struct.unpack_from(">I", flash, bl14.PATCH_AT)[0]
    if handoff not in (bl14.STOCK_PATCH_WORD, hook_word(CPU + WINDOW_AT)):
        raise ValueError(f"ext {bl14.PATCH_AT:#x} holds {handoff:#010x}, not the stock handoff")

    def laid(r):
        span = bytearray(b"\xff" * (SPAN_END - WINDOW_AT))
        for at, blob in r.items():
            span[at - WINDOW_AT:at - WINDOW_AT + len(blob)] = blob
        return bytes(span)
    mine = laid(ring(installer))
    have = bytes(flash[WINDOW_AT:SPAN_END])
    if have not in (b"\xff" * len(have), mine, laid(ring(not installer))):
        raise ValueError(f"ext {WINDOW_AT:#x}-{SPAN_END:#x}: neither blank nor our own ring")
    f = bytearray(flash)
    f[WINDOW_AT:SPAN_END] = mine
    struct.pack_into(">I", f, bl14.PATCH_AT, hook_word(CPU + WINDOW_AT))
    struct.pack_into(">I", f, PARK_HOOK_AT, hook_word(CPU + PARKWIN_AT))
    return f, mpc


def main():
    from ms45emu.image import load_named
    pair = load_named("session1.livetune6-notraps")
    f, m = build(pair.flash, pair.mpc)
    body_words, _ = build_body()
    print(f"patch: ext 0x4EBC = ba {CPU + WINDOW_AT:#x}, "
          f"ext {PARK_HOOK_AT:#x} = ba {CPU + PARKWIN_AT:#x} "
          f"(stock {STOCK_PARK_HEAD:#010x})")
    print(f"window {len(bl14.build_window(0))} words at {WINDOW_AT:#x}; "
          f"parkwin {len(build_parkwin(0))} words at {PARKWIN_AT:#x}; "
          f"stub {len(bl14.build_stub(1, 0))} words at {STUB_AT:#x}")
    print(f"body {len(body_words)} words at {BODY_AT:#x}-"
          f"{BODY_AT + 4 * len(body_words):#x}; stamp {f[STAMP_AT:STAMP_AT + 16]!r}")


if __name__ == "__main__":
    main()
