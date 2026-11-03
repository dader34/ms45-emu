"""BL: the boot-region flasher ring (docs/bootloader.md). One bootloader,
one builder; the version lives in the stamp and nowhere in a name.

The stock loader stays byte-identical everywhere; BL adds a ring of our
code in the 96 KB boot sector's blank span and TWO patched stock words in
the 8 KB sector at 0x4000:

    ext 0x4EBC   the stock handoff `ba 0x8` (the word at CPU 8 is the
                 program's `ba RESET_ENTRY`) -> `ba 0xFFF17000`
    ext 0x17000  the handoff window: ~1 ms RAF poll with the receiver
                 briefly on. Line free -> SCC1R1 restored and `ba 0x8`: the
                 stock boot proceeds with the stock word, exactly as before
                 (register discipline: r3-r8 only; r1/r2/r13/CTR/MSR
                 untouched). Line held at key-on -> the stub.
    ext 0x5228   the park function's head `stwu r1,-0x18(r1)` -> `ba
                 0xFFF17080`. The park is the factory-dialect KWP server the
                 loader falls into when its validity checks fail (a cut cal
                 push, say); valid boots never call it. Traced 2026-10-27:
                 the checks fail -> a ~13k-insn delay loop -> the call block
                 builds the park function's address (lis+addi, the only
                 reference in the whole boot region) and `blrl`s it with r3
                 = the handler table; the function never returns during a
                 park.
    ext 0x17080  the park window: our frame with r3-r8 saved (r3 is the
                 handler-table argument -- LIVE, unlike at the handoff),
                 then the same inert RAF poll. Line free -> SCC1R1
                 restored, r3-r8 restored, frame popped, the replaced `stwu`
                 re-executed verbatim, and the stock prologue continues at
                 0x522C: the factory park behaves exactly as stock. Line
                 held -> the stub.
    ext 0x17140  the 16-byte stamp ("MS45BL", version, flags): the ring
                 body's HELLO reads its announcement straight from here
                 (flasher_body.STAMP_SRC), so the loader identifies itself
                 and no stamp lives in the program area
    ext 0x17180  the relocate stub: copy the body ext -> SRAM, jump
    ext 0x17200  the body (flasher_body.build_body), unmodified

Nothing else changes: the MPC image is untouched (no 0x8 hook -- a factory
program reflash cannot kill the ring), the program image is untouched. The
boot CRC word at 0x1F800 IS recomputed (checksums.fix_boot): nothing reads
it during boot, but the PROGRAM's background checksum task walks
0x0-0x1EFFF against it ("ROM test level 1") and a stale word is self-check
code 11 -- the DME resets itself every ~5 s, the car's reset loop of
2026-10-28. The ring and both patched words lie in that range.

Everything lands in the 96 KB sector's blank span (content ends at
0x16910 / 0x16934 / 0x16BE8 on the three loader builds) and the 8 KB
sector's two words. Guarded: refuse unless the spans are blank or our own
ring, the words are stock or ours, and the loader parks by the call the
ring is built for (PARK_CALL_SITES).

The ring comes in three variants, same windows, same layout, the body's
write window differing (flasher_body.PERM_LOW): the ring (0x8000, the boot
sector only), the installer (0x4000: the 8 KB sector with the two words,
the way back to the stock loader) and the loader swap (0x0: every boot
sector, the reset vector's included -- tools/build/bootwrite.py, bench
only). Any variant may stand where another is.

An older ring layout (stamp at 0x17080, the handoff word only, no park
window) exists on no car any more; BMWeb's Identify still recognises its
stamp so such a DME is told to update.
"""
import os
import struct
import sys
from tools.build import flasher_body
from tools.build.flasher_gate import GateAsm, hook_word, SCC1R1, SC1SR, RE, RAF
from tools.build.flasher_body import EXT, SRAM_BASE, build_body, pack
from ms45emu.checksums import fix_boot
from tools import ROOT

CPU = 0xFFF00000
PATCH_AT = 0x4EBC                         # the handoff word, 8 KB sector 0x4000-0x5FFF
STOCK_HANDOFF = 0x8                       # the word at CPU 8: `ba RESET_ENTRY`
STOCK_PATCH_WORD = 0x4800000A             # `ba 0x8`, measured on the car image
PARK_CALL_AT = 0x3828                     # the lis+addi pair that builds the
PARK_HOOK_AT = 0x5228                     # the park function's head, 8 KB sector
STOCK_PARK_HEAD = 0x9421FFE8              # `stwu r1, -0x18(r1)`
PARK_CALL = (0x3D60FFF0, 0x396B5228)      # the lis+addi pair -- the guard that
                                          # THIS loader parks by call
# Where the loader builds place that call. 24 full reads from four sources
# (2026-10-30, tools/build/bootwrite.py) show three builds of the loader
# across MS45.0 and MS45.1 alike: the two 2003-on builds (A, B) call the
# park at 0x3828; the early 2002-03 build (C) at 0x377C. The park function
# itself, its head word and the handoff word sit at the same addresses in
# all three, so the same ring fits all three; only the guard's address moves.
PARK_CALL_SITES = (PARK_CALL_AT, 0x377C)
WINDOW_AT, PARKWIN_AT = 0x17000, 0x17080
STAMP_AT, STUB_AT, BODY_AT = 0x17140, 0x17180, 0x17200
SPAN_END = 0x1F700                        # keep clear of the CRC area at 0x1F800
WINDOW_POLLS = 20                         # 20 x ~50 us = ~1 ms, pets unnecessary
                                          # (SYPCR 100 ms; the window sits at insn ~4666)
VERSION = 20
# the ring stamp's feature flags (byte 7; bits 0-2 are the body's: MPC
# window, AIF window, installer variant). The app's bl.isCurrent wants the
# version AND these flags exactly (the plain ring's); anything else -- an
# older ring, a variant left on -- is put right by the one update (bl.put).
EE_READ_FLAG = 0x10        # the EEPROM read window is in the body
CRC_FLAG = 0x40            # installed with the boot block's CRC word at 0x1F800
                           # recomputed (2026-10-28): a ring without this bit
                           # may carry the stock word, and the DME resets
                           # itself every ~5 s (checksums.fix_boot, bl.js)
SWAP_FLAG = 0x80           # the loader-swap ring: its body's write window
                           # opens at ext 0x0 (bench only, tools/build/bootwrite.py)
RING_FLAGS = 3 | EE_READ_FLAG | CRC_FLAG            # 0x53; the installer ring adds 4


def build_window(stub_cpu):
    """The handoff window as (word, note) list. r3-r8 only, SCC1R1 restored."""
    a = GateAsm()
    a.li32(3, SCC1R1)
    a.li32(4, SC1SR)
    a.lhz(5, 0, 3)                              # save the loader's SCC1R1
    a.ori_rd(6, 5, RE)
    a.sth(6, 0, 3)                              # receiver on
    a.li(7, WINDOW_POLLS)
    a.label("poll")
    a.li(8, 1000)                               # ~50 us: 1000 x 2-cycle loop
    a.label("wait")
    a.addic_(8, -1)
    a.bne("wait")
    a.lhz(8, 0, 4)                              # SC1SR
    a.andi_(8, 8, RAF)
    a.bne("flasher")
    a.addic_(7, -1)
    a.bne("poll")
    a.sth(5, 0, 3)                              # restore SCC1R1, exactly as found
    a.ba(STOCK_HANDOFF)                         # the stock handoff, verbatim effect
    a.label("flasher")
    a.ba(stub_cpu)
    a.resolve(0)
    return a.words


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
    a.li(7, WINDOW_POLLS)
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


def build_stub(nwords, src_ext):
    """Copy the body from ext to SRAM, jump. Position-parameterized."""
    a = GateAsm()
    a.li32(3, EXT + src_ext)
    a.li32(4, SRAM_BASE)
    a.li32(5, nwords)
    a.label("cp")
    a.lwz(6, 0, 3)
    a.stw(6, 0, 4)
    a.addi(3, 3, 4)
    a.addi(4, 4, 4)
    a.addic_(5, -1)
    a.bne("cp")
    a.ba(SRAM_BASE)
    a.resolve(0)
    return a.words


def ring_flags(installer=False, swap=False):
    """The stamp flags of each ring variant: the ring (3 + the feature bits),
    the installer (bit 2: the 8 KB sector writable), the loader swap (bits
    2 and 7: everything from ext 0x0 writable)."""
    f = RING_FLAGS
    if installer or swap:
        f |= 4
    if swap:
        f |= SWAP_FLAG
    return f


def ring(installer=False, swap=False):
    """{ext offset: bytes} of the ring: windows, stamp, stub and body.

    installer: the body's write window opens down to 0x4000 (the 8 KB
    sector with the two patched words). swap: down to 0x0 -- the whole
    boot region, the reset vector's sector included, for the boot
    overwrite (tools/build/bootwrite.py); bench only."""
    was = flasher_body.STAMP_SRC, flasher_body.PERM_LOW
    flasher_body.STAMP_SRC = STAMP_AT
    if swap:
        flasher_body.PERM_LOW = 0
    elif installer:
        flasher_body.PERM_LOW = 0x4000
    try:
        body_words, _notes = build_body()
    finally:
        flasher_body.STAMP_SRC, flasher_body.PERM_LOW = was
    end = BODY_AT + 4 * len(body_words)
    if end > SPAN_END:
        raise ValueError(f"body spans to {end:#x}, past the span end {SPAN_END:#x}")
    stub = build_stub(len(body_words), BODY_AT)
    if 4 * len(stub) > BODY_AT - STUB_AT:
        raise ValueError(f"stub {len(stub)} words overruns its slot ({(BODY_AT - STUB_AT) // 4} words)")
    return {WINDOW_AT: pack(build_window(CPU + STUB_AT)),
            PARKWIN_AT: pack(build_parkwin(CPU + STUB_AT)),
            STAMP_AT: stamp_bytes(flags=ring_flags(installer, swap)),
            STUB_AT: pack(stub),
            BODY_AT: pack(body_words)}


def park_call_site(flash):
    """Where this loader build places the park call, or None when it does
    not park by that call: the lis+addi pair is looked for anywhere in the
    first 16 KB (the known builds put it at PARK_CALL_SITES; a build not
    yet seen may put it elsewhere, and the ring fits it just the same)."""
    for at in range(0, 0x4000 - 8, 4):
        if struct.unpack_from(">II", flash, at) == PARK_CALL:
            return at
    return None


def stamp_bytes(version=VERSION, flags=RING_FLAGS):
    # every caller passes its variant's flags (ring_flags); the default is
    # this build's ring, NOT the bare 3 it once was -- a bare stamp would
    # promise neither the EEPROM read nor the boot CRC bit.
    # flags bit 4 = the EEPROM read window (in the body); bit 6 = the boot
    # CRC word kept (CRC_FLAG); bit 3 (EE write) stays CLEAR: the ee_write
    # module lives at 0xFF000, outside the ring, so a ring DME can dump the
    # vault but not write it (the matcher gates on the bit)
    return (b"MS45BL" + bytes([version, flags])
            + struct.pack(">II", CPU + WINDOW_AT, CPU + STUB_AT))


def build(flash, mpc, installer=False, swap=False):
    """The stock pair -> the same pair carrying the ring. MPC unchanged.

    installer=True builds the ring's INSTALLER variant: the same windows,
    stub and layout, but the body's write window opened down to 0x4000
    (flasher_body.PERM_LOW) and the stamp's flags bit 2 set. It is the only
    flasher a held line can reach on a ring DME that may rewrite the 8 KB
    sector holding the two patched words -- the way back to the stock
    loader (BMWeb's Restore stock bootloader). swap=True opens the window
    to 0x0 (flags bits 2 and 7): the loader-swap ring, which may rewrite
    every boot sector, the reset vector's included (bootwrite.py; bench
    only). Any variant may stand where another is: the ring check accepts
    all of them."""
    if park_call_site(flash) is None:
        callsite = struct.unpack_from(">II", flash, PARK_CALL_AT)
        raise ValueError(f"ext {PARK_CALL_AT:#x} holds {callsite[0]:#010x},{callsite[1]:#010x} "
                         f"and {PARK_CALL_SITES[1]:#x} is not it either: not a loader build "
                         "this ring was built for")
    head = struct.unpack_from(">I", flash, PARK_HOOK_AT)[0]
    if head not in (STOCK_PARK_HEAD, hook_word(CPU + PARKWIN_AT)):
        raise ValueError(f"ext {PARK_HOOK_AT:#x} holds {head:#010x}, not the park head")
    handoff = struct.unpack_from(">I", flash, PATCH_AT)[0]
    if handoff not in (STOCK_PATCH_WORD, hook_word(CPU + WINDOW_AT)):
        raise ValueError(f"ext {PATCH_AT:#x} holds {handoff:#010x}, not the stock handoff")

    def laid(r):
        span = bytearray(b"\xff" * (SPAN_END - WINDOW_AT))
        for at, blob in r.items():
            span[at - WINDOW_AT:at - WINDOW_AT + len(blob)] = blob
        return bytes(span)
    mine = laid(ring(installer, swap))
    have = bytes(flash[WINDOW_AT:SPAN_END])
    others = [laid(ring(i, s)) for i, s in ((False, False), (True, False), (False, True))
              if (i, s) != (installer, swap)]
    if have not in (b"\xff" * len(have), mine, *others):
        raise ValueError(f"ext {WINDOW_AT:#x}-{SPAN_END:#x}: neither blank nor our own ring")
    f = bytearray(flash)
    f[WINDOW_AT:SPAN_END] = mine
    struct.pack_into(">I", f, PATCH_AT, hook_word(CPU + WINDOW_AT))
    struct.pack_into(">I", f, PARK_HOOK_AT, hook_word(CPU + PARKWIN_AT))
    # the program's boot-block CRC ("ROM test level 1") covers 0x0-0x1EFFF:
    # the ring and both words. Left stale, the DME resets itself every ~5 s
    # (the car, 2026-10-28). The app recomputes it the same way at install
    # time over the DME's own boot region (bl.js withBootCrc).
    fix_boot(f)
    return f, mpc


def main():
    from ms45emu.image import load_named
    pair = load_named("session1.livetune6-notraps")
    f, m = build(pair.flash, pair.mpc)
    body_words, _ = build_body()
    for ext_off, name in ((f, "bl.flash.bin"), (m, "bl.mpc.bin")):
        path = os.path.join(ROOT, "images", name)
        open(path, "wb").write(bytes(ext_off))
        print(f"wrote {path} ({len(ext_off)} bytes)")
    print(f"patch: ext {PATCH_AT:#x} = ba {CPU + WINDOW_AT:#x} (stock {STOCK_PATCH_WORD:#010x}), "
          f"ext {PARK_HOOK_AT:#x} = ba {CPU + PARKWIN_AT:#x} (stock {STOCK_PARK_HEAD:#010x})")
    print(f"window {len(build_window(0))} words at {WINDOW_AT:#x}; "
          f"parkwin {len(build_parkwin(0))} words at {PARKWIN_AT:#x}; "
          f"stub {len(build_stub(1, 0))} words at {STUB_AT:#x}")
    print(f"body {len(body_words)} words at {BODY_AT:#x}-"
          f"{BODY_AT + 4 * len(body_words):#x}; stamp {f[STAMP_AT:STAMP_AT + 16]!r}")


if __name__ == "__main__":
    main()
