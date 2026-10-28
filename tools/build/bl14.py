"""BL14: the boot-region flasher ring (docs/bootloader.md).

The stock loader stays byte-identical everywhere; BL14 adds a ring of our
code in the boot region and one patched instruction:

    ext 0x4EBC   the stock handoff `ba 0x8` (the word at CPU 8 is the
                 program's `ba RESET_ENTRY`) -> `ba 0xFFF17000`
    ext 0x17000  the window: ~1 ms RAF poll with the receiver briefly on.
                 Line free -> restore SCC1R1 and `ba 0x8`: the stock boot
                 proceeds with the stock word, exactly as before. Register
                 discipline is the gate's (r3-r8 only; r1/r2/r13/CTR/MSR
                 untouched).
                 Line held at key-on -> ba the stub.
    ext 0x17080  the 16-byte stamp ("MS45BL", version 14, flags 3) -- the
                 ring body's HELLO reads its announcement straight from
                 here (flasher_body.STAMP_SRC), so the loader identifies
                 itself and no stamp lives in the program area
    ext 0x17080  the relocate stub: copy the body ext -> SRAM, jump
    ext 0x17100  the v13 body (flasher_body.build_body), unmodified

Nothing else changes: the MPC image is untouched (no 0x8 hook -- a factory
program reflash cannot kill BL14), the program image is untouched (no
fix_program; the body range in the program area is not used), and the boot
CRC word at 0x1F800 is left as the stock image had it (nothing reads it
during boot -- traced 2026-10-27, insn 0-4668; recomputation pending the
algorithm pin, bootloader.md P0 item 1).

Everything here lands in the 96 KB boot sector's blank span 0x16934-0x1F7FF
(measured on session1.livetune6-notraps) and the 8 KB sector 0x4000's one
patch word. Guarded: refuse unless the spans are blank and 0x4EBC holds the
stock handoff (idempotent rebuilds allowed).
"""
import os
import struct
import sys
from tools.build import flasher_body
from tools.build.flasher_gate import (GateAsm, hook_word, SCC1R1, SC1SR, RE, RAF)
from tools.build.flasher_body import EXT, SRAM_BASE, build_body, pack
from tools import ROOT

CPU = 0xFFF00000
PATCH_AT = 0x4EBC                       # in the 8 KB sector 0x4000-0x5FFF
STOCK_HANDOFF = 0x8                     # the word at CPU 8: `ba RESET_ENTRY`
STOCK_PATCH_WORD = 0x4800000A           # `ba 0x8`, measured on the car image
WINDOW_AT, STAMP_AT, STUB_AT, BODY_AT = 0x17000, 0x17080, 0x170C0, 0x17180
SPAN_END = 0x1F700                      # keep clear of the CRC area at 0x1F800
WINDOW_POLLS = 20                       # 20 x ~50 us = ~1 ms, pets unnecessary
                                        # (SYPCR 100 ms; the window sits at insn ~4666)
VERSION = 14


def build_window(stub_cpu):
    """The RAF window as (word, note) list. r3-r8 only, SCC1R1 restored."""
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


def stamp_bytes(version=VERSION, flags=3):
    # flags as v13's: the ring body is the full v13 feature set (bit 0 the
    # MPC window, bit 1 the AIF/boot-sector window)
    return (b"MS45BL" + bytes([version, flags])
            + struct.pack(">II", CPU + WINDOW_AT, CPU + STUB_AT))


def build(flash, mpc):
    """The stock pair -> the same pair carrying the BL14 ring. MPC unchanged."""
    current = struct.unpack_from(">I", flash, PATCH_AT)[0]
    hooks_ok = current in (STOCK_PATCH_WORD, hook_word(CPU + WINDOW_AT))
    if not hooks_ok:
        raise ValueError(f"ext {PATCH_AT:#x} holds {current:#010x}, not the stock handoff")
    was = flasher_body.STAMP_SRC               # the ring body announces the
    flasher_body.STAMP_SRC = STAMP_AT          # ring's own stamp, not the gate's
    try:
        body_words, _notes = build_body()
    finally:
        flasher_body.STAMP_SRC = was
    stub = build_stub(len(body_words), BODY_AT)
    window = build_window(CPU + STUB_AT)
    end = BODY_AT + 4 * len(body_words)
    if end > SPAN_END:
        raise ValueError(f"body spans to {end:#x}, past the span end {SPAN_END:#x}")
    f = bytearray(flash)
    for at, blob in ((WINDOW_AT, pack(window)), (STAMP_AT, stamp_bytes()),
                     (STUB_AT, pack(stub)), (BODY_AT, pack(body_words))):
        have = bytes(f[at:at + len(blob)])
        if have not in (b"\xff" * len(blob), blob):   # blank, or ours already
            raise ValueError(f"ext {at:#x}: neither blank nor our own ring")
        f[at:at + len(blob)] = blob
    struct.pack_into(">I", f, PATCH_AT, hook_word(CPU + WINDOW_AT))
    return f, mpc


def main():
    from ms45emu.image import load_named
    pair = load_named("session1.livetune6-notraps")
    f, m = build(pair.flash, pair.mpc)
    body_words, _ = build_body()
    end = BODY_AT + 4 * len(body_words)
    root = ROOT
    for ext_off, name in ((f, "bl14.flash.bin"), (m, "bl14.mpc.bin")):
        path = os.path.join(root, "images", name)
        open(path, "wb").write(bytes(ext_off))
        print(f"wrote {path} ({len(ext_off)} bytes)")
    print(f"patch: ext {PATCH_AT:#x} = ba {CPU + WINDOW_AT:#x} "
          f"(stock {STOCK_PATCH_WORD:#010x})")
    print(f"window {len(build_window(CPU + STUB_AT))} words at {WINDOW_AT:#x}; "
          f"stub {len(build_stub(1, BODY_AT))} words at {STUB_AT:#x}; "
          f"body {len(body_words)} words at {BODY_AT:#x}-{end:#x}")
    print(f"stamp {f[STAMP_AT:STAMP_AT + 16]!r}")


if __name__ == "__main__":
    main()
