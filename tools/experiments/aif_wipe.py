#!/usr/bin/env python
"""The programming log (AIF/UIF) of an MS45.1, wiped in the emulator.

    .venv/bin/python -m tools.experiments.aif_wipe [--flash Flash.bin --mpc MPC.bin] [--out DIR]

The AIF -- the "UIF" WinKFP reads, the log of every car a DME was programmed
in, VIN included -- lives at ext 0x1FB34-0x1FFFF, inside the 96 KB boot
sector (0x8000-0x1FFFF) that no KWP erase command can touch and whose
sector-table entry (0xFFF1F900-0xFFF1FFFF, attr 0x21) carries no write bits.
Programming can only clear bits, so a used entry can never be blanked: the
history can only be removed by erasing the sector. This tool proves that
erase, end to end on the emulator, with nothing mocked:

 1. Build, offline: a program update (signed with the program-signature key
    fix_program holds, the bootregion PoC's delivery) carries a payload at
    MPC 0x6F000 behind the compressed-vector reset word (MPC 0x8). The
    payload, in order:
      - erases the 128 KB calibration sector: blank silicon to stage in.
        Programming only clears bits, so the staging copies are only
        faithful into erased space; the calibration itself is restored
        right afterwards over plain KWP, the same write a flasher runs
        (the kept range is 97 KB and the blank pockets elsewhere total
        78 KB, so there is no room without sacrificing the cal);
      - stages the whole kept range ext [0x8000, 0x1FB34) -- boot loader
        code, sector table, keypairs, the CRC block, stamps -- into it;
      - erases the 96 KB boot sector;
      - restores everything but the AIF: ext 0x1FB34-0x1FFFF stays 0xFF;
      - AND-programs the sector table: entry 2's start 0xFFF4->0xFFF0 (the
        bootregion PoC's unlock) and entry 1's end 0xFFFF->0xFB33 (the boot
        tail shrinks to 0xFFF1FB33, so the AIF range falls to entry 2 and
        ordinary 34/36 can write it);
      - programs a fresh boot CRC (CRC-32/MPEG-2 over ext 0x0-0x1EFFF, the
        stock range, checked against the stock value at build time), and
      - is crash-resumable: a marker halfword at 0x387EC (0xFF fresh ->
        0xA55A staged -> 0xA558 done, one bit at a time) makes every
        interruption converge -- the staging is never re-read from a source
        the erase may already have consumed, and the marker itself sits in
        the boot loader's blank tail, which no later flash touches.
 2. The flash session is exactly a flasher's program update (the same one
    the bootregion PoC runs); the AIF in the chip is untouched by it.
 3. Reset: the loader hands control to the payload, which does all of the
    above against the flash-chip model with the DME's own AMD command set,
    polling as the real part needs and servicing SWSR in every poll loop,
    then starts the program. The chip is compared byte for byte against the
    expected result; the AIF must read blank.
 4. An ordinary session then restores the calibration over 34/36/37 (its
    31 02 erase also cleans the staging leftovers out of the cal sector),
    writes the factory's own first AIF entry back at ext 0x1FB34 through
    the same plain 34/36 -- the wiped log is arbitrarily re-writable over
    KWP -- and re-checks the calibration signature.
 5. Final reset: the marker says done, the payload skips, the program runs
    on the restored calibration, and the entry stays.

What this proves: the log can be wiped with no key the flasher does not
already hold, and the DME that comes out of it is byte-identical to stock
except for two sector-table halfwords, the refreshed boot CRC, and a blank
programming log.
"""

import argparse
import os
import struct
import sys
from ms45emu.board import Board, VALID_MARKS
from ms45emu.image import Pair, IMAGES_DIR
from ms45emu.kwp import Tester
from ms45emu.checksums import fix_program, crc32_mpeg2
from ms45emu.machine import EXT_BASE, FLASH_SIZE

EXT = 0xFFF00000                       # external flash, CPU address
EXTERNAL, INTERNAL = 0x02000000, 0x06000000   # the KWP address windows
PROGRAM, PROGRAM_END = 0x60000, 0xFFF40        # what a flasher sends of each part
CALIBRATION, CALIBRATION_END = 0x40000, 0x5D000
SCHEDULER_TASK, INIT_DONE = 0x3B38C, 0x3FEB26  # how a running program is recognised

HOOK = 8                               # compressed-vector entry 1 (reset) in the MPC image
PAYLOAD_AT = 0x6F000                   # blank tail of the MPC image (stock code ends 0x6E906)

SECTOR = 0x8000                        # the 96 KB boot sector, erased to wipe the AIF
AIF = (0x1FB34, 0x20000)               # the programming log: wiped
KEEP_END = AIF[0]                      # everything of the sector below it: restored
CRC_AT = 0x1F800                       # boot CRC-32/MPEG-2 over ext 0x0-0x1EFFF
CRC_RANGE = (0x0, 0x1F000)

CAL_SECTOR = 0x40000                   # the 128 KB calibration sector: the staging scratch
CAL_SECTOR_END = 0x60000               # (its valid marks at 0x5FF80 are re-burned later)

SECTOR_TABLE = 0x2D94                  # 4 entries x {start32, end32, attr8, next8}
ENTRY1_END = SECTOR_TABLE + 18         # entry 1's end32 low halfword (0xFFFF -> 0xFB33)
ENTRY2_START = SECTOR_TABLE + 24       # entry 2's start32 high halfword (0xFFF4 -> 0xFFF0)

MARK_AT = 0x387EC                      # state marker, in the boot loader's blank tail
MARK_STAGED, MARK_DONE = 0xA55A, 0xA558
STAMP_AT = 0x5FF40                     # program-ID stamp: 31 09 program check writes it,
                                       # the 64 bytes between the cal and the first valid mark
ORIG_START = 0xFFF717B4                # filled from the base image at build time


def banner(text):
    print("\n" + "=" * 74 + f"\n{text}\n" + "=" * 74, flush=True)


def check(cond, msg):
    if not cond:
        raise SystemExit(f"  FAIL: {msg}")
    print(f"  ok: {msg}", flush=True)


def make_progress(label):
    state = {"blocks": 0, "last": 0}

    def progress(at, total):
        state["blocks"] += 1
        if state["blocks"] - state["last"] >= 200 or at >= total:
            print(f"    {label}: {at}/{total} bytes ({state['blocks']} blocks)", flush=True)
            state["last"] = state["blocks"]
    return progress


def aif_slots(flash):
    """The used 64-byte slots of the AIF, as (index, first 40 ascii-ish bytes)."""
    out, at = [], AIF[0]
    while at + 64 <= AIF[1]:
        slot = flash[at:at + 64]
        if slot[0] == 0xFF:
            break
        out.append((at, "".join(chr(c) if 32 <= c < 127 else "." for c in slot[:40])))
        at += 64
    return out


# ---------------------------------------------------------------------------
# The payload. Hand-assembled (a tiny two-pass assembler with labels), every
# word checked against capstone afterwards. Only plain forms -- loads, stores,
# branches -- nothing the emulator's own patching rewrites, no stack, no SPRs,
# volatile registers only, as at the `ba 8` handoff.


class Asm:
    def __init__(self):
        self.words = []                # (word, note)
        self.labels = {}
        self.fixups = []               # (index, kind, label)

    def here(self):
        return len(self.words)

    def label(self, name):
        self.labels[name] = self.here()

    def raw(self, w, note):
        self.words.append((w & 0xFFFFFFFF, note))

    def lis(self, rD, imm):
        self.raw(0x3C000000 | (rD << 21) | (imm & 0xFFFF), f"lis    r{rD}, {imm:#06x}")

    def ori(self, rD, rA, imm):
        self.raw(0x60000000 | (rD << 21) | (rA << 16) | (imm & 0xFFFF),
                 f"ori    r{rD}, r{rA}, {imm:#06x}")

    def li(self, rD, imm):             # addi rD, 0, imm
        self.raw(0x38000000 | (rD << 21) | (imm & 0xFFFF), f"li     r{rD}, {imm:#7d}")

    def li32(self, rD, value):
        self.lis(rD, (value >> 16) & 0xFFFF)
        self.ori(rD, rD, value & 0xFFFF)

    def addi(self, rD, rA, imm):
        self.raw(0x38000000 | (rD << 21) | (rA << 16) | (imm & 0xFFFF),
                 f"addi   r{rD}, r{rA}, {imm:#x}")

    def addic_(self, rD, imm):
        self.raw(0x34000000 | (rD << 21) | (rD << 16) | (imm & 0xFFFF),
                 f"addic. r{rD}, r{rD}, {imm:#x}")

    def lhz(self, rD, d, rA):
        self.raw(0xA0000000 | (rD << 21) | (rA << 16) | (d & 0xFFFF),
                 f"lhz    r{rD}, {d:#x}(r{rA})")

    def sth(self, rS, d, rA):
        self.raw(0xB0000000 | (rS << 21) | (rA << 16) | (d & 0xFFFF),
                 f"sth    r{rS}, {d:#x}(r{rA})")

    def lwz(self, rD, d, rA):
        self.raw(0x80000000 | (rD << 21) | (rA << 16) | (d & 0xFFFF),
                 f"lwz    r{rD}, {d:#x}(r{rA})")

    def lhzx(self, rD, rB):            # lhzx rD, 0, rB
        self.raw(0x7C000000 | (rD << 21) | (rB << 11) | (279 << 1),
                 f"lhzx   r{rD}, 0, r{rB}")

    def sthx(self, rS, rB):            # sthx rS, 0, rB
        self.raw(0x7C000000 | (rS << 21) | (rB << 11) | (407 << 1),
                 f"sthx   r{rS}, 0, r{rB}")

    def cmplw(self, rA, rB):
        self.raw(0x7C000000 | (rA << 16) | (rB << 11) | (32 << 1),
                 f"cmplw  r{rA}, r{rB}")

    def cmplwi(self, rA, imm):
        self.raw(0x28000000 | (rA << 16) | (imm & 0xFFFF), f"cmplwi r{rA}, {imm:#06x}")

    def beq(self, label):
        self.fixups.append((self.here(), "beq", label))
        self.raw(0x41820000, f"beq    {label}")

    def bne(self, label):
        self.fixups.append((self.here(), "bne", label))
        self.raw(0x40820000, f"bne    {label}")

    def ba(self, target):
        self.raw(0x48000002 | (target & 0x03FFFFFC), f"ba     {target:#x}")

    def resolve(self, base):
        # the byte distance goes straight into the low 16 bits: its low two
        # zero bits land on the AA/LK bits, and the field shift above it
        # yields BD = distance/4 (the `beq 0x103c` form capstone confirms)
        for index, kind, label in self.fixups:
            rel = 4 * (self.labels[label] - index)
            op = 0x41820000 if kind == "beq" else 0x40820000
            self.words[index] = (op | (rel & 0xFFFC), self.words[index][1])


# Registers. r3 is the external flash base; r5/r6 full source/destination
# addresses; r4 the data halfword; r7 the count; r8, r10 poll temp and bound;
# r14-r16 the AMD command bytes; r17-r19 SWSR; r20, r21 the table walk;
# r22, r23 the erase setup and sector-erase commands.
R3, R4, R5, R6, R7, R8, R10 = 3, 4, 5, 6, 7, 8, 10
R14, R15, R16, R17, R18, R19, R20, R21, R22, R23 = 14, 15, 16, 17, 18, 19, 20, 21, 22, 23


def program_halfword(a, tag, polls=-1, fail=None):
    """Emit the AMD program cycle + poll for the halfword in r4 to *r6.

    `polls` bounds the poll: the loop gives up after that many passes; with
    `fail` the code branches there when the halfword is still wrong, for a
    caller that stops at the first bad one and reports (the flasher body:
    NAK 4); without it, it falls through with the halfword as it is. The default, -1, is the original
    open-ended wait (2^32 passes, minutes) that the AIF-wipe proof relies on."""
    a.li(R10, polls)
    a.sth(R14, 0xAAA, R3)              # unlock cycle 1
    a.sth(R15, 0x554, R3)              # unlock cycle 2
    a.sth(R16, 0xAAA, R3)              # program setup
    a.sthx(R4, R6)                     # data cycle (the low 16 bits land)
    a.label(f"{tag}_poll")
    a.lhzx(R8, R6)                     # DQ7-style poll: done when it reads back
    a.cmplw(R8, R4)
    a.beq(f"{tag}_ok")
    a.sth(R18, 0, R17)                 # SWSR service (the real part needs it)
    a.sth(R19, 0, R17)
    a.addic_(R10, -1)
    a.bne(f"{tag}_poll")
    if fail is not None:
        a.lhzx(R8, R6)                 # the bound ran out: still wrong -> the caller's failure path
        a.cmplw(R8, R4)
        a.bne(fail)
    a.label(f"{tag}_ok")


def erase_sector(a, tag, sector):
    """Emit the 6-cycle AMD sector erase of ext `sector` + poll."""
    a.li32(R5, EXT | sector)
    a.li(R22, 0x80)
    a.li(R23, 0x30)
    a.sth(R14, 0xAAA, R3)
    a.sth(R15, 0x554, R3)
    a.sth(R22, 0xAAA, R3)              # erase setup
    a.sth(R14, 0xAAA, R3)
    a.sth(R15, 0x554, R3)
    a.sthx(R23, R5)                    # sector erase command
    a.li(R10, -1)
    a.li32(R4, 0x0000FFFF)
    a.label(f"{tag}_poll")
    a.lhzx(R8, R5)                     # DQ7: 0xFFFF only when really done
    a.cmplw(R8, R4)
    a.beq(f"{tag}_done")
    a.sth(R18, 0, R17)
    a.sth(R19, 0, R17)
    a.addic_(R10, -1)
    a.bne(f"{tag}_poll")
    a.label(f"{tag}_done")


def assemble(jobs, patches, table_at, patches_at):
    """The payload's code. `jobs` are (src, dst, halfwords); `patches` are
    (address, halfword) burned after the restore."""
    a = Asm()
    a.lis(R3, 0xFFF0)                          # r3 = the external flash
    a.li32(R17, 0x002FC00E)                    # SWSR
    a.li(R14, 0xAA)
    a.li(R15, 0x55)
    a.li(R16, 0xA0)
    a.li(R18, 0x556C)
    a.li(R19, 0xAA39)
    a.li32(R6, EXT | MARK_AT)
    a.lhzx(R4, R6)
    a.cmplwi(R4, MARK_DONE)
    a.beq("done")                              # already wiped
    a.cmplwi(R4, MARK_STAGED)
    a.beq("erase_boot")                        # staged: resume at the boot erase

    erase_sector(a, "cal", CAL_SECTOR)         # -- blank staging room

    a.li32(R20, table_at)                      # -- stage: src -> cal sector
    a.li(R21, len(jobs))
    a.label("stage_job")
    a.lwz(R5, 0, R20)
    a.lwz(R6, 4, R20)
    a.lwz(R7, 8, R20)
    a.addi(R20, R20, 12)
    a.label("stage_hw")
    a.lhzx(R4, R5)
    program_halfword(a, "s")
    a.addi(R5, R5, 2)
    a.addi(R6, R6, 2)
    a.addic_(R7, -1)
    a.bne("stage_hw")
    a.addic_(R21, -1)
    a.bne("stage_job")
    a.li32(R4, MARK_STAGED)                    # li32: `li` sign-extends 0xA55A
    a.li32(R6, EXT | MARK_AT)
    program_halfword(a, "m")

    a.label("erase_boot")                      # -- erase the 96 KB boot sector
    erase_sector(a, "boot", SECTOR)

    a.li32(R20, table_at)                      # -- restore: cal sector -> src
    a.li(R21, len(jobs))
    a.label("rest_job")
    a.lwz(R6, 0, R20)
    a.lwz(R5, 4, R20)
    a.lwz(R7, 8, R20)
    a.addi(R20, R20, 12)
    a.label("rest_hw")
    a.lhzx(R4, R5)
    program_halfword(a, "r")
    a.addi(R5, R5, 2)
    a.addi(R6, R6, 2)
    a.addic_(R7, -1)
    a.bne("rest_hw")
    a.addic_(R21, -1)
    a.bne("rest_job")

    a.li32(R20, patches_at)                    # -- the sector table, the CRC, the marker
    a.li(R21, len(patches))
    a.label("patch_next")
    a.lwz(R6, 0, R20)
    a.lhz(R4, 6, R20)
    a.addi(R20, R20, 8)
    program_halfword(a, "p")
    a.addic_(R21, -1)
    a.bne("patch_next")

    a.label("done")
    a.ba(ORIG_START)
    return a


MNEMONIC_ALIASES = {}                  # capstone uses the notes' own mnemonics


def verify_disasm(words, base, labels=None):
    """Every word must disassemble to the mnemonic it was emitted with, and
    every branch to the address of its label (a wrong offset with a healthy
    mnemonic would otherwise pass unnoticed)."""
    try:
        from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
    except ImportError:
        print("  (capstone absent: the payload words are not disassembled)")
        return
    md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
    bad = []
    for i, (w, note) in enumerate(words):
        ins = next(md.disasm(struct.pack(">I", w), base + 4 * i), None)
        want = note.split()[0].rstrip(":")
        want = MNEMONIC_ALIASES.get(want, want)
        got = f"{ins.mnemonic} {ins.op_str}".strip() if ins else "?"
        if ins is None or ins.mnemonic != want:
            bad.append((base + 4 * i, w, note, got))
            continue
        if want in ("beq", "bne"):              # the target must be the label's address
            label = note.split()[1]
            target = int(ins.op_str, 16)
            if labels and label in labels and target != base + 4 * labels[label]:
                bad.append((base + 4 * i, w, note, f"{got} (want {base + 4 * labels[label]:#x})"))
                continue
        if want == "ba" and note.startswith("ba"):
            target = int(ins.op_str, 16) & 0xFFFFFFFF      # capstone sign-extends
            if target != int(note.split()[1], 16) & 0xFFFFFFFF:
                bad.append((base + 4 * i, w, note, got))
                continue
        print(f"    {base + 4 * i:05X}: {w:08X}  {note}")
    if bad:
        for at, w, note, got in bad[:10]:
            print(f"    {at:#x}: {w:08X} expected `{note}` disassembles `{got}`")
        raise SystemExit(f"  FAIL: {len(bad)} payload words do not disassemble as intended")
    print(f"  ok: all {len(words)} payload words disassemble as written,"
          " every branch to its label (capstone)")


def plan_jobs():
    """Two jobs covering [0x8000, 0x1FB34) minus the CRC word, staged into the
    erased calibration sector. The CRC word is excluded: it is patched with
    the fresh value afterwards (AND cannot set bits)."""
    n1 = (CRC_AT - SECTOR) // 2
    n2 = (KEEP_END - (CRC_AT + 4)) // 2
    jobs = [(SECTOR, CAL_SECTOR, n1), (CRC_AT + 4, CAL_SECTOR + 2 * n1, n2)]
    staged = 2 * (n1 + n2)
    if CAL_SECTOR + staged > CAL_SECTOR_END - 0x80:      # keep clear of the marks
        raise SystemExit(f"  FAIL: {staged} bytes to stage do not fit the calibration sector")
    return jobs


def phase_build(base):
    banner("1. building the wipe program (offline, no DME involved)")
    global ORIG_START
    flash, mpc = bytearray(base.flash), bytearray(base.mpc)

    stock_word = struct.unpack_from(">I", mpc, HOOK)[0]
    check((stock_word & 0xFC000002) == 0x48000002,
          f"MPC 0x8 holds {stock_word:#010x}, a `ba` (the program's start)")
    ORIG_START = EXT | (stock_word & 0x03FFFFFC)   # the ba field carries 26 bits
    check(mpc[PAYLOAD_AT:] == b"\xff" * (len(mpc) - PAYLOAD_AT),
          f"MPC {PAYLOAD_AT:#x}-{len(mpc) - 1:#x} is blank (payload room)")
    if not all(struct.unpack_from(">I", flash, at)[0] == mark for at, mark in VALID_MARKS):
        print("  (the base pair is a raw read without valid marks; the loader re-burns them)")
    check(flash[ENTRY2_START:ENTRY2_START + 4] == bytes.fromhex("fff40000"),
          "sector entry 2 starts at 0xFFF40000 (stock)")
    check(flash[ENTRY1_END:ENTRY1_END + 2] == b"\xff\xff",
          "sector entry 1 ends at 0xFFF1FFFF (stock: the boot tail, no write bits)")
    stored = int.from_bytes(flash[CRC_AT:CRC_AT + 4], "big")
    check(crc32_mpeg2(flash[CRC_RANGE[0]:CRC_RANGE[1]]) == stored,
          f"the stock boot CRC at {CRC_AT:#x} matches CRC-32/MPEG-2 over 0x0-0x1EFFF")
    check(flash[MARK_AT:MARK_AT + 2] == b"\xff\xff",
          f"the marker halfword at {MARK_AT:#x} is blank (the boot loader's blank tail)")
    slots = aif_slots(flash)
    check(bool(slots), "the base pair has an AIF worth wiping")
    for at, text in slots:
        print(f"    slot @0x{at:05X}: {text}")

    jobs = plan_jobs()
    print(f"  staging {sum(n for _, _, n in jobs) * 2} bytes in {len(jobs)} jobs "
          f"into the erased calibration sector {CAL_SECTOR:#x}-{CAL_SECTOR_END:#x}")

    # the CRC the wiped, patched boot region must carry
    crc_flash = bytearray(flash)
    crc_flash[AIF[0]:AIF[1]] = b"\xff" * (AIF[1] - AIF[0])
    crc_flash[ENTRY1_END:ENTRY1_END + 2] = b"\xfb\x33"
    crc_flash[ENTRY2_START:ENTRY2_START + 2] = b"\xff\xf0"
    new_crc = crc32_mpeg2(crc_flash[CRC_RANGE[0]:CRC_RANGE[1]])
    print(f"  boot CRC {stored:08x} -> {new_crc:08x} (the two table halfwords change it)")

    patches = [(EXT | ENTRY1_END, 0xFB33),      # entry 1 end: the AIF falls to entry 2
               (EXT | ENTRY2_START, 0xFFF0),    # entry 2 start: the bootregion unlock
               (EXT | CRC_AT, new_crc >> 16),   # the fresh CRC, into the blank
               (EXT | CRC_AT + 2, new_crc & 0xFFFF),
               (EXT | MARK_AT, MARK_DONE)]      # the marker, one bit cleared

    a = assemble(jobs, patches, 0, 0)           # pass 1: the code length
    table_at = PAYLOAD_AT + 4 * len(a.words)
    a = assemble(jobs, patches, table_at, table_at + 12 * len(jobs))
    a.resolve(PAYLOAD_AT)
    words = list(a.words)
    for src, dst, n in jobs:                   # the payload walks full CPU addresses
        words += [(EXT | src, f"job src {EXT | src:#x}"),
                  (EXT | dst, f"     dst {EXT | dst:#x}"),
                  (n, f"     {n} halfwords")]
    for addr, hw in patches:
        words += [(addr, f"patch {addr:#x}"), (hw & 0xFFFF, f"      {hw:#06x}")]
    payload = b"".join(struct.pack(">I", w) for w, _ in words)
    check(PAYLOAD_AT + len(payload) <= len(mpc),
          f"payload + tables are {len(payload)} bytes, MPC {PAYLOAD_AT:#x}+ has room")
    verify_disasm(words[:len(a.words)], PAYLOAD_AT, a.labels)

    struct.pack_into(">I", mpc, HOOK, 0x48000002 | PAYLOAD_AT)
    mpc[PAYLOAD_AT:PAYLOAD_AT + len(payload)] = payload
    fix_program(flash, mpc)
    print(f"  MPC 0x8: {stock_word:#010x} -> ba {PAYLOAD_AT:#x}; fix_program re-signed")

    return {"flash": bytes(flash), "mpc": bytes(mpc), "jobs": jobs,
            "patches": patches, "new_crc": new_crc, "payload_len": len(payload)}


def expected_image(pre_wipe, window, plan):
    """The chip the payload must leave behind, byte for byte. The staged and
    restored data comes from the live mapped window -- the emulator patches a
    few words of mapped code (each EIE/EID/NRI becomes an `sc`), and the
    payload stages what its memory shows, so that is the faithful model."""
    exp = bytearray(pre_wipe)
    jobs, new_crc = plan["jobs"], plan["new_crc"]
    exp[CAL_SECTOR:CAL_SECTOR_END] = b"\xff" * (CAL_SECTOR_END - CAL_SECTOR)  # erased, staged into
    for src, dst, n in jobs:
        exp[dst:dst + 2 * n] = window[src:src + 2 * n]
    exp[SECTOR:AIF[1]] = b"\xff" * (AIF[1] - SECTOR)                          # erased
    for src, dst, n in jobs:
        exp[src:src + 2 * n] = window[src:src + 2 * n]                        # restored
    exp[ENTRY1_END:ENTRY1_END + 2] = b"\xfb\x33"
    exp[ENTRY2_START:ENTRY2_START + 2] = b"\xff\xf0"
    exp[CRC_AT:CRC_AT + 4] = struct.pack(">I", new_crc)
    exp[MARK_AT:MARK_AT + 2] = struct.pack(">H", MARK_DONE)
    return bytes(exp)


def phase_flash(base, plan):
    banner("2. flashing it as an ordinary program update (the AIF is untouched)")
    b = Board(base)
    b.boot(max_insns=20_000_000)
    t = Tester(b)
    check(t.authenticate(), "mode-3 seed/key accepted")
    check(t.programming_mode(), "programming mode entered")
    check(t.erase(EXTERNAL + PROGRAM, 0xA0000),
          "31 02 erased the program sectors and the internal flash (the erase flag)")
    ok, sent = t.write_sparse(EXTERNAL + PROGRAM, plan["flash"][PROGRAM:PROGRAM_END],
                              make_progress("external program"))
    check(ok, f"34/36/37 wrote the external program image ({sent} blocks)")
    ok, sent = t.write_sparse(INTERNAL, plan["mpc"], make_progress("internal flash"))
    check(ok, f"34/36/37 wrote the internal flash image ({sent} blocks)")
    check(t.default_mode(), "back to the default session")
    check(t.check_signature("program"), "31 09 accepted the forged program signature")
    check(t.programming_status() == 1, "31 0A: normal")
    check(b.program_valid(), "all four valid marks are in")
    check(bool(aif_slots(b.flash.image)), "the chip still carries its AIF history")
    pre_wipe = bytes(b.flash.image)
    check(t.reset(), "STEUERGERAETE_RESET")
    return b, pre_wipe


def site_words(image):
    """Word offsets in the keep range of the `mtspr EIE/EID/NRI` sites: the
    emulator replaces each with a branch to a native stub (cpu.py), so what
    the payload stages for them is an emulator artifact -- real silicon holds
    the mtspr words, and the compare and the CRC model must skip them."""
    out = []
    for at in range(SECTOR, KEEP_END, 4):
        w = int.from_bytes(image[at:at + 4], "big")
        if (w >> 1) & 0x3FF == 467:                       # mtspr
            spr = (((w >> 11) & 0x1F) << 5) | ((w >> 16) & 0x1F)
            if spr in (80, 81, 82):                        # EIE, EID, NRI
                out.append(at)
    return out


def phase_payload(b, plan, pre_wipe):
    banner("3. reset: the payload stages, erases, restores -- and wipes the AIF")
    b2 = b.reset()
    window = bytes(b2.m.mu.mem_read(EXT_BASE, FLASH_SIZE))    # what the payload will read
    b2.probe(SCHEDULER_TASK, "scheduler")
    b2.boot(max_insns=100_000_000, reset_vector=True)
    chip = bytes(b2.flash.image)
    expected = expected_image(pre_wipe, window, plan)

    if b2.m.read8(INIT_DONE) == 1 and b2.probe_counts["scheduler"] > 10:
        print(f"  note: the program even starts on the blank calibration "
              f"(scheduler ticks: {b2.probe_counts['scheduler']})")
    else:
        print("  note: the program waits for a calibration; the KWP session below restores it")

    check(chip[AIF[0]:AIF[1]] == b"\xff" * (AIF[1] - AIF[0]),
          f"the AIF at ext {AIF[0]:#x}-{AIF[1]:#x} is BLANK ({(AIF[1]-AIF[0])} bytes of 0xFF)")
    # every word the emulator patches in mapped memory (mtspr EIE/EID/NRI native
    # stubs, time-base traps) is an artifact: real silicon holds the stock word,
    # so the compare skips them and the CRC models them back to silicon
    patched = [at for at in range(SECTOR, KEEP_END, 4) if window[at:at + 4] != pre_wipe[at:at + 4]]
    check(set(site_words(pre_wipe)) <= set(patched),
          f"the {len(site_words(pre_wipe))} mtspr sites are among the {len(patched)} patched words")
    allowed = set(patched) | {CAL_SECTOR + (at - SECTOR) for at in patched}
    stray = [at for at in range(len(chip)) if chip[at] != expected[at] and (at & ~3) not in allowed]
    check(not stray,
          "the chip is byte for byte the expected image (boot code, keypairs, sector table, "
          f"CRC and stamps restored, AIF blank, table patched, staging in the cal sector), "
          f"outside the {len(patched)} words the emulator patches"
          + (f" -- stray: {[hex(a) for a in stray[:4]]}" if stray else ""))
    stubbed = [at for at in patched
               if (int.from_bytes(chip[at:at + 4], "big") >> 26) in (16, 17, 18)]
    check(len(stubbed) == len(patched),
          "every patched word in the restored sector came back a branch to a native stub "
          "or an `sc` trap (the emulator's own patching; real silicon stages and "
          "restores its stock words there)")
    check(b2.flash.erases == 2, "exactly two sector erases (the cal scratch, the 96 KB boot sector)")
    n_hw = sum(n for _, _, n in plan["jobs"])
    check(b2.flash.programs == 2 * n_hw + 1 + len(plan["patches"]),
          f"{b2.flash.programs} program cycles = {n_hw} staged + 1 marker + {n_hw} restored "
          f"+ {len(plan['patches'])} patched halfwords")
    silicon = bytearray(chip)                     # the patched words back to silicon
    for at in patched:
        silicon[at:at + 4] = pre_wipe[at:at + 4]
    check(chip[CRC_AT:CRC_AT + 4] == struct.pack(">I", crc32_mpeg2(silicon[CRC_RANGE[0]:CRC_RANGE[1]])),
          "the stored boot CRC matches the wiped, patched boot region as silicon holds it")
    check(chip[ENTRY1_END:ENTRY1_END + 2] == b"\xfb\x33"
          and chip[ENTRY2_START:ENTRY2_START + 2] == b"\xff\xf0",
          "sector table: entry 1 ends at 0xFFF1FB33, entry 2 starts at 0xFFF00000")
    check(struct.unpack_from(">H", chip, MARK_AT)[0] == MARK_DONE,
          f"the marker at {MARK_AT:#x} reads done ({MARK_DONE:#06x})")
    from_payload = [(a, v) for (a, s, v, pc) in b2.flash_writes
                    if PAYLOAD_AT <= pc < PAYLOAD_AT + plan["payload_len"]]
    check(len(from_payload) > 0, f"the payload's stores reached the chip ({len(from_payload)} logged)")
    return b2


def phase_rewrite(b2, base, pre_wipe):
    banner("4. an ordinary session: calibration back, then the factory's first entry")
    t2 = Tester(b2)
    check(t2.authenticate(), "mode-3 seed/key accepted")
    check(t2.programming_mode(), "programming mode entered")
    check(t2.erase(EXTERNAL + CALIBRATION, 0x20000),
          "31 02 calibration erase (the session's erase flag; wipes the staging leftovers)")
    check(bytes(b2.flash.image[CAL_SECTOR:CAL_SECTOR_END]) == b"\xff" * (CAL_SECTOR_END - CAL_SECTOR),
          "the staging scratch is blank again")
    ok, sent = t2.write_sparse(EXTERNAL + CALIBRATION, base.flash[CALIBRATION:CALIBRATION_END],
                               make_progress("calibration"))
    check(ok, f"calibration restored ({sent} blocks)")
    entry = base.flash[AIF[0]:AIF[0] + 64]
    check(t2.write(EXTERNAL + AIF[0], entry),
          f"34/36/37 wrote the factory's 64-byte entry at ext {AIF[0]:#x} -- the wiped AIF")
    check(bytes(b2.flash.image[AIF[0]:AIF[0] + 64]) == entry,
          "the chip holds it (plain KWP: the wiped log is arbitrarily re-writable)")
    stamp = pre_wipe[STAMP_AT:STAMP_AT + 64]
    if stamp != b"\xff" * 64:
        check(t2.write(EXTERNAL + STAMP_AT, stamp),
              f"34/36/37 wrote the program-ID stamp back at ext {STAMP_AT:#x} -- the cal "
              "erase took it with the sector (any cal flash blanks it; a program check "
              "re-stamps, but 31 09 refuses once status is normal)")
        check(bytes(b2.flash.image[STAMP_AT:STAMP_AT + 64]) == stamp,
              "the stamp is back: the cal sector ends byte-identical to pre-wipe")
    check(t2.default_mode(), "back to the default session")
    check(t2.check_signature("data"), "31 09 re-checked the calibration and marked it valid")
    check(b2.program_valid(), "all four valid marks: a healthy DME")
    check(t2.reset(), "STEUERGERAETE_RESET")
    return b2


def phase_final(b3, base, pre_wipe):
    banner("5. final reset: the marker says done, the entry stays, the program runs")
    b4 = b3.reset()
    b4.probe(SCHEDULER_TASK, "scheduler")
    b4.boot(max_insns=40_000_000, reset_vector=True)
    check(b4.m.read8(INIT_DONE) == 1 and b4.probe_counts["scheduler"] > 10,
          f"the program runs on the restored calibration "
          f"(scheduler ticks: {b4.probe_counts['scheduler']})")
    check(b4.flash.programs == 0 and b4.flash.erases == 0,
          "the payload's guard skipped: no program cycle, no erase "
          "(the marker, not the AIF, is the guard)")
    check(b4.flash.image[AIF[0]:AIF[0] + 64] == base.flash[AIF[0]:AIF[0] + 64],
          "the entry written over KWP is still there")
    got = bytes(b4.flash.image[CALIBRATION:CAL_SECTOR_END])
    want = pre_wipe[CALIBRATION:CAL_SECTOR_END]
    ranges = []
    at = 0
    while at < len(got) and len(ranges) < 8:
        if got[at] != want[at]:
            end = at
            while end < len(got) and got[end] != want[end]:
                end += 1
            ranges.append(f"ext {CALIBRATION + at:#x}-{CALIBRATION + end:#x}: "
                          f"got {got[at:min(end, at + 16)].hex()} want {want[at:min(end, at + 16)].hex()}")
            at = end
        else:
            at += 1
    check(got == want,
          "the calibration sector is back to its pre-wipe content, staging leftovers gone"
          + ("" if got == want else " --\n    " + "\n    ".join(ranges)))
    check(struct.unpack_from(">H", b4.flash.image, MARK_AT)[0] == MARK_DONE,
          "the marker still reads done: re-running the wipe is a no-op")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flash", help="1MB external flash dump of the base pair")
    ap.add_argument("--mpc", help="448KB MPC dump of the base pair")
    ap.add_argument("--out", help="also write the built pair here (aifwipe_Flash/MPC.bin)")
    args = ap.parse_args()

    if args.flash and args.mpc:
        with open(args.flash, "rb") as f, open(args.mpc, "rb") as m:
            base = Pair(f.read(), m.read(), "base")
    else:
        flash_path = os.path.join(IMAGES_DIR, "session1.flash.bin")
        mpc_path = os.path.join(IMAGES_DIR, "session1.mpc.bin")
        if not (os.path.isfile(flash_path) and os.path.isfile(mpc_path)):
            raise SystemExit(f"no base pair: give --flash and --mpc, or put {flash_path} there")
        with open(flash_path, "rb") as f, open(mpc_path, "rb") as m:
            base = Pair(f.read(), m.read(), "session1")
    print(f"base pair: {base.name}, program {base.program_id.decode()}", flush=True)

    plan = phase_build(base)
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for kind, data in (("Flash", plan["flash"]), ("MPC", plan["mpc"])):
            path = os.path.join(args.out, f"aifwipe_{kind}.bin")
            with open(path, "wb") as f:
                f.write(data)
            print("wrote", path, flush=True)

    b, pre_wipe = phase_flash(base, plan)
    b2 = phase_payload(b, plan, pre_wipe)
    b3 = phase_rewrite(b2, base, pre_wipe)
    phase_final(b3, base, pre_wipe)

    banner("done: the AIF is wiped, the boot sector restored, the log re-writable over KWP")
    print("The wipe rode a program update signed with the key the flasher already holds.\n"
          "The payload erased the calibration sector for blank staging room, copied the\n"
          "boot sector's kept range into it, erased the 96 KB boot sector, restored all\n"
          "but the programming log, AND-patched the sector table open (boot region and\n"
          "AIF alike) and refreshed the boot CRC. A crash at any point converges: the\n"
          "staging marker at 0x387EC picks the phase to resume, and the worst case is a\n"
          "DME that needs its calibration flashed -- the recovery any flasher performs.\n"
          "The calibration was then restored over plain KWP, and the factory's own first\n"
          "log entry written back the same way. Real hardware needs the DQ7/SWSR loops\n"
          "the payload already carries, and a sector erase takes around a second.")


if __name__ == "__main__":
    main()
