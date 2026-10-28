#!/usr/bin/env python
"""Sector-granular 31 02 erases for the MS45.1 loader, proven on the emulator.

    .venv/bin/python -m tools.experiments.granular_erase [--flash ... --mpc ...] [--phase N]

Stock, any erase request in the program area walks a fixed 17-entry table:
the three external program sectors (640 KB) and all fourteen internal flash
blocks, whatever the request's address and length were (nothing stock parses
the length -- see docs/diff-flash.md). This tool patches the loader's
dispatcher so a program-area request erases exactly the external sectors
overlapping [addr, addr+len), plus the internal blocks only when the request
is itself internal. The one request the flashers actually send -- external
0xFFF60000, length 0xA0000, the whole program area -- never reaches gran's
own walk at all: gran pops its frame and continues in the stock sequence
verbatim (all fourteen internal blocks, the 54-byte program-ID stamp at
0x5FF40 refreshed from the AIF, the marks, the stock reply status), because
WinKFP/WebKFP write the MPC right after with no separate internal erase.
The patch is range-faithful, not permissive:

  - every candidate sector is gated through the loader's own decision()
    (the 0x2D94 permission table; attr bit 1 = program-style), so boot
    sectors and [0x20000,0x40000) stay refused exactly as before;
  - the erase itself runs through the loader's own per-sector dispatch
    (0x13114 -> the RAM driver), so the driver's autoselect check and its
    0xFFF1FFFF boot guard are untouched and still enforce;
  - the calibration path is not patched at all (already single-sector).

The patch is three words at the program-style branch (the li 0x35 / stb pair
that set the last device-ID byte stay stock; `bl marks-check` becomes
`bl gran`, `clrlwi r3,r3` becomes `mr r30,r3`, `cmpwi r3,1` becomes `b` to
the handler tail, which already derives its return from r30) plus a routine
in the loader's blank tail, delivered by the AIF-wipe machinery: a payload
at MPC 0x6F000 (behind the compressed-vector reset word) that stages the
boot sector into the erased calibration sector, erases the 96 KB boot
sector, restores it with the patch burned in, and writes a fresh boot CRC.
Ordinary program flashes never touch the boot sector, so the patch survives
every later flash. Phases:

 1. build the patched pair (offline; every payload word disassembled and
    checked, the boot CRC modelled over silicon bytes)
 2. flash it as an ordinary program update (stock semantics: one full
    31 02, both images, 31 09)
 3. reset: the payload installs the boot-sector patch; the chip is compared
    byte for byte against the model
 4. the patched loader at work, over KWP: a 4 KB request erases one sector
    (internal untouched, marks intact); a spanning request erases two; a
    zero-length request erases nothing but still sets the erase flag a
    34 write needs (proved in a fresh session, into blank silicon);
    [0x20000,0x40000) and the boot region stay refused; a request inside
    sector 0xC0000 takes exactly that sector, the valid marks dying with
    it and returning with the 31 09 program check; the calibration path
    is unchanged (its erase + write + the 31 09 data check restores the
    cal marks pair); the stock full-range request runs the stock sequence
    verbatim -- three sectors, all fourteen internal blocks, the stamp at
    0x5FF40 refreshed from the AIF -- and the app's finishing sequence
    (both 31 09 checks, 31 0A normal) leaves a healthy DME.
 5. a granular flash on a healthy DME: erase one program sector, rewrite
    only its non-blank runs, re-check the signature, reset -- the program
    runs. The wire count is printed against the stock full flash.
"""

import argparse
import os
import struct
import sys
from tools.experiments.aif_wipe import (Asm, banner, check, erase_sector, make_progress,
                      program_halfword, verify_disasm,
                      R3, R4, R5, R6, R7, R14, R15, R16, R17, R18, R19, R20, R21)
from ms45emu.board import Board, VALID_MARKS
from ms45emu.flashchip import SECTORS
from ms45emu.image import Pair, IMAGES_DIR
from ms45emu.kwp import Tester
from ms45emu.checksums import fix_program, crc32_mpeg2
from ms45emu.machine import FLASH_SIZE

EXT = 0xFFF00000                       # external flash, CPU address
EXTERNAL, INTERNAL = 0x02000000, 0x06000000   # the KWP address windows
PROGRAM, PROGRAM_END = 0x60000, 0xFFF40        # what a flasher sends of each part
CALIBRATION, CALIBRATION_END = 0x40000, 0x5D000
SCHEDULER_TASK, INIT_DONE = 0x3B38C, 0x3FEB26  # how a running program is recognised

HOOK = 8                               # compressed-vector entry 1 (reset) in the MPC image
PAYLOAD_AT = 0x6F000                   # blank tail of the MPC image
SECTOR = 0x8000                        # the 96 KB boot sector
KEEP_END = 0x20000                     # the whole sector is kept (the AIF included)
CRC_AT = 0x1F800                       # boot CRC-32/MPEG-2 over ext 0x0-0x1EFFF
CRC_RANGE = (0x0, 0x1F000)
CAL_SECTOR, CAL_SECTOR_END = 0x40000, 0x60000
STAMP_AT = 0x5FF40                     # program-ID stamp, inside the cal sector

GRAN_AT = 0x39000                      # the routine, in the loader's blank tail:
                                       # the loader's code runs past the 96 KB boot
                                       # sector into [0x20000,0x40000), the sector no
                                       # 31 02 or 34 write can touch -- so the patch
                                       # cannot be erased by any later flash
MARK2_AT = 0x387EE                     # install marker, next to the wipe's own
MARK2_STAGED, MARK2_DONE = 0x5A5A, 0x5A58

# the detection stamp, 16 bytes of data in the MPC image's blank tail past
# the payload: KWP can read the internal flash (0x23 / LAR) but never the
# external one, so the app detects the patch by reading this plus the
# hijacked reset word at MPC 0x8. Data only -- the installer never runs it;
# it rides the ordinary phase-2 MPC write and survives every later flash
# until something rewrites the internal flash whole.
MAGIC_AT = 0x6FF00
# version 2: sector 3's erase fixed -- the 0x100000000 bound wrapped
# through li32 to 0, so any request reaching 0xC0000..0x100000 silently
# skipped that sector and answered success (the v12/v13 red). v1 units
# must be re-patched; the app refuses quick flash below this version.
MAGIC = b"BMWEBGRN" + struct.pack(">II", 2, 1)   # id, version, capability flags

# the three external program sectors: (start, end) in CPU terms
PROG_SECTORS = ((0xFFF60000, 0xFFF80000), (0xFFF80000, 0xFFFC0000), (0xFFFC0000, 0x100000000))

# small-data cells (r13 = 0x4017F0), as 16-bit d-fields for loads/stores
MODE, FLAGS, ACC = 0x801E, 0x8018, 0x806C
BUF_PTR, ERASE_OK = 0x8238, 0x802F
BUFD = -0x7F90                         # the 64-byte program buffer, for addi

# loader signatures: the same routines in every pair seen, at shifted addresses
SIGS = {
    "decision":   "9421fff093e1000c39000000b10d8018",
    "dispatch":   "9421fff07c0802a693e1000c90010014" "3be30000" "93ed803c",
    "engine":     "9421ffd87c0802a6bf21000c9001002c39800000",
    "bufclear":   "38a00000388d80707c6429ae",
    "progbytes":  "908d803c906d8040b0ad801c",
    "marksB":     "3c6000008063ffc03d604224",
    "site":       "39800035998d8033",   # li r12,0x35; stb r12,-0x7fcd(r13)
    "tail":       "3be000009bed80309bed8031",
}


def bl_target(flash, at):
    """Where the `bl` at `at` goes, or None if that word is not a bl."""
    w = struct.unpack_from(">I", flash, at)[0]
    if (w & 0xFC000001) != 0x48000001:
        return None
    rel = w & 0x03FFFFFC
    if rel & 0x02000000:               # the 26-bit field is signed
        rel -= 1 << 26
    return at + rel


def locate(flash):
    """The patch-relevant routines by signature; refuses anything ambiguous."""
    out = {}
    for name, sig in SIGS.items():
        pat, hits = bytes.fromhex(sig), []
        at = flash.find(pat)
        while at >= 0:
            hits.append(at)
            at = flash.find(pat, at + 1)
        out[name] = [h for h in hits if SECTOR <= h < KEEP_END]
    for name in ("decision", "dispatch", "engine", "bufclear", "progbytes", "marksB", "tail"):
        check(len(out[name]) == 1,
              f"`{name}` found exactly once in the boot sector "
              f"(hits: {[hex(h) for h in out[name]]})")
        out[name] = out[name][0]
    # the site: li 0x35 / stb followed by a bl into the marks check the
    # program-style path uses (the cal path's identical pair calls another)
    site = [at for at in out["site"] if bl_target(flash, at + 8) == out["marksB"]]
    check(len(site) == 1,
          f"the program-style patch site found exactly once (candidates: "
          f"{[hex(h) for h in out['site']]}, matching: {[hex(h) for h in site]})")
    out["site"] = site[0]
    return out


# ---------------------------------------------------------------------------
# the assembler: aif_wipe's two-pass Asm plus the forms gran needs


def _imm(value, kind):
    """A 16-bit immediate that refuses to truncate: an out-of-range value
    assembles to a silently wrong instruction (the 0x8000-in-addi class).
    "offset" d-form displacements also take 0x8000..0xFFFF -- the loader's
    cell constants are negative displacements spelled as unsigned."""
    ranges = {"offset": (-0x8000, 0xFFFF), "signed": (-0x8000, 0x7FFF),
              "unsigned": (0, 0xFFFF)}
    lo, hi = ranges[kind]
    if not lo <= value <= hi:
        raise ValueError(f"immediate {value:#x} does not fit a {kind} 16-bit field")
    return value & 0xFFFF


class Asm2(Asm):
    def lbz(self, rD, d, rA):
        self.raw(0x88000000 | (rD << 21) | (rA << 16) | _imm(d, "offset"),
                 f"lbz    r{rD}, {d:#x}(r{rA})")

    def stw(self, rS, d, rA):
        self.raw(0x90000000 | (rS << 21) | (rA << 16) | _imm(d, "offset"),
                 f"stw    r{rS}, {d:#x}(r{rA})")

    def addis(self, rD, rA, imm):
        self.raw(0x3C000000 | (rD << 21) | (rA << 16) | _imm(imm, "unsigned"),
                 f"addis  r{rD}, r{rA}, {imm:#06x}")

    def li(self, rD, imm):
        self.raw(0x38000000 | (rD << 21) | _imm(imm, "signed"), f"li     r{rD}, {imm:#7d}")

    def addi(self, rD, rA, imm):
        self.raw(0x38000000 | (rD << 21) | (rA << 16) | _imm(imm, "signed"),
                 f"addi   r{rD}, r{rA}, {imm:#x}")

    def lhz(self, rD, d, rA):
        self.raw(0xA0000000 | (rD << 21) | (rA << 16) | _imm(d, "offset"),
                 f"lhz    r{rD}, {d:#x}(r{rA})")

    def lwz(self, rD, d, rA):
        self.raw(0x80000000 | (rD << 21) | (rA << 16) | _imm(d, "offset"),
                 f"lwz    r{rD}, {d:#x}(r{rA})")

    def cmplwi(self, rA, imm):
        self.raw(0x28000000 | (rA << 16) | _imm(imm, "unsigned"),
                 f"cmplwi r{rA}, {imm:#06x}")

    def slwi(self, rA, rS, n):          # rlwinm rA, rS, n, 0, 31-n (ME is bits 1-5)
        self.raw(0x54000000 | (rS << 21) | (rA << 16) | (n << 11) | (0 << 6) | ((31 - n) << 1),
                 f"slwi   r{rA}, r{rS}, {n}")

    def srwi(self, rA, rS, n):          # rlwinm rA, rS, 32-n, n, 31
        self.raw(0x54000000 | (rS << 21) | (rA << 16) | ((32 - n) << 11) | (n << 6) | (31 << 1),
                 f"srwi   r{rA}, r{rS}, {n}")

    def slw(self, rA, rS, rB):
        self.raw(0x7C000000 | (rS << 21) | (rA << 16) | (rB << 11) | (24 << 1),
                 f"slw    r{rA}, r{rS}, r{rB}")

    def cmpwi(self, rA, imm):
        self.raw(0x2C000000 | (rA << 16) | _imm(imm, "signed"), f"cmpwi  r{rA}, {imm:#x}")

    def andi_(self, rA, rS, imm):
        self.raw(0x70000000 | (rS << 21) | (rA << 16) | _imm(imm, "unsigned"),
                 f"andi.  r{rA}, r{rS}, {imm:#04x}")

    def or_(self, rA, rS, rB):
        self.raw(0x7C000000 | (rS << 21) | (rA << 16) | (rB << 11) | 0x378,
                 f"or     r{rA}, r{rS}, r{rB}")

    def add(self, rD, rA, rB):
        self.raw(0x7C000000 | (rD << 21) | (rA << 16) | (rB << 11) | 0x214,
                 f"add    r{rD}, r{rA}, r{rB}")

    def subfic(self, rD, rA, imm):
        self.raw(0x20000000 | (rD << 21) | (rA << 16) | _imm(imm, "signed"),
                 f"subfic r{rD}, r{rA}, {imm:#06x}")

    def mr(self, rD, rS):
        self.or_(rD, rS, rS)
        self.words[-1] = (self.words[-1][0], f"mr     r{rD}, r{rS}")

    def mflr(self, rD):                 # mfspr rD, spr 8: the spr field is the 8
        self.raw(0x7C0802A6 | (rD << 21), f"mflr   r{rD}")

    def mtlr(self, rS):                 # mtspr spr 8, rS
        self.raw(0x7C0803A6 | (rS << 21), f"mtlr   r{rS}")

    def stwu(self, rS, d, rA):
        self.raw(0x94000000 | (rS << 21) | (rA << 16) | _imm(d, "offset"),
                 f"stwu   r{rS}, {d:#x}(r{rA})")

    def bl(self, target):               # absolute; fixed up in resolve()
        self.raw(0x48000001, f"bl     {target:#x}")

    def b(self, label):
        self.fixups.append((self.here(), "b", label))
        self.raw(0x48000000, f"b      {label}")

    def _bcc(self, op, kind, label):
        self.fixups.append((self.here(), kind, label))
        self.raw(op, f"{kind:<6} {label}")

    def blt(self, label):               # CR0 LT/GT after a cmplw
        self._bcc(0x41800000, "blt", label)

    def bgt(self, label):
        self._bcc(0x41810000, "bgt", label)

    def ble(self, label):
        self._bcc(0x40810000, "ble", label)

    def resolve(self, base):
        ops = {"beq": (0x41820000, 0xFFFC), "bne": (0x40820000, 0xFFFC),
               "blt": (0x41800000, 0xFFFC), "bgt": (0x41810000, 0xFFFC),
               "ble": (0x40810000, 0xFFFC), "b": (0x48000000, 0x03FFFFFC)}
        for index, kind, label in self.fixups:
            op, mask = ops[kind]
            rel = 4 * (self.labels[label] - index)
            self.words[index] = (op | (rel & mask), self.words[index][1])
        for index, (w, note) in enumerate(self.words):
            if note.startswith("bl     0x"):
                target = int(note.split()[1], 16)
                rel = (target - (base + 4 * index)) & 0x03FFFFFC
                # round-trip: the CPU sign-extends this offset from the
                # runtime pc; if base is not where the code executes, every
                # call lands elsewhere (the 0xFFE-mirror stall)
                signed = rel - (1 << 26) if rel & (1 << 25) else rel
                if (base + 4 * index + signed) & 0xFFFFFFFF != target & 0xFFFFFFFF:
                    raise ValueError(
                        f"bl at word {index} ({note}) assembles to a target of "
                        f"{(base + 4 * index + signed) & 0xFFFFFFFF:#x} from base "
                        f"{base:#x} -- pass the runtime address as base")
                self.words[index] = (0x48000001 | rel, note)


def verify_words(words, base, labels):
    """Every word against capstone, every branch to its intended target.
    Capstone prints canonical forms for some aliases (mflr -> mfspr, slwi ->
    rlwinm), so the mnemonic may match either way."""
    from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
    md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
    canonical = {"mflr": "mfspr", "mtlr": "mtspr"}
    bad = []
    for i, (w, note) in enumerate(words):
        ins = next(md.disasm(struct.pack(">I", w), base + 4 * i), None)
        want = note.split()[0].rstrip(":")
        want = canonical.get(want, want)
        got = f"{ins.mnemonic} {ins.op_str}".strip() if ins else "?"
        if ins is None or canonical.get(ins.mnemonic, ins.mnemonic) != want:
            bad.append((base + 4 * i, w, note, got))
            continue
        if want in ("beq", "bne", "b", "blt", "bgt", "ble"):
            label = note.split()[1]
            if label in labels and int(ins.op_str, 16) != base + 4 * labels[label]:
                bad.append((base + 4 * i, w, note, f"{got} (want the label)"))
                continue
        if want in ("bl", "ba"):
            if int(ins.op_str, 16) & 0xFFFFFFFF != int(note.split()[1], 16) & 0xFFFFFFFF:
                bad.append((base + 4 * i, w, note, got))
                continue
        print(f"    {base + 4 * i:05X}: {w:08X}  {note}")
    if bad:
        for at, w, note, got in bad[:8]:
            print(f"    {at:#x}: {w:08X} expected `{note}` disassembles `{got}`")
        raise SystemExit(f"  FAIL: {len(bad)} words do not disassemble as intended")
    print(f"  ok: all {len(words)} words disassemble as written (capstone)")


# ---------------------------------------------------------------------------
# gran: the loader's new erase dispatcher. Runs on the first tick of a
# program-style 31 02 job (MODE == 17), reads the request back from the
# packet buffer it was parsed from, and erases only what it overlaps.

R28, R29, R30, R31 = 28, 29, 30, 31


def assemble_gran(addrs):
    a = Asm2()
    dec, disp, eng = (EXT | addrs[n] for n in ("decision", "dispatch", "engine"))

    a.stwu(1, -0x20, 1)
    a.mflr(0)
    a.stw(0, 0x1C, 1)
    for i, r in enumerate((R28, R29, R30, R31)):
        a.stw(r, 8 + 4 * i, 1)
    a.lwz(R29, BUF_PTR, 13)                    # the request buffer
    a.lbz(R30, 1, R29)                         # the address, low 24 bits
    a.slwi(R30, R30, 16)
    a.lbz(4, 2, R29)
    a.slwi(4, 4, 8)
    a.or_(R30, R30, 4)
    a.lbz(4, 3, R29)
    a.or_(R30, R30, 4)
    a.lbz(4, 4, R29)                           # ... and its window byte
    a.cmplwi(4, 2)
    a.bne("nowin")
    a.addis(R30, R30, 0xFFF0)                  # external: 0xFFFxxxxx
    a.label("nowin")
    a.lbz(R31, 5, R29)                         # the length, 24 bits
    a.slwi(R31, R31, 16)
    a.lbz(4, 6, R29)
    a.slwi(4, 4, 8)
    a.or_(R31, R31, 4)
    a.lbz(4, 7, R29)
    a.or_(R31, R31, 4)
    a.cmpwi(R31, 0)
    a.beq("ret1")                              # zero length: nothing to erase
    a.add(4, R30, R31)
    a.addi(4, 4, -1)                           # r4 = the last byte of the range

    a.lhz(R28, MODE, 13)                       # the job's tick counter
    a.cmplwi(R28, 0x11)
    a.beq("first_tick")

    # -- later ticks. The stock wrapper (marksB) answers 0 on every tick
    #    after the first, and the handler then branches to its sub-range
    #    path at site+0xB0 -- whose job-runner rounds perform the
    #    full-range op's actual sector erases: measured, the per-sector
    #    dispatch/engine calls fire on the LATER ticks, never the first
    #    (the first tick only arms the walk: checks, marks, the stamp).
    #    A full-span request must therefore keep flowing into the stock
    #    machinery every tick, with marksB's measured answers; any other
    #    request already did its work synchronously in the first tick
    #    and only ticks MODE down to the 71 02 01 answer
    a.li32(6, 0xFFF60000)
    a.cmplw(R30, 6)
    a.bne("ret1")
    a.li32(6, 0xFFFFFFFF)
    a.cmplw(4, 6)
    a.bne("ret1")
    a.li(3, 0)                                 # marksB's later-tick answer
    a.li(4, 2)                                 # and its side output, measured
    for i, r in enumerate((R28, R29, R30, R31)):
        a.raw(0x80000000 | (r << 21) | (1 << 16) | (8 + 4 * i),
              f"lwz    r{r}, {8 + 4 * i:#x}(r1)")
    a.lwz(0, 0x1C, 1)
    a.mtlr(0)
    a.addi(1, 1, 0x20)
    subrange = EXT | (addrs["site"] + 0xB0)    # the handler's sub-range path
    a.raw(0x48000002 | (subrange & 0x03FFFFFC), f"ba     {subrange:#x}")
    a.label("first_tick")

    # stock compatibility: the one request the flashers send -- external
    # 0xFFF60000, length 0xA0000 (last byte 0xFFFFFFFF, by wraparound) --
    # leaves gran and runs the stock sequence verbatim from the intact
    # words at site+0x18 (`bl 0xa04c`, the walk). Stock's walk blanks all
    # fourteen internal blocks (the flashers then write the MPC with no
    # separate internal erase) and refreshes the 54-byte stamp at 0x5FF40
    # from the AIF; running the real code beats replicating the side
    # effects piecemeal. The stock gate at the site was the marksB call
    # (0x13c50) plus `cmpwi r3,1`; gran rebuilds only its outcome for the
    # walk (r3 = 1, r4 = 2, cr0 EQ) -- the pre-site FLAGS check has already
    # gated program-style, and only this exact request shape ever comes
    # here. r4 is the wrapper's side output: the walk's per-entry erase
    # dispatch compares against it, and without the 2 the walk books the
    # stamp and marks, answers success, and erases NOTHING (found by
    # tracing the stock chain: subrange-dispatch(0, 2) per table entry
    # never fires with a stale r4) -- the exact way a flasher's full-span
    # request would brick a patched DME.
    stock_seq = EXT | (addrs["site"] + 0x18)
    a.li32(6, 0xFFF60000)
    a.cmplw(R30, 6)
    a.bne("subrange")
    a.li32(6, 0xFFFFFFFF)
    a.cmplw(4, 6)
    a.bne("subrange")
    a.li(3, 1)                                 # the state stock enters the walk in
    a.li(4, 2)                                 # the wrapper's other output, measured
    a.cmpwi(3, 1)
    for i, r in enumerate((R28, R29, R30, R31)):   # pop the frame, then go
        a.raw(0x80000000 | (r << 21) | (1 << 16) | (8 + 4 * i),
              f"lwz    r{r}, {8 + 4 * i:#x}(r1)")
    a.lwz(0, 0x1C, 1)
    a.mtlr(0)
    a.addi(1, 1, 0x20)
    a.raw(0x48000002 | (stock_seq & 0x03FFFFFC), f"ba     {stock_seq:#x}")
    a.label("subrange")

    a.li32(6, 0x70000)                         # cmplwi can't hold 0x70000
    a.cmplw(R30, 6)
    a.blt("internal")                          # internal-window request

    # the three external program sectors, ascending. The valid marks are
    # NOT touched here: their only recoverable death is their own sector
    # erasing (blank -> the 31 09 re-program restores the magic), and a
    # zero-programmed pair is unrecoverable -- programming only clears
    # bits, so 31 09's re-program over 0x00000000 leaves it dead and the
    # check fails (measured, diff_flash --test v3). Stock's walk always
    # erases sector 0xC0000, so stock always ends with the pair blank;
    # a granular erase that avoids that sector deliberately leaves the
    # pair valid -- the closing 31 09 is then vacuous (71 09 00) and the
    # reset, the DME booting the new program, is the verification
    for i, (start, end) in enumerate(PROG_SECTORS):
        a.add(4, R30, R31)                      # request end: r4 is volatile,
        a.addi(4, 4, -1)                        # (last byte); decision/dispatch
        a.li32(6, start)                        # clobber it between passes
        a.cmplw(6, 4)
        a.bgt(f"next{i}")                      # sector starts beyond the range
        a.li32(7, end - 1)                      # the sector's LAST byte, not its
        a.cmplw(7, R30)                         # end: sector 3 ends at 0x100000000,
        a.blt(f"next{i}")                      # which li32 would wrap to 0 and
                                              # skip the sector forever (the v12
                                              # red: 0xD2000 erased nothing)
        a.mr(3, 6)
        a.li(4, 0)
        a.bl(dec)                              # the attr table stays the gate
        a.li32(6, start)                       # decision leaves the attr-table
        a.mr(3, 6)                             # base in r6: reload the sector
        a.bl(disp)                             # the loader's own sector erase
        a.lbz(12, ERASE_OK, 13)
        a.cmpwi(12, 0)
        a.beq("fail")
        a.label(f"next{i}")

    a.label("internal")                        # internal-window request:
    a.add(4, R30, R31)                         # only the overlapping blocks
    a.addi(4, 4, -1)
    a.li(7, 0)
    a.li(12, 0)
    a.label("iloop")
    a.slwi(8, 7, 15)                           # block start
    a.addis(9, 8, 1)                           # block end (exclusive):
    a.addi(9, 9, -0x8000)                      #   start + 0x8000, not -0x8000
    a.cmplw(8, 4)
    a.bgt("idone")
    a.cmplw(9, R30)
    a.ble("inext")
    a.li(10, 1)
    a.subfic(11, 7, 31)
    a.slw(10, 10, 11)
    a.or_(12, 12, 10)
    a.label("inext")
    a.addi(7, 7, 1)
    a.cmplwi(7, 14)
    a.blt("iloop")
    a.label("idone")
    a.cmpwi(12, 0)
    a.beq("ret1")
    a.label("internal_do")
    a.stw(12, ACC, 13)                         # the block bitmask ...
    a.li(12, 0x10)
    a.sth(12, FLAGS, 13)                       # ... the internal mode ...
    a.bl(eng)                                  # ... and the loader's engine
    a.lbz(12, ERASE_OK, 13)
    a.cmpwi(12, 0)
    a.beq("fail")

    a.label("ret1")
    a.li(3, 1)                     # keep ticking: the scheduler counts MODE down
    a.b("out")                     # to 0 and answers 71 02 01 (the walk never
                                   # returns 0 on success; 0 means abort -> 71 02 02)
    a.label("fail")
    a.li(3, 0)                     # abort: the scheduler answers 71 02 02
    a.label("out")
    for i, r in enumerate((R28, R29, R30, R31)):
        a.raw(0x80000000 | (r << 21) | (1 << 16) | (8 + 4 * i),
              f"lwz    r{r}, {8 + 4 * i:#x}(r1)")
    a.lwz(0, 0x1C, 1)
    a.mtlr(0)
    a.addi(1, 1, 0x20)
    a.raw(0x4E800020, "blr")
    return a


def site_patch_words(addrs):
    """The three words that redirect the program-style branch into gran."""
    site, gran = EXT | addrs["site"], EXT | GRAN_AT
    tail = EXT | addrs["tail"]
    return [0x48000001 | ((gran - (site + 8)) & 0x03FFFFFC),   # bl gran
            0x7C7E1B78,                                        # mr r30, r3
            0x48000000 | ((tail - (site + 16)) & 0x03FFFFFC)]  # b <tail>


# ---------------------------------------------------------------------------
# the installer payload: stage the boot sector, erase it, restore it with the
# patch burned in, refresh the boot CRC. Crash-convergent via the marker.


def assemble_install(stage, restore, patches, table1_at, table2_at, patches_at, orig_start):
    a = Asm()
    a.lis(R3, 0xFFF0)
    a.li32(R17, 0x002FC00E)                    # SWSR
    a.li(R14, 0xAA)
    a.li(R15, 0x55)
    a.li(R16, 0xA0)
    a.li(R18, 0x556C)
    a.li(R19, 0xAA39)
    a.li32(R6, EXT | MARK2_AT)
    a.lhzx(R4, R6)
    a.cmplwi(R4, MARK2_DONE)
    a.beq("done")
    a.cmplwi(R4, MARK2_STAGED)
    a.beq("erase_boot")

    erase_sector(a, "cal", CAL_SECTOR)         # -- blank staging room

    a.li32(R20, table1_at)                     # -- stage: boot -> cal sector
    a.li(R21, len(stage))
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
    a.li32(R4, MARK2_STAGED)
    a.li32(R6, EXT | MARK2_AT)
    program_halfword(a, "m")

    a.label("erase_boot")
    erase_sector(a, "boot", SECTOR)

    a.li32(R20, table2_at)                     # -- restore: cal/MPC -> boot
    a.li(R21, len(restore))
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

    a.li32(R20, patches_at)                    # -- the CRC and the marker
    a.li(R21, len(patches))
    a.label("patch_next")
    a.lwz(R6, 0, R20)
    a.lhz(R4, 6, R20)
    a.addi(R20, R20, 8)
    program_halfword(a, "p")
    a.addic_(R21, -1)
    a.bne("patch_next")

    a.label("done")
    a.ba(orig_start)
    return a


def plan_jobs(addrs):
    """Stage/restore jobs covering the boot sector minus two holes: the
    patched words at the site, and the CRC word (patched to the fresh value
    into the blank). gran needs no hole -- it is programmed straight into the
    refused sector's blank tail, which no flash ever erases."""
    holes = sorted([(addrs["site"] + 8, addrs["site"] + 8 + 12), (CRC_AT, CRC_AT + 4)])
    keep, at = [], SECTOR
    for lo, hi in holes:
        if lo > at:
            keep.append((at, lo))
        at = max(at, hi)
    if at < KEEP_END:
        keep.append((at, KEEP_END))

    stage, cal = [], CAL_SECTOR                 # (src off, dst off, halfwords)
    for lo, hi in keep:
        stage.append((lo, cal, (hi - lo) // 2))
        cal += hi - lo
    check(cal <= CAL_SECTOR_END - 0x100,
          f"staging {cal - CAL_SECTOR:#x} bytes fits the calibration sector")
    return stage


# ---------------------------------------------------------------------------


def phase_build(base):
    banner("1. building the granular-erase pair (offline, no DME involved)")
    flash, mpc = bytearray(base.flash), bytearray(base.mpc)
    addrs = locate(bytes(flash))
    print(f"  loader: decision {addrs['decision']:#x}, dispatch {addrs['dispatch']:#x}, "
          f"engine {addrs['engine']:#x}, site {addrs['site']:#x}, tail {addrs['tail']:#x}")

    stock_word = struct.unpack_from(">I", mpc, HOOK)[0]
    check((stock_word & 0xFC000002) == 0x48000002, f"MPC 0x8 holds {stock_word:#010x}, a `ba`")
    orig_start = EXT | (stock_word & 0x03FFFFFC)
    check(mpc[PAYLOAD_AT:] == b"\xff" * (len(mpc) - PAYLOAD_AT), f"MPC {PAYLOAD_AT:#x}+ is blank")
    check(flash[MARK2_AT:MARK2_AT + 2] == b"\xff\xff", f"marker halfword at {MARK2_AT:#x} is blank")
    stored = int.from_bytes(flash[CRC_AT:CRC_AT + 4], "big")
    check(crc32_mpeg2(flash[CRC_RANGE[0]:CRC_RANGE[1]]) == stored,
          f"the stock boot CRC at {CRC_AT:#x} matches CRC-32/MPEG-2 over 0x0-0x1EFFF")

    gran = assemble_gran(addrs)
    gran.resolve(EXT | GRAN_AT)               # the runtime address: bl offsets
    verify_words(gran.words, EXT | GRAN_AT, gran.labels)
    gran_words = [w for w, _ in gran.words]
    check(flash[GRAN_AT:GRAN_AT + 4 * len(gran_words)] == b"\xff" * (4 * len(gran_words)),
          f"the loader's blank tail at {GRAN_AT:#x}+ has room for {len(gran_words)} words")
    patch_words = site_patch_words(addrs)
    site_cpu = EXT | addrs["site"]
    verify_words(list(zip(patch_words,
                          ["bl     " + hex(EXT | GRAN_AT), "mr     r30, r3",
                           "b      " + hex(EXT | addrs["tail"])])),
                 site_cpu + 8, {})
    print(f"  gran: {len(gran_words)} words at ext {GRAN_AT:#x}, three patch words at "
          f"ext {addrs['site'] + 8:#x} ({patch_words[0]:08X} {patch_words[1]:08X} {patch_words[2]:08X})")

    # the boot region after install, as silicon holds it: stock bytes with the
    # patch words and gran burned in -- and the CRC that follows
    silicon = bytearray(flash)
    for i, w in enumerate(patch_words):
        struct.pack_into(">I", silicon, addrs["site"] + 8 + 4 * i, w)
    for i, w in enumerate(gran_words):
        struct.pack_into(">I", silicon, GRAN_AT + 4 * i, w)
    new_crc = crc32_mpeg2(silicon[CRC_RANGE[0]:CRC_RANGE[1]])
    print(f"  boot CRC {stored:08x} -> {new_crc:08x} "
          f"(the three patch words; gran at {GRAN_AT:#x} is outside the CRC range)")

    stage = plan_jobs(addrs)
    patches = [(CRC_AT, new_crc >> 16), (CRC_AT + 2, new_crc & 0xFFFF), (MARK2_AT, MARK2_DONE)]
    a1 = assemble_install(stage, [], patches, 0, 0, 0, orig_start)      # pass 1: sizes
    t1 = PAYLOAD_AT + 4 * len(a1.words)
    t2 = t1 + 12 * len(stage)
    tp = t2 + 12 * (len(stage) + 2)            # restore = the reversed stage + 2 MPC jobs
    td = tp + 8 * len(patches)
    # full CPU addresses: word0 is where the loop programs (external), word1
    # where it reads -- cal staging (external) or the payload's own data
    # (internal MPC). A raw offset in word0 lands in internal flash: the
    # loop would read the MPC image and program it into the chip.
    restore = [(EXT | boot, EXT | cal, n) for boot, cal, n in reversed(stage)]
    restore.append((EXT | addrs["site"] + 8, td, 6))                   # 3 words from the payload's data
    restore.append((EXT | GRAN_AT, td + 12, 2 * len(gran_words)))      # words -> halfwords

    # every program lands in external flash, every read in the cal staging
    # or the payload's own data -- raw offsets here are the classic bug
    for dst, src, n in restore:
        check(dst >> 20 == 0xFFF and (SECTOR <= (dst & 0xFFFFF) < KEEP_END or
                                      (dst & 0xFFFFF) == GRAN_AT),
              f"restore destination {dst:#x} is external, in the boot sector or at gran")
        check(src >> 20 == 0xFFF and CAL_SECTOR <= (src & 0xFFFFF) < CAL_SECTOR_END or
              PAYLOAD_AT <= src < len(mpc),
              f"restore source {src:#x} is the cal staging or the payload data")
    for src, dst, n in stage:
        check(SECTOR <= src < KEEP_END and CAL_SECTOR <= dst < CAL_SECTOR_END,
              f"stage job {src:#x}->{dst:#x} stays boot -> cal staging")

    a = assemble_install(stage, restore, patches, t1, t2, tp, orig_start)
    a.resolve(PAYLOAD_AT)
    words = list(a.words)
    for src, dst, n in stage:                  # the payload walks full CPU addresses
        words += [(EXT | src, f"job src {EXT | src:#x}"), (EXT | dst, f"     dst {EXT | dst:#x}"),
                  (n, f"     {n} halfwords")]
    for dst, src, n in restore:
        words += [(dst, f"job dst {dst:#x}"), (src, f"     src {src:#x}"),
                  (n, f"     {n} halfwords")]
    for off, hw in patches:
        words += [(EXT | off, f"patch {EXT | off:#x}"), (hw & 0xFFFF, f"      {hw:#06x}")]
    words += [(w, f"data   {w:08X}") for w in patch_words]
    words += [(w, f"data   {w:08X}") for w in gran_words]
    payload = b"".join(struct.pack(">I", w) for w, _ in words)
    check(PAYLOAD_AT + len(payload) <= len(mpc),
          f"payload + tables + data = {len(payload)} bytes, MPC {PAYLOAD_AT:#x}+ has room")
    verify_disasm(words[:len(a.words)], PAYLOAD_AT, a.labels)

    struct.pack_into(">I", mpc, HOOK, 0x48000002 | PAYLOAD_AT)
    mpc[PAYLOAD_AT:PAYLOAD_AT + len(payload)] = payload
    check(PAYLOAD_AT + len(payload) <= MAGIC_AT,
          f"the detection stamp at {MAGIC_AT:#x} clears the payload ({len(payload)} bytes)")
    mpc[MAGIC_AT:MAGIC_AT + len(MAGIC)] = MAGIC
    fix_program(flash, mpc)
    print(f"  MPC 0x8: {stock_word:#010x} -> ba {PAYLOAD_AT:#x}; fix_program re-signed")
    print(f"  detection stamp {MAGIC!r} at MPC {MAGIC_AT:#x} (data; readable over KWP via LAR)")

    return {"flash": bytes(flash), "mpc": bytes(mpc), "addrs": addrs,
            "gran_words": gran_words, "patch_words": patch_words, "new_crc": new_crc,
            "stage": stage, "orig_start": orig_start, "payload_len": len(payload)}


def expected_image(pre_install, window, plan):
    """The chip after install, byte for byte. Staged and restored bytes come
    from the live mapped window (the emulator patches a few words of mapped
    code; real silicon stages and restores its stock words there)."""
    exp = bytearray(pre_install)
    exp[CAL_SECTOR:CAL_SECTOR_END] = b"\xff" * (CAL_SECTOR_END - CAL_SECTOR)
    for src, dst, n in plan["stage"]:
        exp[dst:dst + 2 * n] = window[src:src + 2 * n]                # staged
    exp[SECTOR:KEEP_END] = window[SECTOR:KEEP_END]                    # restored
    site = plan["addrs"]["site"]
    for i, w in enumerate(plan["patch_words"]):
        struct.pack_into(">I", exp, site + 8 + 4 * i, w)
    for i, w in enumerate(plan["gran_words"]):
        struct.pack_into(">I", exp, GRAN_AT + 4 * i, w)
    exp[CRC_AT:CRC_AT + 4] = struct.pack(">I", plan["new_crc"])
    struct.pack_into(">H", exp, MARK2_AT, MARK2_DONE)
    return bytes(exp)


def phase_flash(base, plan):
    banner("2. flashing it as an ordinary program update (stock semantics)")
    b = Board(base)
    b.boot(max_insns=20_000_000)
    t = Tester(b)
    check(t.authenticate(), "mode-3 seed/key accepted")
    check(t.programming_mode(), "programming mode entered")
    check(t.erase(EXTERNAL + PROGRAM, 0xA0000),
          "31 02 erased the program sectors and the internal flash (stock)")
    ok, sent = t.write_sparse(EXTERNAL + PROGRAM, plan["flash"][PROGRAM:PROGRAM_END],
                              make_progress("external program"))
    check(ok, f"34/36/37 wrote the external program image ({sent} blocks)")
    ok, sent = t.write_sparse(INTERNAL, plan["mpc"], make_progress("internal flash"))
    check(ok, f"34/36/37 wrote the internal flash image ({sent} blocks)")
    check(t.default_mode(), "back to the default session")
    check(t.check_signature("program"), "31 09 accepted the forged program signature")
    check(t.programming_status() == 1, "31 0A: normal")
    check(b.program_valid(), "all four valid marks are in")
    pre_install = bytes(b.flash.image)
    check(t.reset(), "STEUERGERAETE_RESET")
    return b, pre_install


def phase_install(b, plan, pre_install):
    banner("3. reset: the payload installs the boot-sector patch")
    b2 = b.reset()
    # through the 0xFFF00000 mirror: the payload's own window (r3 = lis
    # 0xFFF0), which also carries the emulator's li-patches -- the 0xFFE
    # mirror is a stale stock copy of them
    window = bytes(b2.m.mu.mem_read(EXT, FLASH_SIZE))            # what the payload reads
    b2.probe(SCHEDULER_TASK, "scheduler")
    b2.boot(max_insns=100_000_000, reset_vector=True)
    chip = bytes(b2.flash.image)
    expected = expected_image(pre_install, window, plan)

    patched = [at for at in range(SECTOR, KEEP_END, 4)
               if window[at:at + 4] != pre_install[at:at + 4]]
    allowed = set(patched) | {CAL_SECTOR + (at - SECTOR) for at in patched}
    stray = [at for at in range(len(chip)) if chip[at] != expected[at] and (at & ~3) not in allowed]
    check(not stray, "the chip is byte for byte the model (patched boot sector, fresh CRC, "
          "staging in the cal sector, AIF intact)"
          + (f" -- {len(stray)} stray bytes, first: {[hex(a) for a in stray[:8]]}" if stray else ""))
    silicon = bytearray(chip)                    # the emulator-patched words back to silicon
    for at in patched:
        if CRC_RANGE[0] <= at < CRC_RANGE[1]:
            silicon[at:at + 4] = pre_install[at:at + 4]
    check(chip[CRC_AT:CRC_AT + 4] ==
          struct.pack(">I", crc32_mpeg2(silicon[CRC_RANGE[0]:CRC_RANGE[1]])),
          "the stored boot CRC matches the installed boot region as silicon holds it")
    site = plan["addrs"]["site"]
    got = [struct.unpack_from(">I", chip, site + 8 + 4 * i)[0] for i in range(3)]
    check(got == plan["patch_words"], f"the three patch words are in: {[hex(w) for w in got]}")
    check(struct.unpack_from(">H", chip, MARK2_AT)[0] == MARK2_DONE, "the marker reads done")
    # what the app's ident will see over KWP: the internal flash is the one
    # window a stock DME lets you read, so the patch must announce itself there
    check(b2.m.read32(HOOK) == 0x48000002 | PAYLOAD_AT,
          "MPC 0x8 still holds the payload hijack (the app's first detection read)")
    check(bytes(b2.m.read(MAGIC_AT, len(MAGIC))) == MAGIC,
          f"MPC {MAGIC_AT:#x} holds the detection stamp (the app's second detection read)")
    check(b2.flash.erases == 2, "exactly two sector erases (cal scratch, boot sector)")
    check(b2.cmf.erases == 0, "the internal flash untouched by the install")
    n_stage = sum(n for _, _, n in plan["stage"])
    n_rest = n_stage + 6 + 2 * len(plan["gran_words"])
    check(b2.flash.programs == n_stage + 1 + n_rest + 3,
          f"{b2.flash.programs} program cycles = {n_stage} staged + marker + {n_rest} restored "
          f"+ CRC/marker")

    # the same reads over the line, which is the only way the app's ident
    # sees them: EDIABAS speicher_lesen_ascii (LAR, 0x23) and
    # seriennummer_lesen, in the 254-byte segments BMWeb's ReadMemory asks
    # for. The payload cache matters as much as the detection: the app
    # re-splices exactly these bytes after each of its own full flashes.
    t = Tester(b2)
    serial = t.serial()
    check(serial is not None and len(serial) >= 4,
          "seriennummer_lesen answers over KWP (the app keys the shadow by it)")
    check(t.read_memory(HOOK, 4) == struct.pack(">I", 0x48000002 | PAYLOAD_AT),
          "LAR reads the reset word at MPC 0x8 over KWP (detection read 1)")
    check(t.read_memory(MAGIC_AT, len(MAGIC)) == MAGIC,
          f"LAR reads the stamp at MPC {MAGIC_AT:#x} over KWP (detection read 2)")
    payload = b"".join(t.read_memory(PAYLOAD_AT + at, min(254, 0x1000 - at))
                       for at in range(0, 0x1000, 254))
    check(payload == bytes(plan["mpc"][PAYLOAD_AT:PAYLOAD_AT + 0x1000]),
          "LAR reads the whole [0x6F000,0x70000) payload over KWP in 254-byte segments "
          "(the cache the app re-splices into its own full flashes)")
    return b2


# ---------------------------------------------------------------------------


def open_session(b, what):
    t = Tester(b)
    check(t.authenticate(), f"{what}: mode-3 seed/key accepted")
    check(t.programming_mode(), f"{what}: programming mode entered")
    return t


def phase_granular(b2, base, plan):
    banner("4. the patched loader at work (all over KWP)")

    # -- session 1: single-sector and spanning erases
    t = open_session(b2, "session 1")
    chip0 = bytes(b2.flash.image)
    n0 = b2.flash.erases
    check(t.erase(EXTERNAL + 0x85000, 0x1000), "31 02 [0x85000,0x86000): positive")
    check(b2.flash.erases == n0 + 1, "exactly one sector erased (0x80000)")
    check(bytes(b2.flash.image[0x80000:0xC0000]) == b"\xff" * 0x40000, "sector 0x80000 is blank")
    check(b2.flash.image[0x60000:0x80000] == chip0[0x60000:0x80000]
          and b2.flash.image[0xC0000:] == chip0[0xC0000:],
          "sectors 0x60000 and 0xC0000 are untouched")
    check(b2.cmf.erases == 0, "the internal flash untouched")
    # the valid marks are NOT killed by an erase that misses their sector:
    # their only recoverable death is sector 0xC0000 erasing (blank -> the
    # 31 09 re-program restores the magic). A zero-programmed pair would be
    # unrecoverable -- programming only clears bits -- so gran never writes
    # them (measured: diff_flash --test v3, 31 09 fails over a zeroed pair)
    check(all(struct.unpack_from(">I", b2.flash.image, at)[0]
              == struct.unpack_from(">I", chip0, at)[0] for at, _ in VALID_MARKS),
          "all four valid marks untouched (an erase missing sector 0xC0000 "
          "leaves the pair valid -- the deliberate divergence from the walk)")


    n0 = b2.flash.erases
    check(t.erase(EXTERNAL + 0x7F000, 0x2000), "31 02 [0x7F000,0x81000): positive")
    check(b2.flash.erases == n0 + 2,
          "a spanning request erased exactly two sectors (0x60000, 0x80000)")
    check(bytes(b2.flash.image[0x60000:0x80000]) == b"\xff" * 0x20000, "sector 0x60000 blank too")
    check(t.reset(), "STEUERGERAETE_RESET (fresh session: the len-0 proof needs no earlier 31 02)")

    # -- session 2: zero length, refusals, the marks sector, cal, stock compat
    b2 = b2.reset()
    b2.boot(max_insns=40_000_000, reset_vector=True)
    t = open_session(b2, "session 2")
    n0 = b2.flash.erases
    r = t.request([0x31, 0x02] + t._region(EXTERNAL + 0x90000, 0), timeout_frames=60)
    check(bool(r) and r[0] == 0x71 and r[2] == 0x01, "31 02 with length 0: positive")
    check(b2.flash.erases == n0, "nothing erased for a zero-length request")
    check(t.write(EXTERNAL + 0x90000, b"\x5a" * 8 + b"\xa5" * 8),
          "34/36/37 into the blank sector after it: the erase flag is set")
    check(b2.flash.image[0x90000:0x90010] == b"\x5a" * 8 + b"\xa5" * 8, "the bytes are in the chip")

    r = t.request([0x31, 0x02] + t._region(EXTERNAL + 0x30000, 0x1000), timeout_frames=60)
    check(bool(r) and r[0] == 0x7F, "[0x20000,0x40000) still refused")
    r = t.request([0x31, 0x02] + t._region(EXTERNAL + 0x10000, 0x1000), timeout_frames=60)
    check(bool(r) and r[0] == 0x7F, "the boot region still refused")

    # -- the app's write-back: a granular erase is always followed by the
    #    content write of the erased sectors (erase and write are one step
    #    in every real flow; no session ends with erased-but-unwritten
    #    sectors). With the program side whole again the cal path below
    #    behaves exactly as on stock: the data check restores the whole cal
    #    marks pair only over intact program content -- over blank sectors
    #    it programs just the first word (0x5FF80) and leaves 0x5FFC0 dead,
    #    a state stock can't even reach, its walk blanking cal as well
    ok, sent = t.write_sparse(EXTERNAL + 0x60000, chip0[0x60000:0xC0000],
                              make_progress("program rewrite"))
    check(ok, f"the erased sectors' content written back ({sent} blocks)")

    # -- the calibration path, unchanged by the patch: cal-style requests
    #    (FLAGS.02 clear) never reach the patched site -- the stock
    #    job-runner serves them, range-aware, one sector
    check(t.erase(EXTERNAL + CALIBRATION, 0x20000),
          "a calibration request is still served (single sector, staging leftovers gone)")
    ok, sent = t.write_sparse(EXTERNAL + CALIBRATION, base.flash[CALIBRATION:CALIBRATION_END],
                              make_progress("calibration"))
    check(ok, f"calibration rewritten ({sent} blocks)")
    check(t.check_signature("data"), "31 09 data check passed: the cal marks return with it")
    check(b2.program_valid(), "all four marks in again (the cal pair from the data check; the "
                              "program pair never died -- its sector was never erased)")

    # -- stock compatibility: the flashers' one erase request (external
    #    0x60000 + 0xA0000) runs the stock sequence verbatim -- three
    #    sectors, all fourteen internal blocks, the stamp refreshed from
    #    the AIF, the marks gone -- because WinKFP and the app write the
    #    MPC right after with no separate internal erase
    n0, c0, p0 = b2.flash.erases, b2.cmf.erases, b2.flash.programs
    check(t.erase(EXTERNAL + PROGRAM, 0xA0000), "the stock full-range request: positive")
    check(b2.flash.erases == n0 + 3 and bytes(b2.flash.image[0x60000:]) == b"\xff" * 0xA0000,
          "all three program sectors erased (the stock walk, verbatim)")
    check(b2.cmf.erases >= c0 + 14, f"and the internal flash too ({b2.cmf.erases - c0} block erases)")
    check(b2.flash.programs == p0 + 31,
          "stock bookkeeping ran: the 54-byte stamp refreshed, the marks zero-programmed (31 halfwords)")
    check(bytes(b2.flash.image[STAMP_AT:STAMP_AT + 12]) == base.program_id,
          f"the stamp holds the AIF's program id {base.program_id.decode()}")
    check(struct.unpack_from(">I", b2.flash.image, 0xFFF80)[0] == 0xFFFFFFFF,
          "the program marks died with their sector (the cal pair survived in the cal tail)")

    # -- restore everything, the way the app finishes a full flash
    ok, sent = t.write_sparse(EXTERNAL + PROGRAM, base.flash[PROGRAM:PROGRAM_END],
                              make_progress("external program"))
    check(ok, f"program restored ({sent} blocks)")
    ok, sent = t.write_sparse(INTERNAL, base.mpc, make_progress("internal flash"))
    check(ok, f"internal flash restored ({sent} blocks)")
    check(t.default_mode(), "back to the default session")
    check(t.check_signature("program"), "31 09 program check passed on the patched loader")
    check(t.check_signature("data"), "31 09 data check passed (the app runs both)")
    check(b2.program_valid(), "all four marks back in: a healthy DME")

    # -- and a granular flash of the marks sector itself on that healthy
    #    DME (gran's own path, where stock would take all three sectors).
    #    31 02 needs the programming session back: the checks above ran
    #    in the default one, and stock refuses 7F 31 33 there (measured)
    check(t.programming_mode(), "programming mode re-entered for the erase")
    n0, c0, p0 = b2.flash.erases, b2.cmf.erases, b2.flash.programs
    chip0 = bytes(b2.flash.image)
    check(t.erase(EXTERNAL + 0xD2000, 0x1000), "granular 31 02 inside sector 0xC0000: positive")
    blank = bytes(b2.flash.image[0xC0000:]) == b"\xff" * 0x40000
    check(b2.flash.erases == n0 + 1 and blank,
          f"exactly sector 0xC0000 erased ({b2.flash.erases - n0} erases, blank={blank}, "
          f"head {bytes(b2.flash.image[0xC0000:0xC0008]).hex()})")
    check(b2.flash.image[0x60000:0xC0000] == chip0[0x60000:0xC0000],
          "sectors 0x60000 and 0x80000 untouched")
    check(b2.cmf.erases == c0, "the internal flash untouched")
    check(b2.flash.programs == p0,
          "no marks bookkeeping: the pair dies with its own sector, never by a write")
    check(all(struct.unpack_from(">I", b2.flash.image, at)[0] == 0xFFFFFFFF
              for at in (0xFFF80, 0xFFFC0)), "the program marks are gone with their sector")
    # the write stops at 0xFFF40: the loader refuses 34/36/37 into its
    # marks tail [0xFFF40,0x100000) just as it refuses the cal tail -- the
    # pair comes back with the 31 09 below, blank -> magic
    ok, sent = t.write_sparse(EXTERNAL + 0xC0000, base.flash[0xC0000:PROGRAM_END],
                              make_progress("sector 0xC0000"))
    check(ok, f"sector 0xC0000 rewritten to 0xFFF40 ({sent} blocks)")
    check(t.check_signature("program"),
          "31 09 program check: real here -- the pair died blank with its sector, "
          "the check revalidates and re-programs it")
    check(b2.program_valid(), "all four valid marks back in (the program pair by the "
                              "check, the cal pair never died)")
    check(t.programming_status() == 1, "31 0A: normal (the app's final gate)")
    check(t.reset(), "STEUERGERAETE_RESET")
    return b2


def phase_granular_flash(b3, base, plan):
    banner("5. a granular program flash on the healthy DME")
    # the target: the base program with one byte changed in sector 0x80000,
    # re-signed offline (fix_program's words live in sector 0x60000)
    flash = bytearray(base.flash)
    flash[0x90000] ^= 0x20
    fix_program(flash, bytearray(base.mpc))
    target = bytes(flash)

    b4 = b3.reset()
    b4.probe(SCHEDULER_TASK, "scheduler")
    b4.boot(max_insns=40_000_000, reset_vector=True)
    check(b4.m.read8(INIT_DONE) == 1 and b4.probe_counts["scheduler"] > 10,
          "the program runs (before: healthy DME)")
    t = open_session(b4, "diff flash")

    cur = bytes(b4.flash.image)
    plan_sectors, wire = [], 0
    for start, size in SECTORS:
        if not (0x60000 <= start < 0x100000):
            continue
        # compare and write only to 0xFFF40: the tail beyond it (the dump's
        # 54-byte stamp copy at 0xFFF40 and the marks) is loader territory,
        # blank after any real flash -- the erase still takes the whole sector
        span = min(size, PROGRAM_END - start)
        if cur[start:start + span] != target[start:start + span]:
            plan_sectors.append((start, size))   # every differing sector: the
                                                 # loader programs only blank-
                                                 # or-identical halfwords, so
                                                 # even bit-clears need the erase
    print(f"  diff plan: erase {[hex(s) for s, _ in plan_sectors]} "
          f"(sector 0x60000: the re-signed CRC/romtest/signature words)")

    for start, size in plan_sectors:
        check(t.erase(EXTERNAL + start, size), f"31 02 erased only sector {start:#x}")
        wsize = min(size, PROGRAM_END - start)   # never past 0xFFF40: the
        ok, sent = t.write_sparse(EXTERNAL + start, target[start:start + wsize],
                                  make_progress(f"sector {start:#x}"))
        wire += sent
        check(ok, f"34/36/37 wrote sector {start:#x} to 0xFFF40 ({sent} blocks)")
    check(t.default_mode(), "back to the default session")
    # 31 09 02 over a still-valid pair answers 71 09 00 ("nothing to
    # check") -- the plan never touched sector 0xC0000, so the pair never
    # died; 01 would mean it ran. Both are healthy answers; the boot
    # check below is this flash's real verification
    r = t.request([0x31, 0x09, 0x02], timeout_frames=200)
    check(bool(r) and r[0] == 0x71 and r[2] in (0x00, 0x01),
          f"31 09 program check answers healthy ({bytes(r).hex() if r else None}; "
          f"0x00 = the still-valid pair, nothing to check)")
    check(b4.program_valid(), "all four marks back in")
    chip = bytes(b4.flash.image)
    diffs = [at for at in range(PROGRAM, PROGRAM_END) if chip[at] != target[at]]
    check(not diffs, f"the program area is byte-identical to the target "
          f"({wire} wire blocks; a stock full flash sends ~2400)"
          + (f" -- first diffs {[hex(a) for a in diffs[:4]]}" if diffs else ""))
    check(t.reset(), "STEUERGERAETE_RESET")

    b5 = b4.reset()
    b5.probe(SCHEDULER_TASK, "scheduler")
    b5.boot(max_insns=40_000_000, reset_vector=True)
    check(b5.m.read8(INIT_DONE) == 1 and b5.probe_counts["scheduler"] > 10,
          f"the program runs on the granularly-flashed image "
          f"(scheduler ticks: {b5.probe_counts['scheduler']})")
    check(struct.unpack_from(">H", b5.flash.image, MARK2_AT)[0] == MARK2_DONE,
          "the install marker still reads done")
    return b5


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flash", help="1MB external flash dump of the base pair")
    ap.add_argument("--mpc", help="448KB MPC dump of the base pair")
    ap.add_argument("--out", help="also write the built pair here (granular_Flash/MPC.bin)")
    ap.add_argument("--phase", type=int, default=5, help="stop after this phase (for iteration)")
    args = ap.parse_args()

    if args.flash and args.mpc:
        with open(args.flash, "rb") as f, open(args.mpc, "rb") as m:
            base = Pair(f.read(), m.read(), "base")
    else:
        with open(os.path.join(IMAGES_DIR, "session1.flash.bin"), "rb") as f, \
                open(os.path.join(IMAGES_DIR, "session1.mpc.bin"), "rb") as m:
            base = Pair(f.read(), m.read(), "session1")
    print(f"base pair: {base.name}, program {base.program_id.decode()}", flush=True)

    plan = phase_build(base)
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for kind, data in (("Flash", plan["flash"]), ("MPC", plan["mpc"])):
            path = os.path.join(args.out, f"granular_{kind}.bin")
            with open(path, "wb") as f:
                f.write(data)
            print("wrote", path, flush=True)
    if args.phase < 2:
        return

    b, pre_install = phase_flash(base, plan)
    if args.phase < 3:
        return
    b2 = phase_install(b, plan, pre_install)
    if args.phase < 4:
        return
    b3 = phase_granular(b2, base, plan)
    if args.phase < 5:
        return
    phase_granular_flash(b3, base, plan)

    banner("done: 31 02 is sector-granular, range-faithful, table-gated")
    print("A program-area request erases exactly the overlapping external sectors; internal\n"
          "only for internal or full-span requests; [0x20000,0x40000) and the boot region are\n"
          "still refused; the RAM driver's guards are untouched. The patch lives in the boot\n"
          "sector's blank tail, delivered by the wipe machinery, and survives every later\n"
          "flash. The next layer, diff_flash.py, builds the shadow/diff flasher on this.\n")


if __name__ == "__main__":
    main()
