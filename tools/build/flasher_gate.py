"""The quick-flash gate: what runs where MPC 0x8 used to jump straight to
the program (docs/fast-flasher.md).

Measured facts this is built on (gate_trace, 2026-10-20): with the marks
valid the loader consumes the vector word at MPC 0x8 at instruction 4668
(~117 us after reset) — the word itself executes as a `ba` — with MSR[EE]
clear and the SCI completely untouched (SCC1R1 = 0; the receiver is the
program's to enable, ~2.5 ms later). So the gate cannot sample a line state
someone else arranged: it owns the SCI for the moment it runs.

    save SCC1R1, set RE, poll SC1SR[RAF] for ~600 us
    RAF seen -> ba flasher entry (the tester holds the line low across the
                reset; a normal key-on never drives it)
    otherwise -> restore SCC1R1, ba the stock start verbatim

A normal boot pays ~20 instructions + <=600 us before the stock start and
nothing else: no bytes arrive on an idle line, so RDRF/SC1DR stay as the
loader left them. The real receiver qualifies a start bit ~1/2 bit time
(~52 us at 9600) after RE goes on, which the 600 us of polls covers.

The image layout this builds (ext offsets):

    0xFD26C  16-byte detection stamp (the app reads this over KWP)
    0xFD300  the gate                (MPC 0x8 -> ba 0xFFFFD300)
    0xFD400  the relocate stub       (copies the body to SRAM, jumps)
    0xFD500  the flasher body        (flasher_body.py, ~6.4 KB)

then fix_program() refreshes romtest sum, program CRC and signature over
the result, exactly as gran's installer did.
"""
import os
import struct
import sys
from tools.experiments.aif_wipe import Asm
from ms45emu.checksums import fix_program
from tools import ROOT

BODY_RANGE = (0xFD26C, 0xFFF40)          # blank in the car image, spec'd for the body
STAMP_AT, GATE_AT, ENTRY_AT = 0xFD26C, 0xFD300, 0xFD400
PARK_MARK_AT = 0xFD280                   # the body's RESET-park PC, for kline's
                                         # watchdog stand-in (blank in v1 images)
GATE_CPU, ENTRY_CPU = 0xFFF00000 + GATE_AT, 0xFFF00000 + ENTRY_AT   # 0xFFFFD300 / 0xFFFFD400
STOCK_HOOK = 0x4BF717B6                  # ba 0xFFF717B4, the stock reset word at MPC 0x8
STOCK_START = 0xFFF717B4
SCC1R1, SC1SR, RE, RAF = 0x30500A, 0x30500C, 0x04, 0x20
MARK_ADDR, MARK_WORD = 0x3F9800, 0x600D600D   # the stub's "flasher has the machine" marker
SWSR, SWSR_SEQ = 0x2FC00E, (0x556C, 0xAA39)

# The LATE gate (the way past a ring that hangs, docs/bootloader.md 0d): on
# a BL DME the ring's ~1 ms handoff window runs before MPC 0x8, so a line
# held across the reset always lands in the ring -- and a ring that cannot
# serve (v16 on the car, 2026-10-28) leaves no fast way to replace it. A
# gate that listens for ~2 s instead of ~600 us can be reached by a line
# that goes low AFTER the ring's window, while the ring lets the boot by.
# Its poll services the software watchdog, which ~600 us never needed. Set
# LATE_GATE before build(); the stamp then carries flag bit 5 so the app
# knows to hold late. Every boot of such a pair pays the ~2 s, and any
# K-line byte in that time enters the flasher: it is put on for the one
# rescue and taken off by the next program flash.
LATE_GATE = False
# How long it listens is TIMED by the time base, not counted in polls: a
# counted loop runs from external flash, every fetch over its 16-bit bus,
# and the 40000 x ~50 us (~2 s on the emulator) of v19's first late gate
# held the CAR ~10 s at every key-on (2026-10-30: no program, no CAN, the
# dash lit up). The loader sets SCCR and the PLL and turns the time base on
# (TBSCR = 1) at reset, before MPC 0x8, and the program never touches
# either, so the gate's time base is the program's: 2.5 MHz (the kernel
# tick is 2500 units = 1 ms; docs/full-boot.md, Time).
TB_HZ = 2_500_000
LATE_MS = 2000
LATE_TICKS = TB_HZ * LATE_MS // 1000     # 5,000,000
# A cap on the polls in case the time base did not run after all: ~5 s on
# the emulator (a poll is ~215 instructions), ~25 s on the car -- a slow
# boot, never a hang.
LATE_CAP = 1_000_000
LATE_WAIT = 100                          # the short wait between SC1SR reads
LATE_FLAG = 0x20
# The late gate's off switch: once the bootloader is written through it, the
# app CHUNKs zeros over the blank word at ext LATE_OFF_AT and the gate goes
# straight to the program from then on -- the installer no longer costs a
# key-on its ~2 s. The word is past the program CRC and the signature
# (both end at 0xFFF40) and is not one of the valid marks (0xFFF80/0xFFFC0),
# and a program flash erases it with its sector, so the next late
# installer comes on armed. Stamp flag bit 6 says the gate reads it.
LATE_OFF_AT = 0xFFFE0
LATE_OFF_LEN = 8                         # what the app CHUNKs (lengths go in 8s);
                                         # the gate reads the first word
LATE_OFF_FLAG = 0x40


class GateAsm(Asm):
    def label(self, name):
        # base Asm keeps the LAST definition of a name, silently: the body's
        # CHUNK_SET NAK and cmf_chunkset's readback loop both said "cs_rb",
        # and every branch went to whichever came last (2026-11-02)
        if name in self.labels:
            raise ValueError(f"label {name!r} defined twice")
        super().label(name)

    def ori_rd(self, rD, rS, imm):
        # ori is the D-form family with the destination in the SECOND
        # register field: base Asm.ori(a, b, imm) encodes `ori rB, rA, imm`,
        # which bit us once already (li32 is immune -- same register both
        # slots, which is why nothing before this hit it)
        self.ori(rS, rD, imm)
        return None

    def andi_(self, rA, rS, imm):        # andi. rA, rS, imm (sets CR0)
        self.raw(0x70000000 | (rS << 21) | (rA << 16) | (imm & 0xFFFF),
                 f"andi.  r{rA}, r{rS}, {imm:#x}")

    def stw(self, rS, d, rA):
        self.raw(0x90000000 | (rS << 21) | (rA << 16) | (d & 0xFFFF),
                 f"stw    r{rS}, {d:#x}(r{rA})")

    def b(self, label):
        self.fixups.append((self.here(), "b", label))
        self.raw(0x48000000, f"b      {label}")

    def bge(self, label):                # bc 4, cr0[lt]: not less than
        self.fixups.append((self.here(), "bge", label))
        self.raw(0x40800000, f"bge    {label}")

    def mftb(self, rD):                  # mftb rD (TBL)
        self.raw(0x7C0C42E6 | (rD << 21), f"mftb   r{rD}")

    def subf(self, rD, rA, rB):          # rD = rB - rA
        self.raw(0x7C000050 | (rD << 21) | (rA << 16) | (rB << 11),
                 f"subf   r{rD}, r{rA}, r{rB}")

    def resolve(self, base):
        # base Asm's resolve only knows the bc forms (BD field); `b` carries
        # its offset in LI (bits 2-25) -- the same trap nrv2b_dec hit
        for index, kind, label in self.fixups:
            rel = 4 * (self.labels[label] - index)
            if kind == "b":
                w = 0x48000000 | (rel & 0x03FFFFFC)
            else:
                w = {"beq": 0x41820000, "bne": 0x40820000,
                     "bge": 0x40800000}[kind] | (rel & 0xFFFC)
            self.words[index] = (w, self.words[index][1])


def hook_word(target):
    """The absolute `ba` PPC assembles at MPC 0x8 (AA set, LI = target>>2)."""
    return 0x48000002 | (target & 0x03FFFFFC)


def build_gate(flasher_entry, late=None):
    """The gate as (word, note) list, for the word at GATE_AT. `late`
    (default LATE_GATE): LATE_MS by the time base (LATE_CAP polls at most),
    each poll servicing the watchdog."""
    late = LATE_GATE if late is None else late
    a = GateAsm()
    if late:
        a.li32(8, 0xFFF00000 + LATE_OFF_AT)
        a.lwz(8, 0, 8)
        a.li(9, -1)
        a.cmplw(8, 9)
        a.bne("off")                            # switched off: the program, now
    a.li32(3, SCC1R1)
    a.li32(4, SC1SR)
    a.lhz(5, 0, 3)                              # save the loader's SCC1R1
    a.ori_rd(6, 5, RE)
    a.sth(6, 0, 3)                              # receiver on
    if late:
        a.li32(9, SWSR)
        a.li(10, SWSR_SEQ[0])
        a.li(11, SWSR_SEQ[1])                   # sth keeps li's low half
        a.li32(6, LATE_TICKS)                   # r6 is free once RE is on
        a.li32(7, LATE_CAP)
        a.mftb(12)                              # when the gate opened
    else:
        a.li(7, 12)                             # 12 polls
    a.label("poll")
    if late:
        a.sth(10, 0, 9)
        a.sth(11, 0, 9)                         # 0x556C / 0xAA39 to SWSR
    a.li(8, LATE_WAIT if late else 1000)        # the stock gate: ~50 us, 1000 x 2-cycle loop
    a.label("wait")
    a.addic_(8, -1)
    a.bne("wait")
    a.lhz(8, 0, 4)                              # SC1SR
    a.andi_(8, 8, RAF)
    a.bne("flasher")
    if late:
        a.mftb(8)
        a.subf(8, 12, 8)                        # ticks since the gate opened (wraps fine)
        a.cmplw(8, 6)
        a.bge("done")
    a.addic_(7, -1)
    a.bne("poll")
    a.label("done")
    a.sth(5, 0, 3)                              # restore SCC1R1, exactly as found
    a.ba(STOCK_START)
    a.label("flasher")
    a.ba(flasher_entry)
    if late:
        a.label("off")                          # nothing touched: SCC1R1 as found
        a.ba(STOCK_START)
    a.resolve(0)
    return a.words


def stamp_bytes(version=1, flags=0):
    return (b"MS45QF" + bytes([version, flags])
            + struct.pack(">II", GATE_CPU, ENTRY_CPU))


def build(flash, mpc, flasher_entry_cpu=ENTRY_CPU):
    """The car's current pair -> the same pair carrying gate + body.

    Guards (refuse, never patch around): the body range must be blank in
    the input, and MPC 0x8 must hold the stock word or our own hook
    already (idempotent rebuilds). Sums and signature come last.
    """
    from tools.build.flasher_body import BODY_AT, build_parts, pack

    start, end = BODY_RANGE
    blank = flash[start:end] == b"\xff" * (end - start)
    current_hook = struct.unpack_from(">I", mpc, 8)[0]
    hooks_ok = current_hook in (STOCK_HOOK, hook_word(0xFFF00000 + GATE_AT))
    if not blank:
        first = next(i for i in range(start, end) if flash[i] != 0xFF)
        raise ValueError(f"body range not blank: first non-FF byte at ext {first:#x}")
    if not hooks_ok:
        raise ValueError(f"MPC 0x8 holds {current_hook:#010x}, not the stock hook")

    stub, body, size, module = build_parts()
    body_end = BODY_AT + size
    if body_end > end:
        raise ValueError(f"body spans to {body_end:#x}, past the range end {end:#x}")

    from tools.build import flasher_body
    # flags bit 1: the boot-sector window + AIF marker service, compiled
    # when flasher_body.ALLOW_BOOT_SECTOR is set -- every body built today
    # (the current version below). Clear, the body is the old v9 one.
    f, m = bytearray(flash), bytearray(mpc)
    boot = bool(flasher_body.ALLOW_BOOT_SECTOR)
    version = 20 if boot else 9                     # v20: CHUNK_SET's NAK 4 is a NAK again (a page
                                                    #     that would not take branched into
                                                    #     cmf_chunkset's readback and ran to PC 0),
                                                    #     MARKS reads each halfword back, ERASE
                                                    #     checks its sector, every hardware wait
                                                    #     bounded -- a NAK where v19 hung or ACKed;
                                                    # v19: the driver's entries resolved per build; v18: the EEPROM bounded to its 4 KB;
                                                    # v17: the QSMCM set up on the EEPROM
                                                    #     path only (v16's stub setup hung
                                                    #     every entry on the car);
                                                    # v16: the stub sets the QSMCM up (the
                                                    #     v15 EEPROM read hung the car);
                                                    # v15: EE_WRITE (the ISN rewrite,
                                                    #     served by the module in ext at
                                                    #     EE_MODULE_AT -- flag bit 3);
                                                    # v14: the EEPROM read window;
                                                    # v13: READ (raw bytes, 4 KB a request);
                                                    # v12: the AIF wipe in every body, its
                                                    #     window shut until a slot is armed;
                                                    # v11: marker slots (v10 wiped once)
    flags = (1 | (2 if boot else 0) | (0x18 if boot else 0))  # bit 0 = v2 MPC window;
                                                    # bit 4 = the EEPROM read window,
                                                    # bit 3 = EE write -- both true of
                                                    # THIS image: the module rides it
                                                    # at EE_MODULE_AT. A splice that
                                                    # carries only the body (the BL
                                                    # installer runs, the ring) keeps
                                                    # bit 4 but must drop bit 3: the
                                                    # dispatch is in the body, the
                                                    # module is not.
    if boot and flasher_body.PERM_LOW < 0x8000:     # bit 2 = the BL installer
        flags |= 4                                  # variant: the window opens at
                                                    # PERM_LOW (the 8 KB sector 0x4000)
    if LATE_GATE:                                   # bit 5 = the late gate: enter it
        flags |= LATE_FLAG | LATE_OFF_FLAG          # with a line held after the reset;
                                                    # bit 6 = it reads its off switch
    f[STAMP_AT:STAMP_AT + 16] = stamp_bytes(version, flags)
                                                    # v9: SET_BAUD holds only once confirmed;
                                                    # v8: pagesets (CHUNK_SET), mask ERASE,
                                                    #     SET_BAUD, table CRC;
                                                    # v7: MPC writes through the loader's own CMF
                                                    #     driver (v6's sequence reset the car);
                                                    # v6: each reply byte's echo read as it goes;
                                                    # v5: the CRC loop services the watchdog;
                                                    # v4: the SCI sends 8E1 (v3 sent 8N1);
                                                    # v3: real-cable hardening (reply
                                                    # gap, rx timeout, header-before-span)
    struct.pack_into(">I", f, PARK_MARK_AT, flasher_body.PARK_PC)
    f[GATE_AT:GATE_AT + 4 * len(build_gate(flasher_entry_cpu))] = pack(build_gate(flasher_entry_cpu))
    f[ENTRY_AT:ENTRY_AT + 4 * len(stub)] = pack(stub)
    f[BODY_AT:body_end] = pack(body)
    from tools.build.flasher_body import EE_MODULE_AT
    f[EE_MODULE_AT:EE_MODULE_AT + 4 * len(module)] = pack(module)
    struct.pack_into(">I", m, 8, hook_word(0xFFF00000 + GATE_AT))
    fix_program(f, m)
    return f, m


def main():
    from ms45emu.image import load_named
    pair = load_named("session1.livetune6-notraps")
    f, m = build(pair.flash, pair.mpc)
    gate = build_gate(0xFFF00000 + ENTRY_AT)
    out = os.path.join(ROOT, "images")
    for ext, blob in (("flash.bin", f), ("mpc.bin", m)):
        path = os.path.join(out, "quickflash1." + ext)
        open(path, "wb").write(blob)
        print(f"wrote {path} ({len(blob)} bytes)")
    print(f"stamp {f[STAMP_AT:STAMP_AT + 16]!r}")
    print(f"park mark {struct.unpack_from('>I', f, PARK_MARK_AT)[0]:#x} at ext {PARK_MARK_AT:#x}")
    print(f"gate: {len(gate)} words at ext {GATE_AT:#x}; hook word {hook_word(0xFFF00000 + GATE_AT):#010x} at MPC 0x8")


if __name__ == "__main__":
    main()
