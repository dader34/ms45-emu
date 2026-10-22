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
    0xFD500  the flasher body        (flasher_body.py, ~2.9 KB)

then fix_program() refreshes romtest sum, program CRC and signature over
the result, exactly as gran's installer did.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aif_wipe import Asm                                       # noqa: E402
from ms45emu.checksums import fix_program                      # noqa: E402

BODY_RANGE = (0xFD26C, 0xFFF40)          # blank in the car image, spec'd for the body
STAMP_AT, GATE_AT, ENTRY_AT = 0xFD26C, 0xFD300, 0xFD400
PARK_MARK_AT = 0xFD280                   # the body's RESET-park PC, for kline's
                                         # watchdog stand-in (blank in v1 images)
GATE_CPU, ENTRY_CPU = 0xFFF00000 + GATE_AT, 0xFFF00000 + ENTRY_AT   # 0xFFFFD300 / 0xFFFFD400
STOCK_HOOK = 0x4BF717B6                  # ba 0xFFF717B4, the stock reset word at MPC 0x8
STOCK_START = 0xFFF717B4
SCC1R1, SC1SR, RE, RAF = 0x30500A, 0x30500C, 0x04, 0x20
MARK_ADDR, MARK_WORD = 0x3F9800, 0x600D600D   # the stub's "flasher has the machine" marker


class GateAsm(Asm):
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

    def resolve(self, base):
        # base Asm's resolve only knows the bc forms (BD field); `b` carries
        # its offset in LI (bits 2-25) -- the same trap nrv2b_dec hit
        for index, kind, label in self.fixups:
            rel = 4 * (self.labels[label] - index)
            if kind == "b":
                w = 0x48000000 | (rel & 0x03FFFFFC)
            else:
                w = (0x41820000 if kind == "beq" else 0x40820000) | (rel & 0xFFFC)
            self.words[index] = (w, self.words[index][1])


def hook_word(target):
    """The absolute `ba` PPC assembles at MPC 0x8 (AA set, LI = target>>2)."""
    return 0x48000002 | (target & 0x03FFFFFC)


def build_gate(flasher_entry):
    """The gate as (word, note) list, for the word at GATE_AT."""
    a = GateAsm()
    a.li32(3, SCC1R1)
    a.li32(4, SC1SR)
    a.lhz(5, 0, 3)                              # save the loader's SCC1R1
    a.ori_rd(6, 5, RE)
    a.sth(6, 0, 3)                              # receiver on
    a.li(7, 12)                                 # 12 polls
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
    a.ba(STOCK_START)
    a.label("flasher")
    a.ba(flasher_entry)
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
    from flasher_body import BODY_AT, build_parts, pack

    start, end = BODY_RANGE
    blank = flash[start:end] == b"\xff" * (end - start)
    current_hook = struct.unpack_from(">I", mpc, 8)[0]
    hooks_ok = current_hook in (STOCK_HOOK, hook_word(0xFFF00000 + GATE_AT))
    if not blank:
        first = next(i for i in range(start, end) if flash[i] != 0xFF)
        raise ValueError(f"body range not blank: first non-FF byte at ext {first:#x}")
    if not hooks_ok:
        raise ValueError(f"MPC 0x8 holds {current_hook:#010x}, not the stock hook")

    stub, body, size = build_parts()
    body_end = BODY_AT + size
    if body_end > end:
        raise ValueError(f"body spans to {body_end:#x}, past the range end {end:#x}")

    f, m = bytearray(flash), bytearray(mpc)
    f[STAMP_AT:STAMP_AT + 16] = stamp_bytes(8, 1)   # v8: pagesets (CHUNK_SET), mask ERASE,
                                                    #     SET_BAUD, table CRC;
                                                    # v7: MPC writes through the loader's own CMF
                                                    #     driver (v6's sequence reset the car);
                                                    # v6: each reply byte's echo read as it goes;
                                                    # v5: the CRC loop services the watchdog;
                                                    # v4: the SCI sends 8E1 (v3 sent 8N1);
                                                    # v3: real-cable hardening (reply
                                                    # gap, rx timeout, header-before-span);
                                                    # flags bit 0 = the v2 MPC window
    import flasher_body                              # PARK_PC is filled only now (build_parts ran)
    struct.pack_into(">I", f, PARK_MARK_AT, flasher_body.PARK_PC)
    f[GATE_AT:GATE_AT + 4 * len(build_gate(flasher_entry_cpu))] = pack(build_gate(flasher_entry_cpu))
    f[ENTRY_AT:ENTRY_AT + 4 * len(stub)] = pack(stub)
    f[BODY_AT:body_end] = pack(body)
    struct.pack_into(">I", m, 8, hook_word(0xFFF00000 + GATE_AT))
    fix_program(f, m)
    return f, m


def main():
    from ms45emu.image import load_named
    pair = load_named("session1.livetune6-notraps")
    f, m = build(pair.flash, pair.mpc)
    gate = build_gate(0xFFF00000 + ENTRY_AT)
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "images")
    for ext, blob in (("flash.bin", f), ("mpc.bin", m)):
        path = os.path.join(out, "quickflash1." + ext)
        open(path, "wb").write(blob)
        print(f"wrote {path} ({len(blob)} bytes)")
    print(f"stamp {f[STAMP_AT:STAMP_AT + 16]!r}")
    print(f"park mark {struct.unpack_from('>I', f, PARK_MARK_AT)[0]:#x} at ext {PARK_MARK_AT:#x}")
    print(f"gate: {len(gate)} words at ext {GATE_AT:#x}; hook word {hook_word(0xFFF00000 + GATE_AT):#010x} at MPC 0x8")


if __name__ == "__main__":
    main()
