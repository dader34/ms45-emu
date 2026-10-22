"""The PPC-side NRV2B decoder for the resident flasher (docs/fast-flasher.md).

Byte-exact the JS encoder in BMWeb (app/renderer/core/flash/nrv2b.js, ported
from ucl-1.03): the 8-bit-bit-buffer n2b_d.c decoder with getbit_8 semantics.
Assembled with aif_wipe.py's Asm (extended below with the byte/shift/branch
ops it lacked), so the same assembler that proved the boot wipe and the AMD
command cycles produces this too.

Entry (the flasher calls it relocated in SRAM; the emulator test calls it via
Machine.call):

    r3 = src, the compressed stream
    r4 = dst, the decompress buffer
    r5 = dst_len

Returns r3 = dst + dst_len on success, 0 on a malformed stream (literal,
match or lookbehind past the buffer -- the safe-decoder checks; the stream
is CRC-checked app-side before it is sent, this is the second lock on the
door). Stops on length, so the encoder's trailing EOF marker is optional.
Clobbers r3-r12 and r14 (dst base); leaf routine, no stack, no LR use.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aif_wipe import Asm                                   # noqa: E402

# registers
SRC, DST, END, BB, LASTOFF, MOFF, MLEN, MPOS, TMP, BIT = 3, 4, 5, 6, 7, 8, 9, 10, 12, 11
BASE = 14                                                  # dst base, for lookbehind checks


class NrvAsm(Asm):
    """Asm plus the ops the decoder needs (encodings per the MPC555 RISC
    CPU reference manual; aif_wipe.py documents the word layout)."""

    def lbz(self, rD, d, rA):
        self.raw(0x88000000 | (rD << 21) | (rA << 16) | (d & 0xFFFF),
                 f"lbz    r{rD}, {d:#x}(r{rA})")

    def stb(self, rS, d, rA):
        self.raw(0x98000000 | (rS << 21) | (rA << 16) | (d & 0xFFFF),
                 f"stb    r{rS}, {d:#x}(r{rA})")

    def lbzx(self, rD, rB):            # lbzx rD, 0, rB
        self.raw(0x7C000000 | (rD << 21) | (rB << 11) | (87 << 1),
                 f"lbzx   r{rD}, 0, r{rB}")

    def stbx(self, rS, rB):            # stbx rS, 0, rB
        self.raw(0x7C000000 | (rS << 21) | (rB << 11) | (215 << 1),
                 f"stbx   r{rS}, 0, r{rB}")

    def rlwinm(self, rA, rS, sh, mb, me):
        self.raw(0x54000000 | (rS << 21) | (rA << 16) | (sh << 11) | (mb << 6) | (me << 1),
                 f"rlwinm r{rA}, r{rS}, {sh}, {mb}, {me}")

    def slwi(self, rA, rS, n):
        self.rlwinm(rA, rS, n, 0, 31 - n)

    def or_(self, rA, rS, rB):
        self.raw(0x7C000378 | (rS << 21) | (rA << 16) | (rB << 11),
                 f"or     r{rA}, r{rS}, r{rB}")

    def mr(self, rA, rS):
        self.or_(rA, rS, rS)

    def subf(self, rA, rB, rC):        # rA = rC - rB
        self.raw(0x7C000050 | (rA << 21) | (rB << 16) | (rC << 11),
                 f"subf   r{rA}, r{rB}, r{rC}")

    def add(self, rA, rB, rC):         # rA = rB + rC
        self.raw(0x7C000214 | (rA << 21) | (rB << 16) | (rC << 11),
                 f"add    r{rA}, r{rB}, r{rC}")

    def cmpwi(self, rA, imm):
        self.raw(0x2C000000 | (rA << 16) | (imm & 0xFFFF),
                 f"cmpwi  r{rA}, {imm:#x}")

    def b(self, label):
        self.fixups.append((self.here(), "b", label))
        self.raw(0x48000000, f"b      {label}")

    def bge(self, label):
        self.fixups.append((self.here(), "bge", label))
        self.raw(0x40800000, f"bge    {label}")

    def blt(self, label):
        self.fixups.append((self.here(), "blt", label))
        self.raw(0x41800000, f"blt    {label}")

    def bgt(self, label):
        self.fixups.append((self.here(), "bgt", label))
        self.raw(0x41810000, f"bgt    {label}")

    def ble(self, label):
        self.fixups.append((self.here(), "ble", label))
        self.raw(0x40810000, f"ble    {label}")

    def blr(self):
        self.raw(0x4E800020, "blr")

    BRANCHES = {"beq": 0x41820000, "bne": 0x40820000, "b": 0x48000000,
                "bge": 0x40800000, "blt": 0x41800000, "bgt": 0x41810000,
                "ble": 0x40810000}

    def resolve(self, base):
        for index, kind, label in self.fixups:
            rel = 4 * (self.labels[label] - index)
            if kind == "b":                          # LI is bits 2-25, not a BD field
                w = 0x48000000 | (rel & 0x03FFFFFC)
            else:
                w = self.BRANCHES[kind] | (rel & 0xFFFC)
            self.words[index] = (w, self.words[index][1])


def _getbit(a, tag):
    """getbit_8 into BIT: bb&0x7F ? bb*2 : (*src++ * 2 + 1); bit = (bb>>8)&1."""
    a.rlwinm(TMP, BB, 0, 25, 31)                    # tmp = bb & 0x7F
    a.cmpwi(TMP, 0)
    a.bne(f"{tag}_kept")
    a.lbz(TMP, 0, SRC)                              # refill: a whole stream byte
    a.addi(SRC, SRC, 1)
    a.slwi(TMP, TMP, 1)
    a.ori(TMP, TMP, 1)
    a.mr(BB, TMP)
    a.b(f"{tag}_done")
    a.label(f"{tag}_kept")
    a.slwi(BB, BB, 1)
    a.label(f"{tag}_done")
    a.rlwinm(BIT, BB, 24, 31, 31)                   # (bb >> 8) & 1: bb's bit 8
    # rotates to bit 0, and only that bit -- bb keeps its spent high bits, so
    # a byte mask here would leak them (0x101 -> 0x202 -> "2")


def build_decoder():
    """The decoder as a list of (word, note); len(words) * 4 bytes of code."""
    a = NrvAsm()
    a.mr(BASE, DST)                                 # r14 = dst base
    a.add(END, DST, END)                            # r5 = dst end
    a.li(BB, 0)
    a.li(LASTOFF, 1)

    a.label("item")
    a.cmplw(DST, END)
    a.bge("ok")                                     # dst == end: done, by length
    a.label("literals")
    _getbit(a, "lit")                               # 1: a literal byte
    a.cmplwi(BIT, 0)
    a.beq("match")
    a.cmplw(DST, END)
    a.bge("fail")                                   # literal past the buffer
    a.lbz(TMP, 0, SRC)
    a.addi(SRC, SRC, 1)
    a.stb(TMP, 0, DST)
    a.addi(DST, DST, 1)
    a.b("literals")

    a.label("match")
    a.li(MOFF, 1)                                   # the offset's ss11 code
    a.label("off_bits")
    _getbit(a, "off1")
    a.slwi(MOFF, MOFF, 1)
    a.or_(MOFF, MOFF, BIT)
    _getbit(a, "off2")                              # 0: another pair follows
    a.cmplwi(BIT, 0)
    a.beq("off_bits")
    a.cmplwi(MOFF, 2)
    a.bne("off_coded")
    a.mr(MOFF, LASTOFF)                             # code 2: the last offset
    a.b("len_bits")
    a.label("off_coded")
    a.addi(MOFF, MOFF, -3)
    a.slwi(MOFF, MOFF, 8)
    a.lbz(TMP, 0, SRC)                              # the offset's low byte
    a.addi(SRC, SRC, 1)
    a.or_(MOFF, MOFF, TMP)
    a.li32(TMP, 0xFFFFFFFF)
    a.cmplw(MOFF, TMP)
    a.beq("ok")                                     # the EOF marker
    a.addi(MOFF, MOFF, 1)
    a.mr(LASTOFF, MOFF)

    a.label("len_bits")
    _getbit(a, "len1")
    a.mr(MLEN, BIT)
    _getbit(a, "len2")
    a.slwi(MLEN, MLEN, 1)
    a.or_(MLEN, MLEN, BIT)
    a.cmplwi(MLEN, 0)
    a.bne("len_have")                               # short form: 1..3
    a.li(MLEN, 1)
    a.label("len_more")
    _getbit(a, "len3")
    a.slwi(MLEN, MLEN, 1)
    a.or_(MLEN, MLEN, BIT)
    _getbit(a, "len4")
    a.cmplwi(BIT, 0)
    a.beq("len_more")
    a.addi(MLEN, MLEN, 2)
    a.label("len_have")
    a.li(TMP, 0xD00)                                # len += m_off > 0xd00
    a.cmplw(MOFF, TMP)
    a.ble("len_done")
    a.addi(MLEN, MLEN, 1)
    a.label("len_done")

    a.subf(MPOS, MOFF, DST)                         # m_pos = dst - m_off
    a.cmplw(MPOS, BASE)
    a.blt("fail")                                   # before the buffer
    a.add(TMP, DST, MLEN)                           # bound: dst + m_len + 1
    a.addi(TMP, TMP, 1)
    a.cmplw(TMP, END)
    a.bgt("fail")                                   # past the buffer
    a.label("copy")
    a.lbzx(TMP, MPOS)
    a.addi(MPOS, MPOS, 1)
    a.stbx(TMP, DST)
    a.addi(DST, DST, 1)
    a.addic_(MLEN, -1)
    a.bge("copy")
    a.b("item")

    a.label("ok")
    a.mr(SRC, DST)                                  # return dst: dst+dst_len
    a.blr()
    a.label("fail")
    a.li(SRC, 0)
    a.blr()
    a.resolve(0)
    return a.words


def main():
    words = build_decoder()
    print(f"{len(words)} words, {len(words) * 4} bytes")
    if "--list" in sys.argv:
        for i, (w, note) in enumerate(words):
            print(f"{i * 4:04x}  {w:08X}  {note}")


if __name__ == "__main__":
    main()
