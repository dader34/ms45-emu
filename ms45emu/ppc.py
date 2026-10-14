"""The PowerPC words the patches are assembled from, and the little
assembler with labels they share (diagpatch, overlay, transport, fold,
singles). Every encoder returns one 32-bit instruction; the register order
follows the mnemonic as written (`_lwz(rt, d, ra)` is `lwz rt, d(ra)`,
`_rlwinm(ra, rs, ...)` is `rlwinm ra, rs, ...`).
"""
import struct

from .machine import R13

R13 = R13                               # the small-data base, 0x4017F0


# ---- the forms ---------------------------------------------------------------
def _d(op, rt, ra, imm):
    assert -0x8000 <= imm <= 0xFFFF, hex(imm)
    return (op << 26) | (rt << 21) | (ra << 16) | (imm & 0xFFFF)


def _x(rt, ra, rb, xo):
    return (31 << 26) | (rt << 21) | (ra << 16) | (rb << 11) | (xo << 1)


def _branch(frm, to, link=False):
    d = (to - frm) & 0xFFFFFFFF                 # addresses wrap: MPC code at 0 reaches 0xFFFxxxxx
    assert d < 0x02000000 or d >= 0xFE000000, (hex(frm), hex(to))
    return (18 << 26) | (d & 0x03FFFFFC) | (1 if link else 0)


def _branch_target(at, word):
    li = word & 0x03FFFFFC
    if li & 0x02000000:
        li -= 0x04000000
    return (at + li) & 0xFFFFFFFF


def _btarget(at, word):
    """Where a plain `b` at `at` goes, or None if the word is not one."""
    if word >> 26 != 18 or word & 1:
        return None
    return _branch_target(at, word)


def _ba(target):
    """ba target: absolute branch, target within +-32 MB of 0."""
    assert target < 0x02000000 or target >= 0xFE000000
    return (18 << 26) | (target & 0x03FFFFFC) | 2


# conditional branches, as (BO, BI) on cr0
BEQ, BNE, BLT, BGT = (12, 2), (4, 2), (12, 0), (12, 1)
BGE, BLE = (4, 0), (4, 1)               # LT clear, GT clear
BDNZ = (16, 0)

ISYNC, BLR, BCTR, BEQLR, RFI = 0x4C00012C, 0x4E800020, 0x4E800420, 0x4D820020, 0x4C000064


# ---- D-form ------------------------------------------------------------------
def _li(rt, v): return _d(14, rt, 0, v)
def _lis(rt, v): return _d(15, rt, 0, v)
def _ori(ra, rs, v): return _d(24, rs, ra, v)
def _addi(rt, ra, v): return _d(14, rt, ra, v)
def _addis(rt, ra, v): return _d(15, rt, ra, v)
def _andi(ra, rs, v): return _d(28, rs, ra, v)          # andi. (sets cr0)
def _lwz(rt, d, ra): return _d(32, rt, ra, d)
def _lhz(rt, d, ra): return _d(40, rt, ra, d)
def _lbz(rt, d, ra): return _d(34, rt, ra, d)
def _stw(rs, d, ra): return _d(36, rs, ra, d)
def _sth(rs, d, ra): return _d(44, rs, ra, d)
def _cmpwi(ra, v): return _d(11, 0, ra, v)
def _cmplwi(ra, v): return _d(10, 0, ra, v)


# ---- X-form ------------------------------------------------------------------
def _cmplw(ra, rb): return _x(0, ra, rb, 32)
def _add(rt, ra, rb): return _x(rt, ra, rb, 266)
def _or(ra, rs, rb): return _x(rs, ra, rb, 444)
def _xor(ra, rs, rb): return _x(rs, ra, rb, 316)
def _mr(ra, rs): return _or(ra, rs, rs)
def _addc(rt, ra, rb): return _x(rt, ra, rb, 10)
def _addze(rt, ra): return (31 << 26) | (rt << 21) | (ra << 16) | (202 << 1)
def _srw(ra, rs, rb): return _x(rs, ra, rb, 536)
def _extsh(ra, rs): return (31 << 26) | (rs << 21) | (ra << 16) | (922 << 1)


def _rlwinm(ra, rs, sh, mb, me):
    # M-form: the bits-6-10 field is the SOURCE (rs), bits 11-15 the DEST (ra)
    return (21 << 26) | (rs << 21) | (ra << 16) | (sh << 11) | (mb << 6) | (me << 1)


def _slwi(ra, rs, n): return _rlwinm(ra, rs, n, 0, 31 - n)
def _srwi(ra, rs, n): return _rlwinm(ra, rs, 32 - n, n, 31)


# ---- special registers --------------------------------------------------------
# mfspr/mtspr split the SPR number: bits 16-20 carry SPR[0:4], bits 11-15
# SPR[5:9]. With 9 (CTR) in the wrong half the word writes SPR 288, a no-op
# that once left CTR at its ambient value and turned a copy loop into a
# 2^32-iteration walk through the map.
def _mfspr(rt, n): return (31 << 26) | (rt << 21) | ((n & 31) << 16) | ((n >> 5) << 11) | (339 << 1)
def _mtspr(n, rs): return (31 << 26) | (rs << 21) | ((n & 31) << 16) | ((n >> 5) << 11) | (467 << 1)
def _mflr(rt): return _mfspr(rt, 8)
def _mtlr(rs): return _mtspr(8, rs)
def _mfctr(rt): return _mfspr(rt, 9)
def _mtctr(rs): return _mtspr(9, rs)
def _mfbbcmcr(rt): return _mfspr(rt, 560)
def _mtbbcmcr(rs): return _mtspr(560, rs)
def _mfmsr(rt): return (31 << 26) | (rt << 21) | (83 << 1)
def _mtmsr(rs): return (31 << 26) | (rs << 21) | (146 << 1)
def _mfcr(rt): return (31 << 26) | (rt << 21) | (19 << 1)
def _mtcr(rs): return (31 << 26) | (rs << 21) | (0xFF << 12) | (144 << 1)


class Asm:
    """Words and labels at a base address. A conditional branch, a `b` or a
    `bl` to a label, and a label's address split into lis/ori halves are
    emitted as tuples and resolved in `bytes`."""

    def __init__(self, base):
        self.base, self.items, self.labels = base, [], {}

    def here(self):
        return self.base + 4 * len(self.items)

    def label(self, name):
        self.labels[name] = self.here()

    def emit(self, *words):
        self.items.extend(words)

    def b(self, name):
        return ("b", name)

    def bc(self, cond, name):
        return (cond, name)

    def lis_lbl(self, rd, name):
        """lis rd, HI16(&name) -- the label's absolute address, resolved late."""
        return ("lis", rd, name)

    def ori_lbl(self, rd, name):
        """ori rd, rd, LO16(&name) -- pairs with lis_lbl for a 32-bit address."""
        return ("ori", rd, name)

    def bl(self, name):
        """bl to a label already placed."""
        self.emit(_branch(self.here(), self.labels[name], link=True))

    def far(self, target):
        """b to an absolute address."""
        self.emit(_branch(self.here(), target))

    def bytes(self):
        out = []
        for i, it in enumerate(self.items):
            if isinstance(it, int):
                out.append(it)
                continue
            at = self.base + 4 * i
            if it[0] == "b":
                out.append(_branch(at, self.labels[it[1]]))
            elif it[0] == "lis":
                _, rd, name = it
                # a label just above an address boundary needs the +0x8000 carry
                # the ori's signed add undoes; the patches sit far from any such edge
                out.append(_lis(rd, (self.labels[name] >> 16) & 0xFFFF))
            elif it[0] == "ori":
                _, rd, name = it
                out.append(_ori(rd, rd, self.labels[name] & 0xFFFF))
            else:
                (bo, bi), target = it[0], self.labels[it[1]]
                out.append((16 << 26) | (bo << 21) | (bi << 16) | ((target - at) & 0xFFFC))
        return struct.pack(f">{len(out)}I", *out)
