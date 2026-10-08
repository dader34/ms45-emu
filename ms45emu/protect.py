"""Engine protection and the spark-cut rev limiter for the MS45.1, in one
patch. Everything here cuts the ignition; nothing touches the limiter's
stored value, so the processor monitor never sees a disagreement.

Each of the three runtime ignition-fire sites (0x379CC, 0x193C4, 0x1976C)
is redirected to a gate. The gate works out the lowest rpm at which spark
should be cut from the current conditions, and returns without arming the
coil once engine speed (r13-0x4BEC, 1 rpm/count) is at or above it:

    spark cut      not in limp home  -> the program's own rev limit (r13-0x4BD6),
                                         whatever the tune, gear or map makes it
    cold start     cool <  warm_c    -> cold_rpm
    oil hot        oil  >= oil_c     -> oil_rpm        + lights the oil-temp warning (r13-0x2F4C)
    coolant hot    cool >= cool_c    -> cool_rpm       (the cluster gauge shows the overheat)

Injection is a different function and is never gated, so fuel is kept
whenever spark is cut. The stored rev limit (r13-0x4BD6) and the limiter's
torque path are left exactly as the stock program computes them, so the
limiter never actually engages below redline and the safety monitor's
redundant copy of the limiter state always agrees with the main code. In
limp home (r13-0x406B) the spark cut stands down and the stock limiter
alone holds the engine at its limp limit.

The two temperatures are live 8-bit variables, degrees C with a -40 offset:

    oil temp     r13-0x4026   (stock c_toil_max_accin compare, 0x59AA4)
    coolant temp r13-0x4038   (used ~80 places; the main tmot)

`build(pair, config)` returns the patched pair with its safety-monitor
sum, checksums and signature refreshed, so it flashes as a program; the
calibration is untouched, so it stacks with a tune and the map switch.
"""
import struct
from dataclasses import dataclass, replace

from . import dme
from .checksums import fix_program
from .image import Pair

EXT = 0xFFF00000
CODE_START, CODE_END = 0xDC860, 0xDCC00    # the map switch's blocks begin at 0xDCC00

VAR_OIL = -0x4026         # oil temp, 8 bit, C = raw - 40
VAR_COOL = -0x4038        # coolant temp, 8 bit, C = raw - 40
VAR_N = dme.VAR_N         # engine speed, 16 bit, 1 rpm/count
OIL_WARN = -0x2F4C        # stock oil-temp check-control output byte
TEMP_OFFSET = 40

SITES = ((0x379CC, 0x377A8), (0x193C4, 0x1F938), (0x1976C, 0x1F938))

VAR_N_MAX = -0x4BD6       # the engine speed limit the program's limiter works to, 16 bit, rpm
                          # (read only; never written by this patch)
VAR_LIMP = -0x406B        # set while the limp home limit (c_n_max_mtc_lih) is in force
NO_CUT = 0x7FFF           # a cut rpm nothing reaches

# An earlier version of this patch hooked the limiter's own store (external
# flash 0x96950, `sth r30,-0x4BD6(r13)`) to lower the limit; the safety
# monitor reset the DME over it. Nothing is hooked there any more, but a pair
# that still carries that hook must get its store back when it is rebuilt or
# the limiter would call into erased flash.
LIMIT_SITE = 0x96950
LIMIT_STORE = 0xB3CDB42A


@dataclass(frozen=True)
class Config:
    spark_cut: bool = True              # ignition cut at the program's own rev limit (pops & bangs)
    oil_c: int | None = 130             # max oil temp, degrees C; None to disable
    oil_rpm: int = 4500
    cool_c: int | None = 115            # max coolant temp, degrees C; None to disable
    cool_rpm: int = 4500
    cold_warm_c: int | None = 50        # cold-start: full revs only at/above this coolant temp; None to disable
    cold_rpm: int = 3500                # the ceiling held while cold

    def check(self):
        for rpm in (self.oil_rpm, self.cool_rpm, self.cold_rpm):
            if not 2000 <= rpm <= 8000:
                raise ValueError(f"rpm {rpm} out of range")
        for c in (self.oil_c, self.cool_c, self.cold_warm_c):
            if c is not None and not 0 <= c <= 200:
                raise ValueError(f"temperature {c} out of range")


# ---- a tiny PowerPC assembler with labels -----------------------------------
def _d(op, rt, ra, imm):
    return (op << 26) | (rt << 21) | (ra << 16) | (imm & 0xFFFF)


BLR = 0x4E800020


class _Asm:
    def __init__(self, base):
        self.base, self.items, self.labels = base, [], {}

    def _here(self):
        return self.base + 4 * len(self.items)

    def label(self, name):
        self.labels[name] = self._here()

    def emit(self, *words):
        self.items.extend(words)

    def bc(self, bo, bi, name):          # conditional branch to a label
        self.items.append(("bc", bo, bi, name))

    def bclr(self, bo, bi):
        self.emit((19 << 26) | (bo << 21) | (bi << 16) | (16 << 1))

    def b_abs(self, target):             # unconditional branch to an absolute address
        self.items.append(("b", target))

    # convenience ops
    def li(self, rt, v):
        self.emit(_d(14, rt, 0, v))

    def lbz(self, rt, ra, d):
        self.emit(_d(34, rt, ra, d))

    def lhz(self, rt, ra, d):
        self.emit(_d(40, rt, ra, d))

    def stb(self, rs, ra, d):
        self.emit(_d(38, rs, ra, d))

    def cmplwi(self, ra, v):
        self.emit(_d(10, 0, ra, v))

    def cmpwi(self, ra, v):
        self.emit(_d(11, 0, ra, v))

    def addi(self, rt, ra, v):
        self.emit(_d(14, rt, ra, v))

    def cmplw(self, ra, rb):
        self.emit((31 << 26) | (0 << 21) | (ra << 16) | (rb << 11) | (32 << 1))

    def words(self):
        out = []
        for i, it in enumerate(self.items):
            if isinstance(it, int):
                out.append(it)
            elif it[0] == "bc":
                _, bo, bi, name = it
                off = self.labels[name] - (self.base + 4 * i)
                out.append((16 << 26) | (bo << 21) | (bi << 16) | (off & 0xFFFC))
            else:
                _, target = it
                off = (target - (self.base + 4 * i)) & 0xFFFFFFFF
                assert off < 0x02000000 or off >= 0xFE000000
                out.append((18 << 26) | (off & 0x03FFFFFC))
        return out

    def bytes(self):
        return struct.pack(f">{len(self.items)}I", *self.words())


# BO/BI condition codes on cr0: LT bit = 0.
BLT, BGE = (12, 0), (4, 0)
BEQ, BNE = (12, 2), (4, 2)


def _gate(addr, orig, cfg):
    """An ignition site's gate. r12 holds the cut rpm, started at the program's
    own stored rev limit (so the spark cut acts wherever the limiter would, for
    any tune/gear/map) and lowered to each temperature limit in force. When
    engine speed reaches the cut rpm the coil is not armed; otherwise fall
    through to the stock fire. r0, r11, r12 are scratch here; the stock fire
    reloads what it needs. The stored rev limit is only read, never written,
    so the safety monitor sees nothing changed."""
    a = _Asm(addr)
    # r12 = cut rpm. Spark cut on -> start from the stored limit, except in
    # limp home, where the stock limiter is left to do its job alone; off ->
    # start from "no cut" and only the temperature limits can lower it.
    a.li(12, NO_CUT)
    if cfg.spark_cut:
        a.lbz(11, 13, VAR_LIMP); a.cmpwi(11, 0); a.bc(*BNE, "limp")
        a.lhz(12, 13, VAR_N_MAX)
        a.label("limp")

    def lower(rpm):
        # if rpm < r12: r12 = rpm
        a.cmplwi(12, rpm)
        tag = f"keep{rpm}_{len(a.items)}"
        a.bc(*BLT, tag)
        a.li(12, rpm)
        a.label(tag)

    if cfg.cold_warm_c is not None:
        a.lbz(11, 13, VAR_COOL); a.cmplwi(11, cfg.cold_warm_c + TEMP_OFFSET); a.bc(*BGE, "warm")
        lower(cfg.cold_rpm)
        a.label("warm")
    if cfg.oil_c is not None:
        a.lbz(11, 13, VAR_OIL); a.cmplwi(11, cfg.oil_c + TEMP_OFFSET); a.bc(*BLT, "oil_ok")
        lower(cfg.oil_rpm)
        a.li(11, 1); a.stb(11, 13, OIL_WARN)           # light the oil-temp warning
        a.label("oil_ok")
    if cfg.cool_c is not None:
        a.lbz(11, 13, VAR_COOL); a.cmplwi(11, cfg.cool_c + TEMP_OFFSET); a.bc(*BLT, "cool_ok")
        lower(cfg.cool_rpm)
        a.label("cool_ok")

    a.lhz(0, 13, VAR_N)                                # engine speed
    a.cmplw(0, 12)
    a.bclr(*BGE)                                       # N >= cut rpm -> return, coil not armed
    a.b_abs(orig)                                      # else fire (LR still = site+4)
    return a.bytes()


def _has_limits(cfg):
    return cfg.cold_warm_c is not None or cfg.oil_c is not None or cfg.cool_c is not None


# ---- patch plumbing ---------------------------------------------------------
def _decode_bl(mpc, off):
    w = struct.unpack_from(">I", mpc, off)[0]
    if w >> 26 != 18:
        return None, w & 1
    li = w & 0x03FFFFFC
    if li & 0x02000000:
        li -= 0x04000000
    return (off + li) & 0xFFFFFFFF, w & 1


def _branch(frm, to, link=0):
    d = (to - frm) & 0xFFFFFFFF
    assert d < 0x02000000 or d >= 0xFE000000, (hex(frm), hex(to))
    return (18 << 26) | (d & 0x03FFFFFC) | link


def _in_area(addr):
    return addr is not None and EXT + CODE_START <= addr < EXT + CODE_END


def _gated(mpc, site):
    tgt, link = _decode_bl(mpc, site)
    return bool(link) and _in_area(tgt)


def _limit_hooked(flash):
    """Whether an earlier version's call sits where the limiter stores its limit."""
    tgt, link = _decode_bl(flash, LIMIT_SITE)
    return bool(link) and tgt is not None and _in_area((EXT + tgt) & 0xFFFFFFFF)


def is_patched(pair):
    return _limit_hooked(pair.flash) or any(_gated(pair.mpc, site) for site, _ in SITES)


def remove(pair):
    flash, mpc = bytearray(pair.flash), bytearray(pair.mpc)
    for site, orig in SITES:
        tgt, link = _decode_bl(mpc, site)
        if tgt == orig:
            continue
        if not _gated(mpc, site):
            raise ValueError(f"the call at 0x{site:X} is neither stock nor a protection patch")
        struct.pack_into(">I", mpc, site, _branch(site, orig, link=1))
    if _limit_hooked(flash):
        struct.pack_into(">I", flash, LIMIT_SITE, LIMIT_STORE)      # an earlier version's hook
    elif struct.unpack_from(">I", flash, LIMIT_SITE)[0] != LIMIT_STORE:
        raise ValueError(f"the limiter's store at 0x{LIMIT_SITE:X} is neither stock nor an earlier protection hook")
    flash[CODE_START:CODE_END] = b"\xff" * (CODE_END - CODE_START)
    fix_program(flash, mpc)
    return Pair(bytes(flash), bytes(mpc), pair.name)


@dataclass(frozen=True)
class Layout:
    config: Config
    gates: tuple            # (site, gate address) per ignition site
    code_end: int


def build(pair, config=None, **overrides):
    """The pair with the protection built in, and its Layout.
    `config` is a Config; keyword overrides tweak the defaults
    (e.g. build(pair, spark_cut=False) for protections without the pops cut)."""
    cfg = replace(config or Config(), **overrides)
    cfg.check()
    if is_patched(pair):
        pair = remove(pair)
    flash, mpc = bytearray(pair.flash), bytearray(pair.mpc)

    for site, orig in SITES:
        tgt, link = _decode_bl(mpc, site)
        if not link or tgt != orig:
            raise ValueError(f"the program does not carry the expected ignition call at 0x{site:X}")
    if struct.unpack_from(">I", flash, LIMIT_SITE)[0] != LIMIT_STORE:
        raise ValueError(f"the program does not store its engine speed limit at 0x{LIMIT_SITE:X} the expected way")

    # One gate per ignition site, each sized to its own folded-in limits.
    pc = EXT + CODE_START
    blobs, gates = [], []
    enabled = cfg.spark_cut or _has_limits(cfg)
    if enabled:
        for site, orig in SITES:
            blob = _gate(pc, orig, cfg)
            blobs.append((pc, blob))
            gates.append((site, pc))
            pc += len(blob)
    need_end = pc - EXT
    if need_end > CODE_END:
        raise ValueError("the code does not fit in the free flash area")
    if flash[CODE_START:need_end] != b"\xff" * (need_end - CODE_START):
        raise ValueError(f"the external flash is not empty at 0x{CODE_START:X}..0x{need_end:X}")

    for at, blob in blobs:
        flash[at - EXT:at - EXT + len(blob)] = blob
    for site, gate_pc in gates:
        struct.pack_into(">I", mpc, site, _branch(site, gate_pc, link=1))

    fix_program(flash, mpc)
    return Pair(bytes(flash), bytes(mpc), pair.name + "+protect"), Layout(cfg, tuple(gates), need_end)
