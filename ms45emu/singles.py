"""Live single values (docs/livetune-design.md, milestone 6): the constants
and flags the program reads straight from the calibration, made to read
through the live-tune mirrors like the tables do.

A table goes through the lookup library, which the overlay hooks. A single
value does not: it is one `lbz/lhz/lha/lwz rD, d(r2)` somewhere in the
program, 4,300 of them for 2,900 values, and r2 never moves. Two things are
done to those instructions, by how often the value is read (measured on the
emulator, ms45emu/names/<program>.singles.json):

- **Read often** (some 540 values, 800 bytes, 97% of the reads): the value
  gets a byte or two of RAM for good, in the pool at the top of the heap, and
  every instruction that reads it is re-pointed there -- `l?z rD, d'(r13)`,
  the same instruction, no cost. The pool is filled from the calibration
  before the program's main routine starts (nothing reads a value earlier),
  and again on close-all. A tester edits such a value by placing a mirror on
  its pool bytes (transport op 07), so one write is live and the save, which
  reads every open range through its descriptor, folds it in unchanged.

- **Everything else**: the instruction becomes a trap that still carries the
  load -- `twi` with TO 28-31 (always taken; the low two bits say which
  load), rD in the rA field and d as it was. The program exception's entry in
  the relocated table (internal flash 0x38) points at `handler`, which forms
  r2 + d, sends it through the overlay's own bitmap-and-descriptor scan,
  loads from wherever that lands, puts the value in rD and returns past the
  trap. So such a value is a mirror of one or two bytes like any table: in
  RAM or on the shelf, nothing held until it is edited. About 2,000 traps a
  second in steady running.

A table in the external flash says which is which, for the tester: the pool
entries, and the runs of calibration bytes every reader of which is patched
(a value outside them takes effect after a save, as before).

Not patched: instructions outside the function map (not known to be code),
ones whose destination is r1, r2 or r13, and ones reachable with MSR[RI]
clear (the first instructions of an exception entry, and after the one NRI
site): an exception there cannot be returned from.
"""
import bisect
import json
import os
import struct
import zlib
from collections import namedtuple

from . import dme, overlay
from .checksums import fix_program
from .diagpatch import BEQ, BNE, BLT, _branch, _d
from .fold import (_Fold, _add, _addi, _addis, _andi, _cmplwi, _cmpwi, _lbz, _lhz, _li, _lis, _lwz,
                   _mflr, _mfctr, _mtctr, _mtlr, _mr, _ori, _rlwinm, _srwi, _stw, BLR)
from .funcmap import FunctionMap
from .image import Pair

R13, R2 = 0x4017F0, 0xFFE47FF0
EXT = 0xFFF00000
MPC_CODE = (0x100, 0x6E550)             # the program's two halves: the internal flash below
EXT_CODE = (0x60000, 0xDC854)           # the old generation's stubs, the external above the loader
TABLE = 0xFA800                         # ext file offsets, in the blank end of the program
CODE, CODE_END = 0xFD000, 0xFFF00       # area (the golden calibration's room ends at 0xF8000)
TABLE_MAGIC = 0x53564C31                # "SVL1"
HEADER = 16                             # magic, pool entries (2), runs (2), pool base, id
POOL = overlay.SINGLES_POOL
VECTOR = 0x38                           # the program exception's entry in the relocated table
MAIN_CALL = 0xFFF717F8                  # the reset sequence's last call: `bl main`
MAIN = 0xFFFD2F8C
NRI_SITES = (0x10768,)                  # mtspr NRI in the program: RI clear after it
RI_WINDOW = 48                          # instructions taken as unrecoverable after each
THRESHOLD = 20                          # reads a second from which a value earns RAM

KINDS = {34: 0, 40: 1, 42: 2, 32: 3}    # lbz, lhz, lha, lwz -> the trap's TO, 28 + kind
SIZES = {34: 1, 40: 2, 42: 2, 32: 4}
TWI = 3
S_CR, S_CTR, S_WORD = (overlay.STATE + at - R13 for at in (0x10, 0x14, 0x18))   # the handler's
                                        # three words, spare in the transport's state block
SRR0, SRR1, SPRG0, SPRG1, SPRG2 = 26, 27, 272, 273, 274   # the program uses SPRG3 only
RFI = 0x4C000064

Site = namedtuple("Site", "pc op rd offset")            # offset: of the calibration
Plan = namedtuple("Plan", "sites skipped ranges pool runs")


def _mfspr(rt, n): return (31 << 26) | (rt << 21) | ((n & 31) << 16) | ((n >> 5) << 11) | (339 << 1)
def _mtspr(n, rs): return (31 << 26) | (rs << 21) | ((n & 31) << 16) | ((n >> 5) << 11) | (467 << 1)
def _mfcr(rt): return (31 << 26) | (rt << 21) | (19 << 1)
def _mtcr(rs): return (31 << 26) | (rs << 21) | (0xFF << 12) | (144 << 1)
def _extsh(ra, rs): return (31 << 26) | (rs << 21) | (ra << 16) | (922 << 1)
def _ba(target): return (18 << 26) | (target & 0x03FFFFFC) | 2


def _file(pc):
    """(image index, offset) of a program address: 0 the internal flash, 1 the external."""
    return (1, pc - EXT) if pc >= EXT else (0, pc)


def profile_path(pair):
    return os.path.join(os.path.dirname(__file__), "names", f"{pair.program_id.decode('latin1')}.singles.json")


def load_rates(pair):
    """Reads a second of each directly read calibration offset, as profiled."""
    with open(profile_path(pair)) as f:
        return {int(k, 16): v for k, v in json.load(f)["rates"].items()}


def _unrecoverable(words):
    """Addresses that may run with MSR[RI] clear: the head of every exception
    handler the relocated table branches to, and what follows an NRI site."""
    out = set()
    starts = list(NRI_SITES)
    for entry in range(0, 0x100, 8):
        w = words.get(entry, 0)
        if w >> 26 == 18 and w & 2:
            t = w & 0x03FFFFFC
            starts.append(t | 0xFC000000 if t & 0x02000000 else t)
    for start in starts:
        out.update(range(start, start + 4 * RI_WINDOW, 4))
    return out


def scan(pair):
    """Every `l?z rD, d(r2)` of the program: (sites to patch, sites left alone
    with the reason)."""
    fm = FunctionMap(pair)
    starts = [f.start for f in fm.functions]

    def in_function(pc):
        i = bisect.bisect_right(starts, pc) - 1
        return i >= 0 and fm.functions[i].start <= pc < fm.functions[i].end

    unrecoverable = _unrecoverable(fm.words)
    sites, skipped = [], []
    for image, (lo, hi), base in ((pair.mpc, MPC_CODE, 0), (pair.flash, EXT_CODE, EXT)):
        for at in range(lo, hi, 4):
            w = struct.unpack_from(">I", image, at)[0]
            op = w >> 26
            if op not in KINDS or (w >> 16) & 31 != 2:
                continue
            d = (w & 0xFFFF) - (0x10000 if w & 0x8000 else 0)
            site = Site(base + at, op, (w >> 21) & 31, R2 + d - dme.CAL_BASE)
            if not 0 <= site.offset < dme.CAL_LENGTH:
                continue
            if not in_function(site.pc):
                skipped.append((site, "not in a known function"))
            elif site.rd in (1, 2, 13):
                skipped.append((site, "loads a base register"))
            elif site.pc in unrecoverable:
                skipped.append((site, "may run with RI clear"))
            else:
                sites.append(site)
    return sites, skipped


def _ranges(sites):
    """The calibration bytes the sites read, as merged [start, end) ranges:
    two reads that overlap share a range, so every byte has one home."""
    spans = sorted((s.offset, s.offset + SIZES[s.op]) for s in sites)
    out = []
    for lo, hi in spans:
        if out and lo < out[-1][1]:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [tuple(r) for r in out]


def plan(pair, rates=None, threshold=THRESHOLD):
    """What `build` does to this pair: the sites, the ranges they read, which
    ranges get RAM ({start: (length, pool offset)}) and the runs of
    calibration every reader of which is patched."""
    rates = load_rates(pair) if rates is None else rates
    sites, skipped = scan(pair)
    ranges = _ranges(sites)
    starts = [lo for lo, _ in ranges]

    def range_of(offset):
        return ranges[bisect.bisect_right(starts, offset) - 1]

    rate = {}
    for s in sites:
        r = range_of(s.offset)
        rate[r] = max(rate.get(r, 0), rates.get(s.offset, 0))
    size = POOL[1] - POOL[0]
    chosen, used = [], 0
    for r in sorted(ranges, key=lambda r: -rate.get(r, 0)):
        need = r[1] - r[0]
        if rate.get(r, 0) < threshold or used + need > size:
            continue
        chosen.append(r)
        used += need
    pool, at = {}, 0
    for lo, hi in sorted(chosen):                   # packed: the calibration's own halfwords
        assert hi - lo <= 16 and at + hi - lo <= size   # sit at odd addresses too
        pool[lo] = (hi - lo, at)
        at += hi - lo

    # a byte is live when every instruction that reads it is patched
    stale = set()
    for s, _ in skipped:
        stale.update(range(s.offset, s.offset + SIZES[s.op]))
    runs = []
    for lo, hi in ranges:
        if any(b in stale for b in range(lo, hi)):
            continue
        if runs and runs[-1][1] == lo:
            runs[-1][1] = hi
        else:
            runs.append([lo, hi])
    return Plan(sites, skipped, ranges, pool, [tuple(r) for r in runs])


def table(p):
    """The table the tester reads: pool entries, then the live runs."""
    body = b"".join(struct.pack(">HH", lo, ((n - 1) << 12) | at) for lo, (n, at) in sorted(p.pool.items()))
    body += b"".join(struct.pack(">HH", lo, hi - lo) for lo, hi in p.runs)
    return struct.pack(">IHHII", TABLE_MAGIC, len(p.pool), len(p.runs), POOL[0], zlib.crc32(body)) + body


def parse_table(data):
    """{"pool": {cal offset: (length, RAM address)}, "runs": [(start, end)], "id"}."""
    magic, n, runs, base, ident = struct.unpack_from(">IHHII", data)
    if magic != TABLE_MAGIC:
        return None
    pool = {}
    for i in range(n):
        lo, v = struct.unpack_from(">HH", data, HEADER + 4 * i)
        pool[lo] = ((v >> 12) + 1, base + (v & 0xFFF))
    at = HEADER + 4 * n
    return {"pool": pool, "id": ident,
            "runs": [(lo, lo + ln) for lo, ln in struct.iter_unpack(">HH", data[at:at + 4 * runs])]}


def _code(stock):
    """The fill, the reset hook and the trap handler, assembled at CODE:
    (bytes, labels). `stock` is the program's own program-exception handler."""
    a = _Fold(EXT + CODE)
    e = a.emit

    # ---- fill: the pool from the calibration. r5-r10, r0, CTR; returns ----
    a.label("fill")
    e(_lis(5, (EXT + TABLE) >> 16), _ori(5, 5, TABLE & 0xFFFF),
      _lhz(6, 4, 5), _cmpwi(6, 0), a.bc(BEQ, "filled"), _mtctr(6), _addi(5, 5, HEADER))
    a.label("fill_entry")
    e(_lhz(7, 0, 5), _lhz(8, 2, 5), _addis(7, 7, dme.CAL_BASE >> 16),
      _rlwinm(9, 8, 0, 20, 31), _lis(10, POOL[0] >> 16), _ori(10, 10, POOL[0] & 0xFFFF), _add(9, 9, 10),
      _srwi(8, 8, 12), _addi(8, 8, 1))
    a.label("fill_byte")
    e(_lbz(0, 0, 7), _d(38, 0, 9, 0), _addi(7, 7, 1), _addi(9, 9, 1),
      _d(13, 8, 8, -1), a.bc(BNE, "fill_byte"),              # addic. r8, r8, -1
      _addi(5, 5, 4), a.bc((16, 0), "fill_entry"))
    a.label("filled")
    e(BLR)

    # ---- the reset sequence's `bl main`, displaced here: fill the pool and
    # take it out of the heap (allocations from the top stop below it)
    a.label("boot")
    e(_mflr(12))
    a.bl("fill")
    e(_mtlr(12), _lis(5, POOL[0] >> 16), _ori(5, 5, POOL[0] & 0xFFFF),
      _stw(5, dme.HEAP_TOP, 13))
    a.far(MAIN)

    # ---- the program exception. Ours is a trap whose word is `twi` with TO
    # 28-31; anything else goes to the program's handler as it came. EE and
    # RI are clear from entry to rfi and nothing here can fault, so the three
    # words in the state block and SPRG0-2 are ours for the duration.
    a.label("handler")
    e(_mtspr(SPRG0, 11), _mtspr(SPRG1, 12), _mtspr(SPRG2, 0),
      _mfcr(0), _stw(0, S_CR, 13),
      _mfspr(11, SRR1), _d(29, 11, 0, 2), a.bc(BEQ, "stock"),          # andis. r0, r11, 2: a trap?
      _mfspr(11, SRR0), _lwz(12, 0, 11),
      _srwi(0, 12, 23), _cmplwi(0, (TWI << 3) | 7), a.bc(BNE, "stock"),
      _stw(12, S_WORD, 13), _mfctr(0), _stw(0, S_CTR, 13),
      _extsh(0, 12), _add(12, 2, 0),                                   # the address read
      a.lis_lbl(0, "scanned"), a.ori_lbl(0, "scanned"), _mtctr(0))
    a.far(overlay.SCAN)                                                # r12 -> its mirror, if any
    a.label("scanned")
    e(_lwz(11, S_WORD, 13), _rlwinm(0, 11, 11, 30, 31),                # which load
      _cmpwi(0, 1), a.bc(BLT, "byte"), a.bc(BEQ, "half"), _cmpwi(0, 3), a.bc(BEQ, "word"),
      _d(42, 0, 12, 0), a.b("loaded"))                                 # lha
    a.label("byte")
    e(_lbz(0, 0, 12), a.b("loaded"))
    a.label("half")
    e(_lhz(0, 0, 12), a.b("loaded"))
    a.label("word")
    e(_lwz(0, 0, 12))
    a.label("loaded")
    e(_rlwinm(11, 11, 19, 24, 28),                                     # rD * 8
      a.lis_lbl(12, "into"), a.ori_lbl(12, "into"), _add(11, 11, 12), _mtctr(11), 0x4E800420)
    a.label("into")                                                    # the value into rD
    for r in range(32):
        e({0: _mtspr(SPRG2, 0), 11: _mtspr(SPRG0, 0), 12: _mtspr(SPRG1, 0)}.get(r, _mr(r, 0)),
          a.b("resume"))
    a.label("resume")
    e(_mfspr(11, SRR0), _addi(11, 11, 4), _mtspr(SRR0, 11),            # past the trap
      _lwz(0, S_CTR, 13), _mtctr(0), _lwz(0, S_CR, 13), _mtcr(0),
      _mfspr(11, SPRG0), _mfspr(12, SPRG1), _mfspr(0, SPRG2), RFI)
    a.label("stock")
    e(_lwz(0, S_CR, 13), _mtcr(0),
      _mfspr(11, SPRG0), _mfspr(12, SPRG1), _mfspr(0, SPRG2), _ba(stock))
    return a.bytes(), a.labels


_BYTES, _LABELS = _code(0)
FILL, BOOT, HANDLER = (_LABELS[n] - EXT for n in ("fill", "boot", "handler"))    # ext file offsets


def is_patched(pair):
    return struct.unpack_from(">I", pair.flash, TABLE)[0] == TABLE_MAGIC


def trap_word(site):
    return (TWI << 26) | ((28 + KINDS[site.op]) << 21) | (site.rd << 16) | ((dme.CAL_BASE + site.offset - R2) & 0xFFFF)


def build(pair, rates=None, threshold=THRESHOLD):
    """The pair with its single values live, re-signed. Composes last, after
    overlay.build, transport.build and fold.build. A pair already built is
    returned as it is: the re-pointed instructions no longer say where they
    read."""
    if is_patched(pair):
        return pair
    if not overlay.is_patched(pair):
        raise ValueError("the overlay is not there: its scan is what the trap handler reads through")
    mpc, flash = bytearray(pair.mpc), bytearray(pair.flash)
    if flash[TABLE:CODE_END].strip(b"\xff"):
        raise ValueError(f"the ext space from 0x{TABLE:X} is not blank")
    vector = struct.unpack_from(">I", mpc, VECTOR)[0]
    if vector >> 26 != 18 or not vector & 2:
        raise ValueError(f"the program exception's table entry is not a `ba`: 0x{vector:08X}")
    stock = vector & 0x03FFFFFC
    stock |= 0xFC000000 if stock & 0x02000000 else 0
    call = MAIN_CALL - EXT
    if struct.unpack_from(">I", flash, call)[0] != _branch(MAIN_CALL, MAIN, link=True):
        raise ValueError("the reset sequence does not end in the call to main this build displaces")

    p = plan(pair, rates, threshold)
    data = table(p)
    code, labels = _code(stock)
    if TABLE + len(data) > CODE or CODE + len(code) > CODE_END:
        raise ValueError("the single-value table or its code does not fit")
    images = (mpc, flash)
    starts = sorted(p.pool)
    for s in p.sites:
        i = bisect.bisect_right(starts, s.offset) - 1
        home = starts[i] if i >= 0 and s.offset < starts[i] + p.pool[starts[i]][0] else None
        if home is None:
            word = trap_word(s)
        else:
            d = POOL[0] + p.pool[home][1] + (s.offset - home) - R13
            assert -0x8000 <= d < 0x8000
            word = (s.op << 26) | (s.rd << 21) | (13 << 16) | (d & 0xFFFF)
        image, at = _file(s.pc)
        struct.pack_into(">I", images[image], at, word)
    flash[TABLE:TABLE + len(data)] = data
    flash[CODE:CODE + len(code)] = code
    struct.pack_into(">I", flash, call, _branch(MAIN_CALL, labels["boot"], link=True))
    struct.pack_into(">I", mpc, VECTOR, _ba(labels["handler"]))
    fix_program(flash, mpc)
    return Pair(bytes(flash), bytes(mpc), pair.name + "+singles")
