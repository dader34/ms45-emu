"""Diagnostic patches for program 0044570LO02S: faster logging on the K
line, a log frame on CAN, and a capture buffer filled once per segment.

`build(pair)` returns the patched pair and a `Layout` that says where
everything is. Three things are added, all in two stubs:

- Fast timing. The default session takes `83 03 04 01 18 14 00`, which
  sets the DME's answer delay to 2 ms and its pause before the next
  request to 12 ms, and nothing shorter. The KWP core that enforces this
  is boot-sector code and cannot be flashed, but the two times are RAM
  bytes, so the 10 ms stub rewrites them to 0 and 2 ms whenever it finds
  exactly those limits there. A tester that never asks for them sees no
  difference.
- A CAN frame every 10 ms from the same stub, through message buffer 15
  of module A, which the program leaves untouched: a counter and up to
  seven bytes of variables.
- A ring of 8-byte records written at the end of the segment task (every
  120 degrees of crank), for values that polling at any rate would miss.
  A tester reads the whole block with one `23` request.

The stubs replace two `bl` instructions and tail-call what those called,
using only r0, r11, r12 and cr0. Their code goes in the unused end of the
external program area (0xDC860 up), which the map-switch builder does not
look at, so the two patches can be applied in either order.

The block lives in the middle of what the program's heap leaves free.
Both stubs first check the heap's two pointers and do nothing with the
block if the heap has grown into it.
"""
import struct
from collections import namedtuple
from dataclasses import dataclass

from . import dme
from .checksums import fix_program
from .image import Pair
from .machine import R13

Field = namedtuple("Field", "name address size")

N = Field("n", R13 + dme.VAR_N, 2)
SEGMENT_TIME = Field("segment_time", R13 + dme.VAR_SEGMENT_TIME, 2)
SEGMENT = Field("segment", R13 + dme.VAR_SEGMENT, 1)
PEDAL = Field("pedal", R13 + dme.VAR_PV, 1)
SPEED = Field("speed", R13 + dme.VAR_VS, 1)
BRAKE = Field("brake", R13 + dme.VAR_BRK_A, 1)
KL15 = Field("kl15", dme.KL15_FLAG, 1)
MAP = Field("map", dme.RAM_FLAG, 1)

CAN_FIELDS = (PEDAL, N, SPEED, KL15, BRAKE, MAP)       # after the counter in byte 0
CAPTURE_FIELDS = (SEGMENT, SEGMENT_TIME, N, PEDAL)     # after the sequence number in byte 0
CAN_ID = 0x7A0

CODE_START, CODE_END = 0xDC860, 0xDCC00        # external flash, file offsets; free from 0xDC854, the map switch's blocks from 0xDCC00
EXT = 0xFFF00000
BUILDER, SEGMENT_END = 0x4B528, 0x32180        # what the two hooked calls call

BLOCK = 0x3FF780
MAGIC = 0xD1A6
HEADER = 8                 # magic (2), 10 ms counter, next slot, last sequence number, 3 spare
SLOTS, RECORD = 30, 8
BLOCK_SIZE = HEADER + SLOTS * RECORD            # 248: one `23` request reads it all
FAST_P2MIN, FAST_P3MIN = 0, 2                   # ms

CAN_A_MB15 = 0x3071F0
MB_TX_INACTIVE, MB_TX_ONCE = 0x80, 0xC0


# ---- a little PowerPC -------------------------------------------------------
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


LOAD, STORE = {1: 34, 2: 40, 4: 32}, {1: 38, 2: 44, 4: 36}
R0, R11, R12, R13_ = 0, 11, 12, 13
BEQ, BNE, BLT, BGT = (12, 2), (4, 2), (12, 0), (12, 1)


class _Asm:
    def __init__(self, base):
        self.base, self.items, self.labels = base, [], {}

    def here(self):
        return self.base + 4 * len(self.items)

    def label(self, name):
        self.labels[name] = self.here()

    def emit(self, *words):
        self.items.extend(words)

    def bc(self, cond, name):
        self.items.append((cond, name))

    def li(self, rt, value):
        self.emit(_d(14, rt, 0, value if value < 0x8000 else value - 0x10000))

    def load(self, rt, address, size):
        self.emit(_d(LOAD[size], rt, R13_, address - R13))

    def store(self, rs, address, size):
        self.emit(_d(STORE[size], rs, R13_, address - R13))

    def copy(self, fields, base_reg, offset):
        """Each field from its variable to offset(base_reg) on, through r0."""
        for f in fields:
            self.load(R0, f.address, f.size)
            self.emit(_d(STORE[f.size], R0, base_reg, offset))
            offset += f.size

    def heap_guard(self, out):
        """Leave for `out` unless the block is clear of the heap on both sides."""
        self.emit(_d(32, R11, R13_, dme.HEAP_BOTTOM), _d(14, R12, R13_, BLOCK - R13), _x(0, R11, R12, 32))
        self.bc(BGT, out)
        self.emit(_d(32, R11, R13_, dme.HEAP_TOP), _d(14, R12, R13_, BLOCK + BLOCK_SIZE - R13), _x(0, R11, R12, 32))
        self.bc(BLT, out)

    def bytes(self):
        out = []
        for i, it in enumerate(self.items):
            if not isinstance(it, int):
                (bo, bi), target = it[0], self.labels[it[1]]
                it = (16 << 26) | (bo << 21) | (bi << 16) | ((target - self.base - 4 * i) & 0xFFFC)
            out.append(it)
        return struct.pack(f">{len(out)}I", *out)


def _frame_stub(base, can_id, can_fields):
    a = _Asm(base)
    # A tester has set the default session's limits: go below them.
    for address, limit in zip((R13 + dme.KWP_P2MIN, R13 + dme.KWP_P3MIN), dme.KWP_FAST_TIMING):
        a.load(R11, address, 1)
        a.emit(_d(11, 0, R11, limit))
        a.bc(BNE, "block")
    for address, fast in ((R13 + dme.KWP_P2MIN, FAST_P2MIN), (R13 + dme.KWP_P3MIN, FAST_P3MIN)):
        a.li(R11, fast)
        a.store(R11, address, 1)
    a.label("block")
    a.heap_guard("done")
    # First time after power-up: an empty block, then the magic.
    a.load(R11, BLOCK, 2)
    a.emit(_d(10, 0, R11, MAGIC))
    a.bc(BEQ, "count")
    a.li(R0, 0)
    a.emit(_d(14, R12, R13_, BLOCK - R13 - 4))
    a.li(R11, BLOCK_SIZE // 4)
    a.label("clear")
    a.emit(_d(37, R0, R12, 4), _d(13, R11, R11, -1))          # stwu r0,4(r12); addic. r11,r11,-1
    a.bc(BNE, "clear")
    a.li(R11, MAGIC)
    a.store(R11, BLOCK, 2)
    a.label("count")
    a.load(R11, BLOCK + 2, 1)
    a.emit(_d(14, R11, R11, 1))
    a.store(R11, BLOCK + 2, 1)
    if can_id is not None:
        length = 1 + sum(f.size for f in can_fields)
        a.emit(_d(15, R12, 0, CAN_A_MB15 >> 16), _d(24, R12, R12, CAN_A_MB15 & 0xFFFF))
        a.li(R0, MB_TX_INACTIVE | length)
        a.emit(_d(44, R0, R12, 0))
        a.li(R0, can_id << 5)
        a.emit(_d(44, R0, R12, 2))
        a.emit(_d(38, R11, R12, 6))                           # the counter
        a.copy(can_fields, R12, 7)
        a.li(R0, MB_TX_ONCE | length)
        a.emit(_d(44, R0, R12, 0))
    a.label("done")
    a.emit(_branch(a.here(), BUILDER))
    return a.bytes()


def _segment_stub(base, capture_fields):
    a = _Asm(base)
    a.heap_guard("done")
    a.load(R11, BLOCK, 2)
    a.emit(_d(10, 0, R11, MAGIC))
    a.bc(BNE, "done")                                         # not set up yet by the 10 ms stub
    a.load(R11, BLOCK + 3, 1)
    a.emit(_d(10, 0, R11, SLOTS))
    a.bc(BLT, "slot")
    a.li(R11, 0)
    a.label("slot")
    a.emit((21 << 26) | (R11 << 21) | (R12 << 16) | (3 << 11) | (28 << 1), _x(R12, R12, R13_, 266))   # r12 = r13 + 8 * slot
    # The sequence number runs 1..255: 0 is a slot never written.
    a.load(R0, BLOCK + 4, 1)
    a.emit(_d(12, R0, R0, 1), _d(28, R0, R0, 0xFF))           # addic r0,r0,1; andi. r0,r0,0xFF
    a.bc(BNE, "seq")
    a.li(R0, 1)
    a.label("seq")
    a.store(R0, BLOCK + 4, 1)
    record = BLOCK + HEADER - R13
    a.emit(_d(38, R0, R12, record))
    a.copy(capture_fields, R12, record + 1)
    a.emit(_d(14, R11, R11, 1), _d(10, 0, R11, SLOTS))
    a.bc(BLT, "next")
    a.li(R11, 0)
    a.label("next")
    a.store(R11, BLOCK + 3, 1)
    a.label("done")
    a.emit(_branch(a.here(), SEGMENT_END))
    return a.bytes()


# ---- the layout, and reading what the stubs write -------------------------------
def _check(fields, first, room, what):
    offset = first
    for f in fields:
        if f.size not in (1, 2):
            raise ValueError(f"{what}: {f.name} must be 1 or 2 bytes")
        if f.size == 2 and (f.address | offset) & 1:
            raise ValueError(f"{what}: {f.name} is 16 bit and must be at an even address and an even offset (it is at {offset})")
        if not 0x3F9800 <= f.address < 0x400000:
            raise ValueError(f"{what}: {f.name} is not in RAM")
        offset += f.size
    if offset > room:
        raise ValueError(f"{what}: {offset - first} bytes of fields, room for {room - first}")


def _unpack(fields, data, first):
    out, offset = {}, first
    for f in fields:
        out[f.name] = int.from_bytes(data[offset:offset + f.size], "big")
        offset += f.size
    return out


@dataclass(frozen=True)
class Layout:
    can_id: int | None
    can_fields: tuple
    capture_fields: tuple
    frame_stub: int
    segment_stub: int
    code_end: int
    block: int = BLOCK
    block_size: int = BLOCK_SIZE

    def frame(self, data):
        """A log frame's data: its counter and fields."""
        return {"counter": data[0], **_unpack(self.can_fields, data, 1)}

    def header(self, block):
        """(set up, 10 ms counter, next slot, last sequence number)"""
        return int.from_bytes(block[0:2], "big") == MAGIC, block[2], block[3], block[4]

    def records(self, block):
        """The records in a block read with `23`, oldest first. The slot
        the segment task writes next is left out: it may be half written."""
        ok, _, slot, _ = self.header(block)
        if not ok or slot >= SLOTS:
            return []
        out, expect = [], None
        for back in range(1, SLOTS):
            at = HEADER + ((slot - back) % SLOTS) * RECORD
            seq = block[at]
            if seq == 0 or (expect is not None and seq != expect):
                break
            out.append({"seq": seq, **_unpack(self.capture_fields, block[at:at + RECORD], 1)})
            expect = seq - 1 or 255
        return out[::-1]


class Capture:
    """Follows the ring over successive reads: `feed(block)` gives the
    records that are new since the last one. `lost` counts the reads that
    came too late, when the ring had gone all the way round."""

    def __init__(self, layout):
        self.layout = layout
        self.last = None
        self.lost = 0

    def feed(self, block):
        records = self.layout.records(block)
        if self.last is not None:
            for i, r in enumerate(records):
                if r["seq"] == self.last:
                    records = records[i + 1:]
                    break
            else:
                if records:
                    self.lost += 1
        if records:
            self.last = records[-1]["seq"]
        return records


# ---- building -----------------------------------------------------------------
def _hooks(mpc):
    """(address, stock instruction, what is there now) for the two calls."""
    return [(at, _branch(at, to, link=True), struct.unpack_from(">I", mpc, at)[0])
            for at, to in ((dme.FRAME_TASK_BUILDER_CALL, BUILDER), (dme.SEGMENT_TASK_LAST_CALL, SEGMENT_END))]


def _in_code_area(at, word):
    return word >> 26 == 18 and word & 1 and EXT + CODE_START <= _branch_target(at, word) < EXT + CODE_END


def is_patched(pair):
    return all(_in_code_area(at, now) for at, _, now in _hooks(pair.mpc))


def remove(pair):
    """The pair without the patch (its checksums and signature brought up to date)."""
    flash, mpc = bytearray(pair.flash), bytearray(pair.mpc)
    for at, stock, now in _hooks(mpc):
        if now != stock and not _in_code_area(at, now):
            raise ValueError(f"the call at 0x{at:X} is neither stock nor this patch")
        struct.pack_into(">I", mpc, at, stock)
    flash[CODE_START:CODE_END] = b"\xff" * (CODE_END - CODE_START)
    fix_program(flash, mpc)
    return Pair(bytes(flash), bytes(mpc), pair.name)


def build(pair, can_id=CAN_ID, can_fields=CAN_FIELDS, capture_fields=CAPTURE_FIELDS):
    """The pair with the diagnostic patch, and its Layout. can_id=None
    leaves the CAN frame out. A pair that already carries the patch is
    rebuilt with what is asked for now."""
    can_fields = tuple(can_fields) if can_id is not None else ()
    capture_fields = tuple(capture_fields)
    if can_id is not None and not 0 <= can_id <= 0x7FF:
        raise ValueError("the log frame needs an 11-bit identifier")
    _check(can_fields, 1, 8, "log frame")
    _check(capture_fields, 1, RECORD, "capture record")

    if is_patched(pair):
        pair = remove(pair)
    flash, mpc = bytearray(pair.flash), bytearray(pair.mpc)
    for at, stock, now in _hooks(mpc):
        if now != stock:
            raise ValueError(f"the program does not carry the expected call at 0x{at:X}")
    if flash[CODE_START - 12:CODE_END] != b"\xff" * (CODE_END - CODE_START + 12):
        raise ValueError(f"the external flash is not empty from 0x{CODE_START - 12:X} to 0x{CODE_END:X}")

    frame_stub = EXT + CODE_START
    code = _frame_stub(frame_stub, can_id, can_fields)
    segment_stub = frame_stub + len(code)
    code += _segment_stub(segment_stub, capture_fields)
    assert CODE_START + len(code) <= CODE_END
    flash[CODE_START:CODE_START + len(code)] = code
    struct.pack_into(">I", mpc, dme.FRAME_TASK_BUILDER_CALL, _branch(dme.FRAME_TASK_BUILDER_CALL, frame_stub, link=True))
    struct.pack_into(">I", mpc, dme.SEGMENT_TASK_LAST_CALL, _branch(dme.SEGMENT_TASK_LAST_CALL, segment_stub, link=True))
    fix_program(flash, mpc)
    layout = Layout(can_id, can_fields, capture_fields, frame_stub, segment_stub, frame_stub + len(code))
    return Pair(bytes(flash), bytes(mpc), pair.name + "+diag"), layout
