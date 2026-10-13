"""The live-tune transport (docs/livetune-design.md, milestone 3): our own
KWP service riding the stock 2C define-packet handler.

The stock handler (entry 0xFFF6FC60, ext file 0x6FC60 — traced 2026-10-11)
accepts only local id 0xF0; anything else it answers `7F 2C 12` and stores
nothing. `build` replaces its first instruction (`stwu r1, -0x20(r1)`) with
a branch to a stub in blank ext space: the stub sees local id 0x6C, runs one
of five ops against the overlay's descriptor table and mirror pools, and
falls through to the stock body, whose `7F 2C 12` becomes the ack. The
response/TX path is boot-sector code and is never touched.

Request layout (the received telegram's data, in SRAM):

  0x3F9A44  SID (0x2C)       0x3F9A47  args...
  0x3F9A45  local id (0x6C)
  0x3F9A46  op

  02 <slot> <offset:2> <n> <n bytes>     write cells into the slot's mirror
                                         (a mirror in RAM only)
  03                                     close all: magic off, bitmap cleared
  04                                     state refresh (read the block by 23)
  05                                     save: fold the open tables into the
                                         calibration and reset (fold.py)
  06 <cal offset:3> <n> <n bytes>        shelf: program blank flash at the
                                         calibration sector's end (fold.py)
  08 <0x5A | 0>                          ask for the open tables to be saved at
                                         the next key-off, or take that back
  07 <slot> <cal offset:3> <length:2>    place: the slot's descriptor becomes
     <mirror:3>                          this range read from this mirror --
                                         an address in the RAM pools (seeded
                                         from where the range reads now) or
                                         a calibration offset on the shelf

The tester decides where every mirror lives (op 07 only checks that it is
inside a pool or the shelf), so RAM is its to manage: a table being edited
sits in RAM, one that is not can be programmed onto the shelf with op 06
and re-placed there, which frees its RAM for the next table. Twenty tables
can be open; the shelf holds 12 KB between two saves.

The state block at 0x3F9E74 (r13-reachable, in the span the KWP writer map
proved quiet) carries the magic, the last op's status, the open count, the
protocol version, the last mirror and the saved MSR — readable with stock
read-by-address.

The stub runs before the handler prologue and uses only r0/r11/r12, cr0,
CTR and (masked, saved in the state block) MSR[EE] -- op 07 also r3-r10,
which it saves on the stack and puts back: the stock body defines
each register (or `mflr`s it) before first use, and never touches CTR at
all (checked over 0xFFF6FC60-0xFFF70100). Masking matters: the SCI receive
interrupt writes the request buffer per byte, and the K line echoes our own
response bytes back into it — unmasked, a racing byte tears the args and
the state mid-op (seen as a zeroed length and a 2^32-iteration copy loop).
"""
import struct

from . import dme, overlay
from .checksums import fix_program
from .diagpatch import BEQ, BNE, BLT, BGT, _branch, _d, _x
from .image import Pair
from .overlay import _Asm                       # the diagpatch assembler + `b` to label

R13 = 0x4017F0
HANDLER = 0xFFF6FC60               # the 2C define-packet handler's entry
HFILE = HANDLER - 0xFFF00000       # the same word as an ext file offset
STOCK_FIRST = 0x9421FFE0           # stwu r1, -0x20(r1)
CODE = 0xDCC00                     # our stub, ext file offset: right after the
CODE_END = 0xE0000                 # diagpatch's 0xDC860-0xDCC00, before the
                                   # old generation's full map-2 copy at 0xE0000
                                   # (gen-5 builds pass code=0xDEC00, past their
                                   # map-switch stubs; the loader's marks at
                                   # file 0xFFF80+ bound the far end)
STATE = overlay.STATE              # 0x3F9E74: the state block, in a proven-quiet gap
                                   # (the receive interrupt's response echo walks
                                   # 0x3F99xx-0x3F9Axx; the old 0x3F9938 block lived
                                   # in its path and tore)
STATE_MAGIC = 0x4C54554E           # "LTUN"
LOCAL_ID = 0x6C
ACK = bytes((0x7F, 0x2C, 0x12))    # what the stock body answers for our id

S_MAGIC, S_STATUS, S_COUNT, S_VERSION, S_MIRROR, S_MSR = 0, 4, 8, 0x0C, 0x1C, 0x20
S_SIZE = 0x24
VERSION = 5                        # 2: ops 06 and 07, no op 01 (version 1 kept a pool
                                   # cursor, a RAM address, in this word). 3: the
                                   # descriptors moved and grew, single values are
                                   # live (singles.py). 4: the key-off saves only
                                   # when asked (op 08). 5: a save keeps the safety
                                   # monitor's sum in step (fold.MON_AT)

# request bytes (absolute; emitted r13-relative): 0x3F9A44 SID, .45 id,
# .46 op, then the args (write: slot .47, offset hword .48, count .4A,
# payload .4B up; place: slot .47, cal offset 3 bytes .48-.4A, length hword
# .4B, mirror 3 bytes .4D-.4F; shelf: see fold.REQUEST).
SID, ID, OP, ARG1, ARG2, ARG3, ARG4, PAYLOAD = range(0x3F9A44, 0x3F9A4C)
P_OFF, P_LEN, P_MIRROR = ARG1 + 1, ARG1 + 4, ARG1 + 6

(STATUS_OK, STATUS_OP, STATUS_FULL, STATUS_ROOM, STATUS_SLOT, STATUS_RANGE, STATUS_TURNING,
 STATUS_BIG, STATUS_FLASH, STATUS_USED, STATUS_SHELVED) = range(11)

# The save (ms45emu/fold.py, installed by fold.build in the internal flash).
# Op 05 branches there with the return address in CTR; it `bctr`s back only
# when it has not saved (r12 says why), and otherwise ends in a reset.
from .fold import ENTRY as SAVE_ENTRY, SHELF as SHELF_ENTRY   # noqa: E402
from . import fold, singles                                   # noqa: E402

BGE = (4, 0)                       # branch if cr0.LT clear  (>=)
BLE = (4, 1)                       # branch if cr0.GT clear  (<=)


def _r13(addr):
    off = addr - R13
    assert -0x8000 <= off < 0x8000, hex(addr)
    return off


def _cmpwi(ra, imm):
    return (11 << 26) | (ra << 16) | (imm & 0xFFFF)


def _lis(rd, hi):
    return _d(15, rd, 0, hi)


def _slwi16(rd):
    # slwi rd, rd, 16  == rlwinm rd, rd, 16, 0, 15
    return (21 << 26) | (rd << 21) | (rd << 16) | (16 << 11) | (0 << 6) | (15 << 1)


def _mtctr(r):
    # mtspr's SPR field is split: bits 16-20 carry SPR[0:4], bits 11-15
    # SPR[5:9] — with 9 in the wrong half it writes SPR 288 (a no-op here,
    # which left CTR at its ambient value and turned every copy loop into
    # a 2^32-iteration walk through the map)
    return (31 << 26) | (r << 21) | ((9 & 31) << 16) | ((9 >> 5) << 11) | (467 << 1)


def _btarget(at, word):
    """Where a plain `b` at `at` goes, or None if the word is not one."""
    if word >> 26 != 18 or word & 1:
        return None
    li = word & 0x03FFFFFC
    if li & 0x02000000:
        li -= 0x04000000
    return (at + li) & 0xFFFFFFFF


def _stub(base):
    a = _Asm(base)
    e = a.emit
    desc = _r13(overlay.DESC)

    # mask MSR[EE] for the whole op: the SCI receive interrupt's byte writer
    # (and the K-line echo of our own response) can tear the request buffer
    # and the state block mid-op — raced twice on the emulator, 2026-10-11.
    # The saved MSR parks in the state block; every path out restores it.
    e(0x7D8000A6, _d(36, 12, 13, _r13(STATE) + S_MSR))         # mfmsr r12; stw r12
    e(0x5580045E, 0x7C000124, 0x4C00012C)                       # rlwinm r0, r12, 0, 17, 15
                                                                # mtmsr r0; isync

    # whose request is this? (the SID check guards against the dispatcher
    # ever reaching the handler with a stale buffer)
    e(_d(34, 0, 13, _r13(SID)), _cmpwi(0, 0x2C), a.bc(BNE, "stock"))
    e(_d(34, 0, 13, _r13(ID)), _cmpwi(0, LOCAL_ID), a.bc(BNE, "stock"))

    # state init on first use: magic, status, count, version
    e(_d(32, 0, 13, _r13(STATE) + S_MAGIC), _lis(12, STATE_MAGIC >> 16))
    e(_d(24, 12, 12, STATE_MAGIC & 0xFFFF), _x(0, 12, 0, 0), a.bc(BEQ, "ready"))
    e(_d(36, 12, 13, _r13(STATE) + S_MAGIC))
    e(_d(14, 0, 0, 0), _d(36, 0, 13, _r13(STATE) + S_STATUS))
    e(_d(36, 0, 13, _r13(STATE) + S_COUNT))
    e(_d(14, 0, 0, VERSION), _d(36, 0, 13, _r13(STATE) + S_VERSION))
    a.label("ready")

    # op dispatch
    e(_d(34, 0, 13, _r13(OP)), _cmpwi(0, 2), a.bc(BEQ, "write"))
    e(_cmpwi(0, 3), a.bc(BEQ, "close"))
    e(_cmpwi(0, 4), a.bc(BEQ, "stateop"))
    e(_cmpwi(0, 5), a.bc(BEQ, "commit"))
    e(_cmpwi(0, 6), a.bc(BEQ, "shelf"))
    e(_cmpwi(0, 7), a.bc(BEQ, "place"))
    e(_cmpwi(0, 8), a.bc(BEQ, "ask"))
    e(_d(14, 0, 0, STATUS_OP), a.b("finish"))

    # ---- 02 write: slot, offset in table, byte count, payload ------------
    a.label("write")
    e(_d(34, 12, 13, _r13(ARG1)))                              # r12 = slot
    e(_d(32, 0, 13, _r13(STATE) + S_COUNT), _x(0, 0, 12, 0), a.bc(BGT, "slot_ok"))
    e(_d(14, 0, 0, STATUS_SLOT), a.b("finish"))
    a.label("slot_ok")
    e(_d(7, 12, 12, 12), _d(14, 11, 13, desc + 4), _x(11, 11, 12, 266))
    e(_d(32, 12, 11, 0), _d(32, 0, 11, 4), _x(0, 12, 0, 40))   # r0 = table length
    e(_d(32, 11, 11, 8), _x(11, 11, 12, 266))                  # r11 = mirror
    e(_d(36, 11, 13, _r13(STATE) + S_MIRROR))
    e(_cmpwi(11, 0), a.bc(BGE, "w_ram"))                       # the chip is at 0xFFExxxxx:
    e(_d(14, 0, 0, STATUS_SHELVED), a.b("finish"))             # a store there is a command
    a.label("w_ram")
    e(_d(40, 12, 13, _r13(ARG2)), _d(34, 11, 13, _r13(ARG4)))  # offset, count
    e(_cmpwi(11, 0), a.bc(BEQ, "w_done"))
    e(_x(12, 12, 11, 266), _x(0, 12, 0, 0), a.bc(BLE, "w_ok"))
    e(_d(14, 0, 0, STATUS_RANGE), a.b("finish"))
    a.label("w_ok")
    e(_d(40, 12, 13, _r13(ARG2)), _d(32, 11, 13, _r13(STATE) + S_MIRROR))
    e(_x(12, 12, 11, 266))                                     # r12 = destination
    e(_d(34, 11, 13, _r13(ARG4)), _mtctr(11))
    e(_d(14, 11, 13, _r13(PAYLOAD)))                           # r11 = source
    a.label("wcopy")
    e(_d(34, 0, 11, 0), _d(38, 0, 12, 0))
    e(_d(14, 11, 11, 1), _d(14, 12, 12, 1), a.bc((16, 0), "wcopy"))
    a.label("w_done")
    e(_d(14, 0, 0, STATUS_OK), a.b("finish"))

    # ---- 03 close all: the overlay's remove() ------------------------------
    a.label("close")
    e(_d(14, 0, 0, 0), _d(36, 0, 13, desc))
    e(_d(36, 0, 13, desc + 4), _d(36, 0, 13, _r13(STATE) + S_COUNT))
    for at in range(0, overlay.BITMAP_SPACE, 4):
        e(_d(36, 0, 13, _r13(overlay.BITMAP) + at))
    # a mirror placed on a single value's own RAM left its edit there: put
    # the calibration's values back (singles.py, when the build has it)
    e(_lis(11, (0xFFF00000 + singles.TABLE) >> 16), _d(24, 11, 11, singles.TABLE & 0xFFFF),
      _d(32, 0, 11, 0), _lis(12, singles.TABLE_MAGIC >> 16), _d(24, 12, 12, singles.TABLE_MAGIC & 0xFFFF),
      _x(0, 12, 0, 0), a.bc(BNE, "closed"))
    e(_d(37, 1, 1, -0x30))                                     # stwu r1, -0x30(r1)
    for i, r in enumerate(range(5, 11)):
        e(fold._stw(r, 8 + 4 * i, 1))
    e(fold._mflr(0), fold._stw(0, 0x24, 1))
    e(_branch(a.here(), 0xFFF00000 + singles.FILL, link=True))
    e(fold._lwz(0, 0x24, 1), fold._mtlr(0))
    for i, r in enumerate(range(5, 11)):
        e(fold._lwz(r, 8 + 4 * i, 1))
    e(fold._addi(1, 1, 0x30))
    a.label("closed")
    e(_d(14, 0, 0, STATUS_OK), a.b("finish"))

    # ---- 08 ask: save at the next key-off (fold.py reads the byte), or not -
    a.label("ask")
    e(_d(34, 0, 13, _r13(ARG1)), _d(38, 0, 13, _r13(overlay.SAVE_ARMED)))
    e(_d(14, 0, 0, STATUS_OK), a.b("finish"))

    # ---- 04 state: the block is the answer, read it with stock 23 --------
    a.label("stateop")
    e(_d(14, 0, 0, STATUS_OK), a.b("finish"))

    # ---- 05 save: fold the open tables into the calibration (fold.py) ----
    # The save runs from the internal flash and ends in a reset; it comes
    # back here only when it did not start: r12 = 0 nothing differs, 1 the
    # engine is turning, 2 the tune is too far from golden for RAM. The
    # stock handler saves LR at its entry (mflr at +4), so LR must be
    # untouched when we fall through -- the return address goes in CTR.
    a.label("commit")
    ret = a.here() + 16                                        # &commit_ret (4 insns ahead)
    e(_lis(12, ret >> 16), _d(24, 12, 12, ret & 0xFFFF), _mtctr(12))
    e(_branch(a.here(), SAVE_ENTRY))                           # b into the save (CTR=return)
    a.label("commit_ret")
    e(_cmpwi(12, 0), a.bc(BEQ, "commit_ok"))
    e(_d(14, 0, 12, STATUS_TURNING - 1), a.b("finish"))        # 1, 2 -> the two refusals
    a.label("commit_ok")
    e(_d(14, 0, 0, STATUS_OK), a.b("finish"))

    # ---- 06 shelf: program blank flash (fold.py, in the internal flash: the
    # chip cannot be read while it takes a word). Entered like the save.
    a.label("shelf")
    e(a.lis_lbl(12, "shelf_ret"), a.ori_lbl(12, "shelf_ret"), _mtctr(12))
    e(_branch(a.here(), SHELF_ENTRY))
    a.label("shelf_ret")
    e(_cmpwi(12, fold.SHELF_OK), a.bc(BEQ, "shelf_ok"))
    e(_d(14, 0, 12, STATUS_FLASH - fold.SHELF_FLASH), _cmpwi(12, fold.SHELF_RANGE), a.bc(BNE, "finish"))
    e(_d(14, 0, 0, STATUS_RANGE), a.b("finish"))
    a.label("shelf_ok")
    e(_d(14, 0, 0, STATUS_OK), a.b("finish"))

    # ---- 07 place: a slot's descriptor, its mirror where the tester says ---
    # r3 slot, r4 count, r5 the range's base, r6 its length, r7 its end as a
    # calibration offset, r8 the mirror, r11 the descriptor.
    f = fold
    a.label("place")
    e(_d(37, 1, 1, -0x30))                                     # stwu r1, -0x30(r1)
    for i, r in enumerate(range(3, 11)):
        e(f._stw(r, 8 + 4 * i, 1))
    e(f._lbz(3, _r13(ARG1), 13), f._lwz(4, _r13(STATE) + S_COUNT, 13))
    e(f._li(0, STATUS_SLOT), f._cmplw(3, 4), a.bc(BGT, "place_out"))
    e(f._li(0, STATUS_FULL), f._cmplwi(3, overlay.SLOTS), a.bc(BGE, "place_out"))
    e(f._lbz(5, _r13(P_OFF), 13), f._slwi(5, 5, 16), f._lhz(0, _r13(P_OFF) + 1, 13), f._or(5, 5, 0))
    e(f._lhz(6, _r13(P_LEN), 13))
    e(f._li(0, STATUS_RANGE), f._cmpwi(6, 0), a.bc(BEQ, "place_out"))
    e(f._add(7, 5, 6), f._lis(12, dme.CAL_LENGTH >> 16), f._ori(12, 12, dme.CAL_LENGTH & 0xFFFF))
    e(f._cmplw(7, 12), a.bc(BGT, "place_out"))
    e(f._lbz(8, _r13(P_MIRROR), 13), f._slwi(8, 8, 16), f._lhz(0, _r13(P_MIRROR) + 1, 13), f._or(8, 8, 0))
    e(f._add(9, 8, 6))                                         # r9 = the mirror's end
    e(f._li(0, STATUS_ROOM))
    for lo, hi in overlay.POOLS + (overlay.SINGLES_POOL,):     # inside one RAM pool?
        e(f._addi(12, 13, _r13(lo)), f._cmplw(8, 12), a.bc(BLT, f"not{lo:X}"))
        e(f._addi(12, 13, _r13(hi)), f._cmplw(9, 12), a.bc(BLE, "place_ram"))
        a.label(f"not{lo:X}")
    lo, hi = overlay.SHELF                                     # or on the shelf?
    e(f._lis(12, lo >> 16), f._ori(12, 12, lo & 0xFFFF), f._cmplw(8, 12), a.bc(BLT, "place_out"))
    e(f._lis(12, hi >> 16), f._ori(12, 12, hi & 0xFFFF), f._cmplw(9, 12), a.bc(BGT, "place_out"))
    e(f._addis(8, 8, dme.CAL_BASE >> 16), f._li(10, 0), a.b("place_have"))
    a.label("place_ram")
    e(f._li(10, 1))
    a.label("place_have")
    e(f._addis(5, 5, dme.CAL_BASE >> 16))                      # r5 = the base address
    e(_d(7, 11, 3, 12), f._addi(11, 11, desc + 4), f._add(11, 11, 13))   # r11 = &desc[slot]
    # a mirror in RAM is seeded from where the range reads now: the slot's
    # present mirror when it already serves this range, else the calibration
    e(f._cmpwi(10, 0), a.bc(BEQ, "place_seeded"), f._mr(9, 5))
    e(f._cmplw(3, 4), a.bc(BGE, "place_seed"))
    e(f._lwz(0, 0, 11), f._cmplw(0, 5), a.bc(BNE, "place_seed"))
    e(f._lwz(0, 8, 11), f._add(9, 5, 0), f._cmplw(9, 8), a.bc(BEQ, "place_seeded"))
    a.label("place_seed")
    e(_mtctr(6), f._mr(12, 8))
    a.label("place_copy")
    e(f._lbz(0, 0, 9), _d(38, 0, 12, 0), f._addi(9, 9, 1), f._addi(12, 12, 1), a.bc((16, 0), "place_copy"))
    a.label("place_seeded")
    e(f._stw(8, _r13(STATE) + S_MIRROR, 13))
    e(f._stw(5, 0, 11), f._add(0, 5, 6), f._stw(0, 4, 11))     # base, end
    e(_x(0, 5, 8, 40), f._stw(0, 8, 11))                       # delta = mirror - base
    # the range's blocks in the bitmap
    e(f._addis(9, 5, -(dme.CAL_BASE >> 16) & 0xFFFF), f._srwi(9, 9, overlay.BLOCK_SHIFT),
      f._addi(7, 7, -1), f._srwi(7, 7, overlay.BLOCK_SHIFT), f._li(6, 1))
    a.label("place_bit")
    e(f._srwi(12, 9, 3), f._add(12, 12, 13), f._lbz(0, _r13(overlay.BITMAP), 12),
      f._rlwinm(10, 9, 0, 29, 31), _x(6, 10, 10, 24), f._or(0, 0, 10),
      _d(38, 0, 12, _r13(overlay.BITMAP)),
      f._addi(9, 9, 1), f._cmplw(9, 7), a.bc(BLE, "place_bit"))
    e(f._cmplw(3, 4), a.bc(BNE, "place_counted"))               # a new slot: the null base
    e(f._li(0, 0), f._stw(0, 12, 11), f._addi(4, 4, 1),        # after it, and the count
      f._stw(4, _r13(STATE) + S_COUNT, 13))
    a.label("place_counted")
    e(f._lis(0, overlay.MAGIC >> 16), f._stw(0, desc, 13))
    e(f._li(0, STATUS_OK))
    a.label("place_out")
    for i, r in enumerate(range(3, 11)):
        e(f._lwz(r, 8 + 4 * i, 1))
    e(f._addi(1, 1, 0x30))

    a.label("finish")
    e(_d(36, 0, 13, _r13(STATE) + S_STATUS))
    a.label("stock")                        # every path out restores interrupts first
    e(_d(32, 12, 13, _r13(STATE) + S_MSR), 0x7D800124, 0x4C00012C)
    e(STOCK_FIRST, _branch(a.here() + 4, HANDLER + 4))
    return a.bytes()


def is_patched(pair):
    t = _btarget(HANDLER, struct.unpack_from(">I", pair.flash, HFILE)[0])
    return t is not None and 0xFFF00000 + CODE <= t < 0xFFF00000 + CODE_END


def build(pair, code=CODE):
    """The pair with the 2C handler hooked and our stub in blank ext space,
    re-signed. Composes after overlay.build (which owns the MPC tail)."""
    mpc, flash = bytearray(pair.mpc), bytearray(pair.flash)
    w = struct.unpack_from(">I", flash, HFILE)[0]
    if w != STOCK_FIRST and not is_patched(pair):
        raise ValueError(f"the 2C handler's entry word is not the stock stwu: 0x{w:08X}")
    if is_patched(pair):
        flash[code:CODE_END] = b"\xff" * (CODE_END - code)      # our own stub, rebuilt
    if flash[code:CODE_END].strip(b"\xff"):
        raise ValueError(f"the ext space from 0x{code:X} is not blank")
    stub = _stub(0xFFF00000 + code)
    if code + len(stub) > CODE_END:
        raise ValueError("the transport stub does not fit")
    flash[code:code + len(stub)] = stub
    struct.pack_into(">I", flash, HFILE, _branch(HANDLER, 0xFFF00000 + code))
    fix_program(flash, mpc)
    return Pair(bytes(flash), bytes(mpc), pair.name + "+livetrans")


# ---- the tester side: our requests, state read back with stock 23 ---------

def _op(t, request):
    r = t.request(request)
    if r != ACK:
        raise ValueError(f"the op was not acked: {None if r is None else r.hex()}")
    return read_state(t)


def read_state(t):
    """The block: status, open count, protocol version, last mirror."""
    magic, status, count, version, _, _, _, mirror = struct.unpack(">8I", t.read_memory(STATE, 8 * 4))
    if magic != STATE_MAGIC:
        raise ValueError("the state block is not initialised (no 0x6C op has run)")
    return {"status": status, "count": count, "version": version, "mirror": mirror}


def descriptors(t):
    """The open tables, as the DME holds them: [(cal offset, length, mirror
    address)], one per slot."""
    count = _op(t, [0x2C, LOCAL_ID, 0x04])["count"]         # op 04 first: a fresh DME has no block
    raw = b"".join(t.read_memory(overlay.DESC + 4 + at, min(120, 12 * count - at))
                   for at in range(0, 12 * count, 120))
    return [(base - dme.CAL_BASE, end - base, (base + delta) & 0xFFFFFFFF)
            for base, end, delta in struct.iter_unpack(">3I", raw)]


def place(t, slot, cal_offset, length, mirror):
    """Op 07: `slot` serves the range from `mirror` -- a RAM address in a
    pool, or a calibration offset on the shelf. The status."""
    return _op(t, [0x2C, LOCAL_ID, 0x07, slot,
                   (cal_offset >> 16) & 0xFF, (cal_offset >> 8) & 0xFF, cal_offset & 0xFF,
                   length >> 8, length & 0xFF,
                   (mirror >> 16) & 0xFF, (mirror >> 8) & 0xFF, mirror & 0xFF])["status"]


def open_table(t, cal_offset, length):
    """Mirror a calibration range in RAM, in the next slot: (slot, mirror
    address), or None when it does not fit (status says why)."""
    assert 0 <= cal_offset <= 0xFFFFFF and 0 <= length <= 0xFFFF
    open_ = descriptors(t)
    ram = [(m, n) for _, n, m in open_ if m < dme.CAL_BASE]
    mirror = overlay.free_ram(ram, length)
    if mirror is None:
        if any(length <= hi - lo for lo, hi in overlay.POOLS):
            return None                         # it would fit an empty pool: park something
        mirror = overlay.POOLS[0][0]            # too big for any: let the DME say so
    return None if place(t, len(open_), cal_offset, length, mirror) else (len(open_), mirror)


def write_cell(t, slot, offset, data):
    """Edit bytes at `offset` inside slot `slot`'s mirror. True on success."""
    assert 1 <= len(data) <= 0xFF and 0 <= offset <= 0xFFFF
    return not _op(t, [0x2C, LOCAL_ID, 0x02, slot,
                       offset >> 8, offset & 0xFF, len(data), *data])["status"]


def program(t, cal_offset, data):
    """Op 06: program blank flash on the shelf, a few words a request. The
    status of the first request that failed, or STATUS_OK."""
    assert not cal_offset & 1
    data = bytes(data) + b"\xff" * (len(data) & 1)
    for at in range(0, len(data), fold.SHELF_MAX):
        chunk = data[at:at + fold.SHELF_MAX]
        to = cal_offset + at
        status = _op(t, [0x2C, LOCAL_ID, 0x06, (to >> 16) & 0xFF, (to >> 8) & 0xFF, to & 0xFF,
                         len(chunk), *chunk])["status"]
        if status:
            return status
    return STATUS_OK


def park(t, slot, shelf_offset):
    """Move slot `slot`'s mirror from RAM to blank flash at `shelf_offset`,
    freeing its RAM. The status."""
    cal_offset, length, mirror = descriptors(t)[slot]
    data = b"".join(t.read_memory(mirror + at, min(120, length - at)) for at in range(0, length, 120))
    return program(t, shelf_offset, data) or place(t, slot, cal_offset, length, shelf_offset)


def ask_save(t, on=True):
    """Op 08: have the DME fold the open tables into the calibration when
    the ignition is switched off (or, with on=False, not after all)."""
    return _op(t, [0x2C, LOCAL_ID, 0x08, overlay.SAVE_ASKED if on else 0])["status"]


def close_all(t):
    """overlay.remove(), from the K line; returns the fresh state."""
    return _op(t, [0x2C, LOCAL_ID, 0x03])


def ping(t):
    """Initialise the block / check the service is alive."""
    return _op(t, [0x2C, LOCAL_ID, 0x04])


def save(t):
    """Fold the open tables into the calibration (op 05). The DME answers
    only when it has not saved: False when nothing differs from the
    calibration, ValueError when it refused (engine turning, or the tune too
    far from golden). When it saves it goes silent and resets into the new
    calibration; returns True then -- read the cells back to confirm."""
    r = t.request([0x2C, LOCAL_ID, 0x05], retries=1)
    if r is None:
        return True
    if r != ACK:
        raise ValueError(f"the save was not acked: {r.hex()}")
    status = read_state(t)["status"]
    if status == STATUS_TURNING:
        raise ValueError("the engine is turning: the save needs it stopped")
    if status == STATUS_BIG:
        raise ValueError("the tune is further from the golden calibration than a save can hold")
    return False
