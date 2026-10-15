"""The live-tune transport (docs/livetune-design.md, milestone 3): our own
KWP service riding the stock 2C define-packet handler.

The stock handler (entry 0xFFF6FC60, ext file 0x6FC60 — traced 2026-10-11)
accepts only local id 0xF0; anything else it answers `7F 2C 12` and stores
nothing. `build` replaces its first instruction (`stwu r1, -0x20(r1)`) with
a branch to a stub in blank ext space: the stub sees local id 0x6C, runs one
of seven ops against the overlay's descriptor table and mirror pools, and
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
and re-placed there, which frees its RAM for the next table. Thirty-six
tables (overlay.SLOTS) can be open; the shelf holds 12 KB between two saves.

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
from .image import Pair
from .ppc import (BEQ, BNE, BLT, BGT, BGE, BLE, BDNZ, BCTR, RFI, ISYNC, R13, Asm, _branch, _btarget,
                  _d, _x, _li, _lis, _ori, _addi, _addis, _lwz, _lhz, _lbz, _stw, _cmpwi, _cmplwi,
                  _cmplw, _add, _or, _mr, _mflr, _mtlr, _mtctr, _mfctr, _mfcr, _mtcr, _mfspr, _mtspr,
                  _rlwinm, _slwi, _srwi, _ba)

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
W_BASE, W_END, W_DELTA = 0x24, 0x28, 0x2C   # the watched slot's descriptor, as armed (op 09)
S_SIZE = 0x30                      # (0x10-0x18 are the exception handlers' scratch words)
VERSION = 6                        # 2: ops 06 and 07, no op 01 (version 1 kept a pool
                                   # cursor, a RAM address, in this word). 3: the
                                   # descriptors moved and grew, single values are
                                   # live (singles.py). 4: the key-off saves only
                                   # when asked (op 08). 5: a save keeps the safety
                                   # monitor's sum in step (fold.MON_AT). 6: op 09
                                   # watches one slot with the data breakpoint

# ---- the watch (op 09): any single value live, one at a time -------------
# The MPC555's L-bus comparators E and F (SPR 152/153) bracket the watched
# slot's calibration range and the first L-bus watchpoint, made a breakpoint
# (LCTRL2 SLW0EN), takes vector 0x1C00 after each read of it: the load has
# executed, SRR0 is the next instruction and BAR (SPR 159) holds the address.
# The handler below reads the slot's mirror instead and puts that in the
# load's rD, so a value no pool holds is live without a trap at every site
# (the trap tier reset the car; singles.py). Masked mode (BRKNOMSK clear)
# ignores the breakpoint while MSR[RI] is 0, so the kernel's unrecoverable
# windows are left alone. The main program never touches SPR 144-159.
CMPE, CMPF, LCTRL1, LCTRL2, BAR = 152, 153, 156, 157, 159
SRR0, SRR1, SPRG0, SPRG1, SPRG2 = 26, 27, 272, 273, 274
LCTRL1_RANGE = (0b110 << 29) | (0b101 << 26) | (0b10 << 18) | (0b10 << 16)   # E greater, F less, reads
LCTRL2_ARM = 0x80000000 | 0x08000000 | 0x02000000 | 0x2       # LW0EN, LW0LA=E&F, LW0LADC, SLW0EN
BP_VECTOR = 0xE0                   # the data breakpoint's entry in the relocated table
BP_STOCK = 0xFFF71AFC              # where that entry goes on the stock program
S_CR, S_CTR, S_WORD = 0x10, 0x14, 0x18      # the handler's scratch (singles.py shares them)
# The safety monitor's ROM test sums calibration 0x240-0x7C8 by address
# (fold.MON_*) from this routine: a watched value there must still sum as
# flash, so a read from here keeps what it loaded.
MONITOR_READER = (0xFFF77688, 0xFFF776D4)
# the canary (op 0A) may plant anywhere in the variables below the stack, except
# the request buffer and the state block it is running from
CANARY_LOW, CANARY_HIGH = 0x3F9800, 0x3FF900
CANARY_KEEP = ((0x3F9A44, 0x3F9B44), (STATE, STATE + 0x30))

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


def _r13(addr):
    off = addr - R13
    assert -0x8000 <= off < 0x8000, hex(addr)
    return off


def _stub(base, stock_bp=BP_STOCK):
    a = Asm(base)
    e = a.emit
    desc = _r13(overlay.DESC)
    state = _r13(STATE)

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
    e(_stw(0, state + W_BASE, 13), _stw(0, state + W_END, 13))
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
    e(_cmpwi(0, 9), a.bc(BEQ, "watch"))
    e(_cmpwi(0, 10), a.bc(BEQ, "canary"))
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
    e(_d(14, 11, 11, 1), _d(14, 12, 12, 1), a.bc(BDNZ, "wcopy"))
    a.label("w_done")
    e(_d(14, 0, 0, STATUS_OK), a.b("finish"))

    # ---- 03 close all: the overlay's remove() ------------------------------
    a.label("close")
    e(_d(14, 0, 0, 0), _d(36, 0, 13, desc))
    e(_d(36, 0, 13, desc + 4), _d(36, 0, 13, _r13(STATE) + S_COUNT))
    e(_mtspr(LCTRL2, 0), ISYNC, _stw(0, state + W_BASE, 13), _stw(0, state + W_END, 13))   # the watch too
    for at in range(0, overlay.BITMAP_SPACE, 4):
        e(_d(36, 0, 13, _r13(overlay.BITMAP) + at))
    # a mirror placed on a single value's own RAM left its edit there: put
    # the calibration's values back (singles.py, when the build has it)
    e(_lis(11, (0xFFF00000 + singles.TABLE) >> 16), _d(24, 11, 11, singles.TABLE & 0xFFFF),
      _d(32, 0, 11, 0), _lis(12, singles.TABLE_MAGIC >> 16), _d(24, 12, 12, singles.TABLE_MAGIC & 0xFFFF),
      _x(0, 12, 0, 0), a.bc(BNE, "closed"))
    e(_d(37, 1, 1, -0x30))                                     # stwu r1, -0x30(r1)
    for i, r in enumerate(range(5, 11)):
        e(_stw(r, 8 + 4 * i, 1))
    e(_mflr(0), _stw(0, 0x24, 1))
    e(_branch(a.here(), 0xFFF00000 + singles.FILL, link=True))
    e(_lwz(0, 0x24, 1), _mtlr(0))
    for i, r in enumerate(range(5, 11)):
        e(_lwz(r, 8 + 4 * i, 1))
    e(_addi(1, 1, 0x30))
    a.label("closed")
    e(_d(14, 0, 0, STATUS_OK), a.b("finish"))

    # ---- 08 ask: save at the next key-off (fold.py reads the byte), or not -
    a.label("ask")
    e(_d(34, 0, 13, _r13(ARG1)), _d(38, 0, 13, _r13(overlay.SAVE_ARMED)))
    e(_d(14, 0, 0, STATUS_OK), a.b("finish"))

    # ---- 09 watch: slot N's range on the data breakpoint; 0xFF takes it off
    a.label("watch")
    e(_lbz(12, _r13(ARG1), 13), _cmplwi(12, 0xFF), a.bc(BEQ, "unwatch"))
    e(_lwz(0, state + S_COUNT, 13), _cmplw(12, 0), a.bc(BLT, "watch_slot"))
    e(_li(0, STATUS_SLOT), a.b("finish"))
    a.label("watch_slot")
    e(_d(7, 11, 12, 12), _addi(11, 11, desc + 4), _add(11, 11, 13))         # r11 = &desc[slot]
    e(_lwz(12, 0, 11), _lwz(0, 4, 11), _lwz(11, 8, 11))                     # base, end, delta
    e(_stw(12, state + W_BASE, 13), _stw(0, state + W_END, 13), _stw(11, state + W_DELTA, 13))
    e(_addi(12, 12, -1), _mtspr(CMPE, 12), _mtspr(CMPF, 0))                 # base-1 < address < end
    e(_lis(12, LCTRL1_RANGE >> 16), _ori(12, 12, LCTRL1_RANGE & 0xFFFF), _mtspr(LCTRL1, 12))
    e(_lis(12, LCTRL2_ARM >> 16), _ori(12, 12, LCTRL2_ARM & 0xFFFF), _mtspr(LCTRL2, 12), ISYNC)
    e(_li(0, STATUS_OK), a.b("finish"))
    a.label("unwatch")
    e(_li(0, 0), _mtspr(LCTRL2, 0), ISYNC, _stw(0, state + W_BASE, 13), _stw(0, state + W_END, 13))
    e(_li(0, STATUS_OK), a.b("finish"))

    # ---- 0A canary: fill RAM [addr, addr+len) with a byte -- a stretch the
    # survey calls free is planted, driven on, and read back with stock 23:
    # what the DME overwrote was not free (tools/ram_writers.py). ARG1-3 the
    # address, ARG4 the length (1-255), ARG4+1 the byte. Only the variables
    # below the stack, and never our own request buffer or state.
    a.label("canary")
    e(_lbz(12, _r13(ARG1), 13), _slwi(12, 12, 16), _lhz(0, _r13(ARG1) + 1, 13), _or(12, 12, 0))
    e(_lbz(11, _r13(ARG4), 13), _cmpwi(11, 0), a.bc(BEQ, "canary_bad"))
    e(_lis(0, CANARY_LOW >> 16), _ori(0, 0, CANARY_LOW & 0xFFFF), _cmplw(12, 0), a.bc(BLT, "canary_bad"))
    e(_add(0, 12, 11), _lis(11, CANARY_HIGH >> 16), _ori(11, 11, CANARY_HIGH & 0xFFFF),
      _cmplw(0, 11), a.bc(BGT, "canary_bad"))
    for lo, hi in CANARY_KEEP:                                 # ours: refused
        e(_addi(11, 13, _r13(hi)), _cmplw(12, 11), a.bc(BGE, f"canary_not{lo:X}"))
        e(_addi(11, 13, _r13(lo)), _cmplw(0, 11), a.bc(BGT, "canary_bad"))
        a.label(f"canary_not{lo:X}")
    e(_lbz(11, _r13(ARG4), 13), _mtctr(11), _lbz(0, _r13(ARG4) + 1, 13))
    a.label("canary_fill")
    e(_d(38, 0, 12, 0), _addi(12, 12, 1), a.bc(BDNZ, "canary_fill"))
    e(_li(0, STATUS_OK), a.b("finish"))
    a.label("canary_bad")
    e(_li(0, STATUS_RANGE), a.b("finish"))

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
    a.label("place")
    e(_d(37, 1, 1, -0x30))                                     # stwu r1, -0x30(r1)
    for i, r in enumerate(range(3, 11)):
        e(_stw(r, 8 + 4 * i, 1))
    e(_lbz(3, _r13(ARG1), 13), _lwz(4, _r13(STATE) + S_COUNT, 13))
    e(_li(0, STATUS_SLOT), _cmplw(3, 4), a.bc(BGT, "place_out"))
    e(_li(0, STATUS_FULL), _cmplwi(3, overlay.SLOTS), a.bc(BGE, "place_out"))
    e(_lbz(5, _r13(P_OFF), 13), _slwi(5, 5, 16), _lhz(0, _r13(P_OFF) + 1, 13), _or(5, 5, 0))
    e(_lhz(6, _r13(P_LEN), 13))
    e(_li(0, STATUS_RANGE), _cmpwi(6, 0), a.bc(BEQ, "place_out"))
    e(_add(7, 5, 6), _lis(12, dme.CAL_LENGTH >> 16), _ori(12, 12, dme.CAL_LENGTH & 0xFFFF))
    e(_cmplw(7, 12), a.bc(BGT, "place_out"))
    e(_lbz(8, _r13(P_MIRROR), 13), _slwi(8, 8, 16), _lhz(0, _r13(P_MIRROR) + 1, 13), _or(8, 8, 0))
    e(_add(9, 8, 6))                                         # r9 = the mirror's end
    e(_li(0, STATUS_ROOM))
    for lo, hi in overlay.POOLS + (overlay.SINGLES_POOL,):     # inside one RAM pool?
        e(_addi(12, 13, _r13(lo)), _cmplw(8, 12), a.bc(BLT, f"not{lo:X}"))
        e(_addi(12, 13, _r13(hi)), _cmplw(9, 12), a.bc(BLE, "place_ram"))
        a.label(f"not{lo:X}")
    lo, hi = overlay.SHELF                                     # or on the shelf?
    e(_lis(12, lo >> 16), _ori(12, 12, lo & 0xFFFF), _cmplw(8, 12), a.bc(BLT, "place_out"))
    e(_lis(12, hi >> 16), _ori(12, 12, hi & 0xFFFF), _cmplw(9, 12), a.bc(BGT, "place_out"))
    e(_addis(8, 8, dme.CAL_BASE >> 16), _li(10, 0), a.b("place_have"))
    a.label("place_ram")
    e(_li(10, 1))
    a.label("place_have")
    e(_addis(5, 5, dme.CAL_BASE >> 16))                      # r5 = the base address
    e(_d(7, 11, 3, 12), _addi(11, 11, desc + 4), _add(11, 11, 13))   # r11 = &desc[slot]
    # a mirror in RAM is seeded from where the range reads now: the slot's
    # present mirror when it already serves this range, else the calibration
    e(_cmpwi(10, 0), a.bc(BEQ, "place_seeded"), _mr(9, 5))
    e(_cmplw(3, 4), a.bc(BGE, "place_seed"))
    e(_lwz(0, 0, 11), _cmplw(0, 5), a.bc(BNE, "place_seed"))
    e(_lwz(0, 8, 11), _add(9, 5, 0), _cmplw(9, 8), a.bc(BEQ, "place_seeded"))
    a.label("place_seed")
    e(_mtctr(6), _mr(12, 8))
    a.label("place_copy")
    e(_lbz(0, 0, 9), _d(38, 0, 12, 0), _addi(9, 9, 1), _addi(12, 12, 1), a.bc(BDNZ, "place_copy"))
    a.label("place_seeded")
    e(_stw(8, _r13(STATE) + S_MIRROR, 13))
    e(_stw(5, 0, 11), _add(0, 5, 6), _stw(0, 4, 11))     # base, end
    e(_x(0, 5, 8, 40), _stw(0, 8, 11))                       # delta = mirror - base
    # the range's blocks in the bitmap
    e(_addis(9, 5, -(dme.CAL_BASE >> 16) & 0xFFFF), _srwi(9, 9, overlay.BLOCK_SHIFT),
      _addi(7, 7, -1), _srwi(7, 7, overlay.BLOCK_SHIFT), _li(6, 1))
    a.label("place_bit")
    e(_srwi(12, 9, 3), _add(12, 12, 13), _lbz(0, _r13(overlay.BITMAP), 12),
      _rlwinm(10, 9, 0, 29, 31), _x(6, 10, 10, 24), _or(0, 0, 10),
      _d(38, 0, 12, _r13(overlay.BITMAP)),
      _addi(9, 9, 1), _cmplw(9, 7), a.bc(BLE, "place_bit"))
    e(_cmplw(3, 4), a.bc(BNE, "place_counted"))               # a new slot: the null base
    e(_li(0, 0), _stw(0, 12, 11), _addi(4, 4, 1),        # after it, and the count
      _stw(4, _r13(STATE) + S_COUNT, 13))
    a.label("place_counted")
    e(_lis(0, overlay.MAGIC >> 16), _stw(0, desc, 13))
    e(_li(0, STATUS_OK))
    a.label("place_out")
    for i, r in enumerate(range(3, 11)):
        e(_lwz(r, 8 + 4 * i, 1))
    e(_addi(1, 1, 0x30))

    a.label("finish")
    e(_d(36, 0, 13, _r13(STATE) + S_STATUS))
    a.label("stock")                        # every path out restores interrupts first
    e(_d(32, 12, 13, _r13(STATE) + S_MSR), 0x7D800124, 0x4C00012C)
    e(STOCK_FIRST, _branch(a.here() + 4, HANDLER + 4))

    # ---- the data breakpoint (vector 0x1C00): the load at SRR0-4 has read
    # the watched range at BAR; put the mirror's bytes in its rD instead.
    # Like singles.py's trap handler: EE and RI are clear from entry to rfi
    # and nothing here can fault, so SPRG0-2 and the state block's scratch
    # words are ours. An address outside the range is not ours (the stock
    # handler gets it, as it came); a load the decode does not know, or the
    # monitor's ROM test reading, keeps what it loaded.
    a.label("bp")
    e(_mtspr(SPRG0, 11), _mtspr(SPRG1, 12), _mtspr(SPRG2, 0), _mfcr(0), _stw(0, state + S_CR, 13))
    e(_mfspr(12, BAR))
    e(_lwz(11, state + W_BASE, 13), _cmplw(12, 11), a.bc(BLT, "bp_stock"))
    e(_lwz(11, state + W_END, 13), _cmplw(12, 11), a.bc(BGE, "bp_stock"))
    e(_lwz(11, state + W_DELTA, 13), _add(12, 12, 11))                      # r12 = the mirror's byte
    e(_mfctr(0), _stw(0, state + S_CTR, 13))
    e(_mfspr(11, SRR0), _lis(0, MONITOR_READER[0] >> 16), _ori(0, 0, MONITOR_READER[0] & 0xFFFF),
      _cmplw(11, 0), a.bc(BLT, "bp_decode"),
      _lis(0, MONITOR_READER[1] >> 16), _ori(0, 0, MONITOR_READER[1] & 0xFFFF),
      _cmplw(11, 0), a.bc(BLT, "bp_out"))
    a.label("bp_decode")
    e(_lwz(11, -4, 11), _stw(11, state + S_WORD, 13))                       # the load's word
    e(_srwi(0, 11, 26), _cmpwi(0, 31), a.bc(BNE, "bp_dform"))
    e(_rlwinm(0, 11, 31, 22, 31))                                          # X-form: its xo
    for xo, kind in ((23, "word"), (55, "word"), (87, "byte"), (119, "byte"),
                     (279, "half"), (311, "half"), (343, "halfs"), (375, "halfs")):
        e(_cmpwi(0, xo), a.bc(BEQ, "bp_" + kind))
    e(a.b("bp_out"))
    a.label("bp_dform")
    for op, kind in ((32, "word"), (33, "word"), (34, "byte"), (35, "byte"),
                     (40, "half"), (41, "half"), (42, "halfs"), (43, "halfs")):
        e(_cmpwi(0, op), a.bc(BEQ, "bp_" + kind))
    e(a.b("bp_out"))
    a.label("bp_word")
    e(_lwz(0, 0, 12), a.b("bp_into"))
    a.label("bp_byte")
    e(_lbz(0, 0, 12), a.b("bp_into"))
    a.label("bp_half")
    e(_lhz(0, 0, 12), a.b("bp_into"))
    a.label("bp_halfs")
    e(_d(42, 0, 12, 0))                                                    # lha
    a.label("bp_into")
    e(_rlwinm(11, 11, 14, 24, 28),                                         # rD * 8
      a.lis_lbl(12, "bp_table"), a.ori_lbl(12, "bp_table"), _add(11, 11, 12), _mtctr(11), BCTR)
    a.label("bp_table")                                                    # the value into rD
    for r in range(32):
        e({0: _mtspr(SPRG2, 0), 11: _mtspr(SPRG0, 0), 12: _mtspr(SPRG1, 0)}.get(r, _mr(r, 0)),
          a.b("bp_out"))
    a.label("bp_out")
    e(_lwz(0, state + S_CTR, 13), _mtctr(0))
    e(_lwz(0, state + S_CR, 13), _mtcr(0),
      _mfspr(11, SPRG0), _mfspr(12, SPRG1), _mfspr(0, SPRG2), RFI)
    a.label("bp_stock")
    e(_lwz(0, state + S_CR, 13), _mtcr(0),
      _mfspr(11, SPRG0), _mfspr(12, SPRG1), _mfspr(0, SPRG2), _ba(stock_bp))
    return a.bytes(), a.labels


_STUB, _LABELS = _stub(0xFFF00000 + CODE)
STUB_SIZE = len(_STUB)
LABEL_OFFSETS = {name: at - (0xFFF00000 + CODE) for name, at in _LABELS.items()}   # the same at any base


def stub_base(pair):
    """Where the stub starts, from the hooked 2C entry; None when it is not there."""
    t = _btarget(HANDLER, struct.unpack_from(">I", pair.flash, HFILE)[0])
    return t if t is not None and 0xFFF00000 + CODE <= t < 0xFFF00000 + CODE_END else None


def is_patched(pair):
    return stub_base(pair) is not None


def build(pair, code=CODE):
    """The pair with the 2C handler hooked, our stub in blank ext space and
    the data breakpoint's vector on the stub's handler, re-signed. Composes
    after overlay.build (which owns the MPC tail)."""
    mpc, flash = bytearray(pair.mpc), bytearray(pair.flash)
    w = struct.unpack_from(">I", flash, HFILE)[0]
    if w != STOCK_FIRST and not is_patched(pair):
        raise ValueError(f"the 2C handler's entry word is not the stock stwu: 0x{w:08X}")
    vector = struct.unpack_from(">I", mpc, BP_VECTOR)[0]
    if vector >> 26 != 18 or not vector & 2:
        raise ValueError(f"the data breakpoint's table entry is not a `ba`: 0x{vector:08X}")
    stock_bp = vector & 0x03FFFFFC
    stock_bp |= 0xFC000000 if stock_bp & 0x02000000 else 0
    if 0xFFF00000 + CODE <= stock_bp < 0xFFF00000 + CODE_END:
        stock_bp = BP_STOCK                                      # ours already: the stock is known
    if is_patched(pair):
        flash[code:CODE_END] = b"\xff" * (CODE_END - code)      # our own stub, rebuilt
    if flash[code:CODE_END].strip(b"\xff"):
        raise ValueError(f"the ext space from 0x{code:X} is not blank")
    stub, labels = _stub(0xFFF00000 + code, stock_bp)
    if code + len(stub) > CODE_END:
        raise ValueError("the transport stub does not fit")
    flash[code:code + len(stub)] = stub
    struct.pack_into(">I", flash, HFILE, _branch(HANDLER, 0xFFF00000 + code))
    struct.pack_into(">I", mpc, BP_VECTOR, _ba(labels["bp"]))
    fix_program(flash, mpc)
    return Pair(bytes(flash), bytes(mpc), pair.name + "+livetrans")


# ---- the tester side: our requests, state read back with stock 23 ---------

def _op(t, request):
    r = t.request(request)
    if r != ACK:
        raise ValueError(f"the op was not acked: {None if r is None else r.hex()}")
    return read_state(t)


def read_state(t):
    """The block: status, open count, protocol version, last mirror, and the
    watched range (base, end) or None."""
    (magic, status, count, version, _, _, _, mirror,
     _, w_base, w_end, _) = struct.unpack(">12I", t.read_memory(STATE, S_SIZE))
    if magic != STATE_MAGIC:
        raise ValueError("the state block is not initialised (no 0x6C op has run)")
    return {"status": status, "count": count, "version": version, "mirror": mirror,
            "watch": (w_base, w_end) if w_end else None}


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
    st = _op(t, [0x2C, LOCAL_ID, 0x07, slot,
                 (cal_offset >> 16) & 0xFF, (cal_offset >> 8) & 0xFF, cal_offset & 0xFF,
                 length >> 8, length & 0xFF,
                 (mirror >> 16) & 0xFF, (mirror >> 8) & 0xFF, mirror & 0xFF])
    # the breakpoint keeps the mirror it was armed with: a watched slot that
    # moved is armed again
    if not st["status"] and st["watch"] and st["watch"][0] == dme.CAL_BASE + cal_offset:
        watch(t, slot)
    return st["status"]


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


def canary(t, addr, length, byte=0xA5):
    """Op 0A: fill RAM [addr, addr+length) with `byte`. The status."""
    assert 1 <= length <= 0xFF
    return _op(t, [0x2C, LOCAL_ID, 0x0A, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF,
                   length, byte])["status"]


def ask_save(t, on=True):
    """Op 08: have the DME fold the open tables into the calibration when
    the ignition is switched off (or, with on=False, not after all)."""
    return _op(t, [0x2C, LOCAL_ID, 0x08, overlay.SAVE_ASKED if on else 0])["status"]


def watch(t, slot):
    """Op 09: slot `slot`'s range goes on the data breakpoint, so every read
    of it sees the mirror -- one slot at a time, the last asked. The status."""
    return _op(t, [0x2C, LOCAL_ID, 0x09, slot])["status"]


def unwatch(t):
    """Op 09 with 0xFF: the breakpoint off; the slot stays open."""
    return _op(t, [0x2C, LOCAL_ID, 0x09, 0xFF])["status"]


def close_all(t):
    """overlay.remove(), from the K line (and the watch off); returns the fresh state."""
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
