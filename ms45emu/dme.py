"""Addresses and helpers for program 0044570LO02S.

Everything here was traced from the disassembly; see the map-switch trace
notes for the derivations. Addresses are CPU addresses.
"""
import struct

from .machine import R13, R2

# ---- safety monitor's "ROM test level 2" -----------------------------------
ROMTEST_ACCUMULATE = 0xFFF77688          # (start, word count, acc_ptr) -> adds words to a 64-bit acc
ROMTEST_SUM_ADDR = 0xFFF60600            # stored expected sum, 64 bit
ROMTEST_RANGES_ADDR = 0xFFF60608         # 3 x (start, end) for the code sum
ROMTEST_SEED = 0x0123456789ABCDEF

# ---- table lookup library (MPC) --------------------------------------------
LOOKUP_ENTRIES = [0xCFC8, 0xD054, 0xD0E4, 0xD178, 0xD210, 0xD264, 0xD2C0, 0xD31C,
                  0xD380, 0xD38C, 0xD39C, 0xD3B8, 0xD3DC, 0xD44C, 0xD4C0, 0xD660]
AXIS_SEARCH_8 = 0xCFC8                   # (axis_ptr, x) -> index/fraction in RAM
TABLE_READ_8 = 0xD380                    # (table_ptr) -> byte at saved index
INTERP_8 = 0xD3DC                        # (table_ptr) -> interpolated byte

# ---- RAM used by the gesture / tach stub (r13 offsets) ----------------------
VAR_N = -0x4BEC          # engine speed, 16 bit
VAR_VS = -0x3F95         # vehicle speed, 8 bit
VAR_PV = -0x4061         # pedal, 8 bit (0.39 %/count)
VAR_BRK_A = -0x4001
VAR_BRK_B = -0x4002
TACH_VAR = -0x3B28       # rpm * 6.4 for CAN 0x316
NV_VAR = -0x3FD1         # stored-data block 56 variable
NV_SAVE_REQ = -0x2CC8 + 56

RAM_FLAG = 0x3FA195      # the map index (0 = map 1) in bits 4-6; builds before generation 4 kept map 2 in bit 0
FLAG_INDEX_SHIFT = 4
FLAG_INDEX_MASK = 0x70
NV_INDEX_SHIFT = 5       # where the index sits in the stored-data byte (the stock value there is 0-2)
VAR_DSC_STATE = -0x3B44  # the DSC button, bit 0x02, as the gesture watches it
DSC_STATE_MASK = 0x02
RAM_HOLD = 0x3FA196
RAM_DISP8 = 0x3FA1ED
RAM_DISP16 = 0x3FA1EE
RAM_BLINKS = 0x3FA1C9    # lamp blinks still to show: the map chosen while the engine runs

CAN_EGS1_STORE = 0x3FDCFC                # the last 0x43F, byte-reversed

CAN_ASC1_STORE = 0x3FDCAC                # where the CAN layer keeps the last 0x153, byte-reversed

TACH_STORE_ADDR = 0x4B6C4                # sth r3,-0x3B28(r13) in the 0x316 builder, hooked by the patch
NV_DESCRIPTOR = 0x28AC + 56 * 0x1C       # init, restore, save pointers

CAL_BASE = 0xFFE40000
CAL_LENGTH = 0x1D000
MAP2_DELTA = 0xA0000                     # builds before generation 4: map 2 was a full copy at 0xE0000
# Generation 4 keeps the extra maps as 1 KB blocks: a header at flash 0xDCC00
# (magic, map count, one r2 word per map at +0x10) and a 256-byte block
# table per map index after it, each entry the flash offset >> 10 of the
# stored block or 0xFFFF for "map 1's".
MAPS_HEADER = 0xFFFDCC00
R2_BLOCKS = (0, 1, 2, 3, 4, 5, 6, 0x12, 0x15, 0x16, 0x17)   # the calibration blocks the program reads through r2
FLASH_CRC_RETURN = 0xFFFDA030        # LR while the background CRC-32 (0xFFFD9E04) walks the external flash
MAPS_HEADER_COUNT = 0x08
MAPS_HEADER_R2 = 0x10
MAPS_TABLE_STRIDE = 0x100
MAPS_BLOCK = 0x400
MAPS_NO_BLOCK = 0xFFFF

# ---- crank-synchronous values (written by the segment task) -----------------
VAR_SEGMENT = -0x4071        # which of the six segments, 8 bit
VAR_SEGMENT_TIME = -0x4BE8   # the last segment's duration, 16 bit, 4 us per count: N = 5,000,000 / it
KL15_FLAG = 0x3FD853

# ---- diagnostics -------------------------------------------------------------
# The KWP core is boot-sector code that the program shares. The timing it
# works to is in RAM, in ms, set by the access-timing service (0x83).
KWP_P2MIN = -0x7DBC          # how long the DME waits before it answers
KWP_P3MIN = -0x7DBB          # how long after its answer a new request is ignored
KWP_FAST_TIMING = (2, 12)    # what `83 03 04 01 18 14 00` leaves there: the limits of the default session

# ---- the program's heap ------------------------------------------------------
# 0x3FF2A0-0x3FF900, handed out at start-up from both ends (allocator
# 0xFFF754EC) and never freed. The program keeps what is left between the
# two pointers in -0x34B2(r13).
HEAP_BOTTOM = -0x7708        # next free address from below, 32 bit
HEAP_TOP = -0x7704           # lowest address taken from above, 32 bit
HEAP_START, HEAP_END = 0x3FF2A0, 0x3FF900

SEGMENT_TASK_LAST_CALL = 0x3235C         # bl 0x32180, the last thing the segment task does
FRAME_TASK_BUILDER_CALL = 0x4BE9C        # bl 0x4B528, the 10 ms task calling the 0x316 builder


def romtest_sum_native(m):
    """The code sum as the DME computes it, by running its own accumulator."""
    acc = 0x3F0000
    m.write32(acc, ROMTEST_SEED >> 32)
    m.write32(acc + 4, ROMTEST_SEED & 0xFFFFFFFF)
    for i in range(3):
        start = m.read32(ROMTEST_RANGES_ADDR + 8 * i)
        end = m.read32(ROMTEST_RANGES_ADDR + 8 * i + 4)
        m.call(ROMTEST_ACCUMULATE, start, (end - start) // 4, acc)
    return struct.unpack(">Q", m.read(acc, 8))[0]


def romtest_sum_stored(m):
    return struct.unpack(">Q", m.read(ROMTEST_SUM_ADDR, 8))[0]


def tach_hook_target(m):
    """Where the patched 0x316 builder branches to, or None when unpatched."""
    w = m.read32(TACH_STORE_ADDR)
    if w >> 26 != 18 or not (w & 1):
        return None
    li = w & 0x03FFFFFC
    if li & 0x02000000:
        li -= 0x04000000
    return (TACH_STORE_ADDR + li) & 0xFFFFFFFF


def nv_routines(m):
    """(init, restore, save) of stored-data block 56."""
    return tuple(m.read32(NV_DESCRIPTOR + 4 * i) for i in range(3))


def selected(m):
    """The map index (0 = map 1) the flag byte selects."""
    return (m.read8(RAM_FLAG) & FLAG_INDEX_MASK) >> FLAG_INDEX_SHIFT


def select(m, index):
    """Point the flag byte at map `index`, keeping its other bits."""
    m.write8(RAM_FLAG, (m.read8(RAM_FLAG) & ~FLAG_INDEX_MASK) | (index << FLAG_INDEX_SHIFT))


def map_count(m):
    """How many maps the header in the flash says are stored, or None."""
    if m.read(MAPS_HEADER, 8) != b"MS45MAPS":
        return None
    return m.read8(MAPS_HEADER + MAPS_HEADER_COUNT)


def map_r2(m, index):
    """The r2 the program is to use with map `index`, from the header."""
    return m.read32(MAPS_HEADER + MAPS_HEADER_R2 + 4 * index)


def cal_address(m, index, offset):
    """Where calibration `offset` of map `index` lives: in its stored block, or in map 1."""
    if index:
        entry = m.read16(MAPS_HEADER + index * MAPS_TABLE_STRIDE + 2 * (offset >> 10))
        if entry != MAPS_NO_BLOCK:
            return 0xFFF00000 + entry * MAPS_BLOCK + (offset & (MAPS_BLOCK - 1))
    return CAL_BASE + offset


def stored_map(m, index):
    """Map `index` as the calibration it was stored from (its safety-monitor sum is map 1's)."""
    cal = bytearray(m.read(CAL_BASE, CAL_LENGTH))
    for b in range(CAL_LENGTH // MAPS_BLOCK):
        at = cal_address(m, index, b * MAPS_BLOCK)
        if at != CAL_BASE + b * MAPS_BLOCK:
            cal[b * MAPS_BLOCK:(b + 1) * MAPS_BLOCK] = m.read(at, MAPS_BLOCK)
    return bytes(cal)


class Gesture:
    """Drives the tach/gesture stub the way the 0x316 builder would, every 10 ms."""

    def __init__(self, m):
        self.m = m
        self.stub = tach_hook_target(m)
        if self.stub is None:
            raise RuntimeError("this pair does not carry the map switch")

    def tick(self, n=0, vs=0, pedal=0, brake=False, rpm_in=0, egs1=None, dsc=None):
        m = self.m
        if egs1 is not None:
            m.write(CAN_EGS1_STORE, egs1[::-1])
        if dsc is not None:
            m.set_sda8(VAR_DSC_STATE, DSC_STATE_MASK if dsc else 0)
        m.set_sda16(VAR_N, n)
        m.set_sda8(VAR_VS, vs)
        m.set_sda8(VAR_PV, pedal)
        m.set_sda8(VAR_BRK_A, 1 if brake else 0)
        m.set_sda8(VAR_BRK_B, 1 if brake else 0)
        m.call(self.stub, int(rpm_in * 6.4))
        return m.sda16(TACH_VAR) / 6.4          # what the cluster will be told

    @property
    def map(self):
        return selected(self.m)

    @property
    def save_requested(self):
        return self.m.sda8(NV_SAVE_REQ) != 0
