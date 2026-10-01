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

RAM_FLAG = 0x3FA195
RAM_HOLD = 0x3FA196
RAM_DISP8 = 0x3FA1ED
RAM_DISP16 = 0x3FA1EE

TACH_STORE_ADDR = 0x4B6C4                # sth r3,-0x3B28(r13) in the 0x316 builder, hooked by the patch
NV_DESCRIPTOR = 0x28AC + 56 * 0x1C       # init, restore, save pointers

CAL_BASE = 0xFFE40000
MAP2_DELTA = 0xA0000


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


class Gesture:
    """Drives the tach/gesture stub the way the 0x316 builder would, every 10 ms."""

    def __init__(self, m):
        self.m = m
        self.stub = tach_hook_target(m)
        if self.stub is None:
            raise RuntimeError("this pair does not carry the map switch")

    def tick(self, n=0, vs=0, pedal=0, brake=False, rpm_in=0):
        m = self.m
        m.set_sda16(VAR_N, n)
        m.set_sda8(VAR_VS, vs)
        m.set_sda8(VAR_PV, pedal)
        m.set_sda8(VAR_BRK_A, 1 if brake else 0)
        m.set_sda8(VAR_BRK_B, 1 if brake else 0)
        m.call(self.stub, int(rpm_in * 6.4))
        return m.sda16(TACH_VAR) / 6.4          # what the cluster will be told

    @property
    def map(self):
        return self.m.read8(RAM_FLAG) & 1

    @property
    def save_requested(self):
        return self.m.sda8(NV_SAVE_REQ) != 0
