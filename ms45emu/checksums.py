"""The program's own integrity checks, recomputed over the image as loaded
in the emulator (which has had its EIE/EID sites patched).

- Program CRC: CRC-32/MPEG-2 over MPC 0x00000-0x6FFFF then external flash
  0x60608-0xFFF3F, stored at flash 0x60000 and 0x60340.
- Safety monitor code sum ("ROM test level 2"): 64-bit sum of big-endian
  words over the ranges listed at flash 0x60608, seed 0x0123456789ABCDEF,
  stored at flash 0x60600.
"""
import struct

_TBL = []
for _i in range(256):
    _c = _i << 24
    for _ in range(8):
        _c = ((_c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if _c & 0x80000000 else (_c << 1) & 0xFFFFFFFF
    _TBL.append(_c)


def crc32_mpeg2(data, crc=0xFFFFFFFF):
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _TBL[(crc >> 24) ^ b]
    return crc


EXT = 0xFFF00000
ROMTEST_SUM = EXT + 0x60600
ROMTEST_RANGES = EXT + 0x60608
PROGRAM_CRC = (EXT + 0x60000, EXT + 0x60340)


def program_crc(m):
    mpc = m.read(0, 0x70000)
    prog = m.read(EXT + 0x60608, 0xFFF40 - 0x60608)
    return crc32_mpeg2(prog, crc32_mpeg2(mpc))


def romtest_sum(m):
    total = 0x0123456789ABCDEF
    for i in range(3):
        start = m.read32(ROMTEST_RANGES + 8 * i)
        end = m.read32(ROMTEST_RANGES + 8 * i + 4)
        data = m.read(start, end - start)
        for (w,) in struct.iter_unpack(">I", data):
            total = (total + w) & 0xFFFFFFFFFFFFFFFF
    return total


def refresh_program_sums(m):
    """Store sums matching the loaded image, in both flash mirrors."""
    crc = program_crc(m)
    total = romtest_sum(m)
    for mirror in (0, -0x100000):
        for a in PROGRAM_CRC:
            m.write32(a + mirror, crc)
        m.write(ROMTEST_SUM + mirror, struct.pack(">Q", total))
