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


# ---- the same sums over a pair's files, for building patched images ---------
PROGRAM_CRC_OFFSETS = (0x60000, 0x60340)
PROGRAM_CRC_RANGE = (0x60608, 0xFFF40)
ROMTEST_SUM_OFFSET, ROMTEST_RANGES_OFFSET = 0x60600, 0x60608
SIGNATURE_OFFSET = 0x60074
SIGNATURE_SEGMENTS, SIGNATURE_LENGTHS = 0x60030, 0x6004C

# The key the program is signed with, as BMWeb-Flasher's Checksums_Signatures has it.
PROGRAM_RSA_N = 8470472580328006956677424405159809178175955696534718361218518906571634405286747173565502454089691240931470915432212928785673566143706092135925769557255439
PROGRAM_RSA_D = 7260405068852577391437792347279836438436533454172615738187301919918543775959908116508429649500721130520546364846625732843778800986047617824899475327781303


def _image_bytes(flash, mpc, start, length):
    """`length` bytes at a CPU address: the internal flash below 0x70000, the external at 0xFFF00000."""
    if start < EXT:
        return bytes(mpc[start:start + length])
    return bytes(flash[start - EXT:start - EXT + length])


def image_program_crc(flash, mpc):
    return crc32_mpeg2(flash[PROGRAM_CRC_RANGE[0]:PROGRAM_CRC_RANGE[1]], crc32_mpeg2(mpc))


def image_romtest_sum(flash, mpc):
    total = 0x0123456789ABCDEF
    for i in range(3):
        start, end = struct.unpack_from(">II", flash, ROMTEST_RANGES_OFFSET + 8 * i)
        for (w,) in struct.iter_unpack(">I", _image_bytes(flash, mpc, start, end - start)):
            total = (total + w) & 0xFFFFFFFFFFFFFFFF
    return total


def program_signature(flash, mpc):
    """The 64 bytes at 0x60074: RSA over the MD5 of the segments the
    program header lists, each 32-bit word byte-swapped."""
    import hashlib
    count = struct.unpack_from(">I", flash, SIGNATURE_SEGMENTS)[0]
    md5 = hashlib.md5()
    for i in range(count):
        start = struct.unpack_from(">I", flash, SIGNATURE_SEGMENTS + 4 + 8 * i)[0]
        length = struct.unpack_from(">I", flash, SIGNATURE_LENGTHS + 4 * i)[0]
        md5.update(_image_bytes(flash, mpc, start, length))
    m = int.from_bytes(md5.digest() + b"\x00", "little")
    le = pow(m, PROGRAM_RSA_D, PROGRAM_RSA_N).to_bytes(64, "little")
    return b"".join(le[4 * i:4 * i + 4][::-1] for i in range(16))


def fix_program(flash, mpc):
    """Bring a changed program's safety-monitor sum, checksums and
    signature up to date, in that order: each covers the one before.
    `flash` is a bytearray and is changed in place."""
    struct.pack_into(">Q", flash, ROMTEST_SUM_OFFSET, image_romtest_sum(flash, mpc))
    crc = image_program_crc(flash, mpc)
    for at in PROGRAM_CRC_OFFSETS:
        struct.pack_into(">I", flash, at, crc)
    flash[SIGNATURE_OFFSET:SIGNATURE_OFFSET + 64] = program_signature(flash, mpc)
