"""The program's own integrity checks, recomputed over the image as loaded
in the emulator (which has had its EIE/EID sites patched).

- Boot block CRC ("ROM test level 1", the first phase of the background
  walker fn_FFFD9E68): CRC-32/MPEG-2 over the range the words at flash
  0x1F808 (start) and 0x1F80C (end, inclusive) name -- 0xFFF00000-0xFFF1EFFF,
  the vectors, the loader and the boot sector up to the sector table --
  seeded from 0x1F9F0, stored at flash 0x1F800. Stale, it fails the
  self-check (code 11) and the DME resets itself every walk, ~5 s: the
  car's reset loop of 2026-10-28 was a BL ring in that range with the
  stock word left at 0x1F800.
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
BOOT_CRC = EXT + 0x1F800                  # stored word; start/end words at +8/+0xC, seed at +0x1F0
BOOT_CRC_OFFSET, BOOT_CRC_RANGE_OFFSET, BOOT_CRC_INIT_OFFSET = 0x1F800, 0x1F808, 0x1F9F0


def boot_crc(m):
    """The boot block's CRC over the range its own table names, or None
    when the table is blank (no such check on this loader)."""
    start, end = m.read32(BOOT_CRC + 8), m.read32(BOOT_CRC + 0xC)
    if start == 0xFFFFFFFF:
        return None
    return crc32_mpeg2(m.read(start, end - start + 1), m.read32(BOOT_CRC + 0x1F0))


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
    """Store sums matching the loaded image, in both flash mirrors: the
    program's and the boot block's (the emulator's site patches sit in
    both ranges)."""
    crc = program_crc(m)
    total = romtest_sum(m)
    boot = boot_crc(m)
    for mirror in (0, -0x100000):
        for a in PROGRAM_CRC:
            m.write32(a + mirror, crc)
        m.write(ROMTEST_SUM + mirror, struct.pack(">Q", total))
        if boot is not None:
            m.write32(BOOT_CRC + mirror, boot)


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


def image_boot_crc(flash):
    """The boot block's CRC over the range the image's own table names
    (ext offsets, the CPU's 0xFFF00000 dropped), or None when the table
    is blank."""
    start, end = struct.unpack_from(">II", flash, BOOT_CRC_RANGE_OFFSET)
    if start == 0xFFFFFFFF:
        return None
    init = struct.unpack_from(">I", flash, BOOT_CRC_INIT_OFFSET)[0]
    return crc32_mpeg2(flash[start - EXT:end - EXT + 1], init)


def fix_boot(flash):
    """Bring the boot block's stored CRC up to date with the boot region as
    it is now -- after a ring or any other change below 0x1F000. `flash`
    is a bytearray and is changed in place."""
    crc = image_boot_crc(flash)
    if crc is not None:
        struct.pack_into(">I", flash, BOOT_CRC_OFFSET, crc)


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
