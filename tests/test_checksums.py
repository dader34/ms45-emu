"""The boot block's CRC ("ROM test level 1", ms45emu/checksums.py): the
stock image carries it right, and a ring built into the boot region
carries it recomputed -- the stale word was the car's reset loop of
2026-10-28."""
import struct

from ms45emu.checksums import (BOOT_CRC_OFFSET, BOOT_CRC_RANGE_OFFSET, EXT, fix_boot,
                               image_boot_crc)
from tools.build import bl


def _stored(flash):
    return struct.unpack_from(">I", flash, BOOT_CRC_OFFSET)[0]


def test_stock_boot_crc_matches_stored(stock):
    start, end = struct.unpack_from(">II", stock.pair.flash, BOOT_CRC_RANGE_OFFSET)
    assert (start, end) == (EXT, EXT + 0x1EFFF)          # vectors, loader, boot sector to the table
    assert image_boot_crc(stock.pair.flash) == _stored(stock.pair.flash)


def test_a_ring_in_the_boot_region_changes_the_crc(stock):
    f = bytearray(stock.pair.flash)
    f[0x17000:0x17004] = b"\x48\x00\x00\x00"              # one word where the ring's window goes
    assert image_boot_crc(f) != _stored(f)
    fix_boot(f)
    assert image_boot_crc(f) == _stored(f)


def test_bl_build_refreshes_the_boot_crc(stock):
    f, _ = bl.build(stock.pair.flash, stock.pair.mpc)
    assert _stored(f) != _stored(stock.pair.flash)             # the ring is inside the range
    assert image_boot_crc(f) == _stored(f)
    installer, _ = bl.build(stock.pair.flash, stock.pair.mpc, installer=True)
    assert image_boot_crc(installer) == _stored(installer)
