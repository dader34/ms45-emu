"""The overlay redirects the lookup routines' table pointers into SRAM
mirrors; the old generation's redirect is preserved; a mirrored table's
reads relocate."""
import os
import struct

import pytest

from ms45emu import Machine, dme, overlay
from ms45emu.image import IMAGES_DIR, Pair

CURVE = 0x4395                    # the 16-entry byte curve the lookup tests use


def _pair():
    # MS45_LIVETUNE_BASE=session1clean runs all of this on the stock program
    # (tools/livetune_build.py --stock --base-prefix) instead of the car's own
    base = os.environ.get("MS45_LIVETUNE_BASE", "session1")
    with open(os.path.join(IMAGES_DIR, f"{base}.flash.bin"), "rb") as f, \
         open(os.path.join(IMAGES_DIR, f"{base}.mpc.bin"), "rb") as m:
        return Pair(f.read(), m.read(), base)


@pytest.fixture(scope="module")
def built():
    return overlay.build(_pair())


@pytest.fixture
def m(built):
    return Machine(built)


def _read(m, index, at=CURVE):
    m.set_sda8(-0x283A, index)
    return m.call(dme.TABLE_READ_8, dme.CAL_BASE + at) & 0xFF


def _stock_byte(pair, cal_offset):
    return pair.flash[0x40000 + cal_offset]


def test_build_is_idempotent(built):
    assert overlay.is_patched(built)
    again = overlay.build(built)
    assert overlay.is_patched(again)
    assert again.mpc == built.mpc


def test_without_descriptors_reads_stock(m, built):
    for i in (0, 5, 15):
        assert _read(m, i) == _stock_byte(built, CURVE + i)


def test_mirrored_read(built):
    m = Machine(built)
    ((_, length, mirror),) = overlay.install(m, [(CURVE, 16)])
    assert length == 16
    m.write8(mirror + 7, _stock_byte(built, CURVE + 7) ^ 0x55)
    assert _read(m, 7) == (_stock_byte(built, CURVE + 7) ^ 0x55)
    for i in (0, 6, 8, 15):               # the rest of the table still mirrors stock
        assert _read(m, i) == _stock_byte(built, CURVE + i)
    overlay.remove(m)
    assert _read(m, 7) == _stock_byte(built, CURVE + 7)


def test_ranges_are_exclusive(m, built):
    ((_, _, mirror),) = overlay.install(m, [(CURVE, 16)])
    m.write8(mirror, 0x00)
    assert _read(m, 0, CURVE - 1) == _stock_byte(built, CURVE - 1)
    assert _read(m, 0, CURVE + 16) == _stock_byte(built, CURVE + 16)


def test_old_generation_redirect_still_works(m, built):
    # r2+2, the one pointer the old generation moves by +0xA0000 when flag
    # bit 0 is set: map 1's word at cal 0x7FF2, map 2's at 0xA7FF2.
    dme.select(m, 0)
    m.write8(dme.RAM_FLAG, m.read8(dme.RAM_FLAG) & ~0x01)
    assert _read(m, 0, 0x7FF2) == built.flash[0x47FF2]
    m.write8(dme.RAM_FLAG, m.read8(dme.RAM_FLAG) | 0x01)
    if not overlay.carries_old(built):
        # the stock program: no map switch, so that byte of RAM moves nothing
        assert _read(m, 0, 0x7FF2) == built.flash[0x47FF2]
        return
    assert _read(m, 0, 0x7FF2) == built.flash[0xE7FF2]
