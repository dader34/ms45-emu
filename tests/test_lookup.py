"""The hooked lookup routines read map 1 or map 2 according to the flag."""
import pytest
from ms45emu import dme

COOLANT_CURVE = dme.CAL_BASE + 0x4395      # 16-entry byte curve, differs between the bench maps


def _read_curve(m, index):
    # Point the library's saved index at `index`, then read through the hooked byte reader.
    m.set_sda8(-0x283A, index)
    return m.call(dme.TABLE_READ_8, COOLANT_CURVE) & 0xFF


def test_flag_clear_reads_map1(patched):
    patched.write8(dme.RAM_FLAG, 0)
    for i in range(16):
        assert _read_curve(patched, i) == patched.pair.flash[0x40000 + 0x4395 + i]


def test_flag_set_reads_map2(patched):
    patched.write8(dme.RAM_FLAG, 1)
    for i in range(16):
        assert _read_curve(patched, i) == patched.pair.flash[0xE0000 + 0x4395 + i]


def test_non_calibration_pointers_are_left_alone(patched):
    # A table in the program area is never redirected, flag or not.
    patched.write8(dme.RAM_FLAG, 1)
    patched.set_sda8(-0x283A, 0)
    prog_ptr = 0xFFF60630
    assert patched.call(dme.TABLE_READ_8, prog_ptr) & 0xFF == patched.pair.flash[0x60630]


def test_stock_and_patched_agree_on_map1(stock, patched):
    patched.write8(dme.RAM_FLAG, 0)
    for i in range(16):
        stock.set_sda8(-0x283A, i)
        assert _read_curve(patched, i) == (stock.call(dme.TABLE_READ_8, COOLANT_CURVE) & 0xFF)


def test_every_hooked_entry_returns(patched):
    # Each hook must fall through to its routine and come back; a wrong
    # branch target would run off into the free area or loop.
    patched.write8(dme.RAM_FLAG, 1)
    axis = dme.CAL_BASE + 0x0504        # an 8-bit axis used by the coolant init
    for entry in dme.LOOKUP_ENTRIES:
        patched.set_sda8(-0x283A, 1)
        patched.set_sda8(-0x283B, 1)
        patched.set_sda8(-0x283C, 2)
        patched.set_sda16(-0x2840, 0)
        patched.set_sda16(-0x283E, 0)
        patched.call(entry, axis, 0x40, max_insns=100_000)
