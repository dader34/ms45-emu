"""The hooked lookup routines read the selected map's blocks, map 1's where a map stores none."""
import pytest
from ms45emu import dme

COOLANT_CURVE = dme.CAL_BASE + 0x4395      # 16-entry byte curve, differs between the bench maps


def _read_curve(m, index):
    # Point the library's saved index at `index`, then read through the hooked byte reader.
    m.set_sda8(-0x283A, index)
    return m.call(dme.TABLE_READ_8, COOLANT_CURVE) & 0xFF


def test_flag_clear_reads_map1(patched):
    dme.select(patched, 0)
    for i in range(16):
        assert _read_curve(patched, i) == patched.pair.flash[0x40000 + 0x4395 + i]


def test_flag_set_reads_map2(patched):
    dme.select(patched, 1)
    map2 = dme.stored_map(patched, 1)
    assert map2[0x4395] != patched.pair.flash[0x40000 + 0x4395], "the bench maps differ here"
    for i in range(16):
        assert _read_curve(patched, i) == map2[0x4395 + i]


def test_a_block_the_map_does_not_store_reads_map1(patched):
    # Block 0x40 is the same in both bench maps, so the table sends it to map 1.
    dme.select(patched, 1)
    assert dme.cal_address(patched, 1, 0x10000) == dme.CAL_BASE + 0x10000
    assert dme.cal_address(patched, 1, 0x4395) != dme.CAL_BASE + 0x4395
    patched.set_sda8(-0x283A, 0)
    assert patched.call(dme.TABLE_READ_8, dme.CAL_BASE + 0x10000) & 0xFF == patched.pair.flash[0x50000]


def test_three_maps_read_their_own_curve(three):
    for index in range(3):
        dme.select(three, index)
        own = dme.stored_map(three, index) if index else three.pair.flash[0x40000:0x5D000]
        for i in range(16):
            assert _read_curve(three, i) == own[0x4395 + i]


def test_non_calibration_pointers_are_left_alone(patched):
    # A table in the program area is never redirected, flag or not.
    dme.select(patched, 1)
    patched.set_sda8(-0x283A, 0)
    prog_ptr = 0xFFF60630
    assert patched.call(dme.TABLE_READ_8, prog_ptr) & 0xFF == patched.pair.flash[0x60630]


def test_stock_and_patched_agree_on_map1(stock, patched):
    dme.select(patched, 0)
    for i in range(16):
        stock.set_sda8(-0x283A, i)
        assert _read_curve(patched, i) == (stock.call(dme.TABLE_READ_8, COOLANT_CURVE) & 0xFF)


def test_every_hooked_entry_returns(patched):
    # Each hook must fall through to its routine and come back; a wrong
    # branch target would run off into the free area or loop.
    dme.select(patched, 1)
    axis = dme.CAL_BASE + 0x0504        # an 8-bit axis used by the coolant init
    for entry in dme.LOOKUP_ENTRIES:
        patched.set_sda8(-0x283A, 1)
        patched.set_sda8(-0x283B, 1)
        patched.set_sda8(-0x283C, 2)
        patched.set_sda16(-0x2840, 0)
        patched.set_sda16(-0x283E, 0)
        patched.call(entry, axis, 0x40, max_insns=100_000)


def test_pointers_formed_from_r2_follow_the_selected_map(three):
    """Nearly a thousand lookups get their table pointer as r2 + d. With a
    map other than map 1 selected r2 is that map's window, so such a pointer
    is an offset into the window: a stored block reads from its copy, one
    the map does not store from map 1, never from whatever shares the
    window's gaps."""
    for index in range(3):
        three.clear_ram()
        dme.select(three, index)
        three.set_reg(2, dme.map_r2(three, index))
        own = dme.stored_map(three, index) if index else three.pair.flash[0x40000:0x5D000]
        r2 = three.reg(2)
        for at in (0x4395, 0x5EBC, 0x10C40, 0x10000, 0x8A52, 0x1C02, 0x6000):   # stored, r2 blocks, and not stored
            three.set_sda8(-0x283A, 0)
            got = three.call(dme.TABLE_READ_8, r2 + at - 0x7FF0) & 0xFF
            assert got == own[at], f"map {index + 1} at 0x{at:X} through r2"
            got = three.call(dme.TABLE_READ_8, dme.CAL_BASE + at) & 0xFF
            assert got == own[at], f"map {index + 1} at 0x{at:X} by address"
    # the stored maps differ where this is checked, so the reads told the maps apart
    maps = [three.pair.flash[0x40000:0x5D000]] + [dme.stored_map(three, i) for i in (1, 2)]
    assert len({m[0x4395] for m in maps}) == 3 and len({bytes(m[0x5EBC:0x5EBE]) for m in maps}) == 3


def test_the_upper_half_and_the_maf_tables_read_map_1(three):
    """Accesses to calibration offsets 0x8000 and up went through r2 + 0x10000
    (addis rX, r2, 1), which with r2 on a map's window lands 32 KB above it;
    the build turns each into lis rX, 0xFFE5, map 1's. Likewise the two
    readers of the MAF / secondary air tables, which took a copy of r2."""
    import struct
    mpc, flash = three.pair.mpc, three.pair.flash
    left = [o for lo, hi, img in ((0, 0x6E550, mpc), (0x60608, 0xDCC00, flash))
            for o in range(lo, hi, 4) if struct.unpack_from(">I", img, o)[0] & 0xFC1FFFFF == 0x3C020001]
    assert left == [], f"{len(left)} addis rX, r2, 1 left"
    assert three.read32(0x4F3A4) == 0x3D40FFE5                    # was addis r10, r2, 1: a power-management read
    assert three.read32(0xFFFB92C8) == 0x3D60FFE5                 # was addis r11, r2, 1, in the external flash
    assert three.read32(0x10F6C) == 0x3D40FFE4                    # id_maf_tab's reader
    assert three.read32(0x11030) == 0x3D60FFE4                    # id_saf_tab's reader
    assert three.read32(0xFFFB9258) == 0x3D220000                 # addis r9, r2, 0 for a block-5 value: left, the window has it
