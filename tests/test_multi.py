"""Three maps, the DSC button as the trigger: the gesture cycles 1-2-3-1 and
never reaches a map the build does not have, the tach and the lamp count the
map, and every map's values are its own."""
from ms45emu import dme

CALLS_PER_SECOND = 100
LOCKOUT_SECONDS = 10


class Button:
    def __init__(self, m, n=0):
        m.clear_ram()
        m.call(dme.nv_routines(m)[0])
        self.g = dme.Gesture(m)
        self.n = n
        self.state = False
        self.idle(LOCKOUT_SECONDS + 1)

    def idle(self, seconds):
        for _ in range(round(seconds * CALLS_PER_SECOND)):
            self.g.tick(n=self.n, rpm_in=self.n, dsc=self.state)
        return self.g.map

    def press(self, times):
        # the gesture counts changes of the button's state; the build wants four
        for _ in range(times):
            self.state = not self.state
            self.g.tick(n=self.n, rpm_in=self.n, dsc=self.state)
        return self.g.map


def test_the_button_cycles_through_the_three_maps_and_back(three):
    b = Button(three)
    assert b.g.map == 0
    assert b.press(3) == 0, "three changes are not the gesture"
    assert b.press(1) == 1
    assert b.g.save_requested
    assert b.g.tick(dsc=b.state) == 2000                     # engine stopped: the tach shows the map
    b.idle(3)
    assert b.press(4) == 2
    assert b.g.tick(dsc=b.state) == 3000
    b.idle(3)
    assert b.press(4) == 0, "after the last map comes map 1, never a fourth"
    assert b.g.tick(dsc=b.state) == 1000
    b.idle(3)
    assert b.press(4) == 1


def test_presses_spread_over_more_than_two_seconds_do_not_count(three):
    b = Button(three)
    b.press(2)
    b.idle(2.5)
    assert b.press(2) == 0
    assert b.press(2) == 1                                   # these four were within the window


def test_running_engine_blinks_the_lamp_map_number_times(three):
    b = Button(three, n=2500)
    assert b.press(4) == 1
    assert three.read8(dme.RAM_BLINKS) == 2
    b.idle(3)
    assert b.press(4) == 2
    assert three.read8(dme.RAM_BLINKS) == 3
    b.idle(3)
    assert b.press(4) == 0
    assert three.read8(dme.RAM_BLINKS) == 1


def test_each_map_has_its_own_single_values(three):
    # 0x5EBC is a 16-bit value the program reads through r2; the bench maps differ there.
    init, restore, save = dme.nv_routines(three)
    maps = [three.pair.flash[0x40000:0x5D000], dme.stored_map(three, 1), dme.stored_map(three, 2)]
    assert len({bytes(m[0x5EBC:0x5EBE]) for m in maps}) == 3
    for index in range(3):
        three.clear_ram()
        three.write8(0x3F0100, index << dme.NV_INDEX_SHIFT)
        three.call(restore, 0x3F0100)
        assert dme.selected(three) == index
        r2 = three.reg(2)
        assert r2 == dme.map_r2(three, index)
        assert three.read16(r2 - 0x2134) == int.from_bytes(maps[index][0x5EBC:0x5EBE], "big")


def test_the_gesture_moves_r2_with_the_map(three):
    b = Button(three)
    assert three.reg(2) == dme.map_r2(three, 0)
    b.press(4)
    assert three.reg(2) == dme.map_r2(three, 1)
    b.idle(3)
    b.press(4)
    assert three.reg(2) == dme.map_r2(three, 2)
    b.idle(3)
    b.press(4)
    assert three.reg(2) == dme.map_r2(three, 0)


def test_the_stored_byte_round_trips_every_map(three):
    init, restore, save = dme.nv_routines(three)
    for index in range(3):
        three.clear_ram()
        dme.select(three, index)
        three.set_sda8(dme.NV_VAR, 1)
        three.call(save, 0x3F0100)
        stored = three.read8(0x3F0100)
        assert stored == (index << dme.NV_INDEX_SHIFT) | 1
        three.clear_ram()
        three.write8(0x3F0100, stored)
        three.call(restore, 0x3F0100)
        assert dme.selected(three) == index
        assert three.sda8(dme.NV_VAR) == 1


def test_every_block_of_every_map_reads_back_whole(three):
    # The stored blocks, through the tables, give back the tunes they were stored from.
    import os
    for index, name in ((1, "bench_map2.bin"), (2, "bench_map3.bin")):
        path = os.path.join(os.path.dirname(__file__), "..", "images", name)
        if not os.path.exists(path):
            continue
        want = open(path, "rb").read()
        got = dme.stored_map(three, index)
        assert all(got[i] == want[i] for i in range(len(want)) if not 0x57DC <= i < 0x57E4)


# ---- seven maps: the most the selection bits allow, with the r2 windows nested ---------
def _bench_map(n):
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "images", f"bench_map{n}.bin")
    return open(path, "rb").read() if os.path.exists(path) else None


def test_seven_maps_each_have_their_own_single_values(seven):
    init, restore, save = dme.nv_routines(seven)
    maps = [seven.pair.flash[0x40000:0x5D000]] + [dme.stored_map(seven, i) for i in range(1, 7)]
    assert len({bytes(m[0x5EBC:0x5EBE]) for m in maps}) == 7
    r2s = set()
    for index in range(7):
        seven.clear_ram()
        seven.write8(0x3F0100, index << dme.NV_INDEX_SHIFT)
        seven.call(restore, 0x3F0100)
        assert dme.selected(seven) == index
        r2 = seven.reg(2)
        assert r2 == dme.map_r2(seven, index)
        r2s.add(r2)
        assert seven.read16(r2 - 0x2134) == int.from_bytes(maps[index][0x5EBC:0x5EBE], "big")
    assert len(r2s) == 7
    # the windows nest, a map's r2 blocks in the gaps of another's: six of
    # them span 96 KB here (the bench maps carry a block more each), not 150
    bases = sorted(dme.map_r2(seven, i) for i in range(1, 7))
    assert [(b - bases[0]) // 1024 for b in bases] == [0, 7, 32, 39, 64, 71]


def test_seven_maps_read_back_whole(seven):
    for index in range(1, 7):
        want = _bench_map(index + 1)
        if want is None:
            continue
        got = dme.stored_map(seven, index)
        assert all(got[i] == want[i] for i in range(len(want)) if not 0x57DC <= i < 0x57E4), f"map {index + 1}"


def test_seven_maps_read_their_own_curve_and_block(seven):
    # the curve at 0x4395 and each map's own block, through the hooked lookup library
    def read(at, index):
        seven.set_sda8(-0x283A, index)
        return seven.call(dme.TABLE_READ_8, dme.CAL_BASE + at) & 0xFF
    for index in range(7):
        seven.clear_ram()
        dme.select(seven, index)
        own = dme.stored_map(seven, index) if index else seven.pair.flash[0x40000:0x5D000]
        for i in range(16):
            assert read(0x4395, i) == own[0x4395 + i], f"map {index + 1}'s curve"
        n = index + 1
        for at in (0x10C40, 0x3000, 0xB000, 0x5400, 0xD400):      # the blocks maps 3-7 change
            for i in (0, 17, 63):
                assert read(at, i) == own[at + i], f"map {n} at 0x{at + i:X}"


def test_the_button_cycles_through_all_seven_maps_and_back(seven):
    b = Button(seven)
    assert b.g.map == 0
    for expect in (1, 2, 3, 4, 5, 6, 0, 1):
        assert b.press(4) == expect
        assert b.g.tick(dsc=b.state) == 1000 * (expect + 1)
        b.idle(3)
