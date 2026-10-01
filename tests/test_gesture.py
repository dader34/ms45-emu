"""The gesture, the tach indication and the stored-data routines, run for real."""
from ms45emu import dme

CALLS_PER_SECOND = 100


def _power_up(m):
    m.clear_ram()
    init, restore, save = dme.nv_routines(m)
    m.call(init)
    return init, restore, save


def test_power_up_indication_then_silence(patched):
    _power_up(patched)
    g = dme.Gesture(patched)
    shown = [g.tick(rpm_in=0) for _ in range(5 * CALLS_PER_SECOND)]
    on = [i for i, v in enumerate(shown) if v > 0]
    assert on, "the map was never shown"
    assert shown[on[0]] in (1000, 2000)
    assert 1.0 <= len(on) / CALLS_PER_SECOND <= 3.5       # the indication length, in seconds
    assert all(v == 0 for v in shown[on[-1] + 1:])          # then the real rpm (0) again


def test_five_second_hold_toggles_the_map_and_requests_a_save(patched):
    _power_up(patched)
    g = dme.Gesture(patched)
    for _ in range(4 * CALLS_PER_SECOND):
        g.tick()                                            # let the power-up indication pass
    assert g.map == 0

    for _ in range(5 * CALLS_PER_SECOND - 1):
        g.tick(pedal=0xFF, brake=True)
    assert g.map == 0, "toggled too early"
    g.tick(pedal=0xFF, brake=True)
    assert g.map == 1
    assert g.save_requested
    assert g.tick(pedal=0xFF, brake=True) == 2000           # the indication starts

    # Holding on does not toggle again; releasing re-arms it.
    for _ in range(6 * CALLS_PER_SECOND):
        g.tick(pedal=0xFF, brake=True)
    assert g.map == 1
    for _ in range(10):
        g.tick(pedal=0)
    for _ in range(5 * CALLS_PER_SECOND):
        g.tick(pedal=0xFF, brake=True)
    assert g.map == 0


def test_gesture_needs_both_pedals_and_a_stopped_engine(patched):
    _power_up(patched)
    g = dme.Gesture(patched)
    for _ in range(4 * CALLS_PER_SECOND):
        g.tick()
    for _ in range(6 * CALLS_PER_SECOND):
        g.tick(pedal=0xFF, brake=False)
    for _ in range(6 * CALLS_PER_SECOND):
        g.tick(pedal=0x80, brake=True)
    for _ in range(6 * CALLS_PER_SECOND):
        g.tick(n=800, pedal=0xFF, brake=True, rpm_in=800)
    assert g.map == 0


def test_running_engine_passes_the_real_rpm_through(patched):
    _power_up(patched)
    g = dme.Gesture(patched)
    assert g.tick(n=3000, rpm_in=3000) == 3000


def test_selection_survives_save_and_restore(patched):
    init, restore, save = _power_up(patched)
    patched.write8(dme.RAM_FLAG, 1)
    patched.set_sda8(dme.NV_VAR, 2)                          # the stock variable keeps its value

    buf = 0x3F0100
    patched.call(save, buf)
    assert patched.read8(buf) == 0x82

    patched.clear_ram()
    patched.write8(buf, 0x82)
    patched.call(restore, buf)
    assert patched.read8(dme.RAM_FLAG) == 1
    assert patched.sda8(dme.NV_VAR) == 2
