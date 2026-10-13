"""The save (ms45emu/fold.py): the open live-tune tables are folded into the
calibration sector itself -- golden copy plus the difference held in RAM
across the erase -- so a reset boots the edited tune, and the next save
starts from it. Runs with the flash model's busy part on: a fetch or a stray
read from the chip while it programs or erases fails the test."""
import os
import struct

import pytest
from unicorn.ppc_const import UC_PPC_REG_CTR, UC_PPC_REG_MSR

from ms45emu import dme, fold, overlay, transport
from ms45emu.board import Board, BOOT_IDLE
from ms45emu.checksums import crc32_mpeg2
from ms45emu.image import IMAGES_DIR, Pair
from ms45emu.kwp import Tester

CURVE, OTHER = 0x4395, 0x4495         # two byte curves, the first at an odd address
SCHEDULER_TASK, INIT_DONE = 0x3B38C, 0x3FEB26
CAL = fold.CAL_FILE


def _pair():
    # MS45_LIVETUNE_BASE=session1clean runs all of this on the stock program
    # (tools/livetune_build.py --stock --base-prefix) instead of the car's own
    base = os.environ.get("MS45_LIVETUNE_BASE", "session1")
    with open(os.path.join(IMAGES_DIR, f"{base}.flash.bin"), "rb") as f, \
         open(os.path.join(IMAGES_DIR, f"{base}.mpc.bin"), "rb") as m:
        return Pair(f.read(), m.read(), base)


@pytest.fixture(scope="module")
def built():
    return fold.build(transport.build(overlay.build(_pair())))


def _booted(pair):
    b = Board(pair)
    b.boot(max_insns=int(0.3 * b.ips))
    return b


def _enter(b, slices=600):
    """Enter the save as its callers do, return address in CTR (a `b .` here),
    and run until it comes back or ends. Returns where it stopped."""
    b.flash.strict()
    b.m.mu.reg_write(UC_PPC_REG_CTR, BOOT_IDLE)
    pc = fold.ENTRY
    for _ in range(slices):
        b.m.mu.emu_start(pc, fold.DONE, count=1_000_000)
        pc = b.m.pc
        if pc in (fold.DONE, fold.FAILED, BOOT_IDLE):
            break
    return pc


def _edit(b, at, xor):
    """Open a 16-byte curve and edit it in its mirror; the edited bytes."""
    opened = [(base - dme.CAL_BASE, end - base)
              for base, end, _ in struct.iter_unpack(">3I", b.m.read(overlay.DESC + 4, 12 * overlay.SLOTS))
              if base] if b.m.read32(overlay.DESC) == overlay.MAGIC else []
    placed = overlay.install(b.m, opened + [(at, 16)])
    mirror = placed[-1][2]
    edited = bytes(v ^ xor for v in b.m.read(dme.CAL_BASE + at, 16))
    b.m.write(mirror, edited)
    return edited


def _expected(flash, edits):
    """The image a save must leave: the edits in the calibration, its CRC."""
    out = bytearray(flash)
    for at, data in edits:
        out[CAL + at:CAL + at + len(data)] = data
    out[CAL + fold.MON_AT:CAL + fold.MON_AT + 8] = fold.monitor_sum(out[CAL:CAL + fold.SECTOR])
    struct.pack_into(">I", out, CAL + fold.CRC_AT,
                     crc32_mpeg2(bytes(out[CAL + fold.CRC_FROM:CAL + fold.CRC_TO])))
    return bytes(out)


def _reset(b):
    """The reset the save ends in: the loader decides whether the program runs."""
    b2 = b.reset()
    b2.probe(SCHEDULER_TASK, "scheduler")
    b2.boot(max_insns=40_000_000, reset_vector=True)
    assert b2.m.read8(INIT_DONE) == 1 and b2.probe_counts["scheduler"] > 10, "the program did not start"
    return b2


def _lookup(b, index, at=CURVE):
    b.m.set_sda8(-0x283A, index)
    return b.m.call(dme.TABLE_READ_8, dme.CAL_BASE + at) & 0xFF


def test_the_monitor_sum_is_the_cars(built):
    # the value the car's own calibration stores: the arithmetic is the DME's
    assert fold.monitor_sum(_pair().flash[CAL:CAL + fold.SECTOR]).hex() == "012345e50c25a259"


def test_build(built):
    assert fold.is_patched(built) and overlay.is_patched(built) and transport.is_patched(built)
    assert fold.golden(built) == built.flash[CAL:CAL + fold.LENGTH]
    assert fold.tune_runs(built) == (0, 2)
    again = fold.build(built)
    assert (again.flash, again.mpc) == (built.flash, built.mpc)
    # everything that drives the chip is in the internal flash
    assert fold.CODE <= fold.ENTRY < fold.DONE < fold.FAILED < fold.CODE_END


def test_returns_untouched_when_nothing_differs(built):
    b = _booted(built)
    regs = list(range(0x1000, 0x1008))
    for i, v in enumerate(regs):
        b.m.set_reg(3 + i, v)
    msr = b.m.mu.reg_read(UC_PPC_REG_MSR) | 0x8000
    b.m.mu.reg_write(UC_PPC_REG_MSR, msr)
    sp = b.m.reg(1)
    assert _enter(b) == BOOT_IDLE and b.m.reg(12) == fold.STATUS_NOTHING     # nothing open
    assert [b.m.reg(3 + i) for i in range(8)] == regs and b.m.reg(1) == sp
    assert b.m.mu.reg_read(UC_PPC_REG_MSR) == msr                            # EE back on
    overlay.install(b.m, [(CURVE, 16)])
    assert _enter(b) == BOOT_IDLE and b.m.reg(12) == fold.STATUS_NOTHING     # open, unedited
    assert b.flash.erases == 0 and b.flash.programs == 0


def test_refuses_with_the_engine_turning(built):
    b = _booted(built)
    _edit(b, CURVE, 0x55)
    b.m.set_sda16(dme.VAR_N, 900)
    assert _enter(b) == BOOT_IDLE and b.m.reg(12) == fold.STATUS_TURNING
    assert b.flash.erases == 0


def test_refuses_a_tune_too_far_from_golden(built):
    b = _booted(built)
    far = bytes(v ^ 0xFF for v in fold.golden(built))             # every word differs
    b.flash.store(fold.GOLD_FILE, far)
    below_stack = b.m.reg(1) - 0x100 - fold.RUNS                  # the check's own frame is on it
    ram = b.m.read(fold.RUNS, below_stack)
    _edit(b, CURVE, 0x55)
    assert _enter(b) == BOOT_IDLE and b.m.reg(12) == fold.STATUS_BIG
    assert b.flash.erases == 0
    assert b.m.read(fold.RUNS, below_stack) == ram                # RAM not given over


@pytest.fixture(scope="module")
def saved(built):
    """One save, then a second one on the DME the first reset into."""
    b = _booted(built)
    first = _edit(b, CURVE, 0x55)
    services = b.watchdog_services
    assert _enter(b) == fold.DONE
    assert b.watchdog_services - services > 1000
    one = bytes(b.flash.image)

    b2 = _reset(b)
    reads = [_lookup(b2, i) for i in (0, 7, 15)]
    second = _edit(b2, OTHER, 0xAA)
    assert _enter(b2) == fold.DONE
    return {"first": first, "second": second, "one": one, "reads": reads,
            "two": bytes(b2.flash.image), "boards": (b, b2)}


def test_save_rewrites_the_calibration(built, saved):
    b, _ = saved["boards"]
    assert b.flash.violations == []                      # nothing fetched or read from the busy chip
    assert b.flash.erases == 1
    assert saved["one"] == _expected(built.flash, [(CURVE, saved["first"])])
    assert b.program_valid()


def test_reset_boots_the_saved_tune(saved):
    # the loader started the program, and the lookup reads the edit from
    # the calibration itself: no descriptors, no mirror
    assert saved["reads"] == [saved["first"][i] for i in (0, 7, 15)]


def test_second_save_keeps_the_first(built, saved):
    _, b2 = saved["boards"]
    assert b2.flash.violations == []
    assert saved["two"] == _expected(built.flash, [(CURVE, saved["first"]), (OTHER, saved["second"])])
    assert fold.golden(Pair(saved["two"], built.mpc, "two")) == fold.golden(built)   # never rewritten
    words, size = fold.tune_runs(saved["two"])
    assert words == 9 + 9 + 2 and size <= fold.RUNS_END - fold.RUNS                  # two odd-aligned curves and the CRC


def test_save_over_the_k_line(built):
    """Op 05: refused with the engine turning, a plain ack when nothing
    differs, and silence -- then the new calibration -- when it saves."""
    b = _booted(built)
    t = Tester(b)
    assert transport.save(t) is False                    # nothing open
    slot, _ = transport.open_table(t, CURVE, 16)
    edited = bytes(v ^ 0x55 for v in b.m.read(dme.CAL_BASE + CURVE, 16))
    assert transport.write_cell(t, slot, 0, list(edited))
    b.m.set_sda16(dme.VAR_N, 900)
    with pytest.raises(ValueError, match="turning"):
        transport.save(t)
    assert transport.read_state(t)["status"] == transport.STATUS_TURNING
    b.m.set_sda16(dme.VAR_N, 0)

    b.flash.strict()
    assert transport.save(t) is True                     # no answer: it is saving
    for _ in range(200):
        if b.m.pc == fold.DONE:
            break
        b.run(b.ips // 100)
    assert b.m.pc == fold.DONE and b.flash.violations == []
    assert bytes(b.flash.image) == _expected(built.flash, [(CURVE, edited)])
    # stock 23 reads RAM, not the calibration: read the saved cells back
    # the way the tuner does, through a freshly seeded mirror
    t2 = Tester(_reset(b))
    _, mirror = transport.open_table(t2, CURVE, 16)
    assert t2.read_memory(mirror, 16) == edited
    assert transport.save(t2) is False                   # and nothing is left to save


def test_save_folds_in_a_shelved_table(built):
    """A table parked in blank flash is part of the tune like one in RAM: the
    save reads it before the erase takes the shelf, and the shelf comes back
    blank."""
    b = _booted(built)
    t = Tester(b)
    b.flash.strict()
    shelf = overlay.SHELF[0]
    slot, _ = transport.open_table(t, CURVE, 16)
    parked = bytes(v ^ 0x55 for v in b.m.read(dme.CAL_BASE + CURVE, 16))
    assert transport.write_cell(t, slot, 0, list(parked))
    assert transport.park(t, slot, shelf) == transport.STATUS_OK
    slot, _ = transport.open_table(t, OTHER, 16)
    in_ram = bytes(v ^ 0xAA for v in b.m.read(dme.CAL_BASE + OTHER, 16))
    assert transport.write_cell(t, slot, 0, list(in_ram))
    assert bytes(b.flash.image[CAL + shelf:CAL + shelf + 16]) == parked

    assert transport.save(t) is True
    for _ in range(200):
        if b.m.pc == fold.DONE:
            break
        b.run(b.ips // 100)
    assert b.m.pc == fold.DONE and b.flash.violations == []
    assert bytes(b.flash.image) == _expected(built.flash, [(CURVE, parked), (OTHER, in_ram)])
    b2 = _reset(b)
    assert [_lookup(b2, i) for i in (0, 15)] == [parked[0], parked[15]]


MONITOR_FAULT = (-0x3C2D, -0x3C13)     # the two bytes the safety monitor's error routine sets


def _monitor_verdict(b, seconds):
    """Run the program and say whether its safety monitor objected to the
    calibration sum: (objected, seconds it took or ran)."""
    for i in range(int(seconds * 10)):
        b.run(b.ips // 10)
        if any(b.m.read8(fold.R13 + at) for at in MONITOR_FAULT):
            return True, (i + 1) / 10
    return False, seconds


def test_save_keeps_the_safety_monitors_sum(built):
    """An edit saved inside the range the safety monitor sums takes the
    stored sum with it, and the monitor of the DME it resets into is content.
    With the old sum left in place the same monitor objects -- which is what
    shows the first result means something."""
    assert fold.monitor_sum(built.flash[CAL:CAL + fold.SECTOR]) == built.flash[CAL + fold.MON_AT:CAL + fold.MON_AT + 8]
    at = fold.MON_FROM + 0x40
    b = _booted(built)
    t = Tester(b)
    slot, _ = transport.open_table(t, at, 16)
    edited = bytes(v ^ 0x5A for v in b.m.read(dme.CAL_BASE + at, 16))
    assert transport.write_cell(t, slot, 0, list(edited))
    b.flash.strict()
    assert transport.save(t) is True
    for _ in range(300):
        if b.m.pc == fold.DONE:
            break
        b.run(b.ips // 100)
    assert b.m.pc == fold.DONE and b.flash.violations == []
    want = _expected(built.flash, [(at, edited)])
    assert want[CAL + fold.MON_AT:CAL + fold.MON_AT + 8] != built.flash[CAL + fold.MON_AT:CAL + fold.MON_AT + 8]
    assert bytes(b.flash.image) == want

    # the control: the same edit with the sum as it was
    stale = bytearray(want)
    stale[CAL + fold.MON_AT:CAL + fold.MON_AT + 8] = built.flash[CAL + fold.MON_AT:CAL + fold.MON_AT + 8]
    struct.pack_into(">I", stale, CAL + fold.CRC_AT,
                     crc32_mpeg2(bytes(stale[CAL + fold.CRC_FROM:CAL + fold.CRC_TO])))
    control = Board(Pair(bytes(stale), built.mpc, "stale", check_program=False))
    control.boot(max_insns=40_000_000, reset_vector=True)
    objected, took = _monitor_verdict(control, 20)
    assert objected, "the monitor never looked: this test would prove nothing"
    window = 3 * took + 1
    assert _monitor_verdict(_reset(b), window) == (False, window)
    # and the untouched build is silent over the same window, so the error
    # routine is not something another check reaches anyway
    assert _monitor_verdict(_booted(built), window) == (False, window)


def test_a_sum_halfword_of_all_ones_is_left_erased(built):
    """The save does not program 0xFFFF (erased flash already reads it). An
    edit chosen so the sum's last halfword is 0xFFFF still saves exactly."""
    at = fold.MON_FROM + 0x80
    cal = built.flash[CAL:CAL + fold.SECTOR]
    low = int.from_bytes(fold.monitor_sum(cal)[6:], "big")
    word = (int.from_bytes(cal[at:at + 4], "big") + ((0xFFFF - low) & 0xFFFF)) & 0xFFFFFFFF
    edited = word.to_bytes(4, "big")
    assert edited != cal[at:at + 4]
    b = _booted(built)
    t = Tester(b)
    slot, _ = transport.open_table(t, at, 4)
    assert transport.write_cell(t, slot, 0, list(edited))
    b.flash.strict()
    assert transport.save(t) is True
    for _ in range(300):
        if b.m.pc == fold.DONE:
            break
        b.run(b.ips // 100)
    assert b.m.pc == fold.DONE and b.flash.violations == []
    want = _expected(built.flash, [(at, edited)])
    assert want[CAL + fold.MON_AT + 6:CAL + fold.MON_AT + 8] == b"\xff\xff"
    assert bytes(b.flash.image) == want
    assert _monitor_verdict(_reset(b), 4) == (False, 4)


@pytest.mark.skipif(not os.environ.get("MS45_SLOW"), reason="minutes; set MS45_SLOW=1")
def test_key_off_saves_without_a_tester(built):
    """Edits still open at key-off are folded in by the DME itself, at the
    end of its after-run, before it lets go of the main relay."""
    b = _booted(built)
    t = Tester(b)
    slot, _ = transport.open_table(t, CURVE, 16)
    edited = bytes(v ^ 0x55 for v in b.m.read(dme.CAL_BASE + CURVE, 16))
    assert transport.write_cell(t, slot, 0, list(edited))
    assert transport.ask_save(t) == transport.STATUS_OK
    assert transport.read_state(t)["count"] == 1         # asking closes nothing
    b.flash.strict()
    b.ignition(False)
    for _ in range(6000):                                # up to a minute of after-run
        b.run(b.ips // 100)
        if b.m.pc in (fold.DONE, fold.FAILED) or b.powered_down:
            break
    assert b.m.pc == fold.DONE and b.flash.violations == []
    assert bytes(b.flash.image) == _expected(built.flash, [(CURVE, edited)])


@pytest.mark.skipif(not os.environ.get("MS45_SLOW"), reason="minutes; set MS45_SLOW=1")
@pytest.mark.parametrize("taken_back", [False, True])
def test_key_off_keeps_nothing_unless_asked(built, taken_back):
    """A tune being tried out goes with the power: no save was asked for
    (or it was, and taken back), so the calibration is not touched."""
    b = _booted(built)
    t = Tester(b)
    slot, _ = transport.open_table(t, CURVE, 16)
    edited = bytes(v ^ 0x55 for v in b.m.read(dme.CAL_BASE + CURVE, 16))
    assert transport.write_cell(t, slot, 0, list(edited))
    if taken_back:
        assert transport.ask_save(t) == transport.STATUS_OK
        assert transport.ask_save(t, False) == transport.STATUS_OK
    before = bytes(b.flash.image)
    b.flash.strict()
    b.ignition(False)
    for _ in range(6000):
        b.run(b.ips // 100)
        if b.m.pc in (fold.DONE, fold.FAILED) or b.powered_down:
            break
    assert b.powered_down and b.flash.erases == 0 and b.flash.programs == 0
    assert bytes(b.flash.image) == before


@pytest.mark.skipif(not os.environ.get("MS45_SLOW"), reason="minutes; set MS45_SLOW=1")
def test_key_off_without_edits_powers_down(built):
    b = _booted(built)
    b.ignition(False)
    for _ in range(6000):
        b.run(b.ips // 100)
        if b.powered_down:
            break
    assert b.powered_down and b.flash.erases == 0
