"""Engine protection and the spark-cut rev limiter (ms45emu/protect.py),
built onto the stock pair and run in the emulator, with temperatures forced
through their RAM variables.

Everything is a spark cut now, so what is checked is spark counts, the oil
warning byte, and that the limiter's own stored limit and flags are left
exactly as the stock program sets them (the safety monitor keeps a redundant
copy of the limiter state and resets the DME when the two disagree).

The emulator has no throttle body, so the stock program sits in its limp
home limit of 1312 rpm (c_n_max_mtc_lih) with the limp flag set. Most tests
run a pair with that limit and flag taken out, to see an engine in order.
The cam-less emulator also collapses engine speed to 0 between crank
resyncs above ~4000 rpm (docs/full-boot.md), so low test limits are used
and the few residual sparks above a cut are the N==0 dips.
"""
import os
import struct
from collections import Counter

import pytest

from ms45emu import Machine, checksums, dme, protect
from ms45emu.board import Board, RESET_ENTRY
from ms45emu.image import Pair
from ms45emu.machine import R13

FRAME = 400_000
SECOND = 100 * FRAME
N_MAX = R13 + protect.VAR_N_MAX
LIMITING = 0x3FD782             # the limiter's controller is holding the engine back
FUEL_CUT = 0x3FD783             # fuel cut on every cylinder: N above the limit + c_add_n_max_fcut
C_N_MAX_MTC_LIH = 0x40000 + 0x5B5A
LIMP_FLAG_SET = 0x96754         # external flash: li r12,1 before the limit routine sets its limp home flag
LI_R12_1, LI_R12_0 = 0x39800001, 0x39800000
NO_LIMIT = 0x1FE0
STOCK_LIMIT = 6520              # id_n_max_mt, which the emulated car (no gearbox on its bus) uses
ID_N_MAX_MT = 0x40000 + 0x612E  # the limit by gear, nine words
ID_N_MAX_H_MT = 0x40000 + 0x611C  # and the raised limit the program allows for a while, the same on a stock tune
# Low test values: 2300 rpm is above every temperature limit, 2500 above the low rev limit.
CFG = protect.Config(spark_cut=True, oil_c=70, oil_rpm=2100, cool_c=90, cool_rpm=2150, cold_warm_c=60, cold_rpm=2000)
LOW_LIMIT = 2400                # a rev limit the emulator can run through, for the spark cut


def _in_order(pair, limit=None, limp=False):
    """The pair as it runs on a car in order: without the limp home limit the
    emulated car would otherwise sit in, and without the flag the limit
    routine sets for it (unless `limp`). With its rev limit at `limit` when
    given."""
    flash = bytearray(pair.flash)
    if not limp:
        struct.pack_into(">H", flash, C_N_MAX_MTC_LIH, NO_LIMIT)
        assert struct.unpack_from(">I", flash, LIMP_FLAG_SET)[0] == LI_R12_1
        struct.pack_into(">I", flash, LIMP_FLAG_SET, LI_R12_0)
    if limit is not None:
        for table in (ID_N_MAX_MT, ID_N_MAX_H_MT):
            struct.pack_into(">9H", flash, table, *[limit] * 9)
    checksums.fix_program(flash, pair.mpc)
    return Pair(bytes(flash), pair.mpc, pair.name)


def _running(pair):
    b = Board(pair)
    b.boot(max_insns=20_000_000)
    return b


class Trial:
    """A stretch of running at one engine speed with the temperatures held.
    The program rewrites its temperatures from the sensors about once a
    second, so they are put back every few ms. Sparks and injections are
    counted; the limiter's limit and flags are read at every step and what
    they showed most of the time is what counts; DME resets are counted."""

    STEPS = 40

    def __init__(self, pair, oil_c, cool_c, rpm, seconds=0.4):
        b = _running(pair)
        self.resets = 0

        def reset(board):
            self.resets += 1
        b.probe(RESET_ENTRY, "reset", on_hit=reset)
        oil, cool = oil_c + protect.TEMP_OFFSET, cool_c + protect.TEMP_OFFSET
        b.m.write8(R13 + protect.OIL_WARN, 0)
        b.crank.rpm = rpm
        seen = []

        def run(seconds):
            for _ in range(self.STEPS):
                b.m.write8(R13 + protect.VAR_OIL, oil)
                b.m.write8(R13 + protect.VAR_COOL, cool)
                b.run(int(seconds * SECOND / self.STEPS))
                seen.append((b.m.read16(N_MAX), b.m.read8(LIMITING), b.m.read8(FUEL_CUT)))

        run(0.3)                                    # let everything see the conditions
        seen.clear()
        b.tpu_a.pulses.clear()
        b.tpu_b.pulses.clear()
        run(seconds)
        self.sparks = sum(1 for ch, r, t in b.tpu_a.pulses if r == "ignition")
        self.injections = sum(1 for ch, r, t in b.tpu_b.pulses if r == "injection")
        self.oil_warning = b.m.read8(R13 + protect.OIL_WARN)
        self.limit, self.limiting, self.fuel_cut = Counter(seen).most_common(1)[0][0]


@pytest.fixture
def base(stock):
    return _in_order(stock.pair)


# ---- image ------------------------------------------------------------------
def test_only_the_gates_change(stock):
    pair, layout = protect.build(stock.pair, CFG)
    changed = {i & ~3 for i in range(len(pair.mpc)) if pair.mpc[i] != stock.pair.mpc[i]}
    assert changed == {site for site, _ in protect.SITES}
    allowed = set(range(protect.CODE_START, layout.code_end)) \
        | set(range(0x60000, 0x60004)) | set(range(0x60074, 0x600B4)) | set(range(0x60340, 0x60344))
    assert {i for i in range(len(pair.flash)) if pair.flash[i] != stock.pair.flash[i]} <= allowed
    assert protect.is_patched(pair) and not protect.is_patched(stock.pair)
    # the limiter's own code is never touched: that is what keeps the safety monitor quiet
    assert pair.flash[0x96950:0x96954] == stock.pair.flash[0x96950:0x96954]


def test_sums_and_signature_valid(stock):
    pair, _ = protect.build(stock.pair, CFG)
    m = Machine(pair)
    assert dme.romtest_sum_native(m) == dme.romtest_sum_stored(m)
    crc = checksums.image_program_crc(pair.flash, pair.mpc)
    assert all(struct.unpack_from(">I", pair.flash, a)[0] == crc for a in checksums.PROGRAM_CRC_OFFSETS)
    assert pair.flash[0x60074:0x60074 + 64] == checksums.program_signature(pair.flash, pair.mpc)


def test_remove_restores_stock(stock):
    back = protect.remove(protect.build(stock.pair, CFG)[0])
    assert back.mpc == stock.pair.mpc and back.flash == stock.pair.flash


def test_gates_only_when_something_is_on(stock):
    limits_only, layout = protect.build(stock.pair, CFG, spark_cut=False)
    assert len(layout.gates) == 3 and protect.is_patched(limits_only)        # temperature limits are spark cuts too
    nothing, _ = protect.build(stock.pair, CFG, spark_cut=False, oil_c=None, cool_c=None, cold_warm_c=None)
    assert nothing.flash == stock.pair.flash and nothing.mpc == stock.pair.mpc
    # a rebuild with less replaces the gates whole
    again, _ = protect.build(protect.build(stock.pair, CFG)[0], CFG, spark_cut=False)
    assert again.flash == limits_only.flash and again.mpc == limits_only.mpc


def test_an_earlier_builds_limiter_hook_is_undone(stock):
    """Builds before this one hooked the limiter's store at 0x96950. A pair
    still carrying that hook must get the stock store back, whether it is
    rebuilt or stripped; otherwise the limiter would call into erased flash."""
    flash = bytearray(stock.pair.flash)
    old_stub = protect.EXT + protect.CODE_START + 0x60                 # somewhere in the code area
    struct.pack_into(">I", flash, protect.LIMIT_SITE, protect._branch(protect.EXT + protect.LIMIT_SITE, old_stub, link=1))
    flash[protect.CODE_START:protect.CODE_START + 0x80] = bytes(range(0x80))
    checksums.fix_program(flash, stock.pair.mpc)
    old = Pair(bytes(flash), stock.pair.mpc, "old")
    assert protect.is_patched(old)
    stripped = protect.remove(old)
    assert stripped.flash == stock.pair.flash and stripped.mpc == stock.pair.mpc
    rebuilt, _ = protect.build(old, CFG)
    assert rebuilt.flash == protect.build(stock.pair, CFG)[0].flash
    assert rebuilt.flash[protect.LIMIT_SITE:protect.LIMIT_SITE + 4] == stock.pair.flash[protect.LIMIT_SITE:protect.LIMIT_SITE + 4]


def test_insane_values_refused(stock):
    for kw in (dict(cold_rpm=500), dict(oil_rpm=9000), dict(cool_c=250)):
        with pytest.raises(ValueError):
            protect.build(stock.pair, CFG, **kw)


# ---- the temperature limits: spark cuts, the stock limiter untouched ----------
def test_warm_engine_is_stock(base):
    pair, _ = protect.build(base, CFG)
    t = Trial(pair, oil_c=50, cool_c=83, rpm=2500)
    u = Trial(base, oil_c=50, cool_c=83, rpm=2500)
    assert t.sparks >= u.sparks * 0.9 and t.oil_warning == 0 and t.resets == 0
    assert (t.limit, t.limiting, t.fuel_cut) == (u.limit, u.limiting, u.fuel_cut) == (STOCK_LIMIT, 0, 0)


def test_cold_start_cuts_spark_until_warm(base):
    pair, _ = protect.build(base, CFG)
    warm = Trial(pair, oil_c=50, cool_c=83, rpm=2500)
    fast = Trial(pair, oil_c=50, cool_c=40, rpm=2500)
    assert fast.sparks <= warm.sparks * 0.2 and fast.injections > 300
    slow = Trial(pair, oil_c=50, cool_c=40, rpm=1500)
    assert slow.sparks >= Trial(base, oil_c=50, cool_c=40, rpm=1500).sparks * 0.9
    assert Trial(pair, oil_c=50, cool_c=60, rpm=2500).sparks >= warm.sparks * 0.9   # at the warm-up temperature: released
    for t in (fast, slow):
        assert t.resets == 0
        assert (t.limit, t.limiting, t.fuel_cut) == (STOCK_LIMIT, 0, 0), "the stock limiter is never involved"


def test_oil_protection_cuts_spark_and_warns(base):
    pair, _ = protect.build(base, CFG)
    warm = Trial(pair, oil_c=50, cool_c=83, rpm=2300)
    hot = Trial(pair, oil_c=70, cool_c=83, rpm=2300)
    assert hot.sparks <= warm.sparks * 0.2 and hot.oil_warning == 1 and hot.resets == 0
    calm = Trial(pair, oil_c=70, cool_c=83, rpm=1500)                  # hot oil warns at any speed
    assert calm.sparks > 0 and calm.oil_warning == 1
    assert Trial(pair, oil_c=69, cool_c=83, rpm=2300).oil_warning == 0
    assert (hot.limit, hot.limiting, hot.fuel_cut) == (STOCK_LIMIT, 0, 0)


def test_coolant_protection_cuts_spark(base):
    pair, _ = protect.build(base, CFG)
    warm = Trial(pair, oil_c=50, cool_c=83, rpm=2300)
    hot = Trial(pair, oil_c=50, cool_c=90, rpm=2300)
    assert hot.sparks <= warm.sparks * 0.2 and hot.oil_warning == 0 and hot.resets == 0   # the cluster's gauge shows this one
    assert (hot.limit, hot.limiting, hot.fuel_cut) == (STOCK_LIMIT, 0, 0)


def test_the_lowest_limit_wins(base):
    pair, _ = protect.build(base, CFG)
    # oil (2100) under coolant (2150): 2120 rpm is above the one, below the other
    both = Trial(pair, oil_c=70, cool_c=95, rpm=2120)
    coolant_only = Trial(pair, oil_c=50, cool_c=95, rpm=2120)
    assert both.sparks <= coolant_only.sparks * 0.3


# ---- the spark cut: at the program's own limit --------------------------------
def test_spark_cut_at_the_rev_limit_keeps_the_fuel(stock):
    low = _in_order(stock.pair, limit=LOW_LIMIT)
    pair, _ = protect.build(low, CFG)
    before = Trial(low, oil_c=50, cool_c=83, rpm=2500)
    t = Trial(pair, oil_c=50, cool_c=83, rpm=2500)                     # above the 2400 limit
    assert t.sparks <= before.sparks * 0.2 and t.injections > 300 and t.resets == 0
    assert t.limit == LOW_LIMIT, "the stored limit is read, never changed"
    below = Trial(pair, oil_c=50, cool_c=83, rpm=2300)
    assert below.sparks >= Trial(low, oil_c=50, cool_c=83, rpm=2300).sparks * 0.9


def test_spark_cut_stands_down_in_limp_home(stock):
    limping = _in_order(stock.pair, limit=LOW_LIMIT, limp=True)
    pair, _ = protect.build(limping, CFG)
    before = Trial(limping, oil_c=50, cool_c=83, rpm=2500)
    t = Trial(pair, oil_c=50, cool_c=83, rpm=2500)
    assert t.limit == before.limit == 1312
    assert t.sparks >= before.sparks * 0.8                             # the stock limiter alone
    cold = Trial(pair, oil_c=50, cool_c=40, rpm=2500)
    assert cold.sparks <= before.sparks * 0.2                          # the temperature limits still work


def test_spark_cut_off_leaves_the_limit_alone(stock):
    low = _in_order(stock.pair, limit=LOW_LIMIT)
    pair, _ = protect.build(low, CFG, spark_cut=False)
    before = Trial(low, oil_c=50, cool_c=83, rpm=2500)
    t = Trial(pair, oil_c=50, cool_c=83, rpm=2500)
    assert t.sparks >= before.sparks * 0.8                             # only the stock limiter acts
    assert Trial(pair, oil_c=50, cool_c=40, rpm=2500).sparks <= before.sparks * 0.2


# ---- stacking and flashing ---------------------------------------------------
def test_stacks_on_the_map_switch(patched):
    pair, _ = protect.build(patched.pair, CFG)
    assert pair.mpc[0x6E550:] == patched.pair.mpc[0x6E550:]
    assert dme.tach_hook_target(Machine(pair)) == dme.tach_hook_target(patched)
    assert protect.remove(pair).mpc == patched.pair.mpc


@pytest.mark.skipif(not os.environ.get("MS45_SLOW"), reason="minutes; set MS45_SLOW=1")
def test_patched_program_passes_the_boot_loader(stock):
    from ms45emu.kwp import Tester
    pair, _ = protect.build(stock.pair)                            # real defaults
    program, program_end, calibration, calibration_end = 0x60000, 0xFFF40, 0x40000, 0x5D000
    b = _running(stock.pair)
    t = Tester(b)
    assert t.authenticate() and t.programming_mode()
    assert t.erase(0x02000000 + program, 0xA0000)
    assert t.write(0x02000000 + program, pair.flash[program:program_end])
    assert t.write(0x06000000, pair.mpc)
    assert t.erase(0x02000000 + calibration, 0x20000)
    assert t.write(0x02000000 + calibration, pair.flash[calibration:calibration_end])
    assert t.default_mode()
    assert t.check_signature("program") and t.check_signature("data")
    assert t.programming_status() == 1
    assert t.reset()
    b2 = b.reset()
    b2.probe(0x3B38C, "scheduler")
    b2.boot(max_insns=40_000_000, reset_vector=True)
    assert b2.probe_counts["scheduler"] > 10
