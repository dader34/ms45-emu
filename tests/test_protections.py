"""The protections (ms45emu/protections.py): a custom program trips nothing
the stock program does not, under the same scenario."""
import pytest

from ms45emu import protect, load_pair
from ms45emu.image import find_pair
from ms45emu.board import Board
from ms45emu.faults import Faults
from ms45emu.funcmap import FunctionMap
from ms45emu.protections import Checks, Reactions, compare
from ms45emu.xdf import Xdf

SCENARIO = dict(rpm=800, seconds=0.5, settle=0.5)
STALE_AT = 0xFFFDC860             # free space inside the program checksum's range, never executed
STALE_SECONDS = 6


@pytest.fixture(scope="module")
def stock_reactions():
    if find_pair("stock") is None:
        pytest.skip("no stock pair on this machine")
    r = Reactions(Board(load_pair("stock")))
    r.scenario(**SCENARIO)
    return r


def test_fault_table(stock):
    f = Faults(stock.pair)
    assert len(f) == 258
    assert f.index(0x2831) == 96 and "Prozessor" in f.text(96)
    assert f.code(44) == 0x280B


def test_stock_baseline(stock, stock_reactions):
    r = stock_reactions
    assert not r.reset, r.report(Faults(stock.pair))
    assert r.reports, "the fault reporter was never entered"
    assert 97 in r.reports                                      # the crank sensor check runs with the crank turning


def test_stock_never_fails_its_self_check(stock_reactions):
    assert stock_reactions.self_reset == {}


def test_a_stale_program_checksum_is_a_self_reset(stock):
    """One word changed in the program and its sums left as they were: the
    background checksum fails, the pre-answer self-check with it, and the
    DME would reset itself without a code (the start-up resets of an early
    map-switch build)."""
    b = Board(stock.pair)                 # sums refreshed over the emulator's own patches here ...
    b.m.write32(STALE_AT, 0x12345678)     # ... and then a word in the program area changed
    r = Reactions(b)
    r.scenario(rpm=0, seconds=STALE_SECONDS, settle=0.5)
    assert 11 in r.self_reset, r.report(Faults(stock.pair))


def test_checks_table(stock):
    fm = FunctionMap(stock.pair)
    checks = Checks(fm, Xdf.find(stock.pair), Faults(stock.pair))
    assert len(checks.checks) > 60
    plaus = checks.checks[fm.by_name("brake_throttle_plausibility").start]
    assert "limp_home_flag" in plaus.limp and plaus.task
    sel = checks.checks[fm.by_name("selftest_processor_monitor").start]
    assert 96 in sel.faults
    assert "c_abc_max_tpu_syn" in sel.cal or not Xdf.find(stock.pair)
    assert "| `brake_throttle_plausibility`" in checks.markdown()


def test_map_switch_trips_nothing_new(patched, stock_reactions):
    r = Reactions(Board(patched.pair))
    r.scenario(**SCENARIO)
    assert compare(stock_reactions, r, Faults(patched.pair)) == []


def test_protect_build_trips_nothing_new(stock, stock_reactions):
    out, _ = protect.build(stock.pair, protect.Config())
    r = Reactions(Board(out))
    r.scenario(**SCENARIO)
    assert compare(stock_reactions, r, Faults(out)) == []
