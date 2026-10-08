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
