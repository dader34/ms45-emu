"""Explaining a routine (ms45emu/explain.py, ms45emu/xdf.py)."""
import pytest

from ms45emu import dme
from ms45emu.board import Board
from ms45emu.explain import explain
from ms45emu.funcmap import FunctionMap
from ms45emu.machine import R13
from ms45emu.xdf import Xdf


@pytest.fixture
def xdf(stock):
    x = Xdf.find(stock.pair)
    if x is None:
        pytest.skip("no XDF for the program (MS45_XDF, or images/*LO02S*.xdf)")
    return x


def test_xdf_items(xdf):
    assert xdf.at(0x171C).name == "c_n_pvs_bls_bts_plaus"            # the trace notes' plausibility threshold
    t = xdf.at(0x4395)
    assert t.name == "ip_tco__v_tco" and t.kind == "table" and t.address == 0xFFE44395
    assert xdf.at(0x4395 + 5) is t
    assert xdf.by_name("id_maf_tab").size == 512
    assert xdf.at(0x1CFFF) is None


def test_builder_static(stock):
    fm = FunctionMap(stock.pair)
    e = explain(fm, fm.by_name("dme1_builder"))
    n, tach = e.ram[R13 + dme.VAR_N], e.ram[R13 + dme.TACH_VAR]
    assert n.name == "N" and [h for _, h, _ in n.sites] == ["R"]
    assert tach.name == "tach_x6_4" and [h for _, h, _ in tach.sites] == ["W"]
    assert any((pc, h) == (dme.TACH_STORE_ADDR, "W") for pc, h, _ in tach.sites)
    assert fm.by_name("mul_fixed_0_8").start in e.calls
    assert "N" in e.report() and "tach_x6_4" in e.report()


def test_plausibility_check_reads_its_thresholds(stock, xdf):
    """The stock brake/throttle plausibility check (trace notes): the fault
    flag is set when N_32, VS and PV_AV are over three calibration thresholds."""
    fm = FunctionMap(stock.pair)
    e = explain(fm, fm.by_name("brake_throttle_plausibility"), xdf)
    names = {u.name for u in e.cal.values()}
    assert {"c_n_pvs_bls_bts_plaus", "c_vs_pvs_bls_bts_plaus", "c_pv_av_pvs_bls_bts_plaus"} <= names
    assert R13 - 0x4073 in e.ram and e.ram[R13 - 0x4073].name == "N_32"
    assert R13 - 0x4059 in e.ram and any(h == "W" for _, h, _ in e.ram[R13 - 0x4059].sites)   # the fault flag


def test_run_confirms_the_scan(stock):
    fm = FunctionMap(stock.pair)
    b = Board(stock.pair)
    b.crank.rpm = 800                                         # before the boot: synchronised by the time the watch starts
    b.boot(max_insns=b.ips // 2)
    e = explain(fm, fm.by_name("dme1_builder"))
    e.run(b, b.ips // 20)                                     # five 10 ms frames
    n = e.ram[R13 + dme.VAR_N]
    assert n.reads >= 3 and 0x320 in n.values
    assert e.ram[R13 + dme.TACH_VAR].writes >= 3
    assert "R" in e.report()
