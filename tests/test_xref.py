"""Cross-references from the running program (ms45emu/xref.py, tools/xref.py)."""
import pytest

from ms45emu import dme
from ms45emu.machine import R13, R2
from ms45emu.board import Board
from ms45emu.e46 import Peers
from ms45emu.xref import Xref, parse_address, describe, function_start

FRAME_0x316_BUILDER = 0x4B528          # stwu r1 / mflr r0 prologue; stores the tach word


def test_address_forms():
    assert parse_address("0x3FA195") == (0x3FA195, 0x3FA196)
    assert parse_address("r13-0x4BEC") == (R13 - 0x4BEC, R13 - 0x4BEC + 1)
    assert parse_address("r13-0x4BEC:2") == (R13 - 0x4BEC, R13 - 0x4BEC + 2)
    assert parse_address("r2+0x2C") == (R2 + 0x2C, R2 + 0x2D)
    assert parse_address("0x3FA195..0x3FA197") == (0x3FA195, 0x3FA198)
    assert parse_address("0xFFE40000:0x400") == (0xFFE40000, 0xFFE40400)
    with pytest.raises(ValueError):
        parse_address("r13*4")
    assert describe(R13 - 0x4BEC) == "0x3FCC04 (r13-0x4bec)"
    assert describe(0x3F0000) == "0x3F0000"


def test_function_start(stock):
    m = stock
    assert function_start(m, FRAME_0x316_BUILDER + 0x180) == FRAME_0x316_BUILDER
    assert function_start(m, FRAME_0x316_BUILDER) == FRAME_0x316_BUILDER


def test_engine_speed_readers_and_writer(stock):
    b = Board(stock.pair)
    b.boot(max_insns=b.ips // 2)
    b.crank.rpm = 800
    x = Xref(b, [parse_address("r13-0x4BEC")])
    Peers(b).run(b.ips // 2)
    x.detach()
    assert x.reads > 100
    writers = [s for s in x.sites.values() if s.kind == "W"]
    assert writers, "nothing wrote the engine speed with the crank turning"
    assert any(0x320 in s.values for s in writers), "the writer never stored 800 rpm"
    # the 0x316 builder reads it for the tach word, and is called from the 10 ms task
    builder = [s for s in x.sites.values() if s.kind == "R" and s.function == FRAME_0x316_BUILDER]
    assert builder
    assert (dme.FRAME_TASK_BUILDER_CALL + 4) in builder[0].callers
    text = x.report()
    assert "r13-0x4bec" in text and "0320" in text
