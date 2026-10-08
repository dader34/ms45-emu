"""An MS45.1 program other than the one the helpers in dme.py were traced
in: it boots under Board and answers diagnostics, because the board is the
hardware and looks up what little it needs from the program.

Needs such a pair (MS45_OTHER_FLASH / MS45_OTHER_MPC, or images/other_*):
for instance 0044570LN00S, the 7549388A.0PA of SP-Daten, on a stock boot
loader with one of its own calibrations."""
import pytest

from ms45emu import load_pair
from ms45emu.board import Board, INTERRUPT_NEST
from ms45emu.image import Pair, find_pair, PROGRAM_ID, PROGRAM_ID_OFFSET
from ms45emu.kwp import Tester


@pytest.fixture
def other():
    if find_pair("other") is None:
        pytest.skip("no pair of another MS45.1 program on this machine (see ms45emu/image.py)")
    pair = load_pair("other")
    assert not pair.traced, "MS45_OTHER_* is the traced program itself"
    return pair


def test_the_nesting_counter_is_found_where_it_was_traced(stock):
    assert stock.pair.traced
    assert Board(stock.pair).interrupt_nest == INTERRUPT_NEST


def test_another_program_boots_and_identifies(other):
    b = Board(other, mips=10)
    assert b.interrupt_nest is not None
    b.boot(max_insns=20_000_000)                     # from the reset vector: the loader starts it
    assert not b.in_loader
    assert b.ticks >= 150 and b.can_a.tx_count > 100             # the OS on its tick, the 10 ms frames on the bus
    assert b.kl15 is None                            # its address is one program's
    ident = Tester(b).ident()
    assert ident is not None and ident[0] == 0x5A
    # the part number the program carries, as BCD in the answer: not the traced program's
    stock_number = bytes.fromhex("07561382")
    assert bytes(ident[4:8]) != stock_number


def test_a_program_of_another_family_is_refused(stock):
    flash = bytearray(stock.pair.flash)
    flash[PROGRAM_ID_OFFSET:PROGRAM_ID_OFFSET + len(PROGRAM_ID)] = b"0012340AB00S"
    with pytest.raises(ValueError):
        Pair(bytes(flash), stock.pair.mpc, "something else")
    assert Pair(bytes(flash), stock.pair.mpc, "mid-flash", check_program=False).traced is False
