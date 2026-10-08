"""The DME's diagnostic side: KWP2000* over the K line, up to programming
mode. Flashing from there is in test_flash.py.
"""
from ms45emu.board import Board
from ms45emu.kwp import Tester


def test_identification(stock):
    b = Board(stock.pair)
    b.boot(max_insns=20_000_000)
    t = Tester(b)
    ident = t.ident()
    assert ident and ident[0] == 0x5A            # positive response to 0x1A
    assert t.serial() is not None


def test_authentication_and_programming_mode(stock):
    b = Board(stock.pair)
    b.boot(max_insns=20_000_000)
    t = Tester(b)
    assert t.authenticate(), "RSA seed/key exchange rejected"
    assert t.programming_mode(), "did not enter programming mode"
