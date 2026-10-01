"""The DME on its CAN bus: the frames it sends, the frames it takes in."""
from collections import Counter

from ms45emu import dme, e46
from ms45emu.board import Board
from ms45emu.toucan import RX_EMPTY, TX_INACTIVE

FRAME = e46.FRAME_INSTRUCTIONS


def test_bus_configuration_matches_the_car(stock):
    b = Board(stock.pair)
    b.boot(max_insns=20_000_000)
    rx = {ident for n, code, ident, length in b.can_a.buffers() if code == RX_EMPTY}
    tx = {ident for n, code, ident, length in b.can_a.buffers() if code == TX_INACTIVE}
    assert {e46.ASC1, e46.ASC3, e46.STEERING, e46.ASC4, e46.KOMBI1, e46.KOMBI2, e46.EGS1, e46.EGS2, e46.EGS3} <= rx
    assert tx == {e46.DME1, e46.DME2, e46.DME3, e46.DME4}
    assert b.can_a.running and b.can_b.running


def test_dme_frames_every_10_ms(stock):
    b = Board(stock.pair)
    b.boot(max_insns=20_000_000)
    b.can_a.tx_log.clear()
    b.run(100 * FRAME)                                        # one second
    counts = Counter(f.id for f in b.can_a.tx_log)
    for ident in (e46.DME1, e46.DME2, e46.DME4):
        assert 95 <= counts[ident] <= 105, (hex(ident), counts[ident])
    times = [f.time for f in b.can_a.tx_log if f.id == e46.DME1]
    gaps = {t1 - t0 for t0, t1 in zip(times, times[1:])}
    assert all(abs(g - FRAME) <= FRAME // 10 for g in gaps)


def test_map_indication_is_on_the_bus(patched):
    b = Board(patched.pair)
    b.boot(max_insns=20_000_000)
    dme1 = [f for f in b.can_a.tx_log if f.id == e46.DME1]
    assert dme1 and e46.rpm_of(dme1[-1]) == 1000             # map 1 on a blank EEPROM


def test_received_frames_reach_the_application(stock):
    b = Board(stock.pair)
    b.boot(max_insns=20_000_000)
    payload = bytes([0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x17, 0x28])
    for _ in range(3):
        assert b.can_a.receive(e46.ASC1, payload) is not None
        b.run(FRAME)
    # The DME stores frames byte-reversed, so little-endian fields read naturally.
    assert b.m.read(dme.CAN_ASC1_STORE, 8) == payload[::-1]
    assert b.can_a.rx_dropped == 0


def test_unknown_identifier_is_filtered(stock):
    b = Board(stock.pair)
    b.boot(max_insns=20_000_000)
    assert b.can_a.receive(0x7E0, bytes(8)) is None
    assert b.can_a.rx_dropped == 1


def test_peers_keep_the_bus_alive(stock):
    b = Board(stock.pair)
    b.boot(max_insns=20_000_000)
    peers = e46.Peers(b)
    peers.set_speed(0)
    peers.run(50 * FRAME)
    assert b.can_a.rx_count >= 4 * 50 - 4                    # four 10 ms frames per 10 ms
    assert b.can_a.rx_dropped == 0
