"""The map switch with the gear lever as its trigger: D-S-D or S-D-S within two seconds.

The DME sees the lever in the gearbox's EGS1 frame (0x43F): the gear in
byte 0, the program symbol for the cluster in the top of byte 2.
"""
import pytest

from ms45emu import dme, e46
from ms45emu.board import Board

CALLS_PER_SECOND = 100

D = e46.egs1(1, e46.PROGRAM_DRIVE_GEAR_DISPLAY)
D_STOCK = e46.egs1(3, e46.PROGRAM_DRIVE)
S = e46.egs1(1, e46.PROGRAM_SPORT)
M = e46.egs1(2, e46.PROGRAM_MANUAL, lever=2)
P = e46.egs1(e46.GEAR_PARK_NEUTRAL, e46.PROGRAM_DRIVE_GEAR_DISPLAY, lever=8)
R = e46.egs1(e46.GEAR_REVERSE, e46.PROGRAM_DRIVE_GEAR_DISPLAY, lever=7)
N = e46.egs1(e46.GEAR_PARK_NEUTRAL, e46.PROGRAM_DRIVE_GEAR_DISPLAY, lever=6)


class Lever:
    def __init__(self, m, n=0):
        m.clear_ram()
        m.call(dme.nv_routines(m)[0])
        self.g = dme.Gesture(m)
        self.n = n

    def hold(self, frame, seconds):
        for _ in range(round(seconds * CALLS_PER_SECOND)):
            self.g.tick(n=self.n, rpm_in=self.n, egs1=frame)
        return self.g.map


def test_d_s_d_switches_and_requests_a_save(shifter):
    lever = Lever(shifter)
    assert lever.hold(D, 4.0) == 0
    assert lever.hold(S, 0.7) == 0, "one move is not the gesture"
    assert lever.hold(D, 0.01) == 1
    assert lever.g.save_requested
    assert lever.g.tick(egs1=D) == 2000                      # engine stopped: the tach shows the map
    assert lever.hold(D, 5.0) == 1


def test_s_d_s_switches_too(shifter):
    lever = Lever(shifter)
    lever.hold(S, 4.0)
    lever.hold(D, 0.7)
    assert lever.hold(S, 0.01) == 1
    assert lever.hold(S, 5.0) == 1


@pytest.mark.parametrize("drive", [D, D_STOCK])
def test_the_limit_is_two_seconds(shifter, drive):
    lever = Lever(shifter)
    lever.hold(drive, 1.0)
    lever.hold(S, 2.0)
    assert lever.hold(drive, 0.01) == 1, "back within 2.00 s"
    lever.hold(drive, 5.0)
    lever.hold(S, 2.01)
    assert lever.hold(drive, 5.0) == 1, "back after 2.01 s"
    # and the late move starts nothing of its own once it has run out
    lever.hold(S, 5.0)
    assert lever.g.map == 1


def test_taps_in_the_gate_are_not_moves(shifter):
    lever = Lever(shifter)
    lever.hold(S, 1.0)
    for _ in range(4):
        lever.hold(M, 0.3)
        lever.hold(S, 0.3)
    assert lever.g.map == 0
    # out of manual and back into the gate is the gesture, as the lever makes the same two moves
    lever.hold(M, 3.0)
    lever.hold(D, 0.5)
    assert lever.hold(S, 0.01) == 1


def test_going_through_the_positions_counts_nothing(shifter):
    lever = Lever(shifter)
    for frame in (P, R, N, D, N, D, N, R, P, R, N, D):
        lever.hold(frame, 0.2)
    assert lever.g.map == 0
    # a move begun before the lever left the forward gears is forgotten
    lever.hold(S, 0.3)
    lever.hold(N, 0.1)
    lever.hold(S, 0.1)
    assert lever.hold(D, 0.1) == 0
    assert lever.hold(S, 0.1) == 1                            # S-D-S, counted from the lever's return


def test_a_frame_without_a_known_symbol_counts_nothing(shifter):
    lever = Lever(shifter)
    lever.hold(D, 1.0)
    for symbol in (0, 3, 6, 7):                               # 0 is what the DME writes when the gearbox is silent
        lever.hold(e46.egs1(1, symbol), 0.2)
        lever.hold(D, 0.2)
    assert lever.g.map == 0


def test_engine_running_keeps_the_rpm_and_blinks_the_lamp(shifter):
    lever = Lever(shifter, n=3000)
    lever.hold(D, 4.0)
    lever.hold(S, 0.5)
    assert lever.g.tick(n=3000, rpm_in=3000, egs1=D) == 3000
    assert lever.g.map == 1
    assert shifter.read8(dme.RAM_BLINKS) == 2                 # twice for map 2
    lever.hold(D, 3.0)
    lever.hold(S, 0.5)
    assert lever.hold(D, 0.01) == 0
    assert shifter.read8(dme.RAM_BLINKS) == 1


def test_on_the_board_with_frames_from_the_bus(shifter):
    b = Board(shifter.pair)
    b.boot(max_insns=20_000_000)
    peers = e46.Peers(b, automatic=True)

    def hold(frame, seconds):
        peers.data[e46.EGS1] = frame
        peers.run(round(seconds * 100) * e46.FRAME_INSTRUCTIONS)
        return dme.selected(b.m)

    assert hold(P, 1.0) == 0
    for frame in (R, N, D):
        assert hold(frame, 0.3) == 0
    assert hold(D, 2.0) == 0
    hold(S, 0.6)
    assert hold(D, 0.1) == 1
    dme1 = [f for f in b.can_a.tx_log if f.id == e46.DME1]
    assert e46.rpm_of(dme1[-1]) == 2000
    assert hold(D, 3.0) == 1
    hold(S, 2.5)
    assert hold(D, 3.0) == 1, "too slow"
    hold(S, 3.0)
    hold(D, 0.8)
    assert hold(S, 0.1) == 0
    assert b.can_a.rx_dropped == 0
