"""The TPU functional model: channel roles read from the booted DME, and
the crank wheel the program measures the engine speed from."""
from ms45emu import dme, e46
from ms45emu.board import Board

ENGINE_STATE = 0x3F9C43          # 0 stopped, 2 running


def test_channel_roles(stock):
    b = Board(stock.pair)
    b.boot(max_insns=25_000_000)
    # Two banks of six for the inline-six: ignition on TPU A, injection on B.
    assert b.tpu_a.channels("ignition") == [0, 1, 2, 3, 4, 5]
    assert b.tpu_b.channels("injection") == [0, 1, 2, 3, 4, 5]
    # The two cam sensors on TPU A 10/12, the crank on 13 with its angle
    # clock on 14, and the angle-match channel on TPU B that times the segments.
    assert b.tpu_a.channels("cam_in") == [10, 12]
    assert b.tpu_a.channels("crank_in") == [13]
    assert b.tpu_a.channels("angle_clock") == [14]
    assert b.tpu_b.channels("angle_match") == [14]
    # PWM outputs (VANOS/idle/purge/...) exist on both modules.
    assert len(b.tpu_a.channels("pwm")) >= 3


def test_output_pulses_are_captured(stock):
    b = Board(stock.pair)
    b.boot(max_insns=25_000_000)
    b.run(5_000_000)
    # The DME services its ignition and injection channels; the model logs them.
    assert sum(b.tpu_a.services[0:6]) > 0
    assert sum(b.tpu_b.services[0:6]) > 0
    assert b.tpu_a.pulses or b.tpu_b.pulses


def test_input_injection(stock):
    b = Board(stock.pair)
    b.boot(max_insns=25_000_000)
    b.imb.poke16(0x304000 + 0x20, 0)              # clear CISR A
    b.tpu_a.inject_input(10, 0x1234)             # a crank edge
    assert b.tpu_a.param(10, 3) == 0x1234
    assert b.imb.peek16(0x304000 + 0x20) & (1 << 10)


def _rpm(b):
    return b.m.sda16(dme.VAR_N)


def test_engine_speed_follows_the_crank(stock):
    b = Board(stock.pair)
    b.boot(max_insns=25_000_000)
    assert _rpm(b) == 0 and b.m.read8(ENGINE_STATE) == 0

    # The wheel turns: the program finds the gap, synchronises, and takes
    # its speed from the time between two angle matches 20 teeth apart.
    b.crank.rpm = 1000
    b.run(b.ips // 4)
    assert b.m.read8(ENGINE_STATE) == 2
    assert abs(_rpm(b) - 1000) <= 2
    assert b.crank.matches > 10

    for rpm in (3000, 650, 6000):
        b.crank.rpm = rpm
        b.run(b.ips // 4)
        assert abs(_rpm(b) - rpm) <= rpm // 200, (rpm, _rpm(b))

    # What the cluster's tachometer gets: DME1, bytes 2-3, rpm * 6.4.
    dme1 = [f for f in b.can_a.tx_log if f.id == e46.DME1]
    assert abs(e46.rpm_of(dme1[-1]) - 6000) <= 30

    b.crank.rpm = 0
    b.run(b.ips // 2)
    assert _rpm(b) == 0 and b.m.read8(ENGINE_STATE) == 0


def test_the_program_keeps_its_schedule_at_10_mips(stock):
    """tools/kline.py clocks the DME at 10 MIPS so that it keeps real time
    for a tester. Everything has to stay served there: the 5 ms scheduler,
    the low interrupt levels (QSPI, the OS events), and the crank."""
    b = Board(stock.pair, mips=10)
    b.probe(0x3B38C, "scheduler")
    b.boot(max_insns=b.ips)
    b.crank.rpm = 3000
    taken, scheduled = dict(b.interrupts_taken), b.probe_counts["scheduler"]
    b.run(b.ips)
    assert 195 <= b.probe_counts["scheduler"] - scheduled <= 205
    assert b.interrupts_taken[9] > taken.get(9, 0) and b.interrupts_taken[13] > taken.get(13, 0)
    assert abs(_rpm(b) - 3000) <= 15
    assert b.watchdog_bad == 0
