"""The TPU functional model: channel roles read from the booted DME."""
from ms45emu.board import Board


def test_channel_roles(stock):
    b = Board(stock.pair)
    b.boot(max_insns=25_000_000)
    # Two banks of six for the inline-six: ignition on TPU A, injection on B.
    assert b.tpu_a.channels("ignition") == [0, 1, 2, 3, 4, 5]
    assert b.tpu_b.channels("injection") == [0, 1, 2, 3, 4, 5]
    # Crank and cam inputs on TPU A 10/12 (the angle-clock function).
    assert b.tpu_a.channels("crank_cam_in") == [10, 12]
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
