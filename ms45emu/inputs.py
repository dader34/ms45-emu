"""Analogue inputs of program 0044570LO02S: the accelerator pedal and the
throttle position sensors, as voltages on the QADC channels the program
reads them from (docs/protections.md, "Pedal and throttle").

The program reads its analogue inputs by logical channel through
`fn_93B4`: a descriptor table at *(r13-0x76A0)+4 (12 bytes a channel,
bit 0x80 of the first byte for QADC B) and a result-slot byte per channel
at r13-0x7078. Resolved on a booted board:

  logical 0x06  QADC A ch 3   pedal sensor 1   0.82 V + 32.8 %/V   (c_v_pvs_ofs_1, c_pvs_slop_1)
  logical 0x12  QADC B ch 0   pedal sensor 2   0.41 V + 65.9 %/V   (c_v_pvs_ofs_2, c_pvs_slop_2)
  logical 0x05  QADC A ch 2   throttle pot 1   0.51 V at the lower stop, rising 1/20.9 V per degree
  logical 0x14  QADC B ch 2   throttle pot 2   4.50 V at the lower stop, falling the same
  logical 0x03, 0x21          the pedal sensors' supply checks: leave at the default

The pedal comes out in PV_AV (r13-0x4061, 0.39 %/count), the throttle
angle in r13-0x48FE (0.007294 degrees/count). The throttle is held where
it is set: the motor drive (MIOS PWM 16/19 and, most likely, the H-bridge
in the output-stage IC on PCS2) is not modelled, so nothing moves it.
"""

PEDAL_1 = ("adc_a", 3, 0.82, 32.8)       # (module, channel, volts at 0 %, % per volt)
PEDAL_2 = ("adc_b", 0, 0.41, 65.9)
THROTTLE_1 = ("adc_a", 2, 0.51, 1 / 20.9)  # (module, channel, volts at 0 degrees, volts per degree)
THROTTLE_2 = ("adc_b", 2, 4.50, -1 / 20.9)
PV_AV = -0x4061                           # r13 offset, 8 bit, 0.390625 %
TPS_AV = -0x48FE                          # r13 offset, 16 bit, 0.007294 degrees
TPS_UNIT = 0.007294


def _counts(volts):
    return max(0, min(0x3FF, int(volts / 5.0 * 1024)))


def set_pedal(board, percent):
    """Both pedal sensors at `percent` of travel (0 released, 100 floored)."""
    for module, ch, v0, slope in (PEDAL_1, PEDAL_2):
        getattr(board, module).channels[ch] = _counts(v0 + percent / slope)


def set_throttle(board, degrees):
    """Both throttle pots at `degrees` above the lower stop."""
    for module, ch, v0, per_degree in (THROTTLE_1, THROTTLE_2):
        getattr(board, module).channels[ch] = _counts(v0 + degrees * per_degree)


def pedal(board):
    """The pedal position the program computed, in %."""
    return board.m.sda8(PV_AV) * 0.390625


def throttle(board):
    """The throttle angle the program computed, in degrees."""
    return board.m.sda16(TPS_AV) * TPS_UNIT
