"""The TPU, modelled per channel (functional model, option 1).

The MPC555 TPU is a 16-channel timer coprocessor running microcode from
DPTRAM. The MS45 loads its own Siemens microcode, so the 4-bit function
number the CPU assigns each channel (via CFSR0-3) indexes a *custom*
function table, not the stock Motorola ROM. This models the channels at
the level the rest of the DME sees: what each channel is for, the host
service acknowledgement, capture of the output channels the firmware
drives (ignition, injection), and injection of input events (crank, cam).

The channel -> function map, read back from a booted stock DME:

  TPU A                         TPU B
  ch0-5  func 8  ignition x6    ch0-5  func 7  injection x6
  ch6    func 6  pwm            ch6    func B  aux
  ch7    func 3  aux            ch7    func C  aux
  ch8    func 3  aux            ch8    func B  aux
  ch9    func 6  pwm            ch9    func 6  pwm
  ch10   func D  crank in       ch10   func 0  input
  ch11   func 6  pwm            ch11   func 5  aux
  ch12   func D  cam in         ch12   func 0  input
  ch13   func F  aux            ch13   func 5  aux
  ch14   func E  aux            ch14   func 1  aux
  ch15   func 6  pwm            ch15   func 6  pwm

Register map (TPU A at 0x304000, B at 0x304400), 16-bit:
  0x00 TPUMCR  0x02 TCR   0x0A CIER  0x0C-0x12 CFSR0-3  0x14/16 HSQR0/1
  0x18/1A HSRR0/1  0x1C/1E CPR0/1  0x20 CISR
  0x100 + ch*0x10 : six parameter words per channel.
"""

# register offsets
TPUMCR, TCR, CIER, CISR = 0x00, 0x02, 0x0A, 0x20
CFSR = (0x0C, 0x0E, 0x10, 0x12)        # CFSR0 holds ch15..12, CFSR3 holds ch3..0
HSQR = (0x14, 0x16)
HSRR = (0x18, 0x1A)                     # HSRR0 ch7..0, HSRR1 ch15..8
CPR = (0x1C, 0x1E)
PARAM = 0x100                          # + ch*0x10 + word*2

# roles keyed by (module, function); the engine outputs are the two banks
# of six, the crank/cam are the func-D inputs on A.
ROLES_A = {8: "ignition", 6: "pwm", 0xD: "crank_cam_in", 3: "aux", 0xF: "aux", 0xE: "aux"}
ROLES_B = {7: "injection", 6: "pwm", 0xB: "aux", 0xC: "aux", 5: "aux", 0: "input", 1: "aux"}


class Tpu:
    def __init__(self, page, base, name):
        self.p = page
        self.base = base
        self.name = name
        self.services = [0] * 16          # host service requests seen per channel
        self.pulses = []                  # (channel, role, instruction) output events
        self.on_pulse = None

    # ---- configuration ----------------------------------------------------
    def _r16(self, off):
        return self.p.peek16(self.base + off)

    def function(self, ch):
        reg = self._r16(CFSR[3 - ch // 4])
        return (reg >> (ch % 4) * 4) & 0xF

    def priority(self, ch):
        return (self._r16(CPR[1 - ch // 8]) >> (ch % 8) * 2) & 3

    def sequence(self, ch):
        return (self._r16(HSQR[1 - ch // 8]) >> (ch % 8) * 2) & 3

    def param(self, ch, i):
        return self.p.peek16(self.base + PARAM + ch * 0x10 + i * 2)

    def set_param(self, ch, i, value):
        self.p.poke16(self.base + PARAM + ch * 0x10 + i * 2, value & 0xFFFF)

    def role(self, ch):
        roles = ROLES_A if self.base == 0x304000 else ROLES_B
        return roles.get(self.function(ch), "unused" if self.priority(ch) == 0 else "aux")

    def channels(self, role):
        return [ch for ch in range(16) if self.role(ch) == role]

    def roles(self):
        return {ch: self.role(ch) for ch in range(16)}

    # ---- runtime ----------------------------------------------------------
    def on_service(self, ch, now=0):
        """The CPU issued a host service request on this channel. For an
        output channel that is the DME scheduling a pulse (spark/injection);
        record it so the timing is observable."""
        self.services[ch] += 1
        role = self.role(ch)
        if role in ("ignition", "injection"):
            self.pulses.append((ch, role, now))
            if len(self.pulses) > 2000:
                del self.pulses[:1000]
            if self.on_pulse is not None:
                self.on_pulse(ch, role, now)

    def inject_input(self, ch, value, now=0, param_index=3):
        """A hardware transition on an input channel: store the captured
        value (time/period) in the channel's parameter RAM and raise its
        interrupt flag, the way the TPU microcode would for the host."""
        self.set_param(ch, param_index, value & 0xFFFF)
        self.p.poke16(self.base + CISR, self.p.peek16(self.base + CISR) | (1 << ch))

    def interrupt_pending(self):
        return bool(self.p.peek16(self.base + CISR) & self.p.peek16(self.base + CIER))
