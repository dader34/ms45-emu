"""The TPU, modelled per channel (functional model, option 1).

The MPC555 TPU is a 16-channel timer coprocessor running microcode from
DPTRAM. The MS45 loads its own Siemens microcode, so the 4-bit function
number the CPU assigns each channel (via CFSR0-3) indexes a *custom*
function table, not the stock Motorola ROM. This models the channels at
the level the rest of the DME sees: what each channel is for, the host
service acknowledgement, capture of the output channels the firmware
drives (ignition, injection), and the crank wheel (`Crank`).

The channel -> function map, read back from a booted stock DME:

  TPU A                         TPU B
  ch0-5  func 8  ignition x6    ch0-5  func 7  injection x6
  ch6    func 6  pwm            ch6    func B  aux
  ch7    func 3  aux            ch7    func C  aux
  ch8    func 3  aux            ch8    func B  aux
  ch9    func 6  pwm            ch9    func 6  pwm
  ch10   func D  cam in         ch10   func 0  input
  ch11   func 6  pwm            ch11   func 5  aux
  ch12   func D  cam in         ch12   func 0  input
  ch13   func F  crank in       ch13   func 5  aux
  ch14   func E  angle clock    ch14   func 1  angle match
  ch15   func 6  pwm            ch15   func 6  pwm

Register map (TPU A at 0x304000, B at 0x304400), 16-bit:
  0x00 TPUMCR  0x02 TCR   0x0A CIER  0x0C-0x12 CFSR0-3  0x14/16 HSQR0/1
  0x18/1A HSRR0/1  0x1C/1E CPR0/1  0x20 CISR
  0x100 + ch*0x10 : eight parameter words per channel.

The crank side, as the program's handlers use it (the microcode itself is
not emulated; `Crank` plays its part):

  A13, crank (handler 0x17FE8)
    word 0     tooth counter, 0..119 over the two revolutions of a cycle
    word 2     tooth period, 4 us units
    byte 0xC   teeth seen since the search began
    byte 0xD   state, with an interrupt when it changes: 9/8/7 no signal,
               6/5 teeth seen and looking for the gap, 4 gap found (the
               program answers by writing the tooth counter: 5, or 65 when
               the cam says it is the other revolution), 3..1 synchronised
  B14, angle match (handler 0x168D4)
    word 7     written (tooth << 1) | 1 by the program to arm a match;
               at that tooth the microcode leaves the time there, shifted
               left one, with its top 8 bits in byte 0xD, and interrupts.
               The time is 23 bits of a 1.25 MHz count.
  The program arms a match every 20 teeth (one cylinder's 120 degrees),
  takes the difference of two times as the segment time X and computes
  the engine speed from it: rpm = 25,000,000 / X.
"""

# register offsets
TPUMCR, TCR, CIER, CISR = 0x00, 0x02, 0x0A, 0x20
CFSR = (0x0C, 0x0E, 0x10, 0x12)        # CFSR0 holds ch15..12, CFSR3 holds ch3..0
HSQR = (0x14, 0x16)
HSRR = (0x18, 0x1A)                     # HSRR0 ch7..0, HSRR1 ch15..8
CPR = (0x1C, 0x1E)
PARAM = 0x100                          # + ch*0x10 + word*2

# roles keyed by (module, function); the engine outputs are the two banks
# of six, the cams are the func-D inputs on A, the crank its func F.
ROLES_A = {8: "ignition", 6: "pwm", 0xD: "cam_in", 3: "aux", 0xF: "crank_in", 0xE: "angle_clock"}
ROLES_B = {7: "injection", 6: "pwm", 0xB: "aux", 0xC: "aux", 5: "aux", 0: "input", 1: "angle_match"}


class Tpu:
    def __init__(self, page, base, name):
        self.p = page
        self.base = base
        self.name = name
        self.services = [0] * 16          # host service requests seen per channel
        self.pulses = []                  # (channel, role, instruction) output events
        self.on_pulse = None
        self.on_request = None            # fn(channel, request) for every host service request

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
    def on_service(self, ch, now=0, request=0):
        """The CPU issued a host service request on this channel. For an
        output channel that is the DME scheduling a pulse (spark/injection);
        record it so the timing is observable."""
        self.services[ch] += 1
        if self.on_request is not None:
            self.on_request(ch, request)
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


# ---- the crank wheel ---------------------------------------------------------
CRANK_CHANNEL, MATCH_CHANNEL = 13, 14          # on TPU A and on TPU B
TEETH_PER_REV, TEETH_PER_CYCLE = 60, 120       # tooth positions, the gap's two included
STATE_STOPPED, STATE_TEETH, STATE_GAP, STATE_SYNCED = 7, 5, 4, 3
HSR_INIT = 3
PERIOD_HZ, MATCH_HZ = 250_000, 1_250_000       # units of the tooth period and of the match time
STALL_SECONDS = 0.1                            # no tooth for this long: no signal


class Crank:
    """A 60-2 crank wheel and the microcode's side of the two channels the
    program follows it with (see the module text). Set `rpm` and the wheel
    turns; the program then finds the gap, synchronises and measures its
    segment times, so its engine speed follows.

    The cam sensors are not driven: with their lines at rest the program
    takes the first gap as the start of the cycle. Ignition and injection
    are not timed off this angle either, only acknowledged as before."""

    def __init__(self, board):
        self.b = board
        self.p = board.imb
        self.a = board.tpu_a.base + PARAM + CRANK_CHANNEL * 0x10
        self.m = board.tpu_b.base + PARAM + MATCH_CHANNEL * 0x10
        self.cisr_a, self.cisr_b = board.tpu_a.base + CISR, board.tpu_b.base + CISR
        self._rpm = 0.0
        self._origin = (0, 0.0)           # (instruction count, tooth position then)
        self.teeth_seen = 0               # since the search began
        self.searching = False            # initialised, no tooth reported yet
        self.next_tooth = None            # instruction count of the next tooth while not synchronised
        self.stall_at = None
        self.armed = None                 # tooth the program wants a match at
        self.match_at = None              # instruction count of that match
        self.matches = 0
        self.p.on_read(self.a, self._read_tooth)
        self.p.on_write(self.a, self._write_tooth)
        self.p.on_read(self.a + 4, self._read_period)
        self.p.on_write(self.m + 0xE, self._arm)
        board.tpu_a.on_request = self._request

    # ---- the wheel --------------------------------------------------------
    @property
    def rpm(self):
        return self._rpm

    @rpm.setter
    def rpm(self, rpm):
        now = self.b.instructions
        self._origin = (now, self.position(now))
        was, self._rpm = self._rpm, float(rpm)
        if self._rpm > 0:
            self.stall_at = None
            if self.state != STATE_SYNCED and self.next_tooth is None:
                self.next_tooth = now + self.tooth_instructions
            if self.armed is not None:
                self._schedule_match()
        elif was > 0:
            self.next_tooth = self.match_at = None
            self.stall_at = now + int(STALL_SECONDS * self.b.ips)

    @property
    def tooth_instructions(self):
        """One tooth position: 60 to a revolution, so 1/rpm of a second."""
        return self.b.ips / self._rpm

    def position(self, now=None):
        """Tooth position in the cycle, 0 <= position < 120, with fraction."""
        at, pos = self._origin
        if self._rpm <= 0:
            return pos
        now = self.b.instructions if now is None else now
        return (pos + (now - at) / self.tooth_instructions) % TEETH_PER_CYCLE

    # ---- channel A13: the crank input ----------------------------------------
    @property
    def state(self):
        return self.p.peek8(self.a + 0xD)

    def _report(self, state):
        self.p.poke8(self.a + 0xC, min(self.teeth_seen, 0xFF))
        self.p.poke8(self.a + 0xD, state)
        self.p.poke16(self.cisr_a, self.p.peek16(self.cisr_a) | (1 << CRANK_CHANNEL))

    def _read_tooth(self, addr, size):
        tooth = int(self.position())
        return tooth if size == 2 else (tooth << 16) | self.p.peek16(self.a + 2) if size == 4 else None

    def _write_tooth(self, addr, size, value):
        """The program names the tooth the wheel is at (after the gap)."""
        if size == 2:
            self._origin = (self.b.instructions, float(value % TEETH_PER_CYCLE))
            if self.state == STATE_GAP:
                self.next_tooth = None
                self._report(STATE_SYNCED)
        return None

    def _read_period(self, addr, size):
        if self._rpm <= 0:
            return None
        period = min(int(PERIOD_HZ / self._rpm), 0xFFFF)
        return period if size == 2 else (period << 16) | self.p.peek16(self.a + 6) if size == 4 else None

    def _request(self, ch, request):
        if ch == CRANK_CHANNEL and request == HSR_INIT:
            self.teeth_seen = 0
            self.searching = True
            self.next_tooth = self.b.instructions + self.tooth_instructions if self._rpm > 0 else None

    # ---- channel B14: the angle match ------------------------------------------
    def _arm(self, addr, size, value):
        if size == 2 and value & 1:
            self.armed = (value >> 1) % TEETH_PER_CYCLE
            self._schedule_match()
        return None

    def _schedule_match(self):
        if self._rpm <= 0:
            self.match_at = None
            return
        ahead = (self.armed - self.position()) % TEETH_PER_CYCLE
        if ahead > TEETH_PER_CYCLE - 20:          # armed for a tooth just gone by: it matches at once
            ahead = 0.0
        self.match_at = self.b.instructions + ahead * self.tooth_instructions

    # ---- time -------------------------------------------------------------
    def next_event(self):
        """The instruction count of the next thing to happen, or None."""
        times = [t for t in (self.next_tooth, self.match_at, self.stall_at) if t is not None]
        return min(times) if times else None

    def service(self):
        """Called by the board at every slice boundary."""
        now = self.b.instructions
        if self.next_tooth is not None and now >= self.next_tooth:
            self.teeth_seen += 1
            self.next_tooth += self.tooth_instructions
            if self.searching:
                self.searching = False
                self._report(STATE_TEETH)
            elif self.state == STATE_TEETH and self.teeth_seen >= 3 and int(self.position()) % TEETH_PER_REV == 0:
                self._report(STATE_GAP)           # the long tooth: the gap has gone by
        if self.match_at is not None and now >= self.match_at:
            time = int(self.match_at / self.b.ips * MATCH_HZ) & 0x7FFFFF
            self.p.poke16(self.m + 0xE, (time & 0x7FFF) << 1)
            self.p.poke8(self.m + 0xD, time >> 15)
            self.p.poke16(self.cisr_b, self.p.peek16(self.cisr_b) | (1 << MATCH_CHANNEL))
            self.armed = self.match_at = None
            self.matches += 1
        if self.stall_at is not None and now >= self.stall_at:
            self.stall_at = None
            self.teeth_seen = 0
            self._report(STATE_STOPPED)
