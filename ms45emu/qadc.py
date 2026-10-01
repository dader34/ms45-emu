"""The two QADC modules (QADC_A at 0x304800, QADC_B at 0x304C00), as far as
the DME uses them at ignition-on.

Configuration the boot programs: queue 2 is a periodic continuous scan
(QACR2 MQ2 = 0x18) with its completion interrupt enabled, queue 1 is a
software/externally started single scan. The scan walks the CCW RAM from
BQ2 to the end-of-queue word (0x3F) and writes one result per CCW into the
result RAM. Completion sets CF2 in QASR0 and the module's interrupt level
(QADCINT IRLQ2 = 3) reaches the SIU as LVL3.

Channel values are "resting": a sensible mid value unless a test sets a
channel. Results are 10 bits.
"""
from unicorn import UC_HOOK_MEM_WRITE

QADC_A, QADC_B = 0x304800, 0x304C00
QADCINT, QACR0, QACR1, QACR2, QASR0, QASR1 = 0x04, 0x0A, 0x0C, 0x0E, 0x10, 0x12
CCW_RAM, RESULT_RJ, RESULT_LJS, RESULT_LJU = 0x200, 0x280, 0x300, 0x380
END_OF_QUEUE = 0x3F
CF1, PF1, CF2, PF2 = 0x8000, 0x4000, 0x2000, 0x1000
CIE1, SSE1, CIE2 = 0x8000, 0x2000, 0x8000

# A scan of queue 2 every this many emulated instructions (~10 ms).
SCAN_INSTRUCTIONS = 400_000


class Qadc:
    def __init__(self, machine, base, name):
        self.m = machine
        self.base = base
        self.name = name
        self.channels = {}            # channel -> 10-bit value
        self.default = 0x200
        self.scans = 0
        self.single_scans = 0
        machine.mu.hook_add(UC_HOOK_MEM_WRITE, self._qacr1_write, begin=base + QACR1, end=base + QACR1 + 1)
        machine.mu.hook_add(UC_HOOK_MEM_WRITE, self._qacr2_write, begin=base + QACR2, end=base + QACR2 + 1)
        self._start_q1 = False
        self.queue2_started = False      # set when queue 2 is switched on; the first scan follows at once

    def _qacr2_write(self, mu, access, addr, size, value, ud):
        if size == 2 and (value >> 8) & 0x1F:
            self.queue2_started = True

    def _qacr1_write(self, mu, access, addr, size, value, ud):
        if size == 2 and value & SSE1 and (value & 0x1F00):
            self._start_q1 = True

    def value(self, channel):
        return self.channels.get(channel, self.default) & 0x3FF

    def _scan(self, start):
        m = self.m
        q = start
        while q < 64:
            ccw = m.read16(self.base + CCW_RAM + 2 * q)
            chan = ccw & 0x3F
            if chan == END_OF_QUEUE:
                break
            v = self.value(chan)
            m.write16(self.base + RESULT_RJ + 2 * q, v)
            m.write16(self.base + RESULT_LJU + 2 * q, v << 6)
            m.write16(self.base + RESULT_LJS + 2 * q, ((v - 0x200) << 6) & 0xFFFF)
            q += 1

    def service(self):
        """Run a software-started queue 1 scan, if one was requested."""
        if self._start_q1:
            self._start_q1 = False
            m = self.m
            qacr1 = m.read16(self.base + QACR1)
            m.write16(self.base + QACR1, qacr1 & ~SSE1)
            self._scan(0)
            m.write16(self.base + QASR0, m.read16(self.base + QASR0) | CF1)
            self.single_scans += 1

    def periodic(self):
        """One period of queue 2."""
        m = self.m
        qacr2 = m.read16(self.base + QACR2)
        mq2 = (qacr2 >> 8) & 0x1F
        if mq2 == 0:
            return
        self._scan(qacr2 & 0x3F)
        m.write16(self.base + QASR0, m.read16(self.base + QASR0) | CF2)
        self.scans += 1

    def interrupt_pending(self):
        m = self.m
        qasr = m.read16(self.base + QASR0)
        return bool((qasr & CF1 and m.read16(self.base + QACR1) & CIE1) or
                    (qasr & CF2 and m.read16(self.base + QACR2) & CIE2))
