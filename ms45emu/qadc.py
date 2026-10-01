"""The two QADC modules (QADC_A at 0x304800, QADC_B at 0x304C00), as far as
the DME uses them at ignition-on.

Queue 2 is a periodic continuous scan (QACR2 MQ2 = 0x18) with its
completion interrupt enabled; queue 1 is a software-started single scan,
re-armed by its handler. A scan walks the CCW RAM from the queue start to
the end-of-queue word (0x3F) and writes one result per CCW into the result
RAM. Completion sets CF1/CF2 in QASR0 and the module's interrupt level
(QADCINT IRLQ = 3) reaches the SIU as LVL3.

Channel values are "resting": mid-scale unless a test sets a channel.
Results are 10 bits.
"""
from .periph import write_zero_to_clear

QADC_A, QADC_B = 0x304800, 0x304C00
QADCINT, QACR0, QACR1, QACR2, QASR0, QASR1 = 0x04, 0x0A, 0x0C, 0x0E, 0x10, 0x12
CCW_RAM, RESULT_RJ, RESULT_LJS, RESULT_LJU = 0x200, 0x280, 0x300, 0x380
END_OF_QUEUE = 0x3F
CF1, PF1, CF2, PF2 = 0x8000, 0x4000, 0x2000, 0x1000
CIE1, SSE1, CIE2 = 0x8000, 0x2000, 0x8000

# A scan of queue 2 every this many emulated instructions (~10 ms).
SCAN_INSTRUCTIONS = 400_000


class Qadc:
    def __init__(self, page, base, name):
        self.p = page
        self.base = base
        self.name = name
        self.channels = {}            # channel -> 10-bit value
        self.default = 0x200
        self.scans = 0
        self.single_scans = 0
        self.q1_due = False           # a software scan was started; completes at the slice boundary
        self.queue2_started = False   # queue 2 switched on; the first scan follows at once
        page.on_write(base + QACR1, self._qacr1_write)
        page.on_write(base + QACR2, self._qacr2_write)
        write_zero_to_clear(page, base + QASR0)

    def _qacr1_write(self, addr, size, value):
        if size == 2 and value & SSE1 and (value & 0x1F00):
            self.q1_due = True
        return None

    def _qacr2_write(self, addr, size, value):
        if size == 2 and (value >> 8) & 0x1F:
            self.queue2_started = True
        return None

    def value(self, channel):
        return self.channels.get(channel, self.default) & 0x3FF

    def _scan(self, start):
        p = self.p
        q = start
        while q < 64:
            ccw = p.peek16(self.base + CCW_RAM + 2 * q)
            chan = ccw & 0x3F
            if chan == END_OF_QUEUE:
                break
            v = self.value(chan)
            p.poke16(self.base + RESULT_RJ + 2 * q, v)
            p.poke16(self.base + RESULT_LJU + 2 * q, v << 6)
            p.poke16(self.base + RESULT_LJS + 2 * q, ((v - 0x200) << 6) & 0xFFFF)
            q += 1

    def service(self):
        """Complete a software-started queue 1 scan, if one is due."""
        if self.q1_due:
            self.q1_due = False
            p = self.p
            p.poke16(self.base + QACR1, p.peek16(self.base + QACR1) & ~SSE1)
            self._scan(0)
            p.poke16(self.base + QASR0, p.peek16(self.base + QASR0) | CF1)
            self.single_scans += 1

    def periodic(self):
        """One period of queue 2."""
        p = self.p
        qacr2 = p.peek16(self.base + QACR2)
        if (qacr2 >> 8) & 0x1F == 0:
            return
        self._scan(qacr2 & 0x3F)
        p.poke16(self.base + QASR0, p.peek16(self.base + QASR0) | CF2)
        self.scans += 1

    def interrupt_pending(self):
        p = self.p
        qasr = p.peek16(self.base + QASR0)
        return bool((qasr & CF1 and p.peek16(self.base + QACR1) & CIE1) or
                    (qasr & CF2 and p.peek16(self.base + QACR2) & CIE2))
