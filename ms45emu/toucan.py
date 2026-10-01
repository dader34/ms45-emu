"""The MPC555's TouCAN modules, as far as the DME uses them.

Module A (0x307080) is the vehicle bus (PT-CAN): the DME receives ASC,
EGS and instrument-cluster frames in message buffers 0-10 and transmits
0x545, 0x338, 0x329 and 0x316 from buffers 11-14, polling IFLAG. Module B
(0x307480) carries ISO-TP style 0x7Ex identifiers and is interrupt driven.

Frames the DME sends are appended to `tx_log` (and handed to `on_tx` if
set); frames from the car go in with `receive(id, data)`, which lands them
in the first empty receive buffer whose identifier matches, as the
hardware's acceptance filter would.
"""
from collections import namedtuple

Frame = namedtuple("Frame", "id data extended time")

# register offsets from the module base
MCR, TCR, ICR, CTRL0, CTRL1, PRESDIV, CTRL2, TIMER = 0x0, 0x2, 0x4, 0x6, 0x7, 0x8, 0x9, 0xA
RXGMASK, RX14MASK, RX15MASK = 0x10, 0x14, 0x18
ESTAT, IMASK, IFLAG, RXECTR, TXECTR = 0x20, 0x22, 0x24, 0x26, 0x27
MB0 = 0x80
MB_SIZE = 16
MBS = 16

# CANMCR bits
MCR_STOP, MCR_FRZ, MCR_HALT, MCR_NOTRDY = 0x8000, 0x4000, 0x1000, 0x0800
MCR_SOFTRST, MCR_FRZACK, MCR_STOPACK = 0x0200, 0x0100, 0x0010

# message buffer codes (control/status bits 7-4)
RX_INACTIVE, RX_FULL, RX_EMPTY, RX_OVERRUN = 0x0, 0x2, 0x4, 0x6
TX_INACTIVE, TX_ONCE = 0x8, 0xC

IDE = 0x0008                      # ID_HIGH bit 3: extended identifier


class TouCan:
    def __init__(self, page, base, name, now):
        self.p = page
        self.base = base
        self.name = name
        self.now = now                     # instruction count, for the timer
        self.tx_log = []
        self.on_tx = None
        self.rx_count = 0
        self.rx_dropped = 0
        self.tx_count = 0
        page.on_write(base + MCR, self._mcr_write)
        page.on_read(base + MCR, self._mcr_read)
        page.on_read(base + TIMER, lambda a, s: self.timer())
        # IFLAG and ESTAT flags clear by writing 0 after reading 1, like the
        # other MPC555 status registers (the driver does `andc` and stores).
        for reg in (IFLAG, ESTAT):
            page.on_write(base + reg, lambda a, size, value: page.peek(a, size) & value)
        for n in range(MBS):
            ctl = self.mb(n)
            page.on_write(ctl, lambda a, size, value, n=n: self._mb_control_write(n, a, size, value))
            page.on_write(ctl + 1, lambda a, size, value, n=n: self._mb_control_write(n, a, size, value))
        page.poke16(base + MCR, MCR_FRZ | MCR_HALT | MCR_NOTRDY | MCR_FRZACK)   # reset state

    # ---- registers --------------------------------------------------------
    def mb(self, n):
        return self.base + MB0 + n * MB_SIZE

    def timer(self):
        return (self.now() // 16) & 0xFFFF           # free running at the CAN bit clock, roughly

    def _mcr_read(self, addr, size):
        if size != 2:
            return None
        v = self.p.peek16(addr) & ~(MCR_NOTRDY | MCR_FRZACK | MCR_STOPACK | MCR_SOFTRST)
        if v & (MCR_HALT | MCR_STOP):
            v |= MCR_NOTRDY
        if v & MCR_FRZ and v & MCR_HALT:
            v |= MCR_FRZACK
        if v & MCR_STOP:
            v |= MCR_STOPACK
        return v

    def _mcr_write(self, addr, size, value):
        if size == 2 and value & MCR_SOFTRST:
            for n in range(MBS):
                self.p.poke16(self.mb(n), 0)
            self.p.poke16(self.base + IFLAG, 0)
            self.p.poke16(self.base + IMASK, 0)
            return (value & ~MCR_SOFTRST) | MCR_FRZ | MCR_HALT
        return None

    @property
    def running(self):
        return not self.p.peek16(self.base + MCR) & (MCR_HALT | MCR_STOP)

    def _mb_control_write(self, n, addr, size, value):
        # The code lands in the low byte whether written as a word or a byte.
        if size == 2:
            code = (value >> 4) & 0xF
            length = value & 0xF
        elif addr == self.mb(n) + 1:
            code = (value >> 4) & 0xF
            length = value & 0xF
        else:
            return None
        if code == TX_ONCE:
            self._transmit(n, length)
            return (value & 0xFF00) | (TX_INACTIVE << 4) | length if size == 2 else (TX_INACTIVE << 4) | length
        return None

    # ---- frames -----------------------------------------------------------
    def _mb_id(self, n):
        hi = self.p.peek16(self.mb(n) + 2)
        lo = self.p.peek16(self.mb(n) + 4)
        if hi & IDE:
            return ((hi >> 5) << 18) | ((hi & 0x7) << 15) | (lo >> 1), True
        return hi >> 5, False

    def _transmit(self, n, length):
        ident, ext = self._mb_id(n)
        data = bytes(self.p.data[self.mb(n) + 6 - self.p.base:self.mb(n) + 6 - self.p.base + min(length, 8)])
        frame = Frame(ident, data, ext, self.now())
        self.tx_count += 1
        self.tx_log.append(frame)
        if len(self.tx_log) > 1000:
            del self.tx_log[:500]
        self.p.poke16(self.mb(n) + 0xE, self.timer())
        self.p.poke16(self.base + IFLAG, self.p.peek16(self.base + IFLAG) | (1 << n))
        if self.on_tx is not None:
            self.on_tx(frame)

    def _mask(self, n):
        off = RX14MASK if n == 14 else RX15MASK if n == 15 else RXGMASK
        return self.p.peek32(self.base + off)

    def receive(self, ident, data, extended=False):
        """A frame from the bus. Returns the buffer it landed in, or None."""
        data = bytes(data)[:8]
        if extended:
            key = (((ident >> 18) & 0x7FF) << 21) | (((ident >> 15) & 0x7) << 16) | ((ident & 0x7FFF) << 1) | (IDE << 16)
        else:
            key = (ident & 0x7FF) << 21
        if not self.running:
            self.rx_dropped += 1
            return None
        for n in range(MBS):
            ctl = self.p.peek16(self.mb(n))
            code = (ctl >> 4) & 0xF
            if code not in (RX_EMPTY, RX_FULL, RX_OVERRUN):
                continue
            mb_id = (self.p.peek16(self.mb(n) + 2) << 16) | self.p.peek16(self.mb(n) + 4)
            mask = self._mask(n)
            if (mb_id ^ key) & mask & 0xFFFFFFFE:
                continue
            new_code = RX_OVERRUN if code != RX_EMPTY and self.p.peek16(self.base + IFLAG) & (1 << n) else RX_FULL
            base = self.mb(n) - self.p.base
            self.p.data[base + 2:base + 6] = key.to_bytes(4, "big")
            self.p.data[base + 6:base + 6 + len(data)] = data
            self.p.poke16(self.mb(n), (new_code << 4) | len(data))
            self.p.poke16(self.mb(n) + 0xE, self.timer())
            self.p.poke16(self.base + IFLAG, self.p.peek16(self.base + IFLAG) | (1 << n))
            self.rx_count += 1
            return n
        self.rx_dropped += 1
        return None

    def interrupt_level(self):
        """The SIU level this module requests, or None."""
        if self.p.peek16(self.base + IFLAG) & self.p.peek16(self.base + IMASK):
            return (self.p.peek16(self.base + ICR) >> 8) & 0x7
        return None

    def buffers(self):
        """(n, code, id, length) for every configured message buffer."""
        out = []
        for n in range(MBS):
            ctl = self.p.peek16(self.mb(n))
            if ctl:
                ident, ext = self._mb_id(n)
                out.append((n, (ctl >> 4) & 0xF, ident, ctl & 0xF))
        return out
