"""The QSMCM's SCI1: the DME's K-line UART.

The firmware runs it at 9600 baud (SCBR = 130) with 9-bit frames and
does the even parity itself, so the ninth bit carries the parity of the
byte. Bytes from the tester go in with `send()`; they are presented one
per byte time (`BYTE_INSTRUCTIONS`) so the DME's receive interrupt sees
them the way a real line delivers them. Bytes the DME transmits are
collected in `tx` (and handed to `on_tx` if set) and echoed back into
the receiver, as the single wire does.
"""

QSMCM = 0x305000
QDSCI_IL = QSMCM + 0x4              # SCI interrupt level (bits 2-0); the firmware uses level 0
SCC1R0 = QSMCM + 0x8
SCC1R1 = QSMCM + 0xA
SC1SR = QSMCM + 0xC
SC1DR = QSMCM + 0xE

# SCC1R1
TIE, TCIE, RIE, ILIE, TE, RE = 0x80, 0x40, 0x20, 0x10, 0x08, 0x04
# SC1SR
TDRE, TC, RDRF, RAF, IDLE, OR = 0x100, 0x80, 0x40, 0x20, 0x10, 0x08

BYTE_INSTRUCTIONS = 40_000_000 * 11 // 9600      # one 9600-baud frame of 11 bits at 40 MHz


class Sci:
    def __init__(self, page, now):
        self.p = page
        self.now = now
        self.rx_queue = []                # bytes from the tester, not yet presented
        self.rx_next_at = 0
        self.tx = bytearray()
        self.on_tx = None
        self._rdr = 0
        self._sr_read = False
        page.poke16(SC1SR, TDRE | TC)
        page.on_read(SC1SR, self._sr_read_fn)
        page.on_read(SC1DR, self._dr_read)
        page.on_write(SC1DR, self._dr_write)
        page.on_write(SC1SR, lambda a, size, value: page.peek16(SC1SR))   # read-only

    # ---- registers --------------------------------------------------------
    def _sr_read_fn(self, addr, size):
        self._sr_read = True
        return None

    def _dr_read(self, addr, size):
        # Reading SC1SR with RDRF set and then SC1DR clears RDRF (and OR).
        if self._sr_read:
            self.p.poke16(SC1SR, self.p.peek16(SC1SR) & ~(RDRF | OR))
        self._sr_read = False
        return self._rdr

    def _dr_write(self, addr, size, value):
        if self.p.peek16(SCC1R1) & TE:
            self.tx.append(value & 0xFF)
            if self.on_tx is not None:
                self.on_tx(value & 0xFF)
            # The K line is one wire: the transmitter hears its own byte,
            # and this driver sends the next one from that receive interrupt.
            self.rx_queue.append(value & 0xFF)
        # The byte leaves at once as far as the program can tell.
        self.p.poke16(SC1SR, self.p.peek16(SC1SR) | TDRE | TC)
        return None

    # ---- the line ---------------------------------------------------------
    def send(self, data):
        """Bytes from the tester."""
        self.rx_queue.extend(bytes(data))

    def service(self):
        """Present the next received byte when its byte time has passed."""
        if not self.rx_queue or self.now() < self.rx_next_at:
            return
        if not self.p.peek16(SCC1R1) & RE:
            self.rx_queue.clear()
            return
        sr = self.p.peek16(SC1SR)
        if sr & RDRF:
            sr |= OR                       # the program was too slow: overrun
        b = self.rx_queue.pop(0)
        parity = bin(b).count("1") & 1
        self._rdr = b | (parity << 8)
        self.p.poke16(SC1SR, sr | RDRF)
        self.rx_next_at = self.now() + BYTE_INSTRUCTIONS

    def interrupt_level(self):
        sr = self.p.peek16(SC1SR)
        cr = self.p.peek16(SCC1R1)
        if (cr & RIE and sr & (RDRF | OR)) or (cr & TIE and sr & TDRE) or (cr & TCIE and sr & TC):
            return self.p.peek16(QDSCI_IL) & 0x7
        return None

    @property
    def idle(self):
        return not self.rx_queue
