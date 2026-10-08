"""The MPC555 QSPI (in the QSMCM at 0x305000) and the devices on its chip
selects, as far as the DME uses them.

The DME fills the 32-entry command RAM once at boot and then runs short
queues: SPCR2 holds NEWQP/ENDQP, SPCR1.SPE starts the transfer, SPSR.SPIF
and the QSPI interrupt report completion. Each command byte is
CONT|BITSE|DT|DSCK|PCS3..0; a transaction to a device is the run of
consecutive entries with CONT set, ended by the entry that clears it.

Chip selects seen in the boot's command RAM (docs/protections.md): PCS1
(code 0xD) is the serial EEPROM (`03 00 00` = READ address 0 is the first
transfer); PCS3 (0x7, queues 8-12, single bytes) is the knock-sensor IC,
whose self-test (fault `286A`) wants every byte it was sent echoed back
in the same transfer. PCS0 (0xE, queues 13-20, 8-byte frames), PCS2
(0xB, queues 0-3, 16-bit pairs) and the entries with no chip select
(0xF, queues 21-26) belong to the output-stage IC's traffic; its
self-test (fault `286B`) wants `AA` in one answer slot, and answering
`AA` on any of them does not satisfy it (docs/protections.md), so they
answer as an open bus until the sequence driver is understood.
"""
import struct

QSMCM = 0x305000
SPCR0 = QSMCM + 0x18
SPCR1 = QSMCM + 0x1A
SPCR2 = QSMCM + 0x1C
SPCR3 = QSMCM + 0x1E
SPSR = QSMCM + 0x1F
RX_RAM = QSMCM + 0x140
TX_RAM = QSMCM + 0x180
CMD_RAM = QSMCM + 0x1C0
QUEUE = 32
BITSE = 0x40                 # command RAM: use SPCR0[BITS] instead of 8 bits

SPE = 0x8000
SPIFIE = 0x8000
SPIF = 0x80


class Eeprom25:
    """A 25-series SPI EEPROM with a 16-bit address: READ 03, WRITE 02,
    WREN 06, WRDI 04, RDSR 05, WRSR 01. Blank (0xFF) unless given an image."""

    def __init__(self, size=0x10000, image=None):
        self.data = bytearray(b"\xff" * size)
        if image:
            self.data[:len(image)] = image
        self.write_enabled = False
        self.reads = 0
        self.writes = 0

    def transaction(self, out: bytes) -> bytes:
        if not out:
            return b""
        op = out[0]
        resp = bytearray(len(out))
        if op == 0x03 and len(out) >= 3:                       # READ addr16, then data
            addr = (out[1] << 8) | out[2]
            for i in range(len(out) - 3):
                resp[3 + i] = self.data[(addr + i) % len(self.data)]
            self.reads += 1
        elif op == 0x02 and len(out) >= 3:                     # WRITE addr16, data
            addr = (out[1] << 8) | out[2]
            if self.write_enabled:
                for i, b in enumerate(out[3:]):
                    self.data[(addr + i) % len(self.data)] = b
                self.writes += 1
            self.write_enabled = False
        elif op == 0x06:
            self.write_enabled = True
        elif op == 0x04:
            self.write_enabled = False
        elif op == 0x05:                                       # RDSR: never busy, WEL as set
            resp[1:] = bytes([0x02 if self.write_enabled else 0x00] * (len(out) - 1))
        return bytes(resp)


class OpenDevice:
    """Nothing on the chip select: every bit reads back high."""

    def transaction(self, out: bytes) -> bytes:
        return b"\xff" * len(out)


class EchoDevice:
    """Shifts back what it is sent: the knock-sensor IC, as far as the
    program's self-test of it goes."""

    def transaction(self, out: bytes) -> bytes:
        return bytes(out)


class ConstantDevice:
    """Answers every byte with the same value (for trying a chip select out)."""

    def __init__(self, value):
        self.value = value

    def transaction(self, out: bytes) -> bytes:
        return bytes([self.value]) * len(out)


PCS_KNOCK, PCS_EEPROM = 0x7, 0xD


class Qspi:
    def __init__(self, page, now=None, ips=40_000_000):
        self.page = page
        self.devices = {pcs: OpenDevice() for pcs in range(16)}
        self.eeprom = Eeprom25()
        self.devices[PCS_EEPROM] = self.eeprom           # PCS1 low
        self.devices[PCS_KNOCK] = EchoDevice()
        self.transfers = 0
        self.log = []
        self.now = now                            # instruction counter, or None: transfers complete at once
        self.ips = ips
        self.done_at = None                       # when the running queue completes (SPIF, interrupt)
        self._done_spsr = 0
        page.on_write(SPCR1, self._spcr1_write)

    def _spcr1_write(self, addr, size, value):
        if size == 2 and value & SPE:
            self._transfer()
            return value & ~SPE                   # the queue has run by the time SPE is read back
        return None

    def next_event(self):
        """When the running queue completes, for the slice to end there."""
        return self.done_at

    def service(self):
        """Report completion once the queue's bits have had their time on the
        wire: SPIF, and with it the interrupt, at the instruction they are
        due rather than at the write that started the queue, so a slice can
        run long and still end exactly there."""
        if self.done_at is not None and self.now() >= self.done_at:
            self.done_at = None
            self.page.poke8(SPSR, self._done_spsr)

    def _transfer(self):
        p = self.page
        spcr2 = p.peek16(SPCR2)
        newqp, endqp = spcr2 & 0x1F, (spcr2 >> 8) & 0x1F
        q = newqp
        entries = []
        while True:
            entries.append(q)
            if q == endqp or len(entries) >= QUEUE:
                break
            q = (q + 1) % QUEUE

        # Entry width: 8 bits unless BITSE is set in its command byte, then
        # SPCR0[BITS] (0 = 16). An 8-bit entry sends the low byte only.
        bits = (p.peek16(SPCR0) >> 10) & 0xF
        wide = bits == 0 or bits > 8
        i = 0
        while i < len(entries):
            cmd = p.peek8(CMD_RAM + entries[i])
            pcs = cmd & 0xF
            group = [entries[i]]
            while p.peek8(CMD_RAM + entries[i]) & 0x80 and i + 1 < len(entries) \
                    and (p.peek8(CMD_RAM + entries[i + 1]) & 0xF) == pcs:
                i += 1
                group.append(entries[i])
            i += 1
            widths = [2 if (p.peek8(CMD_RAM + e) & BITSE and wide) else 1 for e in group]
            out = b"".join(p.peek16(TX_RAM + 2 * e).to_bytes(2, "big")[-w:] for e, w in zip(group, widths))
            resp = self.devices[pcs].transaction(out)
            resp = resp.ljust(len(out), b"\xff")[:len(out)]
            k = 0
            for e, w in zip(group, widths):
                p.poke16(RX_RAM + 2 * e, int.from_bytes(resp[k:k + w], "big"))
                k += w
            self.log.append((pcs, out.hex(), resp.hex()))
            if len(self.log) > 200:
                self.log.pop(0)

        self.transfers += 1
        spsr = SPIF | (endqp & 0x1F)
        if self.now is None:
            p.poke8(SPSR, spsr)
            return
        # the queue's time on the wire: its bits at the SPI clock, 40 MHz
        # over twice SPBR (SPCR0 bits 7-0), a byte or a word per entry
        spbr = max(p.peek16(SPCR0) & 0xFF, 1)
        total_bits = sum(16 if (p.peek8(CMD_RAM + e) & BITSE and wide) else 8 for e in entries)
        seconds = total_bits * 2 * spbr / 40_000_000
        self.done_at = self.now() + max(int(seconds * self.ips), 64)
        self._done_spsr = spsr

    def interrupt_pending(self):
        p = self.page
        return bool(p.peek8(SPSR) & SPIF and p.peek16(SPCR2) & SPIFIE)
