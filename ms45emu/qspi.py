"""The MPC555 QSPI (in the QSMCM at 0x305000) and the devices on its chip
selects, as far as the DME uses them.

The DME fills the 32-entry command RAM once at boot and then runs short
queues: SPCR2 holds NEWQP/ENDQP, SPCR1.SPE starts the transfer, SPSR.SPIF
and the QSPI interrupt report completion. Each command byte is
CONT|BITSE|DT|DSCK|PCS3..0; a transaction to a device is the run of
consecutive entries with CONT set, ended by the entry that clears it.

Chip selects seen in the boot's command RAM: PCS1 (code 0xD) is the serial
EEPROM (`03 00 00` = READ address 0 is the first transfer); PCS0, PCS2 and
PCS3 are other devices, answered as an open bus until modelled.
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


class Qspi:
    def __init__(self, page):
        self.page = page
        self.devices = {pcs: OpenDevice() for pcs in range(16)}
        self.eeprom = Eeprom25()
        self.devices[0xD] = self.eeprom           # PCS1 low
        self.transfers = 0
        self.log = []
        page.on_write(SPCR1, self._spcr1_write)

    def _spcr1_write(self, addr, size, value):
        if size == 2 and value & SPE:
            self._transfer()
            return value & ~SPE                   # the queue has run by the time SPE is read back
        return None

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
            out = b"".join(struct.pack(">H", p.peek16(TX_RAM + 2 * e)) for e in group)
            resp = self.devices[pcs].transaction(out)
            resp = resp.ljust(len(out), b"\xff")[:len(out)]
            for k, e in enumerate(group):
                p.poke16(RX_RAM + 2 * e, int.from_bytes(resp[2 * k:2 * k + 2], "big"))
            self.log.append((pcs, out.hex(), resp.hex()))
            if len(self.log) > 200:
                self.log.pop(0)

        self.transfers += 1
        p.poke8(SPSR, SPIF | (endqp & 0x1F))

    def interrupt_pending(self):
        p = self.page
        return bool(p.peek8(SPSR) & SPIF and p.peek16(SPCR2) & SPIFIE)
