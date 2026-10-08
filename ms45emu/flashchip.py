"""The external flash chip, driven by the DME's own program/erase code.

The MS45's external flash is a word-wide AMD burst-mode device with the
sector layout of the Am29BL802CB (1 MB, bottom boot), which is also how
the DME is partitioned: boot loader in the small sectors and the 128 KB
one below 0x40000, calibration in the 128 KB sector at 0x40000, program in
the 128 + 256 + 256 KB above. The DME's RAM-resident driver unlocks it
(AA@555, 55@2AA), issues a command, then polls the chip until the
operation finishes. We do not model the real toggle-bit/data-poll timing:
erase and program are applied the instant the command completes, so the
driver's very first completion poll reads the final data and the state
machine advances.

`image` is what the chip holds. The emulator's memory is that plus the
emulator's own patches (see cpu.py), so the chip content is kept apart
and is what a reset boots from.

Addresses are chip offsets: the chip answers in both the 0xFFE00000 and
0xFFF00000 windows (the 2 MB chip-select over the 1 MB part), and in the
0x02000000 programming window if it is mapped. Writes come through the
board's write-protect hook; `write()` returns True when it consumed the
access as a command (so the raw store stays dropped).
"""
from .machine import EXT_BASE, FLASH_SIZE

# AMD command-set constants (byte addresses on a x16 part: word 0x555 -> 0xAAA)
UNLOCK1_ADDR, UNLOCK2_ADDR = 0xAAA, 0x554
CMD_UNLOCK1, CMD_UNLOCK2 = 0xAA, 0x55
CMD_ERASE_SETUP = 0x80
CMD_SECTOR_ERASE = 0x30
CMD_CHIP_ERASE = 0x10
CMD_PROGRAM = 0xA0
CMD_AUTOSELECT = 0x90
CMD_RESET = 0xF0
CMD_CFI = 0x98

# (offset, size) of each sector
SECTORS = ((0x00000, 0x4000), (0x04000, 0x2000), (0x06000, 0x2000), (0x08000, 0x18000),
           (0x20000, 0x20000), (0x40000, 0x20000), (0x60000, 0x20000),
           (0x80000, 0x40000), (0xC0000, 0x40000))

# Autoselect / CFI identity the driver may read back. Spansion S29 family;
# the driver accepts the sector-protect read either way, so only the
# manufacturer/device words matter if it checks them at all.
MANUF_ID = 0x0001            # AMD/Spansion
DEVICE_ID = 0x227E           # S29 family code


class FlashChip:
    def __init__(self, machine, name="ext"):
        self.m = machine
        self.name = name
        self.size = FLASH_SIZE
        self.windows = [EXT_BASE, EXT_BASE + FLASH_SIZE]     # 0xFFE00000, 0xFFF00000
        self.image = bytearray(machine.pair.flash)
        self.cmd = []                                        # recent (offset, value) command cycles
        self.autoselect = False
        self.erasing = False                                 # a sector erase was issued: more 0x30s may follow
        self.erases = 0
        self.programs = 0
        self.log = []

    # ---- helpers ----------------------------------------------------------
    def add_window(self, base):
        if base not in self.windows:
            self.windows.append(base)

    def store(self, offset, data):
        """Write `data` to the chip image and every mapped window, bypassing
        the read-only protection."""
        offset &= self.size - 1
        self.image[offset:offset + len(data)] = data
        for base in self.windows:
            self.m.mu.mem_write(base + offset, data)

    def _read_word(self, offset):
        offset &= self.size - 1
        return int.from_bytes(self.image[offset:offset + 2], "big")

    def _erase_range(self, offset, length):
        offset &= self.size - 1
        self.store(offset, b"\xff" * length)
        self.erases += 1
        self.log.append(("erase", offset, length))

    # ---- the write hook ---------------------------------------------------
    _UNLOCK = [(UNLOCK1_ADDR, CMD_UNLOCK1), (UNLOCK2_ADDR, CMD_UNLOCK2)]
    _PROGRAM = _UNLOCK + [(UNLOCK1_ADDR, CMD_PROGRAM)]
    _ERASE = _UNLOCK + [(UNLOCK1_ADDR, CMD_ERASE_SETUP)] + _UNLOCK

    def write(self, addr, size, value):
        """A store into the chip window. Returns True if it was a command."""
        offset = addr & (self.size - 1)
        low = offset & 0xFFE          # command-matching address (word aligned)
        v = value & 0xFF

        # The data cycle of a program command (AA, 55, A0, then <addr>=<data>)
        # is data whatever it looks like. Programming only clears bits.
        if self.cmd[-3:] == self._PROGRAM:
            old = self._read_word(offset)
            self.store(offset, (old & value & 0xFFFF).to_bytes(2, "big"))
            self.programs += 1
            self.cmd.clear()
            return True

        # Reset / read array
        if v == CMD_RESET:
            self.cmd.clear(); self.autoselect = False; self.erasing = False
            return True

        # Further sectors of a multi-sector erase come without an unlock.
        if self.erasing and v == CMD_SECTOR_ERASE:
            self._erase_sector(offset)
            return True
        self.erasing = False

        # Sector erase: AA, 55, 80, AA, 55, 30@sector
        if self.cmd[-5:] == self._ERASE and v == CMD_SECTOR_ERASE:
            self._erase_sector(offset)
            self.erasing = True
            self.cmd.clear()
            return True

        # Chip erase: AA, 55, 80, AA, 55, 10
        if self.cmd[-5:] == self._ERASE and (low, v) == (UNLOCK1_ADDR, CMD_CHIP_ERASE):
            self._erase_range(0, self.size)
            self.cmd.clear()
            return True

        self.cmd.append((low, v))
        self.cmd = self.cmd[-6:]
        if v == CMD_AUTOSELECT:
            self.autoselect = True
        return True

    def _erase_sector(self, offset):
        offset &= self.size - 1
        for start, size in SECTORS:
            if start <= offset < start + size:
                self._erase_range(start, size)
                return
