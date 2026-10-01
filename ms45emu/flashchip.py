"""The external flash chip, driven by the DME's own program/erase code.

The MS45's external flash is a word-wide AMD/Spansion command-set device.
The DME's RAM-resident driver unlocks it (AA@555, 55@2AA), issues a
command, then polls the chip until the operation finishes. We do not model
the real toggle-bit/data-poll timing: erase and program are applied to the
backing memory the instant the command completes, so the driver's very
first completion poll reads the final data and the state machine advances.

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
        self.cmd = []                                        # recent (offset, value) command cycles
        self.autoselect = False
        self.erases = 0
        self.programs = 0
        self.log = []

    # ---- helpers ----------------------------------------------------------
    def add_window(self, base):
        if base not in self.windows:
            self.windows.append(base)

    def _apply(self, offset, data):
        """Write `data` to the chip image and every mapped window, bypassing
        the read-only protection."""
        offset &= self.size - 1
        for base in self.windows:
            self.m.mu.mem_write(base + offset, data)

    def _read_word(self, offset):
        return int.from_bytes(self.m.read(self.windows[0] + (offset & (self.size - 1)), 2), "big")

    def _erase_range(self, offset, length):
        offset &= self.size - 1
        self._apply(offset, b"\xff" * length)
        self.erases += 1
        self.log.append(("erase", offset, length))

    # ---- the write hook ---------------------------------------------------
    def write(self, addr, size, value):
        """A store into the chip window. Returns True if it was a command."""
        offset = addr & (self.size - 1)
        low = offset & 0xFFE          # command-matching address (word aligned)
        v = value & 0xFF

        # Reset / read array
        if v == CMD_RESET:
            self.cmd.clear(); self.autoselect = False
            return True

        self.cmd.append((low, v))
        self.cmd = self.cmd[-6:]

        # Program: AA, 55, A0, then <addr>=<data>
        if len(self.cmd) >= 4 and self.cmd[-4:-1] == [(UNLOCK1_ADDR, CMD_UNLOCK1),
                                                       (UNLOCK2_ADDR, CMD_UNLOCK2),
                                                       (UNLOCK1_ADDR, CMD_PROGRAM)]:
            # flash programming only clears bits: new = old & written
            old = self._read_word(offset)
            self._apply(offset, (old & value & 0xFFFF).to_bytes(2, "big"))
            self.programs += 1
            self.cmd.clear()
            return True

        # Sector erase: AA, 55, 80, AA, 55, 30@sector
        if len(self.cmd) >= 6 and self.cmd[-6:-1] == [(UNLOCK1_ADDR, CMD_UNLOCK1),
                                                      (UNLOCK2_ADDR, CMD_UNLOCK2),
                                                      (UNLOCK1_ADDR, CMD_ERASE_SETUP),
                                                      (UNLOCK1_ADDR, CMD_UNLOCK1),
                                                      (UNLOCK2_ADDR, CMD_UNLOCK2)] and v == CMD_SECTOR_ERASE:
            self._erase_sector(offset)
            self.cmd.clear()
            return True

        # Chip erase: AA, 55, 80, AA, 55, 10
        if len(self.cmd) >= 6 and self.cmd[-6:] == [(UNLOCK1_ADDR, CMD_UNLOCK1),
                                                    (UNLOCK2_ADDR, CMD_UNLOCK2),
                                                    (UNLOCK1_ADDR, CMD_ERASE_SETUP),
                                                    (UNLOCK1_ADDR, CMD_UNLOCK1),
                                                    (UNLOCK2_ADDR, CMD_UNLOCK2),
                                                    (UNLOCK1_ADDR, CMD_CHIP_ERASE)]:
            self._erase_range(0, self.size)
            self.cmd.clear()
            return True

        if v == CMD_AUTOSELECT:
            self.autoselect = True
        return True

    def _erase_sector(self, offset):
        # Uniform 64 KB sectors is close enough; the driver erases on 64 KB
        # boundaries and the KWP job gives the range anyway.
        sector = offset & ~0xFFFF
        self._erase_range(sector, 0x10000)

    # Some drivers erase by writing a region command rather than 0x30; the
    # board also calls this directly from the KWP erase job as a shortcut.
    def erase_region(self, offset, length):
        self._erase_range(offset, length)
