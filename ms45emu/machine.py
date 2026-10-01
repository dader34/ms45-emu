"""An MPC555 as the MS45.1 program sees it, enough to run its routines.

Memory map (CPU addresses):

  0x00000000  MPC internal flash, 448 KB (the "MPC" image)
  0x002F8000  SIU / memory controller / peripheral registers (IMMR = 0x002F0000)
  0x003F8000  internal SRAM up to 0x00400000; r1 starts at 0x00400000
  0xFFE00000  external flash, 2 MB chip-select window over the 1 MB chip, so
              0xFFExxxxx and 0xFFFxxxxx are the same bytes. The program lives
              at 0xFFF60000+, the calibration is addressed as 0xFFE40000+.

Register conventions of the program: r2 = 0xFFE47FF0 (calibration base),
r13 = 0x004017F0 (small-data base).

Peripheral space is mapped as plain RAM reading zero; tests that need a
register to behave install a hook.
"""
import struct

from unicorn import Uc, UC_ARCH_PPC, UC_MODE_32, UC_MODE_BIG_ENDIAN, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_CODE, UcError
from unicorn.ppc_const import UC_PPC_REG_0, UC_PPC_REG_PC, UC_PPC_REG_LR, UC_PPC_REG_CR, UC_PPC_REG_XER, UC_PPC_REG_CTR

R13 = 0x004017F0
R2 = 0xFFE47FF0

MPC_BASE = 0x00000000
MPC_MAP = 0x80000               # mapped size, page rounded
PERIPH_BASE = 0x002F0000
PERIPH_SIZE = 0x20000
RAM_BASE = 0x003F0000
RAM_SIZE = 0x10000              # to 0x00400000
RAM_TOP = RAM_BASE + RAM_SIZE
EXT_BASE = 0xFFE00000
EXT_SIZE = 0x200000
FLASH_SIZE = 0x100000

# Where a routine returns to: an unmapped-looking sentinel that stops emulation.
RETURN_SENTINEL = 0x00100000
SENTINEL_SIZE = 0x1000

MAX_INSNS = 50_000_000


class Machine:
    def __init__(self, pair, periph_ram=True):
        """periph_ram: map the peripheral space as plain RAM (reads zero).
        The board turns this off and maps the pages as MMIO instead."""
        self.pair = pair
        mu = Uc(UC_ARCH_PPC, UC_MODE_32 | UC_MODE_BIG_ENDIAN)
        self.mu = mu

        mu.mem_map(MPC_BASE, MPC_MAP)
        mu.mem_write(MPC_BASE, pair.mpc)

        mu.mem_map(EXT_BASE, EXT_SIZE)
        mu.mem_write(EXT_BASE, pair.flash)
        mu.mem_write(EXT_BASE + FLASH_SIZE, pair.flash)      # the mirror

        if periph_ram:
            mu.mem_map(PERIPH_BASE, PERIPH_SIZE)
        mu.mem_map(RAM_BASE, RAM_SIZE)
        mu.mem_map(RETURN_SENTINEL, SENTINEL_SIZE)

        self.reset_registers()

    # ---- registers -------------------------------------------------------
    def reset_registers(self):
        mu = self.mu
        for i in range(32):
            mu.reg_write(UC_PPC_REG_0 + i, 0)
        mu.reg_write(UC_PPC_REG_0 + 1, RAM_TOP - 0x100)   # stack with a little headroom
        mu.reg_write(UC_PPC_REG_0 + 2, R2)
        mu.reg_write(UC_PPC_REG_0 + 13, R13)
        mu.reg_write(UC_PPC_REG_CR, 0)
        mu.reg_write(UC_PPC_REG_XER, 0)
        mu.reg_write(UC_PPC_REG_CTR, 0)

    def reg(self, n):
        return self.mu.reg_read(UC_PPC_REG_0 + n) & 0xFFFFFFFF

    def set_reg(self, n, value):
        self.mu.reg_write(UC_PPC_REG_0 + n, value & 0xFFFFFFFF)

    @property
    def pc(self):
        return self.mu.reg_read(UC_PPC_REG_PC) & 0xFFFFFFFF

    # ---- memory ----------------------------------------------------------
    def read(self, addr, size):
        return bytes(self.mu.mem_read(addr & 0xFFFFFFFF, size))

    def write(self, addr, data):
        self.mu.mem_write(addr & 0xFFFFFFFF, bytes(data))

    def read8(self, addr):  return self.read(addr, 1)[0]
    def read16(self, addr): return struct.unpack(">H", self.read(addr, 2))[0]
    def read32(self, addr): return struct.unpack(">I", self.read(addr, 4))[0]
    def write8(self, addr, v):  self.write(addr, bytes([v & 0xFF]))
    def write16(self, addr, v): self.write(addr, struct.pack(">H", v & 0xFFFF))
    def write32(self, addr, v): self.write(addr, struct.pack(">I", v & 0xFFFFFFFF))

    # r13-relative small data, as the disassembly shows it
    def sda8(self, off):  return self.read8(R13 + off)
    def sda16(self, off): return self.read16(R13 + off)
    def set_sda8(self, off, v):  self.write8(R13 + off, v)
    def set_sda16(self, off, v): self.write16(R13 + off, v)

    def clear_ram(self):
        self.write(RAM_BASE, bytes(RAM_SIZE))

    # ---- running ---------------------------------------------------------
    def call(self, addr, *args, max_insns=MAX_INSNS):
        """Call a routine with r3..r10 = args and run until it returns. Returns r3."""
        mu = self.mu
        for i, a in enumerate(args):
            self.set_reg(3 + i, a)
        mu.reg_write(UC_PPC_REG_LR, RETURN_SENTINEL)
        mu.emu_start(addr & 0xFFFFFFFF, RETURN_SENTINEL, count=max_insns)
        if self.pc != RETURN_SENTINEL:
            raise RuntimeError(f"routine 0x{addr:X} did not return within {max_insns} instructions (pc=0x{self.pc:X})")
        return self.reg(3)

    def run(self, start, until, max_insns=MAX_INSNS):
        """Run from start until pc == until."""
        self.mu.emu_start(start & 0xFFFFFFFF, until & 0xFFFFFFFF, count=max_insns)
        return self.pc

    def hook_code(self, fn):
        """fn(machine, pc, size) on every instruction."""
        return self.mu.hook_add(UC_HOOK_CODE, lambda mu, addr, size, ud: fn(self, addr, size))

    def hook_mem(self, fn, begin, end):
        """fn(machine, is_write, addr, size, value) for accesses in [begin, end)."""
        def cb(mu, access, addr, size, value, ud):
            fn(self, access == 17, addr, size, value)   # UC_MEM_WRITE == 17
        return self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, cb, begin=begin, end=end - 1)
