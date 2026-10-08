"""The MPC555's internal flash (CMF), as the boot loader's driver uses it.

Two modules: A (0x2FC800) is the first 256 KB of the array, B (0x2FC840)
the remaining 192 KB, each in 32 KB blocks. The driver is Motorola's:

  erase    CMFCTL = BLOCK | PE | SES, a write anywhere in the array (the
           interlock), then EHV pulses until the blocks read erased
  program  CMFCTL = BLOCK | SES, the 64-byte page written to each selected
           block, EHV pulses until the margin read of the page is all zero
  both     refused (driver error 0x87) unless CMFCTL[EPEE] reads 1

Pulses are not timed here: the first one does the whole job. After a
program pulse the hardware shows the *program margin read* while SES is
still set: a 1 for every bit that still needs programming, so all zeros
when it is done. That view is put into the emulator's memory for the
written pages and replaced by the real content when SES is cleared.

`image` is what the array holds. The emulator's memory is that plus the
emulator's own patches (see cpu.py), so it is kept apart, like the
external chip's, and is what a reset boots from.
"""
CMF_A, CMF_B = 0x2FC800, 0x2FC840
CMFMCR, CMFTST, CMFCTL = 0x0, 0x4, 0x8
HVS, EPEE, PE, SES, EHV = 0x80000000, 0x20, 0x4, 0x2, 0x1
BLOCK_SHIFT, BLOCK_SIZE, PAGE_SIZE = 8, 0x8000, 0x40


class Cmf:
    def __init__(self, machine, page, epee=lambda: True):
        self.m = machine
        self.p = page
        self.epee = epee                  # the EPEE pin: program/erase enable
        self.image = bytearray(machine.pair.mpc)
        self.size = len(self.image)
        self.modules = {CMF_A: 0x00000, CMF_B: 0x40000}     # register base -> array offset
        self.latched = {base: {} for base in self.modules}  # address -> (size, value)
        self.margin = {base: set() for base in self.modules}
        self.erases = 0
        self.programs = 0
        self.log = []
        for base in self.modules:
            page.on_read(base + CMFCTL, self._ctl_read)
            page.on_write(base + CMFCTL, self._ctl_write)

    # ---- registers --------------------------------------------------------
    def _ctl_read(self, addr, size):
        if size != 4:
            return None
        v = self.p.peek32(addr) & ~(HVS | EPEE)
        return v | (EPEE if self.epee() else 0)

    def _ctl_write(self, addr, size, value):
        if size != 4:
            return None
        base = addr - CMFCTL
        old = self.p.peek32(addr)
        value &= ~(HVS | EPEE)
        if value & SES and not old & SES:
            self.latched[base].clear()
        if value & EHV and not old & EHV and value & SES and self.epee():
            if value & PE:
                self._erase(base, (value >> BLOCK_SHIFT) & 0xFF)
            else:
                self._program(base)
        if old & SES and not value & SES:
            self._end_sequence(base)
        return value

    # ---- the array --------------------------------------------------------
    def _module(self, addr):
        for base, start in self.modules.items():
            if start <= addr < min(start + 8 * BLOCK_SIZE, self.size):
                return base
        return None

    def array_write(self, addr, size, value):
        """A store into the array: program data while a program sequence
        is open, the erase interlock (or nothing) otherwise."""
        base = self._module(addr)
        if base is None:
            return
        ctl = self.p.peek32(base + CMFCTL)
        if ctl & SES and not ctl & (PE | EHV):
            self.latched[base][addr] = (size, value)

    def _store(self, offset, data):
        self.image[offset:offset + len(data)] = data
        self.m.mu.mem_write(offset, bytes(data))

    def _erase(self, base, blocks):
        start = self.modules[base]
        for i in range(8):
            at = start + i * BLOCK_SIZE
            if blocks & (0x80 >> i) and at < self.size:
                self._store(at, b"\xff" * BLOCK_SIZE)
                self.erases += 1
                self.log.append(("erase", at, BLOCK_SIZE))

    def _program(self, base):
        for addr, (size, value) in self.latched[base].items():
            old = int.from_bytes(self.image[addr:addr + size], "big")
            self.image[addr:addr + size] = (old & value).to_bytes(size, "big")   # programming only clears bits
            self.margin[base].add(addr & ~(PAGE_SIZE - 1))
            self.programs += 1
        self.latched[base].clear()
        for page in self.margin[base]:
            self.m.mu.mem_write(page, bytes(PAGE_SIZE))          # margin read: nothing left to program

    def _end_sequence(self, base):
        for page in self.margin[base]:
            self.m.mu.mem_write(page, bytes(self.image[page:page + PAGE_SIZE]))
        self.margin[base].clear()
        self.latched[base].clear()
