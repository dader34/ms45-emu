"""Peripheral register space as MMIO.

The MPC555's on-chip modules sit at 0x2F8000-0x30FFFF. Mapping those pages
as MMIO means every register access calls into Python, and nothing else
does, which is what keeps emulation fast. Each page has a byte array
behind it, so unmodelled registers simply behave like memory, and the
models hook specific addresses for the registers that must do something.
"""
import struct


class MmioPage:
    """One or more mapped pages with memory-like backing and per-register
    read/write handlers. Handlers get (addr, size, value) and may return a
    value (reads) or the value to store (writes); None means default."""

    def __init__(self, machine, base, size):
        self.m = machine
        self.base = base
        self.size = size
        self.data = bytearray(size)
        self.readers = {}            # addr -> fn(addr, size) -> value or None
        self.writers = {}            # addr -> fn(addr, size, value) -> stored value or None
        machine.mu.mmio_map(base, size, self._read, None, self._write, None)

    # ---- raw backing ------------------------------------------------------
    def peek(self, addr, size):
        off = addr - self.base
        return int.from_bytes(self.data[off:off + size], "big")

    def poke(self, addr, value, size):
        off = addr - self.base
        self.data[off:off + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "big")

    def peek8(self, a):  return self.peek(a, 1)
    def peek16(self, a): return self.peek(a, 2)
    def peek32(self, a): return self.peek(a, 4)
    def poke8(self, a, v):  self.poke(a, v, 1)
    def poke16(self, a, v): self.poke(a, v, 2)
    def poke32(self, a, v): self.poke(a, v, 4)

    # ---- unicorn callbacks ------------------------------------------------
    def _read(self, uc, offset, size, ud):
        addr = self.base + offset
        fn = self.readers.get(addr)
        if fn is not None:
            v = fn(addr, size)
            if v is not None:
                return v
        return self.peek(addr, size)

    def _write(self, uc, offset, size, value, ud):
        addr = self.base + offset
        fn = self.writers.get(addr)
        if fn is not None:
            v = fn(addr, size, value)
            if v is not None:
                value = v
        self.poke(addr, value, size)

    def on_read(self, addr, fn):
        self.readers[addr] = fn

    def on_write(self, addr, fn):
        self.writers[addr] = fn


def write_zero_to_clear(page, addr):
    """Status registers cleared by writing 0 to a flag; 1s leave flags alone."""
    page.on_write(addr, lambda a, size, value: page.peek(a, size) & value)
