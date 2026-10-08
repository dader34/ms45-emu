"""Who reads and writes an address: cross-references from the running program.

A static disassembly answers "which instructions name this address" and
misses everything reached through a pointer, an r2/r13 offset computed at
run time, or a loop over a block. Here the question is put to the
emulator instead: a memory hook on the address while the booted program
runs, and every access is recorded with the instruction that made it, the
value, and where the function it is in was called from (LR).

    x = Xref(board, [parse_address("r13-0x4BEC")])
    board.run(...)
    print(x.report())

Addresses are CPU addresses; `parse_address` also takes the r13/r2
relative forms the disassembly shows (`r13-0x4BEC`, `r2+0x2C`) and a
range (`0x3FA195..0x3FA197`, `0x3FA195:4`). An external-flash address is
watched in both of its windows (0xFFExxxxx and 0xFFFxxxxx are the same
bytes; the program reads the calibration through the first and its own
code and the stored maps through the second).
"""
import struct
from collections import OrderedDict

from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_WRITE
from unicorn.ppc_const import UC_PPC_REG_LR, UC_PPC_REG_PC

from .machine import R13, R2, EXT_BASE, FLASH_SIZE
from .funcmap import FunctionMap

MIRROR = FLASH_SIZE              # the two windows of the external flash are this far apart


def parse_address(text):
    """(start, end) of an address or range, end exclusive.

    `0x3FA195`, `r13-0x4BEC`, `r2+0x2C`, `0x3FA195..0x3FA197` (inclusive
    end, as a disassembly writes it), `0x3FA195:4` (a length), and a
    relative form may take a length too (`r13-0x4BEC:2`)."""
    text = text.strip().replace(" ", "")
    length = None
    if ":" in text:
        text, n = text.rsplit(":", 1)
        length = int(n, 0)
    if ".." in text:
        a, b = text.split("..", 1)
        start, end = _one(a), _one(b) + 1
    else:
        start = _one(text)
        end = start + (length or 1)
    if length is not None and ".." in text:
        raise ValueError(f"{text}: a range and a length")
    if not start < end <= 0x100000000:
        raise ValueError(f"{text}: empty or out of range")
    return start & 0xFFFFFFFF, end


def _one(text):
    low = text.lower()
    for name, base in (("r13", R13), ("r2", R2)):
        if low.startswith(name):
            rest = low[len(name):]
            if rest and rest[0] in "+-":
                return (base + int(rest, 0)) & 0xFFFFFFFF
            if not rest:
                return base
            raise ValueError(f"{text}: expected {name}+offset or {name}-offset")
    return int(text, 0) & 0xFFFFFFFF


def describe(addr, fmap=None):
    """An address with its r13/r2 form beside it when it has one, and its
    name when the function map knows one."""
    text = f"0x{addr:X}"
    for name, base in (("r13", R13), ("r2", R2)):
        off = addr - base
        if -0x8000 <= off < 0x8000:
            text += f" ({name}{off:+#x})"
            break
    var = fmap.variable(addr) if fmap is not None else None
    return text + (f" {var}" if var else "")


def function_start(m, pc, limit=0x4000):
    """A guess at the start of the function pc is in, from the code alone,
    for code the function map does not cover (a routine copied to RAM):
    walking back, the nearest `stwu r1,-N(r1)` or `mflr r0` is a prologue,
    and a `blr` before either ends the previous function, so the function
    starts after it (leaf functions have no prologue). None when neither is
    found within limit bytes."""
    pc &= 0xFFFFFFFF
    at = pc
    while at > pc - limit and at >= 4:
        try:
            w = m.read32(at)
        except Exception:                      # off the mapped memory
            return None
        if _prologue(w):
            while _prologue(m.read32(at - 4)):  # stwu r1 then mflr r0, in either order
                at -= 4
            return at
        if at != pc and w == 0x4E800020:
            start = at + 4
            while m.read32(start) in (0, 0x60000000):    # padding between functions
                start += 4
            return start
        at -= 4
    return None


def _prologue(w):
    return w == 0x7C0802A6 or (w >> 26 == 37 and (w >> 21) & 31 == 1 and (w >> 16) & 31 == 1)


class Site:
    """One instruction's accesses to the watched address."""
    __slots__ = ("pc", "kind", "count", "sizes", "values", "callers", "function", "first_at", "addrs")

    def __init__(self, pc, kind, first_at):
        self.pc = pc
        self.kind = kind
        self.count = 0
        self.sizes = set()
        self.values = OrderedDict()            # value -> times, first seen first
        self.callers = OrderedDict()           # LR -> times
        self.function = None
        self.first_at = first_at
        self.addrs = set()


class Xref:
    MAX_VALUES = 8                            # distinct values kept per site
    MAX_CALLERS = 8

    def __init__(self, board, ranges, trace=None, trace_limit=200, fmap=None):
        """ranges: [(start, end)] from parse_address. trace(text) is called
        for each of the first trace_limit accesses as they happen. fmap is
        the pair's FunctionMap, made here when not given."""
        self.board = board
        self.m = board.m
        self.fmap = fmap if fmap is not None else FunctionMap(board.m.pair)
        self.ranges = list(ranges)
        self.trace = trace
        self.trace_limit = trace_limit
        self.traced = 0
        self.sites = OrderedDict()            # (pc, kind) -> Site
        self.reads = self.writes = 0
        self.functions = {}                   # pc -> function_start(pc), cached: LRs repeat
        self.hooks = []
        mu = self.m.mu
        for start, end in self.ranges:
            windows = [(start, end)]
            if EXT_BASE <= start < EXT_BASE + 2 * MIRROR:
                other = start + (MIRROR if start < EXT_BASE + MIRROR else -MIRROR)
                windows.append((other, other + (end - start)))
            for s, e in windows:
                self.hooks.append(mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._access, begin=s, end=e - 1))
        # Code translated before the hooks existed may not check them: start afresh.
        mu.ctl_flush_tb()

    def detach(self):
        for h in self.hooks:
            self.m.mu.hook_del(h)
        self.hooks = []

    def _access(self, mu, access, addr, size, value, ud):
        write = access == UC_MEM_WRITE
        if not write:
            # The read hook runs before the load: the value is what is in memory now.
            try:
                value = int.from_bytes(mu.mem_read(addr, size), "big")
            except Exception:
                value = None
        pc = mu.reg_read(UC_PPC_REG_PC) & 0xFFFFFFFF
        kind = "W" if write else "R"
        site = self.sites.get((pc, kind))
        if site is None:
            site = self.sites[(pc, kind)] = Site(pc, kind, self.board.instructions)
            site.function = self._function(pc)
        lr = self._caller(mu, site.function)
        site.count += 1
        site.sizes.add(size)
        site.addrs.add(addr)
        if value in site.values:
            site.values[value] += 1
        elif len(site.values) < self.MAX_VALUES:
            site.values[value] = 1
        if lr in site.callers:
            site.callers[lr] += 1
        elif len(site.callers) < self.MAX_CALLERS:
            site.callers[lr] = 1
        if write:
            self.writes += 1
        else:
            self.reads += 1
        if self.trace is not None and self.traced < self.trace_limit:
            self.traced += 1
            self.trace(f"{self.board.instructions / self.board.ips * 1000:9.3f} ms  {kind} 0x{addr:X}"
                       f"{'' if size == 1 else f'/{size}'} = {_fmt(value, size)}  pc 0x{pc:X}"
                       f"{self._fn(site.function)}  lr 0x{lr:X}")

    def _function(self, pc):
        """The start of the function pc is in: from the map, or guessed
        from the code around pc where the map has nothing (RAM copies)."""
        f = self.functions.get(pc)
        if f is None and pc not in self.functions:
            found = self.fmap.at(pc)
            f = self.functions[pc] = found.start if found is not None else function_start(self.m, pc)
        return f

    def _fn(self, function):
        if function is None:
            return " in ?"
        f = self.fmap.at(function)
        return f" in {f.label}" if f is not None and f.start == function else f" in ~0x{function:X}"

    def _caller(self, mu, function):
        """Where the function the access is in was called from. That is LR,
        unless the function has called something itself since (LR then
        points back into it): a function that calls has a frame, and its
        prologue saved the LR it was entered with in the caller's frame,
        at 4 off the back chain."""
        lr = mu.reg_read(UC_PPC_REG_LR) & 0xFFFFFFFF
        if function is not None and self._function(lr) == function:
            try:
                saved = self.m.read32(self.m.read32(self.m.reg(1)) + 4)
            except Exception:
                return lr
            if saved and self._function(saved) is not None:
                return saved
        return lr

    def report(self):
        out = []
        for start, end in self.ranges:
            what = describe(start, self.fmap) if end == start + 1 else f"{describe(start, self.fmap)}..0x{end - 1:X}"
            out.append(f"{what}: {self.reads} reads, {self.writes} writes, {len(self.sites)} sites")
        for site in sorted(self.sites.values(), key=lambda s: (s.function or s.pc, s.pc)):
            sizes = "/".join(str(s) for s in sorted(site.sizes))
            values = ", ".join(_fmt(v, max(site.sizes)) + _times(n) for v, n in site.values.items())
            if len(site.values) >= self.MAX_VALUES:
                values += ", ..."
            callers = ", ".join(f"0x{lr:X} ({self.fmap.label(lr)})" + _times(n) for lr, n in site.callers.items())
            if len(site.callers) >= self.MAX_CALLERS:
                callers += ", ..."
            at = "" if len(site.addrs) == 1 else f"  at {' '.join(f'0x{a:X}' for a in sorted(site.addrs)[:4])}{' ...' if len(site.addrs) > 4 else ''}"
            out.append(f"  {site.kind} pc 0x{site.pc:X}{self._fn(site.function)}  x{site.count} size {sizes}{at}\n"
                       f"      values {values}\n"
                       f"      lr {callers}")
        return "\n".join(out)


def _times(n):
    return f" x{n}" if n > 1 else ""


def _fmt(value, size):
    if value is None:
        return "?"
    return f"{value:0{2 * size}X}"
