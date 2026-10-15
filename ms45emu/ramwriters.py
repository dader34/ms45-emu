"""Who writes a stretch of SRAM, and when.

The single-value pool (singles.py) is bounded by free RAM, and the SRAM
survey (the boot writes 7.6 KB the emulated engine never touches again)
cannot tell "never written while running" from "that code never ran here".
This answers it from the program itself: every store instruction whose
target address can be read off the code (r13-relative, or lis/addi
absolute), which function it is in, and whether that function is reachable
from an OS task or interrupt (runtime), only from the reset path (init), or
from nothing the call graph shows (pointer-called: unknown). Stores through
a pointer the code computes at run time cannot be placed; the functions
holding them are listed so the risk is visible rather than hidden.

A coverage run (survey) adds what the emulator saw: the bytes each phase
of life wrote, and the functions that ran while the engine was running --
a function that ran is runtime whatever the call graph says.
"""
from collections import namedtuple

from .funcmap import FunctionMap, canonical
from .ppc import R13

Store = namedtuple("Store", "pc function addr size base")   # base: 'r13', 'abs', 'r13+'
Writer = namedtuple("Writer", "pc function phase task size")

D_STORES = {36: 4, 37: 4, 38: 1, 39: 1, 44: 2, 45: 2, 52: 4, 53: 4, 54: 8, 55: 8}   # stw(u) stb(u) sth(u) stfs(u) stfd(u)
X_STORES = {151: 4, 183: 4, 215: 1, 247: 1, 407: 2, 439: 2, 663: 4, 695: 4, 727: 8, 759: 8, 918: 2, 662: 4}
STMW, STSWI = 47, 725
BCTRL = 0x4E800421
INDEX_REACH = 0x200                 # how far below a stretch an indexed store's base still counts


def _sext16(v):
    return v - 0x10000 if v & 0x8000 else v


def _base_value(fm, f, pc, ra):
    """What register ra holds at pc, when the function set it with lis (+addi/ori)
    or addis/addi from r13 a few instructions back with no other definition
    in between; None for anything computed."""
    hi = None
    for back in range(pc - 4, max(f.start, pc - 64) - 4, -4):
        w = fm.words.get(back, 0)
        op, rt, ra2 = w >> 26, (w >> 21) & 31, (w >> 16) & 31
        if op in (16, 18) or w in (0x4E800020, 0x4E800420, BCTRL):
            return None                                     # a branch between: not straight-line
        if op == 15 and rt == ra:                           # lis / addis
            if ra2 == 0:
                return ((_sext16(w & 0xFFFF) << 16) + (hi or 0)) & 0xFFFFFFFF
            if ra2 == 13:
                return (R13 + (_sext16(w & 0xFFFF) << 16) + (hi or 0)) & 0xFFFFFFFF
            return None
        if op in (14, 24) and rt == ra and ra2 == ra:       # addi / ori rA, rA, lo: keep looking for the lis
            if hi is not None:
                return None
            hi = _sext16(w & 0xFFFF) if op == 14 else (w & 0xFFFF)
            continue
        if op == 14 and rt == ra and ra2 == 13:             # addi rA, r13, d
            return (R13 + _sext16(w & 0xFFFF) + (hi or 0)) & 0xFFFFFFFF
        if op == 32 and rt == ra and ra2 == 13 and hi is None:   # lwz rA, d(r13): a pointer the
            return ("ptr", (R13 + _sext16(w & 0xFFFF)) & 0xFFFFFFFF)   # boot set up; read it from RAM
        if rt == ra and (op in (14, 15, 24, 25, 32, 33, 34, 35, 40, 41, 42, 43) or op == 31):
            return None                                     # redefined some other way
    return None


def scan_stores(fm, read32=None):
    """Every store in the program with a placeable target: [Store]; and the
    functions holding stores through computed pointers: {function: count}.
    `read32(addr)` (a booted board's RAM) places stores through a pointer
    the program keeps in its small data, as the boot set it."""
    placed, pointer = [], {}
    for f in fm.functions:
        for pc in range(f.start, f.end, 4):
            w = fm.words.get(pc)
            if w is None:
                continue
            op = w >> 26
            rs, ra = (w >> 21) & 31, (w >> 16) & 31
            size = None
            if op in D_STORES or op == STMW:
                size = 4 * (32 - rs) if op == STMW else D_STORES[op]
                d = _sext16(w & 0xFFFF)
                rb = None
            elif op == 31 and ((w >> 1) & 0x3FF) in X_STORES or (op == 31 and (w >> 1) & 0x3FF == STSWI):
                xo = (w >> 1) & 0x3FF
                size = (((w >> 11) & 31) or 32) if xo == STSWI else X_STORES[xo]
                d, rb = 0, (w >> 11) & 31
            if size is None:
                continue
            if ra in (1, 2):                                # the stack, the calibration
                continue
            if rb is not None and rb != 0:                  # X-form with an index register: an
                base = (R13 if ra == 13 else _base_value(fm, f, pc, ra)) if ra else None   # array whose
                if isinstance(base, tuple):                 # base may be placeable, extent is not
                    base = read32(base[1]) if read32 else None
                if base is None:
                    pointer[f] = pointer.get(f, 0) + 1
                else:
                    placed.append(Store(pc, f, base & 0xFFFFFFFF, 0, "indexed"))
                continue
            if ra == 13:
                placed.append(Store(pc, f, (R13 + d) & 0xFFFFFFFF, size, "r13"))
                continue
            base = _base_value(fm, f, pc, ra) if ra else 0
            kind = "abs"
            if isinstance(base, tuple):
                base = read32(base[1]) if read32 else None
                kind = "ptr"
            if base is None:
                pointer[f] = pointer.get(f, 0) + 1
            else:
                placed.append(Store(pc, f, (base + d) & 0xFFFFFFFF, size, kind))
    return placed, pointer


def call_graph(fm):
    """{function: set(functions it reaches by bl or a tail b)}, and the functions with a bctrl."""
    calls = {f: set() for f in fm.functions}
    indirect = set()
    for f in fm.functions:
        for pc in range(f.start, f.end, 4):
            w = fm.words.get(pc, 0)
            if w == BCTRL:
                indirect.add(f)
            if w >> 26 == 18:
                li = w & 0x03FFFFFC
                if li & 0x02000000:
                    li -= 0x04000000
                target = canonical((li if w & 2 else pc + li) & 0xFFFFFFFF)
                g = fm.at(target)
                if g is not None and g is not f and (w & 1 or target == g.start):
                    calls[f].add(g)
    return calls, indirect


def closure(calls, roots):
    seen, frontier = set(roots), list(roots)
    while frontier:
        f = frontier.pop()
        for g in calls.get(f, ()):
            if g not in seen:
                seen.add(g)
                frontier.append(g)
    return seen


def phases(fm, executed=()):
    """{function: 'runtime' | 'init' | 'unknown'}: runtime when reachable from
    an OS task, an interrupt handler or an exception vector (or seen running);
    init when reachable from the reset path only."""
    calls, _ = call_graph(fm)
    runtime_roots = [f for f in fm.functions
                     if "task" in f.sources or "interrupt" in f.sources
                     or (f.name and (f.name.startswith("task") or f.name.endswith("_task")))
                     or (f.name and f.name.startswith("vector") and f.name != "vector0")]
    runtime = closure(calls, runtime_roots) | {f for f in fm.functions if f.start in executed}
    reset = fm.by_name("vector0") or fm.at(0)
    # the stored-data block routines (init, restore, save) are pointer-called at
    # the boot and the key-off: not the running engine
    nv = [f for f in fm.functions if "nvtable" in f.sources]
    init = closure(calls, ([reset] if reset else []) + nv) - runtime
    out = {}
    for f in fm.functions:
        out[f] = "runtime" if f in runtime else "init" if f in init else "unknown"
    return out


def task_of(fm, f, depth=8):
    seen, frontier = set(), [f]
    for _ in range(depth):
        nxt = []
        for g in frontier:
            if g.name and (g.name.startswith("task") or g.name.endswith("_task")):
                return g.label
            if "interrupt" in g.sources:
                return "interrupt"
            for c in g.callers:
                h = fm.at(c)
                if h is not None and h.start not in seen:
                    seen.add(h.start)
                    nxt.append(h)
        frontier = nxt
        if not frontier:
            break
    return None


class Writers:
    def __init__(self, pair, executed=(), read32=None):
        self.fm = FunctionMap(pair)
        self.stores, self.pointer_functions = scan_stores(self.fm, read32)
        self.phase = phases(self.fm, executed)
        # an indexed array's extent is taken to end where the next placed
        # variable starts (the compiler lays them out back to back), capped
        self._starts = sorted({s.addr for s in self.stores if s.base != "indexed"})

    def extent(self, base):
        import bisect
        i = bisect.bisect_right(self._starts, base)
        nxt = self._starts[i] if i < len(self._starts) else base + INDEX_REACH
        return max(1, min(nxt - base, INDEX_REACH))

    def of(self, lo, hi):
        """The placed stores that hit [lo, hi), as Writers (an indexed array
        store carries size 0; see `extent`)."""
        out = []
        for s in self.stores:
            if s.base == "indexed":
                if s.addr != R13 and s.addr < hi and s.addr + self.extent(s.addr) > lo:
                    out.append(Writer(s.pc, s.function, self.phase[s.function], task_of(self.fm, s.function), 0))
            elif s.addr < hi and s.addr + s.size > lo:
                out.append(Writer(s.pc, s.function, self.phase[s.function], task_of(self.fm, s.function),
                                  s.size if s.base != "ptr" else -s.size))
        return sorted(out, key=lambda w: (w.phase != "runtime", w.size == 0, w.pc))

    def free_within(self, lo, hi, least=16):
        """The sub-stretches of [lo, hi) no run-time or unknown-phase placed
        store (array extents included) reaches: [(lo, hi)] of `least` bytes or more."""
        hit = bytearray(hi - lo)
        for s in self.stores:
            if self.phase[s.function] == "init":
                continue
            n = self.extent(s.addr) if s.base == "indexed" else s.size
            if s.base == "indexed" and s.addr == R13:
                continue
            for a in range(max(s.addr, lo), min(s.addr + n, hi)):
                hit[a - lo] = 1
        out, start = [], None
        for i in range(hi - lo + 1):
            ok = i < hi - lo and not hit[i]
            if ok and start is None:
                start = i
            if not ok and start is not None:
                if i - start >= least:
                    out.append((lo + start, lo + i))
                start = None
        return out

    def pointer_risk(self):
        """Functions that store through computed pointers, by phase."""
        by = {"runtime": [], "init": [], "unknown": []}
        for f, n in self.pointer_functions.items():
            by[self.phase[f]].append((f, n))
        return by

    def verdict(self, lo, hi):
        ws = self.of(lo, hi)
        if any(w.phase == "runtime" and w.size for w in ws):
            return "RUNTIME writer"
        if any(w.phase == "runtime" for w in ws):
            return "run-time array nearby (extent unknown)"
        if any(w.phase == "unknown" for w in ws):
            return "writer of unknown phase"
        if ws:
            return "init-only writers"
        return "no placeable writer"
