"""Explain a routine: the calibration items it reads (by XDF name), the RAM
variables it touches (by name where one is known, else as the
disassembly writes them), and what it calls.

Static first: the function's code is walked with the registers that hold
a calibration or RAM base tracked (r2 = calibration + 0x7FF0, r13 = the
small-data base, `lis/addi/addis/ori` forming addresses, as the map
switch's site scanner in BMWeb does it), so that every load, store and
pointer handed to a callee is attributed. A branch ends what is known of
the registers, r2 and r13 aside. Then, when asked, the emulator confirms
it: a run with memory hooks on the calibration and RAM, counting only
the accesses made from inside the function, with the values seen.

    fm = FunctionMap(pair); x = Xdf.find(pair)
    e = explain(fm, fm.by_name("dme1_builder"), x)
    e.run(board, board.ips // 10)        # optional
    print(e.report())
"""
from collections import Counter, OrderedDict

from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_WRITE
from unicorn.ppc_const import UC_PPC_REG_PC

from .machine import R13, R2
from .funcmap import canonical, branch_target
from .xdf import CAL_BASE

CAL_LENGTH = 0x1D000
CAL_WINDOWS = (0xFFE40000, 0xFFF40000)
RAM_START, RAM_END = 0x3F8000, 0x400000
STACK_START = 0x3FF900                        # above the heap (dme.HEAP_END): frames, not variables
R2_OFFSET = R2 - CAL_BASE                     # 0x7FF0

LOADS = {32: 4, 33: 4, 34: 1, 35: 1, 40: 2, 41: 2, 42: 2, 43: 2, 48: 4, 50: 8}
STORES = {36: 4, 37: 4, 38: 1, 39: 1, 44: 2, 45: 2, 52: 4, 54: 8}
UPDATE_FORMS = {33, 35, 37, 39, 41, 43, 45}
# op 31 indexed forms: xo -> (size, is_store)
INDEXED = {23: (4, False), 55: (4, False), 87: (1, False), 119: (1, False), 279: (2, False), 311: (2, False),
           343: (2, False), 375: (2, False), 151: (4, True), 183: (4, True), 215: (1, True), 247: (1, True),
           407: (2, True), 439: (2, True), 535: (4, False), 599: (8, False), 663: (4, True), 727: (8, True)}
# op 31 forms that write rA (logical/shift) rather than rt
WRITES_RA = {24, 26, 28, 60, 124, 284, 316, 412, 444, 476, 536, 792, 824, 922, 954}
ARG_REGS = range(3, 11)


class Use:
    """One address (a calibration item or a RAM variable) as a function uses it."""
    __slots__ = ("addr", "name", "item", "sites", "reads", "writes", "values")

    def __init__(self, addr, name=None, item=None):
        self.addr = addr
        self.name = name
        self.item = item                      # the XDF item, for calibration
        self.sites = []                       # (pc, how, size): how is R, W, ptr, idx
        self.reads = self.writes = 0          # from the run
        self.values = OrderedDict()

    def hows(self):
        c = Counter(h for _, h, _ in self.sites)
        return ", ".join(f"{h} x{n}" if n > 1 else h for h, n in c.items())


class Explanation:
    def __init__(self, fm, function, xdf=None):
        self.fm = fm
        self.f = function
        self.xdf = xdf
        self.calls = Counter()                # callee start -> sites
        self.cal = OrderedDict()              # offset (of the item, or the access) -> Use
        self.ram = OrderedDict()              # address -> Use
        self.unknown = []                     # (pc, how) accesses through registers nothing is known of
        self.ran = 0
        self._scan()

    # ---- static ------------------------------------------------------------------
    def _cal_use(self, offset, pc, how, size):
        if not 0 <= offset < CAL_LENGTH:
            return
        item = self.xdf.at(offset) if self.xdf is not None else None
        key = item.offset if item is not None else offset
        use = self.cal.get(key)
        if use is None:
            use = self.cal[key] = Use(CAL_BASE + key, item.name if item else None, item)
        use.sites.append((pc, how, size))

    def _ram_use(self, addr, pc, how, size):
        use = self.ram.get(addr)
        if use is None:
            use = self.ram[addr] = Use(addr, self.fm.variable(addr))
        use.sites.append((pc, how, size))

    def _use(self, where, pc, how, size):
        kind, value = where
        if kind == "cal":
            self._cal_use(value, pc, how, size)
        elif kind == "ram":
            self._ram_use(value, pc, how, size)
        else:
            for window in CAL_WINDOWS:
                if window <= value < window + CAL_LENGTH:
                    return self._cal_use(value - window, pc, how, size)
            if RAM_START <= value < STACK_START:
                self._ram_use(value, pc, how, size)

    def _scan(self):
        f = self.f
        words = self.fm.words
        bases = {2: ("cal", R2_OFFSET), 13: ("ram", R13)}
        for pc in range(f.start, f.end, 4):
            w = words.get(pc)
            if w is None:
                break
            op = w >> 26
            rt, ra, d = (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
            if d & 0x8000:
                d -= 0x10000
            if op in (16, 18, 19):
                bt = branch_target(pc, w)
                if bt is not None and bt[1]:                       # bl: a callee, with the pointers it gets
                    target = canonical(bt[0])
                    self.calls[target] += 1
                    for reg in ARG_REGS:
                        if reg in bases:
                            self._use(bases[reg], pc, "ptr", 0)
                elif op == 18 and bt is not None and not bt[1] and not (f.start <= canonical(bt[0]) < f.end):
                    self.calls[canonical(bt[0])] += 1              # a tail call
                bases = {2: ("cal", R2_OFFSET), 13: ("ram", R13)}
                continue
            new = None
            if op == 15:                                            # addis / lis
                if ra == 0:
                    new = (rt, ("abs", (d << 16) & 0xFFFFFFFF))
                elif ra in bases:
                    kind, v = bases[ra]
                    new = (rt, (kind, (v + (d << 16)) & 0xFFFFFFFF))
            elif op == 14:                                          # addi / li
                if ra == 0:
                    new = (rt, ("abs", d & 0xFFFFFFFF))
                elif ra in bases:
                    kind, v = bases[ra]
                    new = (rt, (kind, (v + d) & 0xFFFFFFFF))
            elif op == 24 and rt in bases and bases[rt][0] == "abs":    # ori rA, rS, imm (rS is the rt field)
                new = (ra, ("abs", bases[rt][1] | (w & 0xFFFF)))
            elif op in LOADS or op in STORES:
                if ra in bases:
                    kind, v = bases[ra]
                    self._use((kind, (v + d) & 0xFFFFFFFF), pc, "W" if op in STORES else "R", (LOADS | STORES)[op])
                    if op in UPDATE_FORMS:
                        new = (ra, (kind, (v + d) & 0xFFFFFFFF))
                elif ra != 0:
                    self.unknown.append((pc, "W" if op in STORES else "R"))
            elif op == 31 and (w >> 1) & 0x3FF in INDEXED:
                size, store = INDEXED[(w >> 1) & 0x3FF]
                rb = (w >> 11) & 31
                base = bases.get(ra) or bases.get(rb)
                if base is not None:
                    self._use(base, pc, "idx", size)
                else:
                    self.unknown.append((pc, "W" if store else "R"))
            for reg in _written(w):
                if reg not in (2, 13):
                    bases.pop(reg, None)
            if new is not None and new[0] not in (2, 13) and new[0] != 0:
                bases[new[0]] = new[1]

    # ---- dynamic -----------------------------------------------------------------
    def run(self, board, instructions, run=None):
        """Run the board (through run(instructions), board.run by default)
        with hooks on the calibration and RAM (below the stack), counting
        the accesses the function itself makes. Every access of the
        whole program goes through the hook, so this takes about a
        minute and a half of wall time per second of DME time."""
        f = self.f
        mu = board.m.mu

        def access(mu_, kind, addr, size, value, ud):
            pc = canonical(mu_.reg_read(UC_PPC_REG_PC))
            if not f.start <= pc < f.end:
                return
            write = kind == UC_MEM_WRITE
            if not write:
                try:
                    value = int.from_bytes(mu_.mem_read(addr, size), "big")
                except Exception:
                    value = None
            for window in CAL_WINDOWS:
                if window <= addr < window + CAL_LENGTH:
                    offset = addr - window
                    item = self.xdf.at(offset) if self.xdf is not None else None
                    key = item.offset if item is not None else offset
                    use = self.cal.get(key)
                    if use is None:
                        use = self.cal[key] = Use(CAL_BASE + key, item.name if item else None, item)
                        use.sites.append((pc, "run", size))
                    break
            else:
                use = self.ram.get(addr)
                if use is None:
                    use = self.ram[addr] = Use(addr, self.fm.variable(addr))
                    use.sites.append((pc, "run", size))
            if write:
                use.writes += 1
            else:
                use.reads += 1
            if value in use.values:
                use.values[value] += 1
            elif len(use.values) < 6:
                use.values[value] = 1

        hooks = [mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, access, begin=RAM_START, end=STACK_START - 1)]
        for window in CAL_WINDOWS:
            hooks.append(mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, access, begin=window, end=window + CAL_LENGTH - 1))
        mu.ctl_flush_tb()
        try:
            (run or board.run)(instructions)
        finally:
            for h in hooks:
                mu.hook_del(h)
        self.ran += instructions

    # ---- report -------------------------------------------------------------------
    def report(self):
        f, fm = self.f, self.fm
        out = [f"{f.label}  0x{f.start:X}-0x{f.end:X}  {f.size} bytes" + (f"  (found by {'/'.join(sorted(f.sources))})" if not f.name else "")]
        if f.callers:
            out.append("  called from " + ", ".join(f"0x{c:X} ({fm.label(c)})" for c in f.callers[:8]) + (", ..." if len(f.callers) > 8 else ""))
        if self.calls:
            out.append("  calls " + ", ".join(fm.label(t) + (f" x{n}" if n > 1 else "") for t, n in self.calls.most_common()))
        ran = f"  (run: {self.ran / 40_000_000:g} s)" if self.ran else ""
        out.append(f"calibration: {len(self.cal)} items" + (f" ({self.xdf.title})" if self.xdf else " (no XDF: offsets only)") + ran)
        for off, use in sorted(self.cal.items()):
            item = use.item
            what = f"{item.kind} {item.size}B" if item else "?"
            extra = ""
            if item and item.units:
                extra += f" {item.units}"
            if item and item.equation and item.equation not in ("X", "X+0"):
                extra += f" = {item.equation}"
            out.append(f"  0x{off:05X}  {use.name or '-':34} {what:14} {use.hows():16}{self._dyn(use)}{extra}")
        out.append(f"RAM: {len(self.ram)} variables" + ran)
        for addr, use in sorted(self.ram.items()):
            r13 = addr - R13
            form = f"r13{r13:+#x}" if -0x8000 <= r13 < 0x8000 else ""
            out.append(f"  0x{addr:X}  {form:12} {use.name or '-':24} {use.hows():16}{self._dyn(use)}")
        if self.unknown:
            out.append(f"  and {len(self.unknown)} accesses through pointers the scan could not follow"
                       + (" (the run above counts them)" if self.ran else " (--run counts them)"))
        return "\n".join(out)

    def _dyn(self, use):
        if not self.ran:
            return ""
        if not (use.reads or use.writes):
            return "  not touched"
        size = max((s for _, _, s in use.sites if s), default=1)
        values = " ".join(("?" if v is None else f"{v:0{2 * size}X}") + (f"x{n}" if n > 1 else "") for v, n in use.values.items())
        return f"  R{use.reads} W{use.writes}: {values}"


def _written(w):
    """The general registers an instruction writes: enough to stop trusting a base."""
    op = w >> 26
    rt, ra = (w >> 21) & 31, (w >> 16) & 31
    if op in (7, 8, 12, 13, 14, 15) or op in LOADS:
        return [rt] + ([ra] if op in UPDATE_FORMS else [])
    if op in (20, 21, 23, 24, 25, 26, 27, 28, 29):
        return [ra]
    if op in STORES:
        return [ra] if op in UPDATE_FORMS else []
    if op == 31:
        xo = (w >> 1) & 0x3FF
        if xo in INDEXED:
            size, store = INDEXED[xo]
            update = xo in (55, 119, 311, 375, 183, 247, 439)
            return ([] if store else [rt]) + ([ra] if update else [])
        if xo in WRITES_RA or xo & 0x1FF in WRITES_RA:
            return [ra]
        if xo in (144, 146, 210, 467, 598, 854, 982):          # mtcrf mtmsr mtsr mtspr sync icbi dcbz
            return []
        return [rt]
    return []


def explain(fm, function, xdf=None):
    return Explanation(fm, function, xdf)
