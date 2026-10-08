"""The program's functions: where they start and end, what calls them,
which of them run, and the names that are known for them.

Three sources, merged:

- a linear sweep of the code images (`cpu.code_images`): every `bl`
  target is a function, so is every `ba` target (the exception vectors)
  and every prologue (`stwu r1,-N(r1)` / `mflr r0`); for the traced
  program the OS task table and the interrupt dispatch table as well.
  A function runs from its entry to the last return (`blr`, `rfi`, a
  branch out) that no branch before it jumps past, so data between
  functions (descriptor tables, constants) is left out;
- execution coverage from a run under `Board` (a block hook; slow, so it
  is opt-in): how often each function's blocks ran and how often it was
  entered;
- names, from `ms45emu/names/<program>.json`: the routines and variables
  traced by hand (dme.py, the docs, the trace notes). Everything else is
  `fn_<addr>`.

    fm = FunctionMap(pair)
    fm.at(0x4B6AC).name            # 'dme1_builder'
    fm.label(0x4B6AC)              # 'dme1_builder+0x184'
    fm.at(0x4B528).callers         # [0x4BE9C]

`to_json()` is the map for other tools, `ghidra_symbols()` the lines for
Ghidra's ImportSymbolsScript.
"""
import bisect
import json
import os
import struct
from collections import Counter

from .cpu import code_images

NAMES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "names")
EXT_LOW, EXT_HIGH = 0xFFE00000, 0xFFF00000     # the two windows of the external flash
MIRROR = 0x100000

BLR, BCTR, RFI = 0x4E800020, 0x4E800420, 0x4C000064
MFLR_R0 = 0x7C0802A6

# Program 0044570LO02S: the OS task table and the interrupt dispatch table
# (docs/full-boot.md). Only looked at for that program. A task record (0x24
# bytes, from 0xB5C0 on) is priority, 1, TCB, id, 0, a pointer, the entry,
# the wrapper, a pointer: the records are found by their wrapper word, with
# the entry just before it and the id 0x10 before that.
TASK_WRAPPER, TASK_ENTRY, TASK_ID = 0x10550, -4, -0x10
INTERRUPT_TABLE, INTERRUPT_LEVELS = 0xB4C4, 16
# The stored-data block descriptors (dme.NV_DESCRIPTOR): init, restore,
# save and a fourth routine per block, pointer-called, many without a
# prologue.
NV_TABLE, NV_ENTRY_SIZE, NV_BLOCKS, NV_POINTERS = 0x28AC, 0x1C, 69, 4


def canonical(addr):
    """External-flash addresses in their 0xFFFxxxxx window."""
    addr &= 0xFFFFFFFF
    if EXT_LOW <= addr < EXT_HIGH:
        addr += MIRROR
    return addr


def branch_target(pc, w):
    """(target, link) of a `b`/`bl`/`ba`/`bla` (op 18) or `bc` form (op 16), else None."""
    op = w >> 26
    if op == 18:
        li = w & 0x03FFFFFC
        if li & 0x02000000:
            li -= 0x04000000
    elif op == 16:
        li = w & 0xFFFC
        if li & 0x8000:
            li -= 0x10000
    else:
        return None
    target = li if w & 2 else pc + li
    return target & 0xFFFFFFFF, bool(w & 1)


def is_prologue(w):
    return w == MFLR_R0 or (w >> 26 == 37 and (w >> 21) & 31 == 1 and (w >> 16) & 31 == 1 and w & 0x8000)


class Function:
    __slots__ = ("start", "end", "name", "callers", "sources", "hits", "entries")

    def __init__(self, start, end, name=None):
        self.start = start
        self.end = end
        self.name = name
        self.callers = []           # pcs of the `bl` instructions that call it
        self.sources = set()        # how it was found: bl, ba, prologue, task, interrupt, coverage
        self.hits = 0               # blocks executed inside it (coverage)
        self.entries = 0            # times entered at its start (coverage)

    @property
    def size(self):
        return self.end - self.start

    @property
    def label(self):
        return self.name or f"fn_{self.start:X}"

    def __repr__(self):
        return f"<{self.label} 0x{self.start:X}-0x{self.end:X}>"


class FunctionMap:
    def __init__(self, pair, names=None):
        self.pair = pair
        self.images = [(canonical(base), data) for base, data in code_images(pair)]
        self.words = {}                     # canonical address -> instruction word, for the code images
        for base, data in self.images:
            n = len(data) // 4
            unpacked = struct.unpack(f">{n}I", data[:4 * n])
            self.words.update(zip(range(base, base + 4 * n, 4), unpacked))
        self.functions = []                 # sorted by start
        self.starts = []
        self.names = names if names is not None else load_names(pair)
        self.variables = {int(k, 16): v for k, v in self.names.get("variables", {}).items()}
        self.blocks = Counter()
        self.stray = Counter()
        self.extra = {}                     # entries found after the sweep (tail calls, coverage), addr -> source
        self._sweep()
        self._tail_calls()

    # ---- the sweep ------------------------------------------------------------
    def in_code(self, addr):
        return addr in self.words

    def _sweep(self):
        entries = {}
        call_sites = []
        for pc, w in self.words.items():
            bt = branch_target(pc, w)
            if bt is not None:
                target, link = bt
                target = canonical(target)
                if w >> 26 == 18 and self.in_code(target):
                    if link:
                        entries.setdefault(target, set()).add("bl")
                        call_sites.append((pc, target))
                    elif w & 2:                               # ba: the vector tables
                        entries.setdefault(target, set()).add("ba")
            if is_prologue(w) and not is_prologue(self.words.get(pc - 4, 0)):
                entries.setdefault(pc, set()).add("prologue")
        self.tasks = {}                     # task id -> entry, for the ids that are unambiguous
        if self.pair.traced:
            ids = Counter()
            for pc, w in self.words.items():
                if w == TASK_WRAPPER and pc < 0x80000 and self.in_code(canonical(self.words.get(pc + TASK_ENTRY, 0))):
                    entry = canonical(self.words[pc + TASK_ENTRY])
                    entries.setdefault(entry, set()).add("task")
                    task = self.words[pc + TASK_ID]
                    ids[task] += 1
                    self.tasks[task] = entry
            for task, n in ids.items():    # the record before the table's first repeats an id: not a task id
                if n > 1:
                    del self.tasks[task]
            for i in range(INTERRUPT_LEVELS):
                handler = self.words.get(INTERRUPT_TABLE + 4 * i)
                if handler and self.in_code(canonical(handler)):
                    entries.setdefault(canonical(handler), set()).add("interrupt")
            for i in range(NV_BLOCKS):
                for k in range(NV_POINTERS):
                    routine = self.words.get(NV_TABLE + NV_ENTRY_SIZE * i + 4 * k)
                    if routine and self.in_code(canonical(routine)):
                        entries.setdefault(canonical(routine), set()).add("nvtable")
        for addr, name in self._named_functions().items():
            if self.in_code(addr):
                entries.setdefault(addr, set()).add("name")
        for addr, source in self.extra.items():
            entries.setdefault(addr, set()).add(source)
        self.functions = []
        starts = sorted(entries)
        for i, start in enumerate(starts):
            limit = starts[i + 1] if i + 1 < len(starts) else self._image_end(start)
            f = Function(start, self._extent(start, limit))
            f.sources = entries[start]
            self.functions.append(f)
        self.starts = starts
        names = self._named_functions()
        for f in self.functions:
            f.name = names.get(f.start)
        for task, entry in self.tasks.items():           # an OS task without a name is still a task
            f = self.at(entry)
            if f.name is None:
                f.name = f"task{task}"
        for f in self.functions:                         # the compressed vector table: `ba handler` per 8 bytes
            if f.name is None and f.start < 0x100 and f.start % 8 == 0 and "ba" in f.sources:
                f.name = f"vector{f.start // 8}"
        for pc, target in call_sites:
            self.at(target).callers.append(pc)

    def _tail_calls(self):
        """A `b` out of its function into code no function covers is a
        tail call to a routine nothing calls with `bl`: the map switch's
        stubs in the free MPC space, reached by `b` from the hooked
        lookup entries. Added as entries and swept again."""
        found = {}
        for f in self.functions:
            for pc in range(f.start, f.end, 4):
                w = self.words[pc]
                if w >> 26 != 18 or w & 1:
                    continue
                target = canonical(branch_target(pc, w)[0])
                if self.in_code(target) and self.at(target) is None and target not in found:
                    found[target] = "tail"
        if found:
            self.extra.update(found)
            self._sweep()

    def _image_end(self, addr):
        for base, data in self.images:
            if base <= addr < base + len(data):
                return base + len(data)
        return addr

    def _extent(self, start, limit):
        """The end of the function at start: after the last return that no
        branch before it reaches past, and never past limit (the next entry)."""
        reach = start
        pc = start
        while pc < limit:
            w = self.words.get(pc)
            if w is None:
                break
            bt = branch_target(pc, w)
            if bt is not None and not bt[1]:
                target = canonical(bt[0])
                if start <= target < limit:
                    reach = max(reach, target)
                    if w >> 26 == 18 and pc >= reach - 4 and target <= pc:   # a backward `b` closing the function
                        return pc + 4
                elif w >> 26 == 18 and pc >= reach:                           # a branch out: a tail call
                    return pc + 4
            elif w in (BLR, RFI) and pc >= reach:
                return pc + 4
            elif w == BCTR and pc >= reach:
                # A computed jump is a return only when nothing follows it:
                # a switch's `bctr` has its cases after it.
                after = self.words.get(pc + 4, 0)
                if pc + 4 >= limit or is_prologue(after) or after in (0, 0x60000000, 0xFFFFFFFF):
                    return pc + 4
            pc += 4
        return min(pc, limit)

    def _named_functions(self):
        return {int(k, 16): v for k, v in self.names.get("functions", {}).items()}

    # ---- lookups ----------------------------------------------------------------
    def at(self, pc):
        """The function containing pc, or None (data, RAM copies, a gap)."""
        pc = canonical(pc)
        i = bisect.bisect_right(self.starts, pc) - 1
        if i < 0:
            return None
        f = self.functions[i]
        return f if pc < f.end else None

    def label(self, pc):
        """`name+0x10`, or the address itself where no function is known."""
        f = self.at(pc)
        if f is None:
            return f"0x{canonical(pc):X}"
        off = canonical(pc) - f.start
        return f.label + (f"+0x{off:X}" if off else "")

    def by_name(self, name):
        for f in self.functions:
            if f.name == name:
                return f
        return None

    def variable(self, addr):
        return self.variables.get(addr & 0xFFFFFFFF)

    # ---- coverage -----------------------------------------------------------------
    def cover(self, board, instructions, run=None):
        """Run the board that many instructions (through run(instructions),
        board.run by default; e46.Peers.run keeps the bus alive) with a
        block hook, adding to hits/entries. Python is called per basic
        block, so this is slow."""
        from unicorn import UC_HOOK_BLOCK
        blocks = self.blocks

        def hook(mu, addr, size, ud):
            blocks[addr] += 1

        mu = board.m.mu
        h = mu.hook_add(UC_HOOK_BLOCK, hook)
        # Blocks translated before the hook existed do not call it: start afresh.
        mu.ctl_flush_tb()
        try:
            (run or board.run)(instructions)
        finally:
            mu.hook_del(h)
        self._apply_coverage()

    def _apply_coverage(self):
        from .cpu import SCRATCH, MSR_STUB_BASE, MSR_STUB_SIZE
        # Code that ran where the sweep saw no function, and is in the
        # images (not a RAM copy, not one of the emulator's own stubs), is
        # a function the sweep missed: a block start there is an entry.
        found = {}
        for addr in self.blocks:
            a = canonical(addr)
            if self.in_code(a) and self.at(a) is None and a not in self.extra:
                found[a] = "coverage"
        if found:
            self.extra.update(found)
            self._sweep()
        for f in self.functions:
            f.hits = f.entries = 0
        stray = Counter()
        for addr, n in self.blocks.items():
            f = self.at(addr)
            if f is not None:
                f.hits += n
                if canonical(addr) == f.start:
                    f.entries += n
            elif not (SCRATCH - 0x100 <= addr < SCRATCH + 0x1000 or MSR_STUB_BASE <= addr < MSR_STUB_BASE + MSR_STUB_SIZE):
                stray[canonical(addr)] += n
        self.stray = stray                  # executed blocks outside every function and not the emulator's stubs: RAM copies

    @property
    def executed(self):
        return [f for f in self.functions if f.hits]

    # ---- output ---------------------------------------------------------------------
    def to_json(self):
        return {
            "program": self.pair.program_id.decode("latin1"),
            "functions": [{
                "start": f"0x{f.start:X}", "end": f"0x{f.end:X}", "name": f.name,
                "sources": sorted(f.sources), "callers": [f"0x{c:X}" for c in f.callers],
                **({"hits": f.hits, "entries": f.entries} if self.blocks else {}),
            } for f in self.functions],
            "variables": {f"0x{a:X}": n for a, n in sorted(self.variables.items())},
        }

    def ghidra_symbols(self, ext_base=EXT_HIGH):
        """Lines for Ghidra's ImportSymbolsScript: `name address f`. The
        external flash is put at ext_base (0xFFF00000, or 0xFFE00000 for a
        project that mapped the chip there)."""
        out = []
        for f in self.functions:
            addr = f.start
            if addr >= EXT_HIGH:
                addr = addr - EXT_HIGH + ext_base
            out.append(f"{f.label} 0x{addr:X} f")
        for addr, name in sorted(self.variables.items()):
            out.append(f"{name} 0x{addr:X} l")
        return "\n".join(out) + "\n"


def names_path(pair):
    return os.path.join(NAMES_DIR, pair.program_id.decode("latin1") + ".json")


def load_names(pair):
    """The hand-traced names for the pair's program, or empty ones."""
    try:
        with open(names_path(pair)) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"functions": {}, "variables": {}}
