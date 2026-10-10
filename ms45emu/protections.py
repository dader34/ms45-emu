"""The DME's protections, two ways (docs/protections.md).

Statically, `Checks`: every routine that reports a fault (a `li r3, index`
before a call of `fault_report`), with the task it runs under, the
calibration thresholds it reads (by XDF name) and the RAM it reads and
writes; and the writers of the limp-home flags and the engine state.

Dynamically, `Reactions`: a board watched for what the protections do:
faults reported and failed (a probe on `fault_report`), the limp-home
flags and the engine state changing (memory hooks), the watchdog going
unserviced, an exception, a hang. `compare()` says what a pair does that
the stock pair does not under the same scenario, which is the question a
custom program has to answer.

    base = Reactions(Board(stock)); base.scenario(rpm=800, seconds=1)
    mine = Reactions(Board(custom)); mine.scenario(rpm=800, seconds=1)
    print(compare(base, mine, faults))
"""
from collections import Counter, OrderedDict

from unicorn import UC_HOOK_MEM_WRITE

from .machine import R13
from .funcmap import FunctionMap, canonical
from .explain import explain
from .faults import Faults

FAULT_REPORT = 0x26170           # program 0044570LO02S; found by name through the map otherwise
LIMP_HOME_FLAG = R13 - 0x4059    # the brake/throttle plausibility fault flag
LIMP_HOME = R13 - 0x406B         # limp home limit in force (c_n_max_mtc_lih)
ENGINE_STATE = 0x3F9C43
WATCHED = OrderedDict([(LIMP_HOME_FLAG, "limp_home_flag"), (LIMP_HOME, "limp_home"), (ENGINE_STATE, "engine_state")])
# The self-check the program runs before each answer to the monitoring
# module (fn_FFF76ED4, program 0044570LO02S; docs/protections.md). Any
# condition failing makes fn_FFFD2968 count an MO3 error and store to
# 0x800000, a machine check: the DME resets itself and stores no fault.
# code -> (what, test on the flag bytes by r13 offset)
SELF_RESET_CHECKS = {
    12: ("boot RAM test (r13-0x65B7/-0x65B6)", lambda v: v[0x65B7] == 0 and v[0x65B6] == 0xFF),
    11: ("program checksum, selftest_checksum (r13-0x3B8F)", lambda v: v[0x3B8F] == 0),
    10: ("a level-2 safety monitor check (r13-0x3D90/-0x3D8F)", lambda v: v[0x3D90] == 0 and v[0x3D8F] != 0),
    9: ("calibration ROM test of the monitoring level (r13-0x3C13)", lambda v: v[0x3C13] == 0),
}
SELF_RESET_FLAGS = (0x65B7, 0x65B6, 0x3B8F, 0x3D90, 0x3D8F, 0x3C13)
MO3_ERROR = 0xFFFD2968           # the self-reset itself (r3 = code)
MO3_ANSWER = 0xFFF76F80          # the answer routine, every 10 ms from task22

IDLE_RPM = 800                  # where a scenario synchronises the crank before going faster
FAILED_MASK = 0x0F              # r4: 0x10 is "tested"; a low bit is the way it failed


# ---- static --------------------------------------------------------------------------------
class Check:
    __slots__ = ("function", "faults", "task", "cal", "reads", "writes", "limp")

    def __init__(self, function):
        self.function = function
        self.faults = Counter()      # index -> call sites
        self.task = None             # the OS task it runs under, when a caller chain reaches one
        self.cal = []                # calibration items read (XDF names or offsets)
        self.reads = []              # RAM read, named where known
        self.writes = []
        self.limp = []               # which of the watched flags it writes


def _index_before(fm, pc):
    """`li r3, n` in the straight-line code before a call at pc."""
    for k in range(1, 8):
        w = fm.words.get(pc - 4 * k, 0)
        if w >> 26 == 14 and (w >> 21) & 31 == 3 and (w >> 16) & 31 == 0:
            return w & 0xFFFF
        if w >> 26 in (16, 18, 19):
            return None
    return None


def _task_of(fm, f, depth=8):
    """Walk callers up until an OS task (task<n> or a named task) is reached."""
    seen = set()
    frontier = [f]
    for _ in range(depth):
        nxt = []
        for g in frontier:
            if g.name and (g.name.startswith("task") or g.name.endswith("_task")):
                return g.label
            for c in g.callers:
                h = fm.at(c)
                if h is not None and h.start not in seen:
                    seen.add(h.start)
                    nxt.append(h)
        frontier = nxt
        if not frontier:
            break
    return None


class Checks:
    def __init__(self, fm, xdf=None, faults=None):
        self.fm = fm
        self.xdf = xdf
        self.faults = faults
        self.checks = OrderedDict()                   # function start -> Check
        reporters = [f for f in (fm.by_name("fault_report"), fm.by_name("fault_report_b")) if f is not None]
        for rep in reporters:
            for pc in rep.callers:
                idx = _index_before(fm, pc)
                f = fm.at(pc)
                if idx is None or f is None:
                    continue
                self._check(f).faults[idx] += 1
        # the writers of the watched flags, over every function in the map
        for f in fm.functions:
            e = explain(fm, f, None)
            hit = [name for addr, name in WATCHED.items() if addr in e.ram and any(h == "W" for _, h, _ in e.ram[addr].sites)]
            if hit:
                self._check(f).limp = hit
        for c in self.checks.values():
            e = explain(fm, c.function, xdf)
            c.task = _task_of(fm, c.function)
            c.cal = [u.name or f"0x{off:X}" for off, u in sorted(e.cal.items())]
            c.reads = [u.name or f"r13{a - R13:+#x}" for a, u in sorted(e.ram.items()) if any(h in ("R", "idx") for _, h, _ in u.sites)]
            c.writes = [u.name or f"r13{a - R13:+#x}" for a, u in sorted(e.ram.items()) if any(h == "W" for _, h, _ in u.sites)]

    def _check(self, f):
        c = self.checks.get(f.start)
        if c is None:
            c = self.checks[f.start] = Check(f)
        return c

    def markdown(self):
        out = ["| Check | Task | Faults | Thresholds (calibration) | Reads | Writes |", "|---|---|---|---|---|---|"]
        for c in sorted(self.checks.values(), key=lambda c: (c.task or "~", c.function.start)):
            faults = ", ".join(self._fault(i) + (f" x{n}" if n > 1 else "") for i, n in sorted(c.faults.items()))
            if c.limp:
                faults = ", ".join(c.limp) + (": " + faults if faults else "")
            out.append(f"| `{c.function.label}` 0x{c.function.start:X} | {c.task or ''} | {faults} | {_short(c.cal)} | {_short(c.reads)} | {_short(c.writes)} |")
        return "\n".join(out)

    def _fault(self, index):
        if self.faults is None:
            return str(index)
        code = self.faults.code(index)
        text = self.faults.text(index)
        return f"{index} {code:04X}" + (f" {text}" if text else "") if code else str(index)


def _short(items, n=8):
    return ", ".join(items[:n]) + (f", +{len(items) - n}" if len(items) > n else "")


# ---- dynamic -------------------------------------------------------------------------------
class Reactions:
    def __init__(self, board, fm=None):
        self.board = board
        self.fm = fm if fm is not None else FunctionMap(board.m.pair)
        self.reports = {}              # fault index -> Counter(verdict)
        self.failed = Counter()        # fault index -> failed reports
        self.first_failed = {}         # fault index -> instruction count
        self.transitions = {name: [] for name in WATCHED.values()}   # (instructions, value)
        self.exceptions = Counter()
        self.watchdog_stalls = []      # (instructions, services) when a run went 20 ms with no service
        self.hang = None
        self.ran = 0
        rep = self.fm.by_name("fault_report")
        entry = rep.start if rep is not None else (FAULT_REPORT if board.m.pair.traced else None)
        if entry is not None:
            board.probe(entry, "fault_report", on_hit=self._reported)
        self.hang_sites = {pc for pc, w in self.fm.words.items() if w == 0x48000000}
        mu = board.m.mu
        self._hooks = [mu.hook_add(UC_HOOK_MEM_WRITE, self._flag_write, begin=addr, end=addr) for addr in WATCHED]
        # The self-reset: its checks evaluated each time the program is
        # about to answer the monitoring module (the flags pass through bad
        # values while the boot initialises them, which it never looks at),
        # and the recorder itself, reached only with the module talking.
        self.self_reset = {}               # code -> instruction count it first failed at
        self.mo3_errors = Counter()        # codes fn_FFFD2968 was called with
        if board.m.pair.traced:
            board.probe(MO3_ANSWER, "mo3_answer", on_hit=self._self_check)
            board.probe(MO3_ERROR, "mo3_error", on_hit=lambda bd: self.mo3_errors.update([bd.m.reg(3)]))
        mu.ctl_flush_tb()
        self._last = {addr: board.m.read8(addr) for addr in WATCHED}

    def _reported(self, board):
        idx, verdict = board.m.reg(3), board.m.reg(4)
        self.reports.setdefault(idx, Counter())[verdict] += 1
        if verdict & FAILED_MASK:
            self.failed[idx] += 1
            self.first_failed.setdefault(idx, board.instructions)

    def _self_check(self, board):
        flags = {off: board.m.read8(R13 - off) for off in SELF_RESET_FLAGS}
        for code, (_, ok) in SELF_RESET_CHECKS.items():
            if code not in self.self_reset and not ok(flags):
                self.self_reset[code] = board.instructions

    def _flag_write(self, mu, access, addr, size, value, ud):
        v = value & 0xFF
        if v != self._last.get(addr):
            self._last[addr] = v
            self.transitions[WATCHED[addr]].append((self.board.instructions, v))

    def run(self, instructions, run=None):
        """Run the board, watching the watchdog on the way."""
        b = self.board
        step = b.ips // 50                                   # 20 ms: two services expected
        end = b.instructions + instructions
        while b.instructions < end:
            n = min(step, end - b.instructions)
            before = b.watchdog_services
            (run or b.run)(n)
            self.ran += n
            # Once the OS services the watchdog it does so every 10 ms;
            # before that (the reset path, the EEPROM load) it is not armed.
            if before and b.watchdog_services == before and n >= step and not b.powered_down:
                self.watchdog_stalls.append((b.instructions, before))
            pc = b.m.pc
            if canonical(pc) in self.hang_sites and self.hang is None:
                self.hang = canonical(pc)
            if b.other_exceptions:
                self.exceptions = Counter(b.other_exceptions)
            if self.hang is not None or b.powered_down:
                break

    def scenario(self, rpm=0, seconds=1.0, settle=0.5, speed=0, key_off=False, automatic=False, pedal=0.0, throttle=0.0):
        """Boot (settle), then run `seconds` with the E46 peers on the bus,
        the crank at rpm, the pedal at `pedal` % and the throttle held at
        `throttle` degrees (ms45emu/inputs.py; None leaves the channels
        at mid-scale), and the ignition off when asked."""
        from .e46 import Peers
        from . import inputs
        b = self.board
        if b.m.pair.traced:
            if pedal is not None:
                inputs.set_pedal(b, pedal)
            if throttle is not None:
                inputs.set_throttle(b, throttle)
        # With the cam sensors not modelled, the crank handler accepts the
        # gap only at some speeds (it checks the cam levels against the
        # segment it expects, and restarts the search on a mismatch), so a
        # start straight at 1300 rpm may never synchronise. The engine
        # passes through idle anyway: synchronise there, then speed up.
        ramp = rpm > IDLE_RPM and not self.ran
        b.crank.rpm = IDLE_RPM if ramp else rpm
        peers = Peers(b, automatic=automatic)
        if speed:
            peers.set_speed(speed)
        if not self.ran:
            b.boot(max_insns=b.ips // 1000)             # the reset entry; the rest of the boot runs watched
        if settle:
            self.run(int(settle * b.ips), run=lambda n: peers.run(n))
        if ramp:
            b.crank.rpm = rpm
        if key_off:
            b.ignition(False)
        self.run(int(seconds * b.ips), run=lambda n: peers.run(n))
        return self

    @property
    def reset(self):
        """A reset on hardware: the watchdog went unserviced, the CPU hung,
        an exception was not handled, or the program's own pre-answer
        self-check failed (it resets itself, storing nothing)."""
        return bool(self.watchdog_stalls) or self.hang is not None or bool(self.exceptions) or bool(self.self_reset)

    def report(self, faults=None):
        b = self.board
        out = [f"{b.m.pair.name}: {self.ran / b.ips:g} s; watchdog services {b.watchdog_services}"
               + (f", UNSERVICED at {[f'{i / b.ips:.3f} s' for i, _ in self.watchdog_stalls[:3]]}" if self.watchdog_stalls else "")
               + (f"; HUNG at 0x{self.hang:X} ({self.fm.label(self.hang)})" if self.hang is not None else "")
               + (f"; exceptions {dict(self.exceptions)}" if self.exceptions else "")]
        for code, at in sorted(self.self_reset.items()):
            out.append(f"SELF-RESET (MO3 code {code}: {SELF_RESET_CHECKS[code][0]}) at {at / b.ips:.3f} s: the DME resets itself, no fault stored")
        out.append(f"faults reported: {len(self.reports)}, failed: {len(self.failed)}")
        for idx, n in sorted(self.failed.items()):
            verdicts = " ".join(f"{v:02X}x{c}" for v, c in sorted(self.reports[idx].items()))
            out.append(f"  {faults.describe(idx) if faults else f'fault {idx}'}: {n} failed, first at {self.first_failed[idx] / b.ips:.3f} s ({verdicts})")
        for name, tr in self.transitions.items():
            if tr:
                out.append(f"{name}: " + ", ".join(f"{v:02X} at {i / b.ips:.3f} s" for i, v in tr[:10]) + (" ..." if len(tr) > 10 else ""))
        return "\n".join(out)


def compare(base, other, faults=None):
    """What `other` did that `base` did not: the lines a custom program must explain."""
    out = []
    for code in sorted(set(other.self_reset) - set(base.self_reset)):
        out.append(f"self-reset: MO3 code {code}, {SELF_RESET_CHECKS[code][0]}, at "
                   f"{other.self_reset[code] / other.board.ips:.3f} s (the DME resets itself and stores no fault)")
    for idx in sorted(set(other.failed) - set(base.failed)):
        out.append(f"fails {faults.describe(idx) if faults else f'fault {idx}'} ({other.failed[idx]}x, first at {other.first_failed[idx] / other.board.ips:.3f} s); the base does not")
    for name in WATCHED.values():
        bv = {v for _, v in base.transitions[name]}
        for i, v in other.transitions[name]:
            if v not in bv:
                out.append(f"{name} becomes {v:02X} at {i / other.board.ips:.3f} s; the base never does")
                break
    if other.watchdog_stalls and not base.watchdog_stalls:
        out.append(f"watchdog unserviced at {other.watchdog_stalls[0][0] / other.board.ips:.3f} s: a reset on hardware")
    if other.hang is not None and base.hang is None:
        out.append(f"hangs at 0x{other.hang:X}: a reset on hardware")
    if other.exceptions and not base.exceptions:
        out.append(f"exceptions {dict(other.exceptions)}: a reset on hardware")
    return out
