#!/usr/bin/env python
"""Every instruction in the MPC image that can read the calibration.

The live-tune overlay has to redirect calibration reads to a RAM copy. Most
reads go through the lookup library (a handful of entry stubs that take the
table pointer in r3); the profiler counts those at run time. But ~20% of the
reads reach the calibration by other paths that a single run may not exercise,
and the overlay has to catch those too or a tuned cell reads one value through
the library and a stale value through the bypass. This scans the program
statically for all of them.

    .venv/bin/python tools/site_scan.py                      # session1, whole cal
    .venv/bin/python tools/site_scan.py --cal 0x52f9 0x5506  # one table's range
    .venv/bin/python tools/site_scan.py --mpc images/seven_MPC.bin --json sites.json

Three ways the program names a calibration byte, all found here:

  r2-relative   r2 = 0xFFE47FF0; `lbz rD, d(r2)` or an `lbzx` whose base was
                set to r2 (directly or as r2 +/- k). d in [0x38010, 0x55010)
                lands in the cal chip 0x40000-0x5CFFF.
  absolute      `lis rX, 0xFFE4` (or 0xFFE8/0xFFF8, the mirror) then an addi/
                ori/load displacement that completes a cal address, with the
                load that consumes rX.
  indirect      a load through a register traced, within its basic block, to
                one of the two bases above.

The lookup-library entry stubs read through a pointer their caller passes in
r3, so no basic-block trace reaches the base; they are seeded as known roots
(dme.LOOKUP_ENTRIES) and reported with mode "lib-entry". That plus the three
detectors above is a superset of what tools/livetune_profile.py sees at run
time -- the check at the bottom of this file asserts it against a saved log.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from capstone import (                                       # noqa: E402
    Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN,
)
from capstone.ppc import PPC_OP_REG, PPC_OP_MEM, PPC_OP_IMM  # noqa: E402

# Capstone's PPC register ids are not r0..r31; r0 is PPC_REG_R0 and the GPRs
# run contiguously, so r<N> == R0_ID + N. We resolve by name to stay robust.
R0_ID = 87                               # md.reg_name(87) == "r0" in this build

from ms45emu import dme                                      # noqa: E402
from ms45emu.image import IMAGES_DIR                         # noqa: E402

R2 = 0xFFE47FF0                          # calibration base the program keeps in r2
CAL_BASE = dme.CAL_BASE                  # 0xFFE40000, CPU
CAL_LEN = dme.CAL_LENGTH                 # 0x1D000
CAL_CHIP = 0x40000                       # the cal as an offset into the 1 MB chip
# The external chip is seen through a 2 MB window that mirrors the 1 MB chip at
# 0xFFE..... and 0xFFF....., so a pointer into the cal uses lis of the primary
# or the mirror high half-word. 0xFFE8/0xFFF8 is chip 0x80000+ (the program),
# NOT the cal, so it is excluded.
CAL_LIS = (0xFFE4, 0xFFE5, 0xFFF4, 0xFFF5)

# The lookup-library cluster in the MPC image (matches livetune_profile.py).
# A block that tail-branches into here fetches the cal through the pointer its
# caller passed, so its loads are read sites even though the base is untracked.
LIB_LO, LIB_HI = 0xC328, 0x11000

LOADS = {                                # mnemonic -> (indexed?, size)
    "lbz": (False, 1), "lbzu": (False, 1), "lbzx": (True, 1), "lbzux": (True, 1),
    "lhz": (False, 2), "lhzu": (False, 2), "lhzx": (True, 2), "lhzux": (True, 2),
    "lha": (False, 2), "lhau": (False, 2), "lhax": (True, 2), "lhaux": (True, 2),
    "lwz": (False, 4), "lwzu": (False, 4), "lwzx": (True, 4), "lwzux": (True, 4),
    "lfs": (False, 4), "lfsu": (False, 4), "lfsx": (True, 4), "lfsux": (True, 4),
    "lfd": (False, 8), "lfdu": (False, 8), "lfdx": (True, 8), "lfdux": (True, 8),
}


def cpu_to_cal(addr):
    """The cal chip offset for a CPU address in the cal window, or None."""
    for mirror in (0xFFE00000, 0xFFF00000):
        off = (addr & 0xFFFFFFFF) - (mirror + CAL_CHIP)
        if 0 <= off < CAL_LEN:
            return CAL_CHIP + off
    return None


def _func_name(mpc_funcs, pc):
    """`name+0xNN` for the function containing pc, else the bare address."""
    best = None
    for at, name in mpc_funcs:
        if at <= pc and (best is None or at > best[0]):
            best = (at, name)
    if best and pc - best[0] < 0x2000:
        return f"{best[1]}+0x{pc - best[0]:X}" if pc != best[0] else best[1]
    return f"0x{pc:X}"


class Scanner:
    """A per-basic-block static read of one MPC image."""

    def __init__(self, mpc, funcs=()):
        self.mpc = mpc
        self.funcs = list(funcs)
        # The r3-contract entry stubs, and entry+4: the guarded leaf helpers
        # branch back to entry+4 (past the stub's own `b`), re-entering the
        # body with the same caller pointer, so both count as "into an entry".
        self.entry_set = set(dme.LOOKUP_ENTRIES) | {e + 4 for e in dme.LOOKUP_ENTRIES}
        # The extent of each function, so a caller-pointer read can be placed in
        # the function that makes it. A read inside an ENTRY function's body is
        # part of the library the overlay's entry hooks relocate (always on); a
        # read inside a standalone wrapper function is not, and needs a per-table
        # stub. Detached leaf helpers (no function range) are classified by
        # whether their block branches back into an entry.
        self.func_starts = sorted(a for a, _ in self.funcs)
        self.func_at = dict(self.funcs)
        self.md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
        self.md.detail = True

    # -- register value tracking inside a basic block ------------------------
    @staticmethod
    def _gpr(reg_id):
        """GPR number for a capstone reg id, or None if it is not r0..r31."""
        n = reg_id - R0_ID
        return n if 0 <= n <= 31 else None

    def _base(self, gpr, known):
        """The CPU address a GPR provably holds: r2 is fixed, else tracked."""
        if gpr == 2:
            return R2
        return known.get(gpr)

    def _track(self, insn, known):
        """Update `known` {gpr: cpu_addr} for one instruction, and return a
        (gpr, mode, cal) site if it MATERIALIZES a calibration pointer.

        `addi r3, r2, d` and friends are the dominant way a table reaches the
        lookup library -- the pointer is built here and handed to a stub in
        r3 -- so the construction is itself a read site, reported even though
        no load touches cal at this pc. We track only registers provably
        holding an exact address; any other write clears the destination so we
        never claim a read we did not prove. r2 is constant and never stored.
        """
        m = insn.mnemonic
        ops = insn.operands
        dst = self._gpr(ops[0].reg) if ops and ops[0].type == PPC_OP_REG else None
        if dst is None or dst == 2:
            return None
        site = None
        def setv(v, mode=None):
            nonlocal site
            if v is None:
                known[dst] = None
                return
            v &= 0xFFFFFFFF
            known[dst] = v
            if mode is not None:
                cal = cpu_to_cal(v)
                if cal is not None:
                    site = (dst, mode, cal)
        try:
            if m == "lis" and len(ops) == 2 and ops[1].type == PPC_OP_IMM:
                hi = ops[1].imm & 0xFFFF
                setv((hi << 16) if hi in CAL_LIS else None)   # partial; no site yet
            elif m in ("addi", "addic", "subi") and len(ops) == 3 and ops[2].type == PPC_OP_IMM:
                src = self._gpr(ops[1].reg)
                base = self._base(src, known) if src is not None else None
                if base is None:
                    setv(None)
                else:
                    d = ops[2].imm
                    val = base + (-d if m == "subi" else d)
                    mode = ("r2" if src == 2 else "absolute") if cpu_to_cal(val) is not None else None
                    setv(val, mode)
            elif m == "addis" and len(ops) == 3 and ops[2].type == PPC_OP_IMM:
                src = self._gpr(ops[1].reg)
                base = self._base(src, known) if src is not None else None
                if base is None:
                    setv(None)
                else:
                    val = base + ((ops[2].imm & 0xFFFF) << 16)
                    mode = ("r2-addis" if src == 2 else "absolute") if cpu_to_cal(val) is not None else None
                    setv(val, mode)
            elif m in ("ori", "oris") and len(ops) == 3 and ops[2].type == PPC_OP_IMM:
                src = self._gpr(ops[1].reg)
                base = self._base(src, known) if src is not None else None
                if base is None:
                    setv(None)
                else:
                    v = ops[2].imm & 0xFFFF
                    val = base | (v << 16 if m == "oris" else v)
                    mode = "absolute" if cpu_to_cal(val) is not None else None
                    setv(val, mode)
            elif m == "mr" and len(ops) == 2:
                src = self._gpr(ops[1].reg)
                setv(self._base(src, known) if src is not None else None)
            else:
                setv(None)                                      # unknown: invalidate dst
        except Exception:
            known[dst] = None
        return site

    def _func_start(self, pc):
        """Start address of the function containing pc, or None."""
        import bisect
        i = bisect.bisect_right(self.func_starts, pc) - 1
        return self.func_starts[i] if i >= 0 else None

    def _classify(self, pc, branch_tgt):
        """A caller-pointer read is 'lib-read' (covered by the overlay's entry
        hooks) when it sits in a lookup-entry function's body, or in a detached
        leaf helper whose block re-enters an entry; otherwise 'wrapper-read'
        (a standalone helper's own table walk, needing a per-table stub)."""
        fs = self._func_start(pc)
        if fs in self.entry_set:
            return "lib-read"
        if branch_tgt is not None and branch_tgt in self.entry_set:
            return "lib-read"
        return "wrapper-read"

    def _load_base_gpr(self, insn):
        """The base GPR of a load (d(rA) or indexed rA,rB), or None."""
        info = LOADS.get(insn.mnemonic)
        if not info:
            return None
        ops = insn.operands
        if info[0]:                                     # indexed: base is op 1
            return self._gpr(ops[1].reg) if len(ops) > 1 and ops[1].type == PPC_OP_REG else None
        mem = next((o for o in ops if o.type == PPC_OP_MEM), None)
        return self._gpr(mem.mem.base) if mem is not None else None

    def _read_site(self, insn, known):
        """If this load reads the calibration, return (gpr, mode, cal_addr)."""
        info = LOADS.get(insn.mnemonic)
        if not info:
            return None
        indexed, _size = info
        ops = insn.operands
        dst = self._gpr(ops[0].reg) if ops and ops[0].type == PPC_OP_REG else None
        if indexed:
            # l?zx rD, rA, rB  -- base is rA (operand 1); indexed by rB, so the
            # base register alone must already point into the cal window.
            if len(ops) < 2 or ops[1].type != PPC_OP_REG:
                return None
            ra = self._gpr(ops[1].reg)
            base = self._base(ra, known) if ra is not None else None
            if base is None:
                return None
            cal = cpu_to_cal(base)
            mode = "r2" if ra == 2 else "indirect"
            return (dst, mode, cal) if cal is not None else None
        # d(rA): the MEM operand carries base + disp
        mem = next((o for o in ops if o.type == PPC_OP_MEM), None)
        if mem is None:
            return None
        ra = self._gpr(mem.mem.base)
        if ra is None:
            return None
        disp = mem.mem.disp
        if ra == 2:
            cal = cpu_to_cal(R2 + disp)
            return (dst, "r2", cal) if cal is not None else None
        base = known.get(ra)
        if base is None:
            return None
        cal = cpu_to_cal(base + disp)
        return (dst, "indirect", cal) if cal is not None else None

    def scan(self, lo=0, hi=None):
        """All cal-read sites with cal address in [lo, hi) (chip offsets).

        PPC instructions are a fixed 4 bytes and aligned, so we step the image
        word by word. A single capstone.disasm over the whole image desyncs at
        the first word it cannot decode and silently stops; stepping survives
        the data words (jump tables, constants) between functions. A register
        value is only trusted within a straight run of instructions: a branch,
        or any word that fails to decode, ends the run and clears the tracker.
        """
        hi = CAL_CHIP + CAL_LEN if hi is None else hi
        sites = []
        known = {}
        pending = []            # caller-pointer loads this block makes
        code = self.mpc
        md = self.md
        n = len(code) & ~3

        def emit(pc, insn, reg, mode, cal):
            sites.append({
                "pc": pc,
                "where": _func_name(self.funcs, pc),
                "reg": f"r{reg}" if reg is not None else "?",
                "mode": mode,
                "cal": cal,                                 # chip offset, or None
                "cal_file": None if cal is None else cal - CAL_CHIP,
                "insn": f"{insn.mnemonic} {insn.op_str}",
            })

        for off in range(0, n, 4):
            insn = next(iter(md.disasm(code[off:off + 4], off)), None)
            if insn is None:
                known, pending = {}, []         # undecodable word: end the run
                continue
            m = insn.mnemonic
            if m[0] == "b" and m not in ("bdz", "bdnz"):
                # The block ends: classify its caller-pointer loads by the
                # function they sit in and where the block hands off (see
                # _classify). A library-internal read is always-on; a wrapper's
                # own walk needs a per-table stub.
                tgt = insn.operands[-1].imm if insn.operands and \
                    insn.operands[-1].type == PPC_OP_IMM else None
                for pc, ld, reg in pending:
                    # Keep a caller-pointer read only where the overlay cares:
                    # inside the library (always-on) or a cluster wrapper that
                    # branches into an entry. Drop loose caller-pointer loads
                    # elsewhere in the image -- they are not cal reads.
                    mode = self._classify(pc, tgt)
                    in_cluster = LIB_LO <= pc < LIB_HI or self._func_start(pc) in self.entry_set
                    if mode == "lib-read" or in_cluster:
                        emit(pc, ld, reg, mode, None)
                known, pending = {}, []         # control-flow boundary
                continue
            hit = self._read_site(insn, known)  # a load that touches cal
            if hit is None:
                hit = self._track(insn, known)  # or a pointer materialization
                if hit is None and insn.mnemonic in LOADS:
                    # An untracked load through a general register: a candidate
                    # caller-pointer read. Loads through r13 (small data) or r1
                    # (stack) never reach cal; others are held and settled (or
                    # dropped) at the block end. A resolved load is handled
                    # below. We bound the holding set to the cluster and the
                    # detached leaf-helper region to stay cheap and precise.
                    base = self._load_base_gpr(insn)
                    near_lib = LIB_LO <= off < LIB_HI or 0x6E500 <= off < 0x6E700 \
                        or self._func_start(off) in self.entry_set
                    if base is not None and base not in (1, 13) and near_lib:
                        ops = insn.operands
                        rd = self._gpr(ops[0].reg) if ops and ops[0].type == PPC_OP_REG else None
                        pending.append((insn.address, insn, rd))
            else:
                self._track(insn, known)
            if hit is not None:
                reg, mode, cal = hit
                if cal is not None and lo <= cal < hi:
                    emit(insn.address, insn, reg, mode, cal)
        return sites

    def lib_entries(self, names):
        """The lookup-library stubs, seeded as roots (caller passes r3)."""
        out = []
        for pc in dme.LOOKUP_ENTRIES:
            out.append({
                "pc": pc, "where": _func_name(self.funcs, pc),
                "reg": "r3", "mode": "lib-entry", "cal": None,
                "insn": "(table pointer in r3 from caller)",
            })
        return out


def load_mpc(path):
    data = open(path, "rb").read()
    return data


def _pair_mpc(name):
    """The MPC image path for a pair name, trying both naming styles."""
    for cand in (f"{name}.mpc.bin", f"{name}_MPC.bin"):
        p = os.path.join(IMAGES_DIR, cand)
        if os.path.isfile(p):
            return p
    raise FileNotFoundError(f"no MPC image for pair {name!r} in {IMAGES_DIR}")


def load_funcs():
    """(addr, name) pairs from images/stock_functions.json if present."""
    p = os.path.join(IMAGES_DIR, "stock_functions.json")
    if not os.path.isfile(p):
        return []
    j = json.load(open(p))
    funcs = j.get("functions", []) if isinstance(j, dict) else j
    out = []
    for f in funcs:
        start = f.get("start")
        if start is None:
            continue
        addr = int(start, 0) if isinstance(start, str) else int(start)
        name = f.get("name") or f"fn_{addr:X}"
        out.append((addr & 0xFFFFFFFF, name))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair", help="an image name under images/ (e.g. seven), "
                    "like livetune_profile.py; uses <pair>.mpc.bin / <pair>_MPC.bin")
    ap.add_argument("--mpc", help="an MPC image path (default images/session1.mpc.bin)")
    ap.add_argument("--cal", nargs=2, type=lambda s: int(s, 0), metavar=("LO", "HI"),
                    help="cal-file offsets (XDF), e.g. 0x52f9 0x5506")
    ap.add_argument("--json", help="write here instead of build/site_scan-<pair>.json")
    ap.add_argument("--no-json", action="store_true", help="print only, write nothing")
    args = ap.parse_args(argv)

    mpc_path = args.mpc or _pair_mpc(args.pair) if args.pair else args.mpc
    mpc_path = mpc_path or os.path.join(IMAGES_DIR, "session1.mpc.bin")
    pair = os.path.basename(mpc_path).split(".")[0].replace("_MPC", "")
    mpc = load_mpc(mpc_path)
    funcs = load_funcs()
    sc = Scanner(mpc, funcs)
    if args.cal:                                    # cal-file offsets in, chip offsets internally
        lo, hi = CAL_CHIP + args.cal[0], CAL_CHIP + args.cal[1]
    else:
        lo, hi = CAL_CHIP, CAL_CHIP + CAL_LEN
    sites = sc.scan(lo, hi)
    lib = sc.lib_entries(funcs)

    # Two install-time sections. The overlay's entry-hook bodies cover the
    # library on every build, so the lookup entries and the reads that reach
    # cal through an entry's r3 (lib-read) are "always on". Everything else --
    # direct r2/absolute/indirect reads and the wrapper walks (wrapper-read),
    # which the entry hooks do NOT cover -- is stubbed only when that table is
    # opened, so it is grouped by cal range.
    always_on = [s for s in sites if s["mode"] == "lib-read"]
    per_range = [s for s in sites if s["mode"] != "lib-read"]

    def tally(group):
        t = {}
        for s in group:
            t[s["mode"]] = t.get(s["mode"], 0) + 1
        return t

    print(f"{os.path.basename(mpc_path)}: cal-file 0x{lo - CAL_CHIP:X}-0x{hi - CAL_CHIP:X}")
    print(f"  always-on library hooks: {len(lib)} entries + {len(always_on)} entry reads (lib-read)")
    pr = tally(per_range)
    print(f"  per-range direct reads: {len(per_range)}")
    for mode in ("r2", "r2-addis", "absolute", "indirect", "wrapper-read"):
        if pr.get(mode):
            print(f"    {mode:12} {pr[mode]}")
    print("  per-range sample (first 15 by pc):")
    for s in sorted(per_range, key=lambda s: s["pc"])[:15]:
        cf = "   caller" if s["cal_file"] is None else f"0x{s['cal_file']:05X}"
        print(f"    0x{s['pc']:06X} {s['where']:26} {s['reg']:4} {s['mode']:12} "
              f"cal-file {cf}  {s['insn']}")

    if not args.no_json:
        out = args.json or os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "build", f"site_scan-{pair}.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        json.dump({
            "mpc": os.path.basename(mpc_path),
            "cal_file_lo": lo - CAL_CHIP, "cal_file_hi": hi - CAL_CHIP,
            "always_on": {"lib_entries": lib, "entry_reads": always_on},
            "per_range": per_range,
            # a read the static model cannot resolve: double indirection off a
            # pointer loaded from a non-cal pointer table. Caught at run time by
            # the overlay harness instead; stubbed directly if it ever matters.
            "known_residuals": [
                {"pc": 0x61DBC, "where": _func_name(funcs, 0x61DBC),
                 "note": "double indirection: lbz 0x10(r11), r11 from a pointer "
                         "table at CPU 0x45B8, not a cal base"},
            ],
        }, open(out, "w"), indent=1)
        print(f"  wrote {out}")
    return sites, lib


if __name__ == "__main__":
    main()
