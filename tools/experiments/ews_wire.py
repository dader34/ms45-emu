"""The EWS-wire receive path: which peripheral feeds the validator's
workA/workB, and at what baud/format — the parameters a passive tap
needs (the wire-sniff plan: ISN = ~(telegram[2]<<8 | telegram[3]^0xFF)).

Static (default): every function that addresses the validator variables
(workA 0x3FD538, workB 0x3FDC70, isn 0x3FC9BC, accepted 0x3FC9AC, reject
0x3FEFAC, gate/sync bytes) or builds a QSMCM SCI2 register address
(0x305004/10/12/14/16 — SCI1 at +8..E is the K-line, per sci.py).  The
filler of workA/workB is the receive handler; what it reads IS the wire.

Dynamic (--run): trace the QSMCM's SCI block while the board runs with
ignition on, to watch the firmware configure and service SCI2.

    .venv/bin/python -m tools.experiments.ews_wire [--run] [--disasm]
"""
import argparse
import struct
import sys
from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN

from ms45emu.image import load_named
from ms45emu.board import Board
from ms45emu.funcmap import FunctionMap
from ms45emu.dme import R13

VARS = {
    0x3FD538: "workA",
    0x3FDC70: "workB",
    0x3FC9BC: "isn",
    0x3FC9B0: "~isn",
    0x3FC9AC: "accepted",
    0x3FEFAC: "reject",
    0x3FDC79: "gate",
    0x3FDC7A: "ews flag",
    0x3FDC6E: "sync state",
}
SCI2 = {0x305004: "QSCI2_IL", 0x305010: "SCC2R0", 0x305012: "SCC2R1",
        0x305014: "SC2SR", 0x305016: "SC2DR"}
LOADS = ("lwz", "lbz", "lhz", "lwzu", "lbzu", "lhzu", "lha", "lhau")


def r13_ref(mn, ops):
    """off(r13) D-form → absolute address, else None."""
    if not ops.endswith("(r13)"):
        return None
    off = int(ops.rsplit("(", 1)[0].split(",")[-1].strip(), 0)
    if off >= 0x8000:
        off -= 0x10000
    return R13 + off


def scan_static(pair, want_disasm):
    fm = FunctionMap(pair)
    md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
    var_hits = {}          # function label -> [(pc, text, var, rw)]
    sci2_hits = {}
    dumps = set()

    for fn in fm.functions:
        known = {}          # register -> known absolute value (built this function)
        for pc in range(fn.start, fn.end, 4):
            w = fm.words.get(pc)
            if w is None:
                continue
            ins = list(md.disasm(struct.pack(">I", w), pc))
            if not ins:
                continue
            i = ins[0]
            ops = i.op_str
            parts = [o.strip() for o in ops.split(",")]

            # addi rD, r13, simm: an r13-built POINTER — how a receiver would
            # address workA/workB byte-wise (invisible to D-form scans)
            if i.mnemonic == "addi" and len(parts) == 3 and parts[1] == "r13":
                rD = parts[0]
                if rD.startswith("r") and rD[1:].isdigit():
                    imm = int(parts[2], 0)
                    if imm >= 0x8000:
                        imm -= 0x10000
                    known[int(rD[1:])] = R13 + imm
                    if R13 + imm in VARS:
                        var_hits.setdefault(fm.label(fn.start), []).append(
                            (pc, f"addi {ops} -> &{VARS[R13 + imm]}", VARS[R13 + imm], "P"))
                        if VARS[R13 + imm] in ("workA", "workB"):
                            dumps.add(fn.start)
                continue
            # lis/addis rD, imm  /  ori,addi rA, rS, imm: track built constants
            if i.mnemonic in ("lis", "addis") and len(parts) == 2:
                rD = parts[0]
                if rD.startswith("r") and rD[1:].isdigit():
                    known[int(rD[1:])] = int(parts[1], 0) << 16
                continue
            if i.mnemonic in ("ori", "oris", "addi", "addic", "addic.") and len(parts) == 3:
                rD, rS = parts[0], parts[1]
                if rD.startswith("r") and rS.startswith("r"):
                    nD, nS = int(rD[1:]), int(rS[1:])
                    if nS in known:
                        imm = int(parts[2], 0)
                        if i.mnemonic == "oris":
                            known[nD] = known[nS] | (imm << 16)
                        elif i.mnemonic == "ori":
                            known[nD] = known[nS] | imm
                        else:
                            if imm >= 0x8000:
                                imm -= 0x10000
                            known[nD] = known[nS] + imm
                        continue
                    # any other definition forgets what it knew
                    known.pop(nD, None)
                continue

            # memory ops: r13-relative (small data) or a known peripheral base
            addr = r13_ref(i.mnemonic, ops)
            if addr is None and (i.mnemonic in LOADS or i.mnemonic.startswith("st")):
                # indexed form: stb rX, rBase, rIdx / lbz rX, rBase, rIdx
                if len(parts) == 3 and all(p.startswith("r") and p[1:].isdigit() for p in parts):
                    for cand in (1, 2):
                        reg = parts[cand]
                        if reg[1:].isdigit():
                            n = int(reg[1:])
                            if n in known and known[n] in VARS:
                                addr = known[n]
                                break
            if addr is not None:
                if addr in VARS:
                    rw = "W" if i.mnemonic.startswith("st") else "R"
                    var_hits.setdefault(fm.label(fn.start), []).append((pc, f"{i.mnemonic} {ops}", VARS[addr], rw))
                    if VARS[addr] in ("workA", "workB") and rw == "W":
                        dumps.add(fn.start)
                continue
            if i.mnemonic in LOADS or i.mnemonic.startswith("st"):
                # base register in parentheses, last part
                if "(" in parts[-1] and parts[-1].endswith(")"):
                    base = parts[-1][parts[-1].index("(") + 1:-1]
                    off_s = parts[-1][:parts[-1].index("(")]
                    if base.startswith("r") and base[1:].isdigit():
                        nB = int(base[1:])
                        if nB in known:
                            off = int(off_s, 0)
                            if off >= 0x8000:
                                off -= 0x10000
                            absa = known[nB] + off
                            if absa in SCI2:
                                rw = "W" if i.mnemonic.startswith("st") else "R"
                                sci2_hits.setdefault(fm.label(fn.start), []).append(
                                    (pc, f"{i.mnemonic} {ops}  ; {SCI2[absa]}", SCI2[absa], rw))
                                dumps.add(fn.start)

    print(f"== functions touching the validator variables ==")
    for label, hits in sorted(var_hits.items()):
        print(f"\n  {label}")
        for pc, text, var, rw in hits:
            print(f"    {pc:08X} {rw} {var:10s} {text}")

    print(f"\n== functions touching QSMCM SCI2 registers ==")
    for label, hits in sorted(sci2_hits.items()):
        print(f"\n  {label}")
        for pc, text, reg, rw in hits:
            print(f"    {pc:08X} {rw} {reg:9s} {text}")

    if not want_disasm:
        return
    print(f"\n== disassembly of the {len(dumps)} candidate functions ==")
    for start in sorted(dumps):
        fn = next(f for f in fm.functions if f.start == start)
        label = fm.label(start)
        print(f"\n---- {label} {start:08X}-{fn.end:08X} ----")
        for pc in range(start, min(fn.end, start + 4 * 160), 4):
            w = fm.words.get(pc)
            if w is None:
                continue
            ins = list(md.disasm(struct.pack(">I", w), pc))
            text = f"{i.mnemonic} {i.op_str}" if (i := ins[0] if ins else None) else f".word {w:08X}"
            print(f"  {pc:08X}  {w:08X}  {text}")


def scan_dynamic():
    from ms45emu import e46
    from collections import Counter
    b = Board(load_named("session1"))
    log = []

    def trace(kind, addr, size, value):
        log.append((kind, addr, size, value, b.m.pc))
    for page in (b.siu, b.imb, b.mios, b.canp):
        page.trace = trace

    print("booting ...")
    b.boot(max_insns=20_000_000)
    log.clear()
    b.ignition(True)
    print("cranking to idle (e46.running) ...")
    e46.running(b)
    log.clear()                          # steady state at idle is what we want
    b.run(400_000_000)                   # 10 s of idle

    per = Counter((kind, addr, size) for kind, addr, size, value, pc in log)
    pcs = {}
    for kind, addr, size, value, pc in log:
        pcs.setdefault((kind, addr, size), set()).add(pc)
    print(f"{len(log)} peripheral accesses in 10 s at idle")
    for (kind, addr, size), n in per.most_common(60):
        names = {0x305008: "SCC1R0", 0x30500A: "SCC1R1", 0x30500C: "SC1SR", 0x30500E: "SC1DR",
                 0x305014: "PORTQS", 0x305016: "PQSPAR/DDRQS"}.get(addr, "")
        print(f"  {kind} {addr:06X} {names:14s} size{size} ×{n:8d}  pcs={' '.join(f'{p:08X}' for p in sorted(pcs[(kind, addr, size)])[:4])}")
    # the MPIOSM gpio port, for the bit-bang hypothesis
    for a in range(0x306000, 0x306020, 2):
        print(f"  mios {a:06X} = {b.mios.peek16(a):04X}")


def dump_at(pair, start, end=None):
    fm = FunctionMap(pair)
    md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
    fn = next((f for f in fm.functions if f.start <= start < f.end), None)
    end = end or min(fn.end if fn else start + 0x100, start + 4 * 120)
    print(f"---- {fm.label(fn.start) if fn else '?'} around {start:08X} ----")
    for pc in range(start, end, 4):
        w = fm.words.get(pc)
        if w is None:
            continue
        ins = list(md.disasm(struct.pack(">I", w), pc))
        text = f"{i.mnemonic} {i.op_str}" if (i := ins[0] if ins else None) else f".word {w:08X}"
        print(f"  {pc:08X}  {w:08X}  {text}")


def watch_writers():
    """Who writes workA/workB, with PC — boot, ignition, then a full
    crank-to-idle (e46.running), the strongest EWS stimulus there is."""
    from ms45emu import e46
    b = Board(load_named("session1"))
    writes = []          # (pc, addr, size, value)

    def cb(m, is_write, addr, size, value):
        if is_write:
            writes.append((m.pc, addr, size, value))
    for lo, hi in ((0x3FD538, 0x3FD53C), (0x3FDC70, 0x3FDC74)):
        m = b.m.hook_mem(cb, lo, hi)

    print("booting ...")
    b.boot(max_insns=20_000_000)
    n0 = len(writes)
    print(f"boot: {n0} writes")
    b.ignition(True)
    b.run(200_000_000)
    print(f"ignition 5 s: {len(writes) - n0} more")
    n0 = len(writes)
    print("cranking to idle (e46.running) ...")
    e46.running(b)
    print(f"engine run: {len(writes) - n0} more")
    b.run(200_000_000)
    print(f"idle 5 s: {len(writes) - n0} more")

    from collections import Counter
    per_pc = Counter((pc, addr, size) for pc, addr, size, value in writes)
    print(f"\n{len(writes)} writes total; by (pc, target):")
    for (pc, addr, size), n in per_pc.most_common(30):
        last = next(v for p, a, s, v in reversed(writes) if p == pc and a == addr and s == size)
        tgt = "workA" if addr < 0x3FD540 else "workB"
        print(f"  {pc:08X} -> {tgt} +{addr - (0x3FD538 if addr < 0x3FD540 else 0x3FDC70):#x} "
          f"size{size} ×{n}  last={last & ((1 << (8 * size)) - 1):02X}")
    print("\nworkA =", bytes(b.m.read8(a) for a in range(0x3FD538, 0x3FD53C)).hex(),
          " workB =", bytes(b.m.read8(a) for a in range(0x3FDC70, 0x3FDC74)).hex(),
          " isn =", bytes(b.m.read8(a) for a in range(0x3FC9BC, 0x3FC9BE)).hex(),
          " accepted =", bytes(b.m.read8(a) for a in range(0x3FC9AC, 0x3FC9B0)).hex())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", action="store_true", help="dynamic QSMCM trace instead of the static scan")
    ap.add_argument("--watch", action="store_true", help="write-watch workA/workB through crank")
    ap.add_argument("--disasm", action="store_true", help="dump candidate functions")
    ap.add_argument("--at", type=lambda s: int(s, 16), help="disassemble around this address")
    ap.add_argument("--to", type=lambda s: int(s, 16))
    args = ap.parse_args()
    if args.run:
        scan_dynamic()
    elif args.watch:
        watch_writers()
    elif args.at:
        dump_at(load_named("session1"), args.at, args.to)
    else:
        scan_static(load_named("session1"), args.disasm)
    return 0


if __name__ == "__main__":
    sys.exit(main())
