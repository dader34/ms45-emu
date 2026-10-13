#!/usr/bin/env python
"""Milestone 1 of the live-tune build (docs/livetune-design.md): what the
running program reads out of the calibration, and which SRAM is free.

    .venv/bin/python tools/livetune_profile.py [--pair seven | --flash F --mpc M]
        [--rpm 900] [--pedal 0] [--settle 0.2] [--seconds 1.0] [--idle]

Boots the pair (default: the car's own session1, which carries no map
switch), lets the OS settle, then runs with the crank turning and the pedal
held, and reports:

  - the calibration ranges the program read as tables (the background
    CRC-32 walker, which sweeps the whole sector, is counted separately):
    which of them the lookup-library cluster reads (0xC328-0x10FFF of the
    MPC image: axis_search_8, the lookup_Dxxx family and its relatives),
    which blocks of the map-switch block layout they fall into, and the
    hottest tables;
  - for a pair that carries the map switch, the reads of the MS45MAPS
    header and block tables;
  - SRAM no instruction ever stored to (mirror-slot candidates), by zone,
    and the stack's low-water mark (deepest r1 at any store).

Nothing is changed; it only watches.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unicorn import UC_HOOK_MEM_WRITE                        # noqa: E402
from unicorn.ppc_const import UC_PPC_REG_0                   # noqa: E402

from ms45emu import dme                                     # noqa: E402
from ms45emu.board import Board                              # noqa: E402
from ms45emu.e46 import Peers                                # noqa: E402
from ms45emu.funcmap import FunctionMap                      # noqa: E402
from ms45emu.image import IMAGES_DIR, Pair, load_pair        # noqa: E402
from ms45emu.inputs import set_pedal                         # noqa: E402
from ms45emu.xref import Xref                                # noqa: E402

CAL_OFF = dme.CAL_BASE - 0xFFE00000          # 0x40000: the calibration as a chip offset
RAM_LO, RAM_HI = 0x3F8000, 0x400000
GRAN = 8
SCHEDULER_TASK = 0x3B38C                     # names: scheduler_task
ENGINE_STATE = 0x3F9C43                      # names: engine_state
LIB_LO, LIB_HI = 0xC328, 0x11000             # the lookup-library cluster in the MPC image
WALKER_LO, WALKER_HI = 0xFFFD9E00, 0xFFFDA400    # flash_crc32_walker and its caller

ZONES = ((0x3F8000, 0x3F97F0, "below r13 reach"),
         (0x3F97F0, 0x3FA104, "r13-reachable"),
         (0x3FA104, 0x3FC004, "MTOS window"),
         (0x3FC004, 0x3FF2A0, "mid SRAM"),
         (0x3FF2A0, 0x3FF900, "heap"),
         (0x3FF900, 0x400000, "stack / high small data"))


def chip_offset(addr):
    """A CPU address as an offset into the external flash chip, or None."""
    a = addr & 0xFFFFFFFF
    if 0xFFF00000 <= a:
        return a - 0xFFF00000
    if 0xFFE00000 <= a < 0xFFF00000:
        return a - 0xFFE00000
    return None


def coalesce(offsets, gap=0x20):
    spans = []
    for o in sorted(offsets):
        if spans and o - spans[-1][1] <= gap:
            spans[-1][1] = o
        else:
            spans.append([o, o])
    return spans


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair", help="named pair (stock/patched/three/seven/shifter)")
    ap.add_argument("--flash", help="external flash dump (default: images/session1.*)")
    ap.add_argument("--mpc", help="MPC dump")
    ap.add_argument("--rpm", type=float, default=900, help="crank speed (default 900)")
    ap.add_argument("--pedal", type=int, default=0, help="pedal position %% (default 0)")
    ap.add_argument("--settle", type=float, default=0.2, metavar="SECONDS")
    ap.add_argument("--seconds", type=float, default=1.0, metavar="SECONDS")
    ap.add_argument("--idle", action="store_true", help="no crank, no pedal: the settled OS only")
    args = ap.parse_args()

    if args.flash and args.mpc:
        with open(args.flash, "rb") as f, open(args.mpc, "rb") as m:
            pair = Pair(f.read(), m.read(), os.path.basename(args.flash).split(".")[0])
    elif args.pair:
        pair = load_pair(args.pair)
    else:
        with open(os.path.join(IMAGES_DIR, "session1.flash.bin"), "rb") as f, \
             open(os.path.join(IMAGES_DIR, "session1.mpc.bin"), "rb") as m:
            pair = Pair(f.read(), m.read(), "session1")

    b = Board(pair)
    fmap = FunctionMap(pair)
    print(f"pair {pair.name}: program {pair.program_id.decode('latin1')}", flush=True)
    nmaps = dme.map_count(b.m)
    if nmaps:
        print(f"map switch: {nmaps} maps, active index {dme.selected(b.m)}", flush=True)

    ranges = [(dme.CAL_BASE, dme.CAL_BASE + dme.CAL_LENGTH)]
    if nmaps:
        ranges.append((dme.MAPS_HEADER, dme.MAPS_HEADER + 0x100 + nmaps * dme.MAPS_TABLE_STRIDE))
    x = Xref(b, ranges, fmap=fmap)

    ram_map = bytearray((RAM_HI - RAM_LO) // GRAN)
    n_stores = [0]
    min_r1 = [1 << 32]

    def on_store(mu, access, addr, size, value, ud):
        n_stores[0] += 1
        r1 = mu.reg_read(UC_PPC_REG_0 + 1)
        if r1 < min_r1[0]:
            min_r1[0] = r1
        i = ((addr & ~7) - RAM_LO) >> 3
        if 0 <= i < len(ram_map):
            ram_map[i] = 1

    b.m.mu.hook_add(UC_HOOK_MEM_WRITE, on_store, begin=RAM_LO, end=RAM_HI - 1)

    b.probe(SCHEDULER_TASK, "scheduler")
    print(f"boot: settling {args.settle:g} s", flush=True)
    b.boot(max_insns=int(args.settle * b.ips))
    if args.idle:
        print("running: the settled OS only (--idle)", flush=True)
        b.run(int(args.seconds * b.ips))
    else:
        peers = Peers(b, automatic=True)
        set_pedal(b, args.pedal)
        b.crank.rpm = args.rpm
        print(f"running: crank {args.rpm:g} rpm, pedal {args.pedal} %", flush=True)
        peers.run(int(args.seconds * b.ips))

    print(f"after {args.seconds:g} s: scheduler ticks={b.probe_counts['scheduler']}, "
          f"engine speed N={b.m.sda16(dme.VAR_N)}, engine_state={b.m.read8(ENGINE_STATE):#04x}, "
          f"tpu requests={b.tpu_requests}, SRAM stores={n_stores[0]}", flush=True)

    # ---- calibration reads -------------------------------------------------
    # (site, cal-relative offsets); the background walker counted apart
    walker = []
    per_site = []
    for (pc, kind), s in x.sites.items():
        if kind != "R":
            continue
        offs = {o - CAL_OFF for o in (chip_offset(a) for a in s.addrs)
                if o is not None and CAL_OFF <= o < CAL_OFF + dme.CAL_LENGTH}
        if not offs:
            continue
        if WALKER_LO <= pc < WALKER_HI:
            walker.append((s, offs))
        else:
            per_site.append((s, offs))

    walk_reads = sum(s.count for s, _ in walker)
    walk_offs = set().union(*(offs for _, offs in walker)) if walker else set()
    print(f"\ncalibration (0x40000-0x5CFFF, {dme.CAL_LENGTH:#x} bytes):", flush=True)
    print(f"  background CRC walker: {walk_reads} reads over {len(walk_offs)} offsets "
          f"(sweeps everything; not table lookups -- excluded below)", flush=True)

    total = sum(s.count for s, _ in per_site)
    all_offs = set().union(*(offs for _, offs in per_site)) if per_site else set()
    lib = [(s, o) for s, o in per_site if LIB_LO <= s.pc < LIB_HI]
    lib_reads = sum(s.count for s, _ in lib)
    lib_offs = set().union(*(o for _, o in lib)) if lib else set()
    print(f"  table reads: {total} from {len(per_site)} sites, {len(all_offs)} distinct offsets, "
          f"{len({o >> 10 for o in all_offs})} of {dme.CAL_LENGTH // 0x400} blocks", flush=True)
    if total:
        print(f"  through the lookup-library cluster (MPC {LIB_LO:#x}-{LIB_HI - 1:#x}): "
              f"{lib_reads} reads ({100 * lib_reads / total:.0f}%), {len(lib_offs)} offsets, "
              f"{len(lib)} sites", flush=True)
    other = [(s, o) for s, o in per_site if not (LIB_LO <= s.pc < LIB_HI)]
    if other:
        print(f"  outside the cluster: {sum(s.count for s, _ in other)} reads from {len(other)} sites:",
              flush=True)
        for s, o in sorted(other, key=lambda t: -t[0].count)[:10]:
            print(f"    0x{s.pc:X} {fmap.label(s.pc)} x{s.count}, {len(o)} offsets", flush=True)

    spans = coalesce(all_offs)
    hot = []
    for lo, hi in spans:
        readers = sorted(((s.count, s.pc) for s, offs in per_site
                          if any(lo <= o <= hi for o in offs)), reverse=True)
        hot.append((sum(n for n, _ in readers), lo, hi, readers))
    print(f"  ranges read ({len(spans)}), hottest first:", flush=True)
    for tot, lo, hi, readers in sorted(hot, reverse=True)[:25]:
        text = ", ".join(f"{'lib ' if LIB_LO <= pc < LIB_HI else ''}{fmap.label(pc)} x{n}"
                         for n, pc in readers[:3])
        print(f"    cal {lo:#07x}-{hi:#07x} ({hi - lo + 1:4d} B, block {lo >> 10:2d}) "
              f"reads {tot:6d}  {text}", flush=True)

    # ---- the map switch's header and block tables ---------------------------
    if nmaps:
        lo_c, hi_c = 0xDCC00, 0xDCC00 + 0x100 + nmaps * dme.MAPS_TABLE_STRIDE
        hdr = [s for (pc, kind), s in x.sites.items()
               if kind == "R" and any(o is not None and lo_c <= o < hi_c
                                      for o in (chip_offset(a) for a in s.addrs))]
        print(f"\nmap header/block tables (chip 0x{lo_c:X}..0x{hi_c - 1:X}): "
              f"{sum(s.count for s in hdr)} reads from {len(hdr)} sites", flush=True)
        for s in sorted(hdr, key=lambda s: -s.count)[:8]:
            print(f"    0x{s.pc:X} {fmap.label(s.pc)} x{s.count}", flush=True)

    # ---- SRAM ---------------------------------------------------------------
    print(f"\nSRAM: {n_stores[0]} stores, {sum(ram_map)} of {len(ram_map)} 8-byte granules written, "
          f"deepest r1 at a store: {min_r1[0]:#x} ({0x3FFFF00 - min_r1[0]:#x} below the stack top)",
          flush=True)
    free, run_start = [], None
    for i, v in enumerate(ram_map):
        if not v:
            if run_start is None:
                run_start = RAM_LO + i * GRAN
        else:
            if run_start is not None and RAM_LO + i * GRAN - run_start >= 0x40:
                free.append((run_start, RAM_LO + i * GRAN))
            run_start = None
    if run_start is not None and RAM_HI - run_start >= 0x40:
        free.append((run_start, RAM_HI))
    print("  never written (spans >= 0x40 B):" if free else "  never written: nothing")
    for lo, hi in free:
        zone = next((name for a, z, name in ZONES if a <= lo < z), "?")
        print(f"    {lo:#08x}-{hi - 1:#08x} ({hi - lo:5d} B)  {zone}", flush=True)


if __name__ == "__main__":
    main()
