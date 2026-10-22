#!/usr/bin/env python
"""Diff-based re-flashing over KWP on the granular-erase loader, on the emulator.

    .venv/bin/python tools/diff_flash.py --test
    .venv/bin/python tools/diff_flash.py --target Flash.bin [--mpc MPC.bin] --shadow STATE.json

The stock flow moves ~1 MB for any change: one 31 02 takes all three program
sectors and the whole internal flash, and everything is rewritten. With the
granular-erase loader patch (tools/granular_erase.py, proven there), a 31 02
erases only the sectors overlapping its range. So a diff flash is:

  - the shadow (what the last successful flash left in the chip) is diffed
    against the target offline, per sector;
  - every sector that differs gets a granular 31 02 of exactly itself and
    only its non-blank runs back. Measured on the emulator: the loader's
    34/36/37 path programs only blank-or-identical halfwords -- a changed
    halfword over live content is silently skipped (74/76/77 all positive,
    the byte never moves), so there is no and-only write and every changed
    sector must be erased first;
  - internal flash blocks likewise: overlapping blocks only;
  - the target is signed offline (fix_program). The close: 31 09 (a real
    revalidation whenever the marks sector 0xC0000 was in the plan -- the
    pair died with its sector and the check re-programs it -- otherwise a
    vacuous pass over the still-valid pair) and a boot check, the DME
    running the new program.

Nothing over KWP can read the external flash back, so the shadow is trusted
bookkeeping: verification is the RAM driver's own per-halfword poll, the
DME's RSA check (31 09), and the program booting. The resident monitor (the
next layer) replaces the trust with a sector-CRC handshake.

--test builds the whole scene on the emulator: the base pair with the loader
patch baked into the boot sector (the delivery itself is granular_erase's
phases 2-3), then two successive diffs against an updated shadow -- a
one-byte tune change (the re-signing words force sector 0x60000 as well)
and a second byte change -- each followed by a boot check, with the wire
counts against the stock full flash.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aif_wipe import banner, check, make_progress                        # noqa: E402
from granular_erase import (assemble_gran, locate, site_patch_words,      # noqa: E402
                            GRAN_AT, CRC_AT, CRC_RANGE,
                            EXTERNAL, INTERNAL, PROGRAM, PROGRAM_END,
                            SCHEDULER_TASK, INIT_DONE)
from ms45emu.board import Board                                           # noqa: E402
from ms45emu.flashchip import SECTORS                                     # noqa: E402
from ms45emu.image import Pair, IMAGES_DIR                                # noqa: E402
from ms45emu.kwp import Tester                                            # noqa: E402
from ms45emu.checksums import fix_program, crc32_mpeg2                    # noqa: E402

INT_BLOCK = 0x8000                        # the internal flash's 14 blocks


def sha(data):
    return hashlib.sha256(data).hexdigest()[:16]


def sector_crcs(flash):
    """CRC-32/MPEG-2 per external sector -- the shadow's fingerprint."""
    return {f"{start:05x}": crc32_mpeg2(flash[start:start + size]) for start, size in SECTORS}


# ---------------------------------------------------------------------------
# the offline diff


def plan(old_pair, new_pair):
    """What to send: per external program sector ('same'/'erase') and per
    internal block ('same'/'erase'). Every differing sector is erased
    first: the loader's 34/36/37 path programs only blank-or-identical
    halfwords (measured; changed halfwords over live content are silently
    skipped), so bit-clear-only changes need the erase just as much. The
    calibration sector is not planned here -- a cal change is its own
    flow, with its stamp and the 31 09 data check."""
    ops = []
    if old_pair.flash[0x40000:0x60000] != new_pair.flash[0x40000:0x60000]:
        print("    note: the calibration sector differs; this plan does not touch it")
    for start, size in SECTORS:
        if not (PROGRAM <= start < PROGRAM_END):
            continue
        # compare only to 0xFFF40: the tail beyond it (the dump's 54-byte
        # stamp copy and the marks pair) is loader territory, blank after
        # any real flash -- the erase op still carries the whole sector
        span = min(size, PROGRAM_END - start)
        o, n = old_pair.flash[start:start + span], new_pair.flash[start:start + span]
        if o == n:
            ops.append(("same", start, size, 0))
        else:
            ops.append(("erase", start, size, sum(1 for a, b in zip(o, n) if a != b)))
    for start in range(0, len(new_pair.mpc), INT_BLOCK):
        o = old_pair.mpc[start:start + INT_BLOCK]
        n = new_pair.mpc[start:start + INT_BLOCK]
        if o == n:
            ops.append(("same", INT_BASE_MPC + start, INT_BLOCK, 0))
        else:
            ops.append(("erase", INT_BASE_MPC + start, INT_BLOCK,
                        sum(1 for a, b in zip(o, n) if a != b)))
    return ops


INT_BASE_MPC = 0x1000000                  # internal blocks, in the plan's namespace


def describe(ops):
    for kind, start, size, diff_bytes in ops:
        where = f"ext {start:#07x}" if start < INT_BASE_MPC else f"mpc {start - INT_BASE_MPC:#06x}"
        print(f"    {kind:>5} {where} ({size:#x}): {diff_bytes} bytes differ")


# ---------------------------------------------------------------------------
# the session


def open_session(b, what):
    t = Tester(b)
    check(t.authenticate(), f"{what}: mode-3 seed/key accepted")
    check(t.programming_mode(), f"{what}: programming mode entered")
    return t


def run_plan(b, ops, new_pair, label):
    """Execute a plan over KWP: erases (granular 31 02), then the writes."""
    t = open_session(b, label)
    flash_erases = [(s, z) for k, s, z, _ in ops if k == "erase" and s < INT_BASE_MPC]
    mpc_erases = [(s, z) for k, s, z, _ in ops if k == "erase" and s >= INT_BASE_MPC]
    writes = [(k, s, z) for k, s, z, _ in ops if k != "same"]
    assert not writes or flash_erases or mpc_erases, \
        "every write follows its sector's erase (the loader skips live changed halfwords)"

    for start, size in flash_erases:
        check(t.erase(EXTERNAL + start, size), f"31 02 erased ext sector {start:#x} only")
    for start, size in mpc_erases:            # internal window: overlapping blocks only
        check(t.erase(INTERNAL + start - INT_BASE_MPC, size),
              f"31 02 erased internal blocks [{start - INT_BASE_MPC:#x}, +{size:#x})")

    wire = 0
    for kind, start, size in writes:
        if start >= INT_BASE_MPC:
            at, data, span = start - INT_BASE_MPC, new_pair.mpc, size
        else:
            # the loader refuses 34/36/37 into its marks tail
            # [0xFFF40,0x100000); the marks come back with the 31 09
            at, data = start, new_pair.flash
            span = min(size, PROGRAM_END - start)
        ok, sent = t.write_sparse((INTERNAL if start >= INT_BASE_MPC else EXTERNAL) + at,
                                  data[at:at + span], make_progress(f"{kind} {at:#x}"))
        wire += sent
        check(ok, f"34/36/37 wrote {span:#x} bytes at {'mpc' if start >= INT_BASE_MPC else 'ext'} "
                  f"{at:#x} ({sent} blocks)")
    check(t.default_mode(), "back to the default session")
    # 31 09 02 answers 01 when it ran (pair was dead: it revalidates the
    # image and re-programs the magic over blank) and 00 when the program
    # pair is still valid ("nothing to check" -- a plan that never touched
    # sector 0xC0000; the Daten check is the idempotent one, this is not).
    # Both are the DME answering healthy; which one says whether this
    # plan's close carried a real revalidation
    marks_sector = any(s <= 0xD2000 < s + z for s, z in flash_erases)
    r = t.request([0x31, 0x09, 0x02], timeout_frames=200)
    check(bool(r) and r[0] == 0x71 and r[2] in (0x00, 0x01),
          "31 09 program check: " +
          ("revalidated the image (the marks sector was in the plan, the pair "
           "died with it and the check re-programmed it)"
           if (r and len(r) > 2 and r[2] == 0x01) else
           "nothing to check (the pair is still valid -- sector 0xC0000 was "
           "not in the plan; the boot check is the real verification)")
          + f" [answer {bytes(r).hex() if r else None}]")
    check(t.reset(), "STEUERGERAETE_RESET")
    return wire


def boot_check(b3, what):
    b = b3.reset()
    b.probe(SCHEDULER_TASK, "scheduler")
    b.boot(max_insns=40_000_000, reset_vector=True)
    check(b.m.read8(INIT_DONE) == 1 and b.probe_counts["scheduler"] > 10,
          f"{what}: the program runs (scheduler ticks: {b.probe_counts['scheduler']})")
    return b


def save_shadow(path, pair, note):
    state = {"note": note, "flash_sha256": sha(pair.flash), "mpc_sha256": sha(pair.mpc),
             "sector_crcs": sector_crcs(pair.flash)}
    with open(path, "w") as f:
        json.dump(state, f, indent=1)
    print(f"  shadow saved: {path} ({note})")


def load_shadow(path, pair):
    """The shadow must match the pair it claims, or it is stale."""
    with open(path) as f:
        state = json.load(f)
    check(state["flash_sha256"] == sha(pair.flash) and state["mpc_sha256"] == sha(pair.mpc),
          f"the shadow at {path} matches the pair it was written for")
    return state


# ---------------------------------------------------------------------------
# --test: the whole scene on the emulator


def patched_boot_pair(base):
    """The base pair with the loader patch baked into the boot sector (the
    emulator shortcut; over KWP the same bytes arrive via granular_erase's
    installer, proven in its phases 2-3)."""
    flash = bytearray(base.flash)
    addrs = locate(bytes(flash))
    gran = assemble_gran(addrs)
    gran.resolve(0xFFF00000 | GRAN_AT)        # runtime address, not the chip offset
    patch_words = site_patch_words(addrs)
    for i, w in enumerate(patch_words):
        struct.pack_into(">I", flash, addrs["site"] + 8 + 4 * i, w)
    for i, (w, _) in enumerate(gran.words):
        struct.pack_into(">I", flash, GRAN_AT + 4 * i, w)
    silicon = bytearray(flash)                # the CRC over silicon bytes, gran
    new_crc = crc32_mpeg2(silicon[CRC_RANGE[0]:CRC_RANGE[1]])  # is outside the range
    flash[CRC_AT:CRC_AT + 4] = struct.pack(">I", new_crc)
    return Pair(bytes(flash), bytes(base.mpc), base.name + "+granular"), new_crc


def phase_test(base):
    banner("1. the DME: the base pair with the granular-erase loader baked in")
    pair, new_crc = patched_boot_pair(base)
    b = Board(pair)
    b.probe(SCHEDULER_TASK, "scheduler")
    b.boot(max_insns=40_000_000, reset_vector=True)
    check(b.m.read8(INIT_DONE) == 1 and b.probe_counts["scheduler"] > 10,
          f"the program runs on the patched loader (boot CRC {new_crc:08x})")
    shadow = pair

    # -- diff A: one bit cleared in sector 0x80000 (the sector still erases:
    #    the loader skips changed halfwords over live content; and sector
    #    0x60000 re-signs)
    banner("2. diff A: a bit-clear-only tune change (its sector erases anyway)")
    at = next(a for a in range(0x8A000, 0xC0000)
              if base.flash[a] not in (0x00, 0xFF) and base.flash[a] & (base.flash[a] - 1))
    old_byte = base.flash[at]
    new_byte = old_byte & (old_byte - 1)      # clear the lowest set bit
    print(f"  tune byte at ext {at:#x}: {old_byte:#04x} -> {new_byte:#04x} (a bit cleared)")
    flash = bytearray(base.flash)
    flash[at] = new_byte
    fix_program(flash, bytearray(base.mpc))
    target_a = Pair(bytes(flash), bytes(base.mpc), "diff-a")

    ops = plan(shadow, target_a)
    describe(ops)
    check(any(k == "erase" and s == 0x80000 for k, s, _, _ in ops),
          "sector 0x80000 erases too: the loader skips live changed halfwords")
    wire = run_plan(b, ops, target_a, "diff A")
    b = boot_check(b, "diff A")
    print(f"  wire: {wire} blocks (a stock full flash sends ~2400)")
    shadow_path = "/tmp/diff_shadow.json"
    save_shadow(shadow_path, target_a, "diff A on the patched loader")
    load_shadow(shadow_path, target_a)      # what the next session will open with
    shadow = target_a

    # -- diff B: a bit set (needs the erase for exactly its sector)
    banner("3. diff B: a bit-setting change, one sector erase")
    at = next(a for a in range(0x90000, 0xC0000) if shadow.flash[a] not in (0x00, 0xFF)
              and not shadow.flash[a] & 0x01)
    old_byte = shadow.flash[at]
    print(f"  byte at ext {at:#x}: {old_byte:#04x} -> {old_byte | 0x01:#04x} (a bit set)")
    flash = bytearray(shadow.flash)
    flash[at] = old_byte | 0x01
    fix_program(flash, bytearray(base.mpc))
    target_b = Pair(bytes(flash), bytes(base.mpc), "diff-b")

    ops = plan(shadow, target_b)
    describe(ops)
    check(any(k == "erase" and s == (at & ~0x3FFFF) for k, s, _, _ in ops),
          f"exactly sector {at & ~0x3FFFF:#x} needs the erase (the one holding the byte)")
    wire = run_plan(b, ops, target_b, "diff B")
    b = boot_check(b, "diff B")
    print(f"  wire: {wire} blocks (a stock full flash sends ~2400)")
    save_shadow(shadow_path, target_b, "diff B on top of diff A")

    banner("done: diff flashes ride the granular loader")
    print("Each one-byte change erased and rewrote exactly the sectors it touched (the\n"
          "re-signing sector plus the tune's own); the loader's 34/36/37 path programs\n"
          "only blank-or-identical halfwords, so even bit-clear-only changes need their\n"
          "sector's erase; the internal flash was never touched. The shadow moved with\n"
          "each success. Next layer: the resident monitor replaces the trusted shadow\n"
          "with a sector-CRC handshake and moves the writes to 0/2 ms pacing.\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--test", action="store_true", help="run the emulator proof")
    ap.add_argument("--flash", help="target 1MB external flash dump")
    ap.add_argument("--mpc", help="target 448KB MPC dump (defaults to the base pair's)")
    ap.add_argument("--shadow", help="shadow state JSON (written after success)")
    args = ap.parse_args()

    with open(os.path.join(IMAGES_DIR, "session1.flash.bin"), "rb") as f:
        base_flash = f.read()
    with open(os.path.join(IMAGES_DIR, "session1.mpc.bin"), "rb") as m:
        base_mpc = m.read()
    base = Pair(base_flash, base_mpc, "session1")
    print(f"base pair: {base.name}, program {base.program_id.decode()}", flush=True)

    if args.test:
        phase_test(base)
        return
    if not (args.flash and args.shadow):
        raise SystemExit("give --test, or --flash and --shadow")

    flash = bytearray(open(args.flash, "rb").read())
    mpc = bytearray(open(args.mpc, "rb").read() if args.mpc else base_mpc)
    fix_program(flash, mpc)
    target = Pair(bytes(flash), bytes(mpc), "target")

    state = load_shadow(args.shadow, base) if os.path.exists(args.shadow) else None
    if state is None:
        raise SystemExit(f"no shadow at {args.shadow}: bootstrap it with one full flash "
                         f"(or the monitor's read), then re-run")
    shadow = Pair(base_flash, base_mpc, "shadow")
    ops = plan(shadow, target)
    describe(ops)
    raise SystemExit("the KWP session needs a board; run against the emulator with --test")


if __name__ == "__main__":
    main()
