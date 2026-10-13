#!/usr/bin/env python
"""Proof of concept: the MS45.1 boot region opened to KWP writes, end to end.

    .venv/bin/python tools/bootregion_poc.py [--flash Flash.bin --mpc MPC.bin]
                                            [--out DIR]

Everything runs against the emulator, on the pair it is given (default
images/session1.*). The DME's own code does every check; nothing is mocked.

The chain, in the order the script runs it:

 1. Build, offline: the stock MPC image's compressed-vector reset entry
    (word 8, `ba 0xFFF717B4`) is redirected to a 19-instruction payload in
    the image's blank tail (0x6F000). The payload issues one AMD program
    cycle that clears a single bit of the sector table's entry-2 start
    (0xFFF40000 -> 0xFFF00000, AND-compatible: F4 & F0 = F0), then branches
    to the program start it replaced. fix_program() brings the safety-monitor
    sum, both program CRCs and the RSA signature up to date over the changed
    MPC image -- with the program-signature key BMWeb-Flasher carries.
 2. Flash it exactly the way a flasher flashes a program: mode-3 seed/key,
    programming mode, one 31 02 erase (program sectors + internal flash),
    34/36/37 for the external and internal images. On the stock sector
    table a 34 aimed at the boot region (ext 0x1F810) is still refused
    with NRC 0x40 -- no sector entry covers it.
 3. 31 09 checks the program and accepts the signature; the loader marks
    it valid. Reset: the loader hands control to `ba 8` as always, which is
    now the payload. It patches the table in the chip (one program cycle,
    no erase) and starts the program.
 4. A second, ordinary programming session: after a 31 02 calibration
    erase (which is what sets the session's erase flag), the same 34/36/37
    that the stock DME refused now writes 8 bytes at ext 0x1F810 -- inside
    the boot region. The calibration is then restored and re-signed, so the
    DME ends the demo healthy, with all four valid marks.
 5. Final reset: the program boots, the payload's guard sees the byte
    already patched and skips (idempotent), and the byte planted over KWP
    is still in the boot region.

What this proves: write access to the boot region needs no new key and no
RAM-upload exploit -- a program update signed with the key the flasher
already holds is enough, because the sector table that locks the boot
region lives in the boot region itself and is AND-programmable.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu.board import Board, VALID_MARKS          # noqa: E402
from ms45emu.image import Pair, IMAGES_DIR            # noqa: E402
from ms45emu.kwp import Tester                        # noqa: E402
from ms45emu.checksums import fix_program             # noqa: E402

EXT = 0xFFF00000                       # external flash, CPU address
EXTERNAL, INTERNAL = 0x02000000, 0x06000000   # the KWP address windows
PROGRAM, PROGRAM_END = 0x60000, 0xFFF40        # what a flasher sends of each part
CALIBRATION, CALIBRATION_END = 0x40000, 0x5D000
SCHEDULER_TASK, INIT_DONE = 0x3B38C, 0x3FEB26  # how a running program is recognised

SECTOR_TABLE = 0x2D94                  # 4 entries x {start32, end32, attr8, next8}
ENTRY2 = SECTOR_TABLE + 2 * 12         # entry 2's start32: the calibration's 0xFFF40000
HOOK = 8                               # compressed-vector entry 1 (reset) in the MPC image
PAYLOAD_AT = 0x6F000                   # blank tail of the MPC image (stock code ends 0x6E906)
RESET_ENTRY_WORD = 0x4BF717B6          # ba 0xFFF717B4, what MPC 0x8 holds from the factory

DEMO_AT, DEMO_DATA = 0x1F810, b"\xa5" * 8       # in the boot region, blank, outside the
# boot CRC's range (0x0-0x1EFFF) and the tail (0x1F900+), so planting it breaks nothing


def _ba(target):
    """`ba <target>` as the firmware encodes it (see cpu._ba)."""
    return 0x48000002 | (target & 0x03FFFFFC)


# The payload, one word per line, checked against capstone. Only plain
# integer/load/store/branch forms: nothing the emulator's own patching looks
# for (no mtspr/mfspr/mtmsr, no lis rX,0x30).
PAYLOAD_WORDS = [
    (0x3C60FFF0, "lis    r3, 0xFFF0"),          # r3 = the external flash
    (0x88832DAD, "lbz    r4, 0x2DAD(r3)"),      # entry 2's start byte
    (0x2C0400F0, "cmpwi  r4, 0xF0"),            # already patched?
    (0x4182003C, "beq    done"),                #   yes: nothing to do (idempotent)
    (0x38C000AA, "li     r6, 0xAA"),
    (0xB0C30AAA, "sth    r6, 0xAAA(r3)"),       # AMD unlock cycle 1
    (0x38C00055, "li     r6, 0x55"),
    (0xB0C30554, "sth    r6, 0x554(r3)"),       # AMD unlock cycle 2
    (0x38C000A0, "li     r6, 0xA0"),
    (0xB0C30AAA, "sth    r6, 0xAAA(r3)"),       # program setup
    (0x3900FFF0, "li     r8, 0xFFF0"),          # the data halfword (low 16 bits)
    (0xB1032DAC, "sth    r8, 0x2DAC(r3)"),      # data cycle: FFF4 & FFF0 = FFF0
    (0x3940FFFF, "li     r10, -1"),             # poll bound
    (0xA1232DAC, "lhz    r9, 0x2DAC(r3)"),      # poll:
    (0x2809FFF0, "cmplwi r9, 0xFFF0"),
    (0x4182000C, "beq    done"),
    (0x354AFFFF, "addic. r10, r10, -1"),
    (0x4082FFF0, "bne    poll"),                # (a real DME would poll DQ7/DQ6)
    (0x4BF717B6, "ba     0xFFF717B4"),          # done: the very word we replaced
]
PAYLOAD = b"".join(struct.pack(">I", w) for w, _ in PAYLOAD_WORDS)


def banner(text):
    print("\n" + "=" * 74 + f"\n{text}\n" + "=" * 74, flush=True)


def check(cond, msg):
    if not cond:
        raise SystemExit(f"  FAIL: {msg}")
    print(f"  ok: {msg}", flush=True)


def make_progress(label):
    state = {"blocks": 0, "last": 0}

    def progress(at, total):
        state["blocks"] += 1
        if state["blocks"] - state["last"] >= 200 or at >= total:
            print(f"    {label}: {at}/{total} bytes ({state['blocks']} blocks)", flush=True)
            state["last"] = state["blocks"]
    return progress


def raw_34(t, start, length):
    """A 34 RequestDownload exactly as Tester.write sends it, without the 36s."""
    region = Tester._region(start, length)
    region[4:4] = [0x00]
    return t.request([0x34] + region)


def phase_build(base):
    banner("1. building the patched program (offline, no DME involved)")
    mpc, flash = bytearray(base.mpc), bytearray(base.flash)

    stock_word = struct.unpack_from(">I", mpc, HOOK)[0]
    check(stock_word == RESET_ENTRY_WORD,
          f"MPC 0x8 holds {stock_word:#010x} = ba 0xFFF717B4 (the program's start)")
    check(mpc[PAYLOAD_AT:] == b"\xff" * (len(mpc) - PAYLOAD_AT),
          f"MPC {PAYLOAD_AT:#x}-{len(mpc) - 1:#x} is blank (payload room; stock code ends 0x6E906)")
    check(flash[ENTRY2:ENTRY2 + 4] == bytes.fromhex("fff40000"),
          f"sector entry 2 ({ENTRY2:#x}) starts at 0xFFF40000 (the calibration)")
    check(all(bytes(flash[at:at + 4]) == mark.to_bytes(4, "big") for at, mark in VALID_MARKS),
          "the base pair carries all four valid marks (a DME that runs its program)")

    struct.pack_into(">I", mpc, HOOK, _ba(PAYLOAD_AT))
    mpc[PAYLOAD_AT:PAYLOAD_AT + len(PAYLOAD)] = PAYLOAD
    fix_program(flash, mpc)

    print(f"  MPC 0x8: {stock_word:#010x} -> {struct.unpack_from('>I', mpc, HOOK)[0]:#010x}"
          f" (ba {PAYLOAD_AT:#x})")
    print(f"  payload: {len(PAYLOAD)} bytes at MPC {PAYLOAD_AT:#x}:")
    try:
        from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
        md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
        for i, (w, note) in enumerate(PAYLOAD_WORDS):
            ins = next(md.disasm(struct.pack(">I", w), PAYLOAD_AT + 4 * i))
            print(f"    {PAYLOAD_AT + 4 * i:05X}: {w:08X}  {ins.mnemonic:7s} {ins.op_str:16s}  ; {note}")
    except ImportError:
        for i, (w, note) in enumerate(PAYLOAD_WORDS):
            print(f"    {PAYLOAD_AT + 4 * i:05X}: {w:08X}  {note}")
    changed = sorted(set(at & ~7 for at in range(len(flash)) if flash[at] != base.flash[at]))
    print(f"  external flash changed at {[hex(a) for a in changed]}"
          f" (the program CRCs and the signature; the safety-monitor sum's ranges"
          f" do not cover the payload, so it did not move) -- the sector table itself is NOT touched")
    return bytes(flash), bytes(mpc)


def phase_flash(base, patched_flash, patched_mpc):
    banner("2. flashing it as an ordinary program update (the KWP session a flasher runs)")
    b = Board(base)
    b.boot(max_insns=20_000_000)
    t = Tester(b)
    check(t.authenticate(), "mode-3 seed/key accepted (the unlock flag is set)")
    check(t.programming_mode(), "programming mode entered")

    check(t.erase(EXTERNAL + PROGRAM, 0xA0000),
          "31 02 erased the three program sectors and the internal flash (the erase flag is set)")

    r = raw_34(t, EXTERNAL + DEMO_AT, len(DEMO_DATA))
    check(r == bytes.fromhex("7f3440"),
          f"34 at ext {DEMO_AT:#x} on the STOCK sector table -> {r.hex() if r else 'no answer'}"
          f" (NRC 0x40: no entry covers the boot region)")

    ok, sent = t.write_sparse(EXTERNAL + PROGRAM, patched_flash[PROGRAM:PROGRAM_END],
                              make_progress("external program"))
    check(ok, f"34/36/37 wrote the external program image ({sent} blocks)")
    ok, sent = t.write_sparse(INTERNAL, patched_mpc, make_progress("internal flash"))
    check(ok, f"34/36/37 wrote the internal flash image ({sent} blocks)")

    check(t.default_mode(), "back to the default session")
    check(t.programming_status() == 5, "31 0A: program signature not checked yet")
    check(t.check_signature("program"),
          "31 09 accepted the program -- the RSA signature fix_program forged over the patched image")
    check(t.programming_status() == 1, "31 0A: normal again (the calibration was never touched)")
    check(b.program_valid(), "all four valid marks are in: the loader will start this program")
    check(t.reset(), "STEUERGERAETE_RESET")
    return b


def phase_boot(b):
    banner("3. reset: the loader starts the patched program; the payload patches the table")
    b2 = b.reset()
    b2.probe(SCHEDULER_TASK, "scheduler")
    _, why = b2.boot(max_insns=40_000_000, reset_vector=True)
    check(b2.m.read8(INIT_DONE) == 1 and b2.probe_counts["scheduler"] > 10,
          f"the patched program runs (scheduler ticks: {b2.probe_counts['scheduler']}; {why})")
    check(bytes(b2.flash.image[ENTRY2:ENTRY2 + 4]) == bytes.fromhex("fff00000"),
          f"sector entry 2 now starts at 0xFFF00000: one bit cleared in the chip, no erase")
    writes = [(a, v, pc) for (a, s, v, pc) in b2.flash_writes if a >= EXT]
    for a, v, pc in writes:
        who = "the payload" if PAYLOAD_AT <= pc < PAYLOAD_AT + len(PAYLOAD) else "the program's own start (stock)"
        print(f"    store {v & 0xFFFF:04x} at {a:#010x} from pc={pc:#x} -- {who}")
    from_payload = [(a, v) for a, v, pc in writes if PAYLOAD_AT <= pc < PAYLOAD_AT + len(PAYLOAD)]
    check(len(from_payload) == 4 and any(a == 0xFFF02DAC and v & 0xFFFF == 0xFFF0 for a, v in from_payload),
          "the payload's four stores reached the chip: 3 AMD command cycles + the one data cycle")
    check(b2.flash.programs == 1 and b2.flash.erases == 0,
          "one program cycle, no erase -- the boot region was never erased "
          "(the program's own start pokes the chip too; those are unknown commands, nothing is programmed)")
    return b2


def phase_demo(b2, stock_cal):
    banner("4. the payoff: an ordinary 34/36 write into the boot region")
    t2 = Tester(b2)
    check(t2.authenticate(), "mode-3 seed/key accepted")

    r = raw_34(t2, EXTERNAL + DEMO_AT, len(DEMO_DATA))
    print(f"    34 at ext {DEMO_AT:#x} on the PATCHED table, before any 31-erase this session"
          f" -> {r.hex() if r else 'no answer'} (the erase flag is still clear)")

    check(t2.programming_mode(), "programming mode entered")
    check(t2.erase(EXTERNAL + CALIBRATION, 0x20000),
          "31 02 calibration erase (sets the session's erase flag; restored below)")
    check(t2.write(EXTERNAL + DEMO_AT, DEMO_DATA),
          f"34/36/37 wrote {len(DEMO_DATA)} bytes at ext {DEMO_AT:#x} -- INSIDE the boot region")
    check(bytes(b2.flash.image[DEMO_AT:DEMO_AT + len(DEMO_DATA)]) == DEMO_DATA,
          f"the chip really holds {DEMO_DATA.hex()} at ext {DEMO_AT:#x}")
    reply = next(rep for req, rep in reversed(t2.log) if req and req[0] == 0x34)
    print(f"    the accepted 34 answered {reply[4:-1].hex()} (positive, 0x74)")

    ok, sent = t2.write_sparse(EXTERNAL + CALIBRATION, stock_cal, make_progress("calibration"))
    check(ok, f"calibration restored ({sent} blocks)")
    check(t2.default_mode(), "back to the default session")
    check(t2.check_signature("data"), "31 09 re-checked the calibration and marked it valid")
    check(b2.program_valid(), "all four valid marks back: a healthy DME again, patch included")
    check(t2.reset(), "STEUERGERAETE_RESET")
    return b2


def phase_final(b2):
    banner("5. final reset: healthy DME, patch in place, the planted byte still there")
    b3 = b2.reset()
    b3.probe(SCHEDULER_TASK, "scheduler")
    _, why = b3.boot(max_insns=40_000_000, reset_vector=True)
    check(b3.m.read8(INIT_DONE) == 1 and b3.probe_counts["scheduler"] > 10,
          f"the program boots normally (scheduler ticks: {b3.probe_counts['scheduler']})")
    check(b3.flash.image[ENTRY2 + 1] == 0xF0 and b3.flash.programs == 0,
          "the patched table byte persisted, and the payload's guard skipped: no second program cycle")
    check(bytes(b3.flash.image[DEMO_AT:DEMO_AT + len(DEMO_DATA)]) == DEMO_DATA,
          f"the byte planted over KWP at ext {DEMO_AT:#x} is still there")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flash", help="1MB external flash dump of the base pair")
    ap.add_argument("--mpc", help="448KB MPC dump of the base pair")
    ap.add_argument("--out", help="also write the built pair here (bootpatch_Flash/MPC.bin)")
    args = ap.parse_args()

    if args.flash and args.mpc:
        with open(args.flash, "rb") as f, open(args.mpc, "rb") as m:
            base = Pair(f.read(), m.read(), "base")
    else:
        flash_path = os.path.join(IMAGES_DIR, "session1.flash.bin")
        mpc_path = os.path.join(IMAGES_DIR, "session1.mpc.bin")
        if not (os.path.isfile(flash_path) and os.path.isfile(mpc_path)):
            raise SystemExit(f"no base pair: give --flash and --mpc, or put {flash_path} there")
        with open(flash_path, "rb") as f, open(mpc_path, "rb") as m:
            base = Pair(f.read(), m.read(), "session1")
    print(f"base pair: {base.name}, program {base.program_id.decode()}", flush=True)

    patched_flash, patched_mpc = phase_build(base)
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for kind, data in (("Flash", patched_flash), ("MPC", patched_mpc)):
            path = os.path.join(args.out, f"bootpatch_{kind}.bin")
            with open(path, "wb") as f:
                f.write(data)
            print("wrote", path, flush=True)

    b = phase_flash(base, patched_flash, patched_mpc)
    b2 = phase_boot(b)
    phase_demo(b2, base.flash[CALIBRATION:CALIBRATION_END])
    phase_final(b2)

    banner("done: the boot region is writable through the ordinary flash protocol")
    print("The program update was signed with the key the flasher already holds; the\n"
          "loader installed and started it; the payload it carries needed one AND-\n"
          "programmable bit of the sector table -- which lives in the boot region it\n"
          "was protecting -- and after that the same 34/36 the stock DME answers with\n"
          "NRC 0x40 writes the boot region. No new key, no RAM upload, no erase of a\n"
          "boot sector. See docs/bootregion-poc.md for the analysis.")


if __name__ == "__main__":
    main()
