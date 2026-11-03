"""The way past a ring that hangs: the LATE installer gate, on the emulator
(docs/bootloader.md 0d).

Run from the ms45-emu root:
    .venv/bin/python -m tools.proofs.bl_late_entry_test

The car (2026-10-28) carries a v16 ring that takes a held line and never
answers, so the in-place update (bl_update_test) cannot start: its one
session runs on that ring. The way out writes nothing through the ring:

  1. the DME's own loader flashes the program with the installer body and
     the LATE gate spliced in (flasher_gate.LATE_GATE: ~2 s of polls at MPC
     0x8, each servicing the watchdog; stamp flag bit 5);
  2. the app resets the DME and holds the line only AFTER the ring's ~1 ms
     window has let the boot by; the late gate takes it, and the body runs;
  3. on that body: the boot sector rewritten with this build's ring (the
     app's own bl.splice (its put)), the AIF ladder round it, then the
     installer switched off (bl.lateOff: zeros over the blank word at ext
     LATE_OFF_AT), RESET;
  4. a line held across the reset now lands in the new ring, and a free
     line boots straight past the switched-off gate to the program.

The stand-in for the car's ring: this build's ring stamped v16 with its
stub replaced by `b .` -- taken, it never sends a byte, as on the car.
Checked: an early hold (the app's normal entry) lands in that ring; a free
line boots through the ring and the late gate to the program with the
watchdog serviced throughout; a late hold reaches the installer body; the
update leaves the boot sector equal to bl.build's and the 8 KB sector
and the MPC untouched; then a held line lands in the new ring.
"""
import json
import os
import struct
import subprocess
import time

from tools.build import bl
from tools.build import flasher_body
from tools.build import flasher_gate as g
from ms45emu.image import load_named
from ms45emu.board import RESET_ENTRY
from ms45emu.checksums import fix_program
from tools.build.flasher_body import SRAM_BASE, REPLY_OFF
from tools.proofs.flasher_session_test import Session, expect
from tools.proofs.bl_test import fresh, hello_wait, taken_from_reset, WATCHDOG_MS, bl_pair
from ms45emu.board import Board
from tools.proofs.bl_app_test import BMWEB, BOOT, BOOT_LEN, SECT8K, SECT8K_LEN, read_outer
from tools.proofs.bl_restore_test import read_region, ladder
from tools.proofs.bl_update_test import app_image, GUARD_AT
from ms45emu.checksums import crc32_mpeg2

HANG = 0x48000000                         # `b .`
LATE_MS = 300                             # where the app's hold starts, DME ms
                                          # after the gate opens (the app waits
                                          # from the reset's reply, which comes
                                          # earlier still)


# the app's splice (bl.withLateInstaller over the exported blob); the
# caller signs, as the app's full flash does
CARRY_JS = r"""
const fs = require('fs');
global.fastFlasher = { BODY_START: 0xfd26c, BODY_END: 0xfff40 };
const { bl } = require(process.argv[1] + '/app/renderer/core/flash/bl.js');
const r = bl.withLateInstaller(new Uint8Array(fs.readFileSync(process.argv[2])),
                                 new Uint8Array(fs.readFileSync(process.argv[3])));
fs.writeFileSync(process.argv[2] + '.out', r.flash);
fs.writeFileSync(process.argv[3] + '.out', r.mpc);
"""


# the app's off switch (bl.lateOff): where, how long, and the CHUNK's
# packed bytes as the app's session client (codec = nrv2b) sends them
OFF_JS = r"""
global.fastFlasher = { BODY_START: 0xfd26c, BODY_END: 0xfff40 };
const { bl } = require(process.argv[1] + '/app/renderer/core/flash/bl.js');
const { nrv2b } = require(process.argv[1] + '/app/renderer/core/flash/nrv2b.js');
const packed = nrv2b.encode(new Uint8Array(bl.LATE_OFF_LEN));
console.log(JSON.stringify([bl.LATE_OFF_AT, bl.LATE_OFF_LEN, Buffer.from(packed).toString('hex')]));
"""


def app_late_off():
    out = subprocess.run(["node", "-e", OFF_JS, BMWEB], check=True, capture_output=True, text=True)
    at, ln, packed = json.loads(out.stdout)
    return at, ln, bytes.fromhex(packed)


def app_carry(f, m, tmp):
    fp, mp = os.path.join(tmp, "late.flash.bin"), os.path.join(tmp, "late.mpc.bin")
    open(fp, "wb").write(f)
    open(mp, "wb").write(m)
    subprocess.run(["node", "-e", CARRY_JS, BMWEB, fp, mp], check=True)
    of, om = bytearray(open(fp + ".out", "rb").read()), bytearray(open(mp + ".out", "rb").read())
    fix_program(of, om)
    return bytes(of), bytes(om)


def in_gate(pc):
    return g.GATE_CPU <= pc < g.ENTRY_CPU


def main():
    t0 = time.time()
    tmp = os.environ.get("TMPDIR", "/tmp")
    pair = load_named(os.environ.get("BL_BASE", "session1.livetune6-notraps"))
    stock_f, mpc0 = bytes(pair.flash), bytes(pair.mpc)
    new_f = bytes(bl.build(stock_f, mpc0)[0])
    new_stamp = new_f[bl.STAMP_AT:bl.STAMP_AT + 16]

    hung = bytearray(new_f)
    hung[bl.STAMP_AT + 6] = 16
    struct.pack_into(">I", hung, bl.STUB_AT, HANG)
    stub_cpu = bl.CPU + bl.STUB_AT

    # ---- the car today: a held line lands in the ring and stays ----------
    b = fresh(bytes(hung), mpc0, "v16 ring")
    b.sci.line_hold = True
    reached, why = b.boot(max_insns=2_000_000, until=stub_cpu, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: an early hold did not reach the v16 stand-in's stub ({why})")
    b.run_from(stub_cpu, 200_000, until=0x1)
    if b.m.pc != stub_cpu or b.sci.tx:
        raise SystemExit(f"FAIL: the stand-in ring did not hang (pc={b.m.pc:#x}, tx={bytes(b.sci.tx).hex()})")
    print("early hold [v16 stand-in]: the ring takes it and never answers, as on the car")

    # ---- stage 1's result: the program with the late installer -----------
    # what the app's slow flash writes (its splice, then signed), checked
    # against the gate build itself but for the EE-write flag the splice
    # drops (the module does not ride a body-only splice)
    inst_f, inst_m = app_carry(bytes(hung), mpc0, tmp)
    was = flasher_body.PERM_LOW
    flasher_body.PERM_LOW = 0x4000
    g.LATE_GATE = True
    try:
        ref_f, ref_m = g.build(bytes(hung), mpc0)
    finally:
        g.LATE_GATE = False
        flasher_body.PERM_LOW = was
    ref_f = bytearray(ref_f)
    ref_f[g.STAMP_AT + 7] &= ~0x08
    fix_program(ref_f, bytearray(ref_m))
    diff = [i for i in range(len(inst_f)) if inst_f[i] != ref_f[i]]
    if diff or inst_m != bytes(ref_m):
        raise SystemExit(f"FAIL: the app's splice differs from the gate build at ext "
                         f"{[hex(x) for x in diff[:6]]} (MPC equal: {inst_m == bytes(ref_m)})")
    print("late installer: the app's splice (bl.withLateInstaller) == the gate build")
    inst_stamp = bytes(inst_f[g.STAMP_AT:g.STAMP_AT + 16])
    if not inst_stamp[7] & g.LATE_FLAG:
        raise SystemExit(f"FAIL: the late installer's stamp lacks flag {g.LATE_FLAG:#x}")
    if inst_f[:0x20000] != bytes(hung[:0x20000]):
        raise SystemExit("FAIL: the installer splice touched the boot region")
    print(f"late installer: stamp {inst_stamp[:6].decode()} v{inst_stamp[6]} flags {inst_stamp[7]:#04x}")
    if not inst_stamp[7] & g.LATE_OFF_FLAG:
        raise SystemExit(f"FAIL: the late installer's stamp lacks the off-switch flag {g.LATE_OFF_FLAG:#x}")
    off_at, off_len, off_packed = app_late_off()
    if (off_at, off_len) != (g.LATE_OFF_AT, g.LATE_OFF_LEN):
        raise SystemExit(f"FAIL: the app's off switch is {off_len} bytes at {off_at:#x}, not {g.LATE_OFF_LEN} at {g.LATE_OFF_AT:#x}")
    if inst_f[off_at:off_at + off_len] != b"\xff" * off_len:
        raise SystemExit("FAIL: the late installer went on with its off switch written")
    # a read of a DME whose installer was switched off carries the zeros:
    # the app's splice must put the switch back to armed
    was_off = bytearray(hung)
    was_off[off_at:off_at + off_len] = bytes(off_len)
    fix_program(was_off, bytearray(mpc0))
    rearmed, _ = app_carry(bytes(was_off), mpc0, tmp)
    if rearmed[off_at:off_at + off_len] != b"\xff" * off_len:
        raise SystemExit("FAIL: the splice kept a switched-off word from the pair it was given")
    print(f"  ok: off switch at ext {off_at:#x} (app == gate build), blank in the splice even from a switched-off read")

    # ---- a free line: ring window, late gate, program; watchdog fed -------
    b = fresh(inst_f, inst_m, "late gate, line free")
    reached, why = b.boot(max_insns=3_000_000, until=g.GATE_CPU, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: line free, the boot never reached the late gate ({why})")
    open_at = b.instructions
    b.watchdog_window()
    reached, why = b.run_from(g.GATE_CPU, 400_000_000, until=RESET_ENTRY)
    if not reached:
        raise SystemExit(f"FAIL: line free, the late gate never handed on to the program ({why})")
    gate_ms = (b.instructions - open_at) * 1000 / b.ips
    gap = b.watchdog_gap_ms()
    if not 0.9 * g.LATE_MS <= gate_ms <= 1.1 * g.LATE_MS:
        raise SystemExit(f"FAIL: the late gate listened {gate_ms:.0f} ms, not ~{g.LATE_MS} ms by the time base")
    if gap >= WATCHDOG_MS:
        raise SystemExit(f"FAIL: the watchdog went {gap:.1f} ms unserviced in the late gate")
    print(f"boot [line free]: past the ring, the late gate listens {gate_ms:.0f} DME ms "
          f"(watchdog gap {gap:.2f} ms), the program starts")

    # ---- the same on a slower CPU: timed, not counted ------------------------
    # the car fetches the gate's loop from external flash, ~5x slower than
    # this emulator's 1 instruction per clock; a CPU a quarter as fast
    # (mips=10, the time base still 2.5 MHz) must still see ~LATE_MS, where
    # a counted loop would take four times as long
    slow = Board(bl_pair(inst_f, inst_m, "late gate, slow CPU"), mips=10)
    reached, why = slow.boot(max_insns=3_000_000, until=g.GATE_CPU, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: slow CPU, the boot never reached the late gate ({why})")
    open_at = slow.instructions
    reached, why = slow.run_from(g.GATE_CPU, 200_000_000, until=RESET_ENTRY)
    if not reached:
        raise SystemExit(f"FAIL: slow CPU, the late gate never handed on to the program ({why})")
    slow_ms = (slow.instructions - open_at) * 1000 / slow.ips
    if not 0.9 * g.LATE_MS <= slow_ms <= 1.1 * g.LATE_MS:
        raise SystemExit(f"FAIL: on a CPU a quarter as fast the late gate listened {slow_ms:.0f} ms")
    print(f"boot [line free, CPU a quarter as fast]: the late gate still listens {slow_ms:.0f} DME ms")

    # ---- a late hold: past the ring's window, into the late gate ----------
    b = fresh(inst_f, inst_m, "late hold", waits=True)
    reached, why = b.boot(max_insns=3_000_000, until=g.GATE_CPU, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: the boot never reached the late gate ({why})")
    b.run_from(g.GATE_CPU, LATE_MS * b.ips // 1000, until=0x1)
    if not in_gate(b.m.pc):
        raise SystemExit(f"FAIL: {LATE_MS} ms in, the late gate had already let go (pc={b.m.pc:#x})")
    b.sci.line_hold = True
    reached, why = b.run_from(b.m.pc, 2_000_000, until=SRAM_BASE)
    if not reached:
        raise SystemExit(f"FAIL: a late hold did not reach the installer body ({why})")
    b.run_from(SRAM_BASE, 100_000, until=0x1)
    s = Session(b)
    if not s.until(lambda: SRAM_BASE <= b.m.pc < SRAM_BASE + REPLY_OFF, budget=200_000):
        raise SystemExit(f"FAIL: the installer body is not in SRAM (pc={b.m.pc:#x})")
    print(f"late hold [{LATE_MS} ms into the gate]: the ring let the boot by, the late gate took the line")
    hello_wait(s, "late installer", inst_stamp)

    # ---- the update, on the installer body ---------------------------------
    guard = s.read(GUARD_AT, 8)
    if guard != stock_f[GUARD_AT:GUARD_AT + 8]:
        raise SystemExit(f"FAIL: the park call READ {guard.hex()}")
    boot, s8 = read_region(s, b)
    low, mid = read_outer(s, b)
    nb, ch = app_image(boot, s8, low, mid, tmp)
    print(f"  ok: bl.survey says ring {ch['survey']['ring']!r}, stamp {ch['survey']['stamp']}; current {ch['current']}")
    if ch["current"] or ch["survey"]["ring"] != "older" or not ch["boot"]:
        raise SystemExit("FAIL: the app does not see an older ring to put right")
    if nb != new_f[BOOT:BOOT + BOOT_LEN]:
        raise SystemExit("FAIL: bl.splice (the app's put) differs from bl.build's boot sector")

    # ---- Repair: a TORN span (no ring the survey knows) ------------------------
    # the write cut in its first half: the stamp and the stub gone, the body
    # still there. The put refuses it; Repair (force) writes the ring over it
    torn = bytearray(boot)
    at = bl.WINDOW_AT - BOOT
    torn[at:at + 0x200] = b"\xff" * 0x200
    try:
        app_image(bytes(torn), s8, low, mid, tmp)
    except ValueError as e:
        if "neither a blank span nor a ring" not in str(e):
            raise SystemExit(f"FAIL: the put refused the torn span for the wrong reason: {e}")
        print("  ok: the put refuses a torn span (neither blank nor a ring of ours)")
    else:
        raise SystemExit("FAIL: the put accepted a torn span")
    nb2, ch2 = app_image(bytes(torn), s8, low, mid, tmp, force=True)
    if ch2["survey"]["ring"] is not None or nb2 != new_f[BOOT:BOOT + BOOT_LEN]:
        raise SystemExit(f"FAIL: Repair (forced put) on the torn span: survey {ch2['survey']['ring']!r}, "
                         f"boot sector == bl.build's: {nb2 == new_f[BOOT:BOOT + BOOT_LEN]}")
    print("  ok: Repair (forced put) lays this build's ring over the torn span")
    ladder(s, [(BOOT, nb, "the 96 KB boot sector (the new ring)")])
    st = s.read(bl.STAMP_AT, 16)
    if st != new_stamp:
        raise SystemExit(f"FAIL: stamp after the update {st.hex()}")
    print(f"  ok: stamp {st[:6].decode()} v{st[6]} flags {st[7]:#04x} read back")
    if bytes(b.flash.image[SECT8K:SECT8K + SECT8K_LEN]) != s8:
        raise SystemExit("FAIL: the session touched the 8 KB sector")

    # ---- the installer switched off (bl.lateOff) --------------------------------
    hdr = struct.pack(">IHHI", off_at, off_len, len(off_packed), crc32_mpeg2(off_packed))
    expect(s.xfer(0x03, hdr + off_packed), 0x03, "CHUNK of the off switch (the app's packing)")
    if s.read(off_at, off_len) != bytes(off_len):
        raise SystemExit("FAIL: the off switch did not read back as zeros")
    print(f"  ok: installer switched off: zeros at ext {off_at:#x}, no erase")
    expect(s.xfer(0x06), 0x06, "RESET")

    # ---- a held line now lands in the new ring -------------------------------
    b2, s2 = taken_from_reset(b, "the new ring")
    hello_wait(s2, "the new ring", new_stamp)
    img = bytes(b2.flash.image)
    mark = range(flasher_body.MARK_AT, flasher_body.MARK_AT + 2 * flasher_body.MARK_SLOTS)
    want = bytearray(inst_f)
    want[BOOT:BOOT + BOOT_LEN] = new_f[BOOT:BOOT + BOOT_LEN]
    want[off_at:off_at + off_len] = bytes(off_len)
    stray = [i for i in range(len(img)) if img[i] != want[i] and i not in mark]
    if stray:
        raise SystemExit(f"FAIL: ext {stray[0]:#x} differs ({len(stray)} bytes)")
    if bytes(b2.cmf.image) != inst_m:
        raise SystemExit("FAIL: the MPC changed")
    print("  ok: boot sector == bl.build, the rest as stage 1 left it, but for the spent marker "
          "slot and the off switch; MPC untouched")
    expect(s2.xfer(0x06), 0x06, "RESET")

    # ---- key-on now: the switched-off gate lets the boot straight by -------------
    b3 = fresh(img, inst_m, "installer switched off")
    reached, why = b3.boot(max_insns=3_000_000, until=g.GATE_CPU, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: switched off, the boot never reached MPC 0x8's gate ({why})")
    open_at = b3.instructions
    reached, why = b3.run_from(g.GATE_CPU, 1_000_000, until=RESET_ENTRY)
    if not reached:
        raise SystemExit(f"FAIL: switched off, the gate did not hand on to the program ({why})")
    off_ms = (b3.instructions - open_at) * 1000 / b3.ips
    if off_ms > 0.1:
        raise SystemExit(f"FAIL: the switched-off gate still took {off_ms:.2f} ms")
    print("boot [installer switched off]: the gate hands on to the program at once (under 0.1 ms)")
    # and a late hold no longer finds an installer: the program has the line
    b4 = fresh(img, inst_m, "switched off, late hold", waits=True)
    reached, why = b4.boot(max_insns=3_000_000, until=g.GATE_CPU, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: the boot never reached the gate ({why})")
    b4.run_from(g.GATE_CPU, LATE_MS * b4.ips // 1000, until=0x1)
    if in_gate(b4.m.pc):
        raise SystemExit(f"FAIL: {LATE_MS} ms in, the switched-off gate still listens (pc={b4.m.pc:#x})")
    b4.sci.line_hold = True
    reached, _ = b4.run_from(b4.m.pc, 2_000_000, until=SRAM_BASE)
    if reached:
        raise SystemExit("FAIL: a late hold still reached the installer body after the switch-off")
    print(f"late hold [{LATE_MS} ms, switched off]: no installer, the program runs")
    print("=" * 64)
    print(f"ALL OK -- past the hung ring by the late gate, {time.time() - t0:.0f}s wall")


if __name__ == "__main__":
    main()
