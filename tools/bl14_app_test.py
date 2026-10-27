"""BMWeb's bootloader install (core/flash/bl14.js, which installs BL15),
proven on the emulator.

Run from the ms45-emu root: .venv/bin/python tools/bl14_app_test.py

The app installs BL14 in two steps; this runs the second as the app does it:

1. the DME carries the INSTALLER body (flasher_body.PERM_LOW=0x4000, stamp
   flags 7) -- what step 1's Fast Flash Program puts on it;
2. over the wire, as bl14.install does: READ [0x4000,0x6000) and
   [0x8000,0x20000) off the DME, splice the ring in with the APP'S OWN
   bl14.splice (node, on the bytes just read), then AIF ARM -> ERASE the
   96 KB sector -> blank-check -> CHUNK x24 -> VERIFY -> ERASE the 8 KB
   sector -> blank-check -> CHUNK x2 -> VERIFY -> AIF DONE -> READ the stamp.

Then the DME is reset: with the line free it boots its program; with the
line held it lands in BL14, whose HELLO says MS45BL v14. The programming log
and everything outside the ring and the handoff word are byte-identical to
before (the app keeps the DME's own loader and log); the MPC is untouched.
"""
import json
import os
import struct
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import flasher_body                                             # noqa: E402
import bl14                                                     # noqa: E402
import bl15                                                     # noqa: E402
from ms45emu.image import load_named                            # noqa: E402
from ms45emu.board import RESET_ENTRY                           # noqa: E402
from ms45emu.checksums import crc32_mpeg2                       # noqa: E402
from flasher_gate import build as gate_build, ENTRY_CPU         # noqa: E402
from flasher_body import SRAM_BASE, REPLY_OFF, MARK_ARMED, AIF_ARM, AIF_DONE  # noqa: E402
from flasher_session_test import Session, expect                # noqa: E402
from bl14_test import (fresh, hello_wait, marker, chunk_span,   # noqa: E402
                       taken_from_reset, taken, S_AIF)
from flasher_gate import stamp_bytes                            # noqa: E402

BMWEB = os.path.normpath(os.path.join(ROOT, "..", "inpa-mac-bridge"))
BOOT, BOOT_LEN = 0x8000, 0x18000
SECT8K, SECT8K_LEN = 0x4000, 0x2000
AIF_START = 0x1FB34

SPLICE_JS = r"""
const fs = require('fs');
global.fastFlasher = { BODY_START: 0xfd26c, BODY_END: 0xfff40 };
const { bl14 } = require(process.argv[1] + '/app/renderer/core/flash/bl14.js');
const boot = fs.readFileSync(process.argv[2]);
const s8 = fs.readFileSync(process.argv[3]);
const guard = fs.readFileSync(process.argv[4]);
const r = bl14.splice(new Uint8Array(boot), new Uint8Array(s8), new Uint8Array(guard));
fs.writeFileSync(process.argv[2] + '.out', r.boot);
fs.writeFileSync(process.argv[3] + '.out', r.sect8k);
console.log(JSON.stringify({ boot: r.bootChanged, sect8k: r.sect8kChanged }));
"""


def app_splice(boot, s8, guard, tmp):
    bp, sp, gp = (os.path.join(tmp, n) for n in ("boot.bin", "s8k.bin", "guard.bin"))
    open(bp, "wb").write(boot)
    open(sp, "wb").write(s8)
    open(gp, "wb").write(guard)
    out = subprocess.run(["node", "-e", SPLICE_JS, BMWEB, bp, sp, gp], check=True,
                         capture_output=True, text=True).stdout
    return open(bp + ".out", "rb").read(), open(sp + ".out", "rb").read(), json.loads(out)


def read_area(s, off, ln):
    out = b""
    while len(out) < ln:
        out += s.read(off + len(out), min(4096, ln - len(out)))
    return out


def rewrite(s, base, data, note):
    expect(s.xfer(0x02, struct.pack(">I", base)), 0x02, f"ERASE {note}")
    fr = s.xfer(0x01, struct.pack(">II", base, len(data)), budget=90_000_000)
    if struct.unpack(">I", fr[4:8])[0] != crc32_mpeg2(b"\xff" * len(data)):
        raise SystemExit(f"FAIL: {note} not blank after ERASE")
    chunk_span(s, base, data, note)
    expect(s.xfer(0x04, struct.pack(">III", base, len(data), crc32_mpeg2(data))),
           0x04, f"VERIFY {note}")


def main():
    t0 = time.time()
    tmp = os.environ.get("TMPDIR", "/tmp")
    pair = load_named(os.environ.get("BL14_BASE", "session1.livetune7"))
    flasher_body.PERM_LOW = 0x4000
    inst_f, inst_m = gate_build(pair.flash, pair.mpc)
    flasher_body.PERM_LOW = 0x8000
    board = fresh(inst_f, inst_m, "bl14-app-install", waits=True)
    board.sci.line_hold = True
    reached, why = board.boot(max_insns=2_000_000, until=ENTRY_CPU + 4, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: never reached the gate entry ({why})")
    s = Session(board)
    if not s.until(lambda: SRAM_BASE <= board.m.pc < SRAM_BASE + REPLY_OFF, budget=2_000_000):
        raise SystemExit("FAIL: the installer body never reached SRAM")
    hello_wait(s, "installer body", stamp_bytes(13, 7))
    chip0 = bytes(board.flash.image)
    mpc0 = bytes(board.cmf.image)

    # ---- what bl14.install does ------------------------------------------
    s8 = read_area(s, SECT8K, SECT8K_LEN)
    boot = read_area(s, BOOT, BOOT_LEN)
    # the emulator stubs a few loader words in the CPU's view (cpu.patched);
    # a READ returns that view, the chip holds the true words. On hardware
    # the two are the same: put the chip's words back so the test writes
    # what a real DME would have read
    boot = bytearray(boot)
    s8 = bytearray(s8)
    # BL14_AS_EMULATED=1 writes back what the emulator's READ really gives
    # (the stubbed view), as the app does when it runs against kline.py
    for at, orig in ([] if os.environ.get("BL14_AS_EMULATED") else board.cpu.patched.items()):
        if at < 0xFFF00000:
            continue
        off = at - 0xFFF00000
        if BOOT <= off < BOOT + BOOT_LEN:
            struct.pack_into(">I", boot, off - BOOT, orig)
        if SECT8K <= off < SECT8K + SECT8K_LEN:
            struct.pack_into(">I", s8, off - SECT8K, orig)
    if os.environ.get("BL14_AS_EMULATED"):
        chip0 = bytes(chip0[:SECT8K]) + bytes(s8) + bytes(chip0[SECT8K + SECT8K_LEN:BOOT]) \
            + bytes(boot) + bytes(chip0[BOOT + BOOT_LEN:])
        print(f"  note: as emulated -- {len([a for a in board.cpu.patched if a >= 0xFFF00000])} stubbed words ride along")
    elif bytes(boot) != chip0[BOOT:BOOT + BOOT_LEN] or bytes(s8) != chip0[SECT8K:SECT8K + SECT8K_LEN]:
        raise SystemExit("FAIL: the wire READs disagree with the chip")
    print("  ok: READ 8 KB + 96 KB off the DME == the chip")

    guard = s.read(bl15.PARK_CALL_AT, 8)
    nb, ns, ch = app_splice(bytes(boot), bytes(s8), guard, tmp)
    want_f, _ = bl15.build(chip0, mpc0)
    if nb != bytes(want_f[BOOT:BOOT + BOOT_LEN]) or ns != bytes(want_f[SECT8K:SECT8K + SECT8K_LEN]):
        raise SystemExit("FAIL: the app's splice differs from tools/bl15.build on the same image")
    print(f"  ok: bl14.splice (the app's JS) == bl15.build; changed {ch}")
    # a loader that parks some other way is refused before anything is sent
    bad = subprocess.run(["node", "-e", SPLICE_JS, BMWEB,
                          *(os.path.join(tmp, n) for n in ("boot.bin", "s8k.bin")),
                          os.path.join(tmp, "s8k.bin")], capture_output=True, text=True)
    if bad.returncode == 0 or "park call" not in bad.stderr:
        raise SystemExit("FAIL: a foreign park call was not refused")
    print("  ok: a loader with another park call is refused")

    if marker(s) != 0xFFFF:
        raise SystemExit("FAIL: marker not fresh")
    expect(s.xfer(S_AIF, bytes([AIF_ARM])), S_AIF, "AIF ARM")
    if marker(s) != MARK_ARMED:
        raise SystemExit("FAIL: marker not armed")
    rewrite(s, BOOT, nb, "the 96 KB boot sector (ring, inert)")
    rewrite(s, SECT8K, ns, "the 8 KB sector (handoff + park words)")
    expect(s.xfer(S_AIF, bytes([AIF_DONE])), S_AIF, "AIF DONE")
    st = s.read(bl15.STAMP_AT, 16)
    if st != bl15.stamp_bytes():
        raise SystemExit(f"FAIL: stamp after install {st.hex()}")
    print(f"  ok: stamp {st[:6].decode()} v{st[6]} flags {st[7]:#04x} read back")

    img = bytes(board.flash.image)
    diff = [i for i in range(len(img)) if img[i] != chip0[i]]
    allowed = lambda i: (bl15.WINDOW_AT <= i < bl15.SPAN_END or bl14.PATCH_AT <= i < bl14.PATCH_AT + 4
                         or bl15.PARK_HOOK_AT <= i < bl15.PARK_HOOK_AT + 4
                         or flasher_body.MARK_AT <= i < flasher_body.MARK_AT + 128)
    stray = [i for i in diff if not allowed(i)]
    if stray:
        raise SystemExit(f"FAIL: the install changed ext {stray[0]:#x} ({len(stray)} bytes outside the ring)")
    if img[AIF_START:0x20000] != chip0[AIF_START:0x20000]:
        raise SystemExit("FAIL: the programming log changed")
    if bytes(board.cmf.image) != mpc0:
        raise SystemExit("FAIL: the MPC changed")
    print(f"  ok: {len(diff)} bytes changed, all in the ring, the handoff word and the marker; "
          "log and MPC untouched")
    expect(s.xfer(0x06), 0x06, "RESET")

    # ---- line free: the program; line held: BL14 -------------------------
    b = board.reset()
    reached, why = b.boot(max_insns=3_000_000, until=RESET_ENTRY, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: line free, the DME did not reach its program ({why})")
    print("boot [line free]: the program starts")
    b2, s2 = taken_from_reset(b, "installed by the app's sequence")
    hello_wait(s2, "BL15 after the app install", bl15.stamp_bytes())

    # ---- the park path: a tune that no longer checks out ------------------
    # (a push cut by a power loss): the loader parks instead of handing off,
    # and only BL15's park hook still lets a held line into the flasher
    parked = bytearray(board.flash.image)
    parked[0x40000:0x5D000] = b"\xff" * 0x1D000      # the mid-push worst case
    b3 = fresh(parked, board.cmf.image, "bl15-parked")
    parks = []
    h = b3.m.hook_code(lambda mach, addr, size: parks.append(addr) if addr == 0xFFF0522C else None)
    b3.boot(max_insns=2_000_000, reset_vector=True)
    b3.m.mu.hook_del(h)
    if not parks:
        raise SystemExit("FAIL: the blanked tune did not park the loader (no park to test)")
    print("boot [tune blank, line free]: the loader parks, through the stock prologue")
    b4, s4 = taken(parked, board.cmf.image, "parked DME, line held", deep=True)
    hello_wait(s4, "BL15 from the park", bl15.stamp_bytes())
    print("=" * 64)
    print(f"ALL OK -- the app's bootloader (BL15) install, {time.time() - t0:.0f}s wall")


if __name__ == "__main__":
    main()
