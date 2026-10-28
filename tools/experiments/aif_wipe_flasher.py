"""AIF wipe through the resident flasher -- emulator experiment + the car flow.

    .venv/bin/python -m tools.experiments.aif_wipe_flasher [--fast-wait]

The point: wipe the programming log (AIF/UIF) WITHOUT installing a program.
aif_wipe.py already proves the erase, but it rides in behind the reset vector
and so needs a full program update to run. The resident flasher is the same
"drop into the loader and send it commands" state, owns the machine from
SRAM, and already has an ERASE service -- so it is the natural host, and
(unlike the reset payload) it has a host feeding it data, so the restore
streams in over the wire with no on-chip staging.

The AIF (ext 0x1FB34-0x1FFFF) sits at the top of the single 96 KB boot sector
(0x8000-0x1FFFF, SECTORS entry (0x08000, 0x18000)). Erase is sector-granular,
so wiping it erases the boot loader too -- the body survives because it runs
from SRAM, and the gate/body/CMF-less erase live in the program sector and the
from tools import ROOT
MPC, none of which the wipe touches.

THE CAR FLOW (v10, boot window + resume marker). Every step is marker-driven
and idempotent, so the first run and a crash resume are the SAME code:

  marker = AIF READ
  if marker == DONE: nothing to do
  if marker == 0xFFFF: AIF ARM        -> marker 0xA55A, BEFORE any erase
  ERASE 0x8000                        -> refused unless the marker is armed
  SECTOR_QUERY 0x8000 -> must be blank (the on-silicon erase check)
  CHUNK the stock boot content [0x8000, 0x1FB34) from the host's copy
  VERIFY
  AIF DONE                            -> marker 0xA558

Arm-before-erase is the whole safety argument: the body refuses a boot-sector
erase unless the marker is armed, so the instant the loader can vanish there
is already an armed marker in the (un-erased) loader tail at 0x387EC. On any
reconnect the host reads it; armed-not-done means "resume" -- re-erase (blank
again), re-restore, done. The marker, the gate (0xFD300), the body (0xFD500)
and the MPC reset hook all live outside the erased sector, so the recovery
machinery can never be destroyed by the thing it recovers.

No sector-table unlock and no MARKS: the AIF is left blank (the goal), the
boot sector is not gated by the cal/program valid marks, and the boot CRC at
0x1F800 covers 0x0-0x1EFFF -- it excludes the AIF, and every byte in range is
restored identically, so the CRC still matches with nothing recomputed.

Gated OFF on every shipped body: flasher_body.ALLOW_BOOT_SECTOR, which this
script flips for the build only. With it set the stamp is v10, flags bit 1;
without it the body is byte-identical v9 and has neither the window nor the
S_AIF service.
"""
import os
import struct
import sys
import time

from tools.build import flasher_body
flasher_body.ALLOW_BOOT_SECTOR = True            # emulator-only; see the docstring

from ms45emu.image import load_named, Pair
from ms45emu.board import Board, RESET_ENTRY
from ms45emu.checksums import crc32_mpeg2
from tools.build.flasher_gate import build, ENTRY_CPU, stamp_bytes
from tools.build.flasher_body import (SRAM_BASE, REPLY_OFF, MARK_AT, MARK_ARMED,
                          MARK_DONE, AIF_READ, AIF_ARM, AIF_DONE)
from tools.proofs.flasher_session_test import (Session, frame, lit_nrv2b,
                                  fast_waits, expect, expect_nak)
from tools.experiments.aif_wipe import aif_slots, AIF

S_AIF = 9
EXT = 0xFFF00000
# The base program image the v10 body is spliced into. The bench DME is on
# livetune7 (no flasher yet: stamp blank, MPC 0x8 the stock hook), so the
# built (flash, mpc) here IS the bootstrap image to full-flash onto it.
IMAGE = os.environ.get("AIF_IMAGE", "session1.livetune7")
BOOT = 0x8000
BOOT_END = 0x20000
AIF_START, AIF_END = AIF                 # 0x1FB34-0x1FFFF: wiped, left blank
CHUNK = 4096
WATCHDOG_MS = 100
FAST = "--fast-wait" in sys.argv


# ---------------------------------------------------------------------------
# The tester, as the car's app would drive it.

def try_open_body(board):
    """Break-held boot into the flasher body; (Session, hello) or None when
    the body is UNREACHABLE. Reaching the gate runs boot-loader code that
    lives in the boot sector, so once that sector is erased the reset reaches
    neither the gate nor the stock loader -- the body cannot be re-entered to
    resume. Returning None instead of raising lets the convergence test map
    exactly which interruptions are reboot-recoverable and which are not."""
    sci = board.sci
    s = Session(board)
    sci.line_hold = True
    reached, _why = board.boot(max_insns=2_000_000, until=ENTRY_CPU + 4, reset_vector=True)
    if not reached:
        return None
    in_body = lambda: SRAM_BASE <= board.m.pc < SRAM_BASE + REPLY_OFF   # noqa: E731
    if not s.until(in_body, budget=2_000_000):
        return None
    sci.line_hold = False
    if not s.until(lambda: len(sci.tx) >= 21):
        return None
    hello = bytes(sci.tx[:21])
    if hello != frame(0x40, stamp_bytes(13, 3)):
        raise SystemExit(f"FAIL: HELLO mismatch: {hello.hex()} "
                         f"(want v13 flags 0x03: {frame(0x40, stamp_bytes(13, 3)).hex()})")
    board.watchdog_window()
    board.sci.model_overrun = True
    return s, hello


def open_body(board):
    """As try_open_body, but the body MUST be reachable (fresh v10 DME)."""
    r = try_open_body(board)
    if r is None:
        raise SystemExit("FAIL: never reached the flasher body on a fresh image")
    return r


def marker(s):
    """The resume marker halfword (0xFFFF / ARMED / DONE)."""
    fr = s.xfer(S_AIF, bytes([AIF_READ]))
    if fr[3] != (S_AIF | 0x40):
        raise SystemExit(f"FAIL: AIF READ: {fr.hex()}")
    return struct.unpack(">H", fr[4:6])[0]


def restore_chunks(s, stock):
    """CHUNK the stock boot content [0x8000, 0x1FB34) back. The proven
    all-literal NRV2B form carries full 8-literal groups, so the stream is
    padded to a multiple of 8 with 0xFF; those bytes land at the head of the
    (erased) AIF and program as a no-op, so the AIF stays blank."""
    payload = bytearray(stock[BOOT:AIF_START])
    if len(payload) % 8:
        payload += b"\xff" * (8 - len(payload) % 8)
    n = 0
    for off in range(0, len(payload), CHUNK):
        data = bytes(payload[off:off + CHUNK])
        comp = lit_nrv2b(data)
        hdr = struct.pack(">IHHI", BOOT + off, len(data), len(comp), crc32_mpeg2(comp))
        fr = s.xfer(0x03, hdr + comp)
        if fr[3] != 0x43:
            raise SystemExit(f"FAIL: CHUNK at {BOOT + off:#x}: {fr.hex()}")
        n += 1
    return n


# The marker-driven wipe: first run AND resume, one body of code. `stop_after`
# aborts the session right after the named phase (for the convergence test);
# None runs it through. Returns the phases it actually performed.
PHASES = ("arm", "erase", "blankcheck", "restore", "verify", "done")


def do_wipe(s, board, stock, stop_after=None, chunks_before_kill=None):
    did = []
    mk = marker(s)
    if mk == MARK_DONE:
        return did
    if mk == 0xFFFF:
        expect(s.xfer(S_AIF, bytes([AIF_ARM])), S_AIF, "AIF ARM (marker 0xFFFF -> 0xA55A)")
        if marker(s) != MARK_ARMED:
            raise SystemExit("FAIL: marker not armed after AIF ARM")
        did.append("arm")
        if stop_after == "arm":
            return did
    elif mk != MARK_ARMED:
        raise SystemExit(f"FAIL: marker reads {mk:#06x}, neither blank/armed/done")

    expect(s.xfer(0x02, struct.pack(">I", BOOT)), 0x02, "ERASE the boot sector (armed)")
    did.append("erase")
    if stop_after == "erase":
        return did

    # the on-silicon blank check: the body reads the sector straight off the
    # chip, and it must be all-0xFF before we stream the restore over it
    fr = s.xfer(0x01, struct.pack(">II", BOOT, BOOT_END - BOOT), budget=90_000_000)
    expect(fr, 0x01, "SECTOR_QUERY of the erased boot sector")
    if struct.unpack(">I", fr[4:8])[0] != crc32_mpeg2(b"\xff" * (BOOT_END - BOOT)):
        raise SystemExit("FAIL: boot sector did NOT read blank after ERASE "
                         "(a hardware-protected sector would show here)")
    did.append("blankcheck")
    if stop_after == "blankcheck":
        return did

    if stop_after == "restore" and chunks_before_kill is not None:
        _restore_partial(s, stock, chunks_before_kill)   # leave it half-done
        did.append("restore(partial)")
        return did
    restore_chunks(s, stock)
    did.append("restore")
    if stop_after == "restore":
        return did

    want = crc32_mpeg2(stock[BOOT:AIF_START])
    expect(s.xfer(0x04, struct.pack(">III", BOOT, AIF_START - BOOT, want)),
           0x04, "VERIFY of the restored boot content")
    did.append("verify")
    if stop_after == "verify":
        return did

    expect(s.xfer(S_AIF, bytes([AIF_DONE])), S_AIF, "AIF DONE (marker 0xA55A -> 0xA558)")
    if marker(s) != 0xFFFF:                     # v11: that slot is spent, the next is current
        raise SystemExit("FAIL: the next marker slot is not fresh after AIF DONE")
    did.append("done")
    return did


def _chunk_frame(off, data):
    """A CHUNK request's payload: header + the all-literal NRV2B stream."""
    comp = lit_nrv2b(data)
    return struct.pack(">IHHI", off, len(data), len(comp), crc32_mpeg2(comp)) + comp


def _restore_partial(s, stock, k):
    """Program only the first k CHUNKs, to model an interrupt mid-restore."""
    payload = bytearray(stock[BOOT:AIF_START])
    if len(payload) % 8:
        payload += b"\xff" * (8 - len(payload) % 8)
    for i, off in enumerate(range(0, len(payload), CHUNK)):
        if i >= k:
            break
        data = bytes(payload[off:off + CHUNK])
        comp = lit_nrv2b(data)
        hdr = struct.pack(">IHHI", BOOT + off, len(data), len(comp), crc32_mpeg2(comp))
        fr = s.xfer(0x03, hdr + comp)
        if fr[3] != 0x43:
            raise SystemExit(f"FAIL: partial CHUNK at {BOOT + off:#x}: {fr.hex()}")


def assert_wiped(board, stock, label, slot=0):
    img = bytes(board.flash.image)
    if img[AIF_START:AIF_END] != b"\xff" * (AIF_END - AIF_START):
        raise SystemExit(f"FAIL [{label}]: the AIF is not blank")
    if img[BOOT:AIF_START] != stock[BOOT:AIF_START]:
        first = next(i for i in range(BOOT, AIF_START) if img[i] != stock[i])
        raise SystemExit(f"FAIL [{label}]: boot content differs from stock at ext {first:#x}")
    if img[:BOOT] != stock[:BOOT]:
        raise SystemExit(f"FAIL [{label}]: a sector below 0x8000 was touched")
    if aif_slots(img):
        raise SystemExit(f"FAIL [{label}]: a used AIF slot survived")
    at = MARK_AT + 2 * slot
    if struct.unpack(">H", img[at:at + 2])[0] != MARK_DONE:
        raise SystemExit(f"FAIL [{label}]: marker slot {slot} is not DONE")


def boots(board, label):
    fresh = board.reset()
    reached, why = fresh.boot(max_insns=2_000_000, until=RESET_ENTRY + 4, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL [{label}]: the wiped DME does not boot ({why})")
    return fresh


def fresh_board(pair):
    return Board(Pair(bytes(pair[0]), bytes(pair[1]), "aifwipe", check_program=False),
                 waits=fast_waits() if FAST else None)


# ---------------------------------------------------------------------------

def main():
    t0 = time.time()
    base = load_named(IMAGE)
    stock = bytes(base.flash)
    f, m = build(base.flash, base.mpc)
    assert f[BOOT:AIF_START] == stock[BOOT:AIF_START]
    if not aif_slots(stock):
        raise SystemExit("FAIL: the base image has a blank AIF -- nothing to wipe")

    # ---- the straight-through run -------------------------------------
    print("=" * 60, "\nstraight-through wipe\n" + "=" * 60)
    board = fresh_board((f, m))
    s, hello = open_body(board)
    print(f"hello: {hello[4:10].decode()} v{hello[10]} flags {hello[11]:#04x}")
    slots = aif_slots(stock)
    print(f"AIF before: {len(slots)} used slot(s), first {slots[0][1].strip('.')!r}")

    # the gate is real: a boot-sector erase BEFORE arming is refused
    expect_nak(s.xfer(0x02, struct.pack(">I", BOOT)), 0x02, 1,
               "ERASE 0x8000 refused while the marker is not armed")
    # and the window is only the boot sector -- nothing below it
    expect_nak(s.xfer(0x02, struct.pack(">I", 0x6000)), 0x02, 1,
               "ERASE at 0x6000 (below the boot sector) still refused")

    # v12: the window is shut to writes until a slot is armed -- the old line
    # test's CHUNK over the loader at 0x10000 is refused, nothing programmed
    loader = bytes(board.flash.image[0x10000:0x11000])
    expect_nak(s.xfer(0x03, _chunk_frame(0x10000, bytes(((i * 7919 + 13) & 0xFF) for i in range(4096)))),
               0x03, 1, "CHUNK into the boot sector refused while the marker is not armed")
    if bytes(board.flash.image[0x10000:0x11000]) != loader:
        raise SystemExit("FAIL: the refused CHUNK changed the loader at 0x10000")

    did = do_wipe(s, board, stock)
    print("  phases:", " -> ".join(did))
    expect_nak(s.xfer(0x03, _chunk_frame(0x10000, b"\x00" * 4096)), 0x03, 1,
               "CHUNK into the boot sector refused again once the wipe is done")
    assert_wiped(board, stock, "straight")
    print("  ok: AIF blank, boot content == stock, <0x8000 untouched, marker DONE")
    gap = board.watchdog_gap_ms()
    if gap > WATCHDOG_MS:
        raise SystemExit(f"FAIL: watchdog went {gap:.0f} ms unserviced")
    print(f"  ok: longest watchdog gap {gap:.1f} ms (limit {WATCHDOG_MS})")
    boots(board, "straight")
    print("  ok: the wiped DME boots the program")

    # ---- v11: a second wipe on the same DME takes the next marker slot ----
    did = do_wipe(s, board, stock)
    if "erase" not in did:
        raise SystemExit(f"FAIL: the second wipe did not run ({did})")
    assert_wiped(board, stock, "second", slot=1)
    print("  ok: a second wipe ran on marker slot 1 (v10 refused every wipe after its first)")

    # ---- the bench spare's state: v10 spent slot 0 -------------------------
    spent = bytearray(f)
    spent[MARK_AT:MARK_AT + 2] = struct.pack(">H", MARK_DONE)
    board = fresh_board((spent, m))
    s, _ = open_body(board)
    if marker(s) != 0xFFFF:
        raise SystemExit("FAIL: with slot 0 spent the current slot does not read fresh")
    did = do_wipe(s, board, stock)
    assert_wiped(board, stock, "after-v10", slot=1)
    boots(board, "after-v10")
    print("  ok: a DME whose v10 wipe spent slot 0 wipes on slot 1 and boots")

    # ---- the recovery map: kill at each phase, then try to reconnect ----
    # Reaching the flasher runs boot-loader code that lives in the boot
    # sector, so once that sector is erased the DME can't be re-entered to
    # resume (proven: a blank boot sector reaches neither the gate nor the
    # stock loader). The marker is only readable while the loader still boots.
    # This maps exactly which interruptions are reboot-recoverable.
    #   RECOVERABLE   = reconnect reaches the body, resume completes, boots
    #   COMMITTED     = boot sector not bootable; bootstrap (full flash) only
    print("=" * 60, "\nrecovery map (kill at each phase, try to reconnect)\n" + "=" * 60)
    kills = [("arm", None), ("erase", None), ("blankcheck", None),
             ("restore", 10), ("verify", None)]
    # arm is before the erase (boot sector intact); verify is after the
    # restore (boot content whole again) -- both MUST be recoverable. The
    # erased-and-not-yet-restored middle MUST NOT be.
    must_recover = {"arm", "verify"}
    must_not = {"erase", "blankcheck"}
    for phase, k in kills:
        board = fresh_board((f, m))
        s, _ = open_body(board)
        did = do_wipe(s, board, stock, stop_after=phase, chunks_before_kill=k)
        if marker(s) != MARK_ARMED:
            raise SystemExit(f"FAIL [kill@{phase}]: marker not ARMED after the kill")
        board = board.reset()                   # the interruption
        s2 = try_open_body(board)
        if s2 is None:
            verdict = "COMMITTED (boot sector not bootable -> bootstrap only)"
            if phase in must_recover:
                raise SystemExit(f"FAIL [kill@{phase}]: expected RECOVERABLE, got {verdict}")
        else:
            resumed = do_wipe(s2[0], board, stock)
            assert_wiped(board, stock, f"kill@{phase}")
            boots(board, f"kill@{phase}")
            verdict = f"RECOVERABLE (resumed {resumed}, boots)"
            if phase in must_not:
                raise SystemExit(f"FAIL [kill@{phase}]: expected COMMITTED, got {verdict}")
        print(f"  kill@{phase} (did {did}): {verdict}")

    print("=" * 60)
    print("Recovery map: safe to interrupt BEFORE the erase (arm) and AFTER the")
    print("restore (verify); the erased middle is COMMITTED -- a power loss there")
    print("needs a bootstrap (full flash), the resume marker cannot help.")
    print(f"ALL OK -- straight-through wipe + recovery map, {time.time() - t0:.0f}s wall")
    return 0


if __name__ == "__main__":
    sys.exit(main())
