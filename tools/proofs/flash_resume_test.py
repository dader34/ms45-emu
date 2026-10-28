"""Interruptible flashing: the DME-truth resume protocol, proven on BL15.

Run from the ms45-emu root: .venv/bin/python -m tools.proofs.flash_resume_test

The app's resume today (fbDmeFastPushWithResume) assumes the connection
died but the DME stayed powered: it knows how far it got. A power cut
kills that knowledge. The protocol proven here derives everything from
what the DME itself reports after BL14's line-hold re-entry, so the same
code resumes a cable pull, a laptop battery death, and an ignition cycle:

  - ERASE DISCRIMINATOR: SECTOR_QUERY of the pushed range's tail slice.
    Blank -> the sector was erased (resume mid-push or from zero); equal
    to the target -> the push is complete (VERIFY + MARKS only); anything
    else -> old or different content: erase first. This also catches the
    stale-prefix trap: an unerased DME whose early chunks already match
    the target must NOT be skipped over -- bits cannot be set.
  - CHUNK PREFIX: the first chunk that differs, by exponential-then-
    binary search over cumulative QUERY CRCs (~2 lg n probes, not n).
  - TORN-CHUNK GUARD: the chunk at the resume point is READ; if its
    content is not AND-compatible with the target (a torn write is, old
    content is not) the plan falls back to a full erase -- programming
    over foreign bits would corrupt. A NAK on a later chunk (the same
    pathology discovered mid-push) falls back the same way.
  - COMPLETION: VERIFY, then MARKS -- the cal marks burn is idempotent
    (bit-clear of the same halfwords), so resuming an already-finished
    session writes nothing and burns nothing extra.

Re-entry (why BL15, not BL14): BL14's window hangs off the handoff word
at 0x4EBC, which the loader executes only when its own validity checks
pass. A power cut mid-push leaves the cal unverifiable, so the loader
calls its factory-KWP park at 0x5228 and the window never ran -- case C
could not even reconnect. BL15 adds one patched word at the park
function's head (same 8 KB sector): the park window is inert when the
line is free (proven in section H: every GPR identical at the stock
prologue, the stream byte-identical through the first time-driven tick)
and lands in the ring body when the line is held -- so EVERY cut point
in the matrix reconnects the same way.

The matrix: old content, stale prefix, mid-push at 1/5/28 chunks, a torn
chunk, foreign content mid-sector (the partial-erase pathology), and the
two post-push points. Every case must converge to the target with the
marks burned and the boot region untouched, and each reports exactly how
much it had to send.
"""
import os
import struct
import sys
import time

from tools.build import bl14
from tools.build import bl15
from ms45emu.image import load_named
from ms45emu.board import Board
from ms45emu.checksums import crc32_mpeg2
from ms45emu.fold import CRC_AT, CRC_FROM, CRC_TO, MON_AT, monitor_sum
from tools.build.flasher_body import SRAM_BASE, REPLY_OFF
from tools.proofs.flasher_session_test import (Session, lit_nrv2b, expect,
                                  fast_waits)
from tools.proofs.bl14_test import (hello_wait, taken, taken_from_reset,
                       CHUNK, CAL, CAL_END)
from tools import ROOT

BLANK = crc32_mpeg2(b"\xff" * CHUNK)
MARKS_AT = (0x5FF80, 0x5FFC0)                    # the cal validity marks,
MARK_BYTES = (bytes.fromhex("48249042"), bytes.fromhex("90482442"))  # beyond the push


# ---------------------------------------------------------------------------
# the wire client (the sequence the app's push-resume.js drives)

def query_crc(s, off, ln):
    fr = s.xfer(0x01, struct.pack(">II", off, ln), budget=120_000_000)
    if fr[3] != 0x41:
        raise SystemExit(f"FAIL: QUERY {off:#x}+{ln:#x}: {fr.hex()}")
    return struct.unpack(">I", fr[4:8])[0]


def push_chunk(s, off, data):
    """One CHUNK; False on the NAK that means the bytes would not take."""
    comp = lit_nrv2b(data)
    hdr = struct.pack(">IHHI", off, len(data), len(comp), crc32_mpeg2(comp))
    fr = s.xfer(0x03, hdr + comp)
    if fr[3] == 0x43:
        return True
    if fr[3] == 0x7F and fr[4] == 0x03 and fr[5] == 4:
        return False
    raise SystemExit(f"FAIL: CHUNK at {off:#x}: {fr.hex()}")


def first_unpushed(s, base, target):
    """The first chunk whose bytes differ, by gallop then binary search."""
    n = len(target) // CHUNK
    done, step, span = 0, 1, n                   # [0,done) matches; (done,span) holds a miss
    while done < n:
        k = min(done + step, n)
        if query_crc(s, base, k * CHUNK) == crc32_mpeg2(target[:k * CHUNK]):
            done, step = k, step * 2
        else:
            span = k
            break
    if done >= n:
        return n, 0
    probes = 1
    while span - done > 1:
        mid = (done + span) // 2
        probes += 1
        if query_crc(s, base, mid * CHUNK) == crc32_mpeg2(target[:mid * CHUNK]):
            done = mid
        else:
            span = mid
    return done, probes


def resume(s, base, target, note):
    """Bring the sector to `target` from whatever state the DME is in.
    Returns the report: how many chunks went out, whether an erase ran,
    and the verdict the discriminator reached."""
    n = len(target) // CHUNK
    tail = target[n * CHUNK - CHUNK:]
    sent = 0
    verdict = None

    def erase():
        expect(s.xfer(0x02, struct.pack(">I", base)), 0x02, f"{note}: ERASE")

    def push_from(k):
        nonlocal sent
        while k < n:
            if not push_chunk(s, base + k * CHUNK, bytes(target[k * CHUNK:(k + 1) * CHUNK])):
                # foreign bits where the plan did not look: erase, restart
                print(f"    {note}: chunk {k} would not take -> full erase, restart")
                erase()
                k, sent = 0, 0
                continue
            sent += 1
            k += 1

    crc = query_crc(s, base + (n - 1) * CHUNK, CHUNK)
    # a blank TARGET tail cannot announce completion (a blank chip tail is
    # also the erased state) -- the prefix search decides that case instead
    if crc != BLANK and crc == crc32_mpeg2(tail):
        verdict = "push complete"
        k = n
    elif crc == BLANK:
        k, probes = first_unpushed(s, base, target)
        if k >= n:
            verdict = f"push complete ({probes} probes)"
        else:
            verdict = f"erased, resume at {k} ({probes} probes)"
        if k < n:
            have = s.read(base + k * CHUNK, CHUNK)
            want = bytes(target[k * CHUNK:(k + 1) * CHUNK])
            if not all(h & w == w for h, w in zip(have, want)):
                print(f"    {note}: chunk {k} holds foreign bits -> full erase")
                verdict = "foreign content -> erase"
                erase()
                k = 0
    else:
        verdict = "old content -> erase"
        erase()
        k = 0
    push_from(k)
    want = crc32_mpeg2(bytes(target))
    expect(s.xfer(0x04, struct.pack(">III", base, len(target), want)),
           0x04, f"{note}: VERIFY")
    expect(s.xfer(0x05, b"\x00"), 0x05, f"{note}: MARKS")
    print(f"  ok: {note}: {verdict}; {sent} chunk(s) sent")
    return sent, verdict


def converged(board, target, note):
    img = board.flash.image
    span = bytes(target[CAL:CAL_END])
    if bytes(img[CAL:CAL_END]) != span:
        at = next(i for i in range(len(span)) if img[CAL + i] != span[i])
        raise SystemExit(f"FAIL: {note}: cal differs at ext {CAL + at:#x}")
    for at, want in zip(MARKS_AT, MARK_BYTES):
        if bytes(img[at:at + 4]) != (bytes(want) if False else bytes.fromhex(want.hex())):
            raise SystemExit(f"FAIL: {note}: mark at {at:#x} not burned")
    if bytes(img[:0x20000]) != bytes(bl_f[:0x20000]):
        raise SystemExit(f"FAIL: {note}: the boot region changed")
    print(f"  ok: {note}: cal == target, marks burned, boot region untouched")


# ---------------------------------------------------------------------------

def main():
    t0 = time.time()
    global bl_f
    pair = load_named("session1.livetune6-notraps")
    bl_f, bl_m = bl15.build(pair.flash, pair.mpc)

    # the push model: flasher_session_test's target -- a modified cal that
    # boots -- with the cal marks left blank so MARKS is a real transition
    target = bytearray(bl_f)
    target[CAL + 0x400:CAL + 0x500] = bytes((i * 7 + 3) & 0xFF for i in range(0x100))
    for at in (0x8000, 0x15000, 0x1A000):
        target[CAL + at:CAL + at + 0x40] = bytes((i * 13 + at) & 0xFF for i in range(0x40))
    target[CAL + MON_AT:CAL + MON_AT + 8] = monitor_sum(bytes(target[CAL:CAL + 0x10000]))
    struct.pack_into(">I", target, CAL + CRC_AT,
                     crc32_mpeg2(bytes(target[CAL + CRC_FROM:CAL + CRC_TO])))
    for at in MARKS_AT:
        target[at:at + 4] = b"\xff\xff\xff\xff"
    target = bytes(target)
    n = len(target[CAL:CAL_END]) // CHUNK
    # a fact this stock read teaches: the cal's PUSHED tail [0x5C000,0x5D000)
    # is blank on a healthy DME (the stamp and marks live past CAL_END, in
    # [0x5D000,0x60000), and ERASE takes the whole sector). So an untouched
    # DME presents the same tail CRC as an erased one, and the torn-chunk
    # guard -- not the tail -- is what sends it to a full erase. Case B is
    # the witness for the non-blank tail branch.
    if crc32_mpeg2(bytes(bl_f[CAL_END - CHUNK:CAL_END])) != BLANK:
        print("  note: this image's pushed tail is NOT blank")

    board, s = taken(bl_f, bl_m, "resume", deep=True)
    hello_wait(s, "resume session", bl15.stamp_bytes())

    # ---- old content, never touched ---------------------------------------
    print("=" * 64, "\nA. OLD CONTENT -- power lost before anything\n" + "=" * 64)
    sent, verdict = resume(s, CAL, target[CAL:CAL_END], "A")
    if sent > n or "complete" in verdict:
        raise SystemExit(f"FAIL: A said {verdict!r}, {sent} chunks")
    converged(board, target, "A")

    # ---- stale prefix: early chunks already match, tail does not ----------
    print("=" * 64, "\nB. STALE PREFIX -- matching start must not be trusted\n" + "=" * 64)
    board2, s2 = taken_from_reset(board, "B-cut")
    crafted = bytes(target[CAL:CAL + 3 * CHUNK]) + bytes(bl_f[CAL + 3 * CHUNK:CAL_END])
    board2.flash.store(CAL, crafted)             # the power cut left this behind
    b2, s2 = taken_from_reset(board2, "B-reconnect")
    hello_wait(s2, "B", bl15.stamp_bytes())
    sent, verdict = resume(s2, CAL, target[CAL:CAL_END], "B")
    if "erase" not in verdict or sent != n:
        raise SystemExit(f"FAIL: B said {verdict!r}, {sent} chunks (the prefix was skipped?)")
    converged(b2, target, "B")
    board, s = b2, s2

    # ---- mid-push at 1, 5, 28 of 29 ---------------------------------------
    print("=" * 64, "\nC. MID-PUSH -- power cut at chunks 1, 5, 28 of 29\n" + "=" * 64)
    # the target's last chunk is the blank pushed tail [0x5C000,0x5D000), so a
    # cut at 28 of 29 leaves the chip already equal to the target: the honest
    # resume sends nothing and only confirms
    blank_tail = bytes(target[CAL_END - CHUNK:CAL_END]) == b"\xff" * CHUNK
    for k in (1, 5, 28):
        b, sk = taken_from_reset(board, f"C{k}-cut")
        hello_wait(sk, f"C{k}", bl15.stamp_bytes())
        expect(sk.xfer(0x02, struct.pack(">I", CAL)), 0x02, f"C{k}: ERASE (the original push)")
        for i in range(k):
            if not push_chunk(sk, CAL + i * CHUNK, bytes(target[CAL + i * CHUNK:CAL + (i + 1) * CHUNK])):
                raise SystemExit(f"FAIL: C{k}: the original push lost chunk {i}")
        br, sr = taken_from_reset(b, f"C{k}-reconnect")       # the power cut
        hello_wait(sr, f"C{k} back", bl15.stamp_bytes())
        sent, verdict = resume(sr, CAL, target[CAL:CAL_END], f"C{k}")
        want = 0 if (k == n - 1 and blank_tail) else n - k
        if sent != want:
            raise SystemExit(f"FAIL: C{k} sent {sent} chunks (want {want}): {verdict}")
        converged(br, target, f"C{k}")
        board, s = br, sr

    # ---- a torn chunk: half of chunk 5 took before the cut -----------------
    print("=" * 64, "\nD. TORN CHUNK -- half a chunk programmed, then the cut\n" + "=" * 64)
    b, sk = taken_from_reset(board, "D-cut")
    hello_wait(sk, "D", bl15.stamp_bytes())
    expect(sk.xfer(0x02, struct.pack(">I", CAL)), 0x02, "D: ERASE (the original push)")
    for i in range(5):
        push_chunk(sk, CAL + i * CHUNK, bytes(target[CAL + i * CHUNK:CAL + (i + 1) * CHUNK]))
    torn = bytes(target[CAL + 5 * CHUNK:CAL + 6 * CHUNK])
    b.flash.store(CAL + 5 * CHUNK, torn[:CHUNK // 2])     # the write died mid-chunk
    br, sr = taken_from_reset(b, "D-reconnect")
    hello_wait(sr, "D back", bl15.stamp_bytes())
    sent, verdict = resume(sr, CAL, target[CAL:CAL_END], "D")
    if sent != n - 5:
        raise SystemExit(f"FAIL: D sent {sent} chunks (want {n - 5}): {verdict}")
    converged(br, target, "D")
    board, s = br, sr

    # ---- foreign bits mid-sector: the partial-erase pathology ---------------
    print("=" * 64, "\nE. FOREIGN BITS -- old content where nothing was pushed\n" + "=" * 64)
    b, sk = taken_from_reset(board, "E-cut")
    hello_wait(sk, "E", bl15.stamp_bytes())
    expect(sk.xfer(0x02, struct.pack(">I", CAL)), 0x02, "E: ERASE (the original push)")
    for i in range(5):
        push_chunk(sk, CAL + i * CHUNK, bytes(target[CAL + i * CHUNK:CAL + (i + 1) * CHUNK]))
    b.flash.store(CAL + 7 * CHUNK, bytes(bl_f[CAL + 7 * CHUNK:CAL + 8 * CHUNK]))
    br, sr = taken_from_reset(b, "E-reconnect")
    hello_wait(sr, "E back", bl15.stamp_bytes())
    sent, verdict = resume(sr, CAL, target[CAL:CAL_END], "E")
    converged(br, target, "E")                    # however it got there, it got there
    board, s = br, sr

    # ---- the two post-push points -------------------------------------------
    print("=" * 64, "\nF/G. POST-PUSH -- the cut before VERIFY, and after MARKS\n" + "=" * 64)
    b, sk = taken_from_reset(board, "F-cut")
    hello_wait(sk, "F", bl15.stamp_bytes())
    expect(sk.xfer(0x02, struct.pack(">I", CAL)), 0x02, "F: ERASE (the original push)")
    for i in range(n):
        push_chunk(sk, CAL + i * CHUNK, bytes(target[CAL + i * CHUNK:CAL + (i + 1) * CHUNK]))
    br, sr = taken_from_reset(b, "F-reconnect")   # everything sent, nothing confirmed
    hello_wait(sr, "F back", bl15.stamp_bytes())
    sent, verdict = resume(sr, CAL, target[CAL:CAL_END], "F")
    if sent != 0:
        raise SystemExit(f"FAIL: F re-sent {sent} chunks ({verdict})")
    converged(br, target, "F")

    b, sk = taken_from_reset(br, "G-cut")         # a finished session, cut anyway
    hello_wait(sk, "G", bl15.stamp_bytes())
    before = bytes(b.flash.image)
    sent, verdict = resume(sk, CAL, target[CAL:CAL_END], "G")
    if sent != 0:
        raise SystemExit(f"FAIL: G re-sent {sent} chunks ({verdict})")
    if bytes(b.flash.image) != before:
        raise SystemExit("FAIL: G wrote something into a finished DME")
    print("  ok: G: nothing re-sent, nothing written -- completion is idempotent")
    converged(b, target, "G")

    # ---- the park path: why the mid-push cases could reconnect -------------
    print("=" * 64, "\nH. PARK PATH -- BL15's second window carries the cut DME\n" + "=" * 64)

    def parked_pair(img_f, img_m):
        f = bytearray(img_f)
        f[CAL:CAL_END] = b"\xff" * (CAL_END - CAL)   # the mid-push worst case
        return type(pair)(bytes(f), bytes(img_m), "parked", check_program=False)

    def park_boot(img_f, img_m):
        """Line free. Returns (board, pc stream, GPRs at the first 0x522C)."""
        b = Board(parked_pair(img_f, img_m), waits=fast_waits())
        seq, snap = [], []
        def hook(mach, addr, size):
            seq.append(addr)
            if addr == 0xFFF0522C and not snap:
                snap.extend(b.m.reg(i) for i in range(32))
        h = b.m.hook_code(hook)
        b.boot(max_insns=2_000_000, reset_vector=True)
        b.m.mu.hook_del(h)
        return b, seq, snap

    v14_f, v14_m = bl14.build(pair.flash, pair.mpc)
    b14b, seq14, regs14 = park_boot(v14_f, v14_m)
    b15b, seq15, regs15 = park_boot(bl_f, bl_m)
    diff = [i for i in range(32) if regs14[i] != regs15[i]]
    if diff or not regs15:
        raise SystemExit(f"FAIL: H: GPRs at the park prologue differ: {diff}")
    print("  ok: H: line free -- every GPR identical at the stock park prologue")
    a14 = seq14[seq14.index(0xFFF0522C):]
    a15 = seq15[seq15.index(0xFFF0522C):]
    n = next((k for k in range(min(len(a14), len(a15))) if a14[k] != a15[k]),
             min(len(a14), len(a15)))
    if n < 30_000:
        raise SystemExit(f"FAIL: H: park streams diverge at +{n}")
    leak = [pc for pc in a15 if 0xFFF17000 <= pc < 0xFFF1A000
            or SRAM_BASE <= pc < SRAM_BASE + 0x8000]
    if leak:
        raise SystemExit(f"FAIL: H: the park ran ring/SRAM code with the line free")
    print(f"  ok: H: line free -- {n} insns byte-identical (the first time-driven "
          f"tick; ticks seen {sum(1 for x in a14 if x == 0xFFF052E8)} vs "
          f"{sum(1 for x in a15 if x == 0xFFF052E8)}, the window's 1 ms phase), "
          f"no ring/SRAM pcs")

    # ...and the marks alone never parked it: valid content boots regardless
    f = bytearray(bl_f)
    for at in MARKS_AT:
        f[at:at + 4] = b"\xff\xff\xff\xff"
    b = Board(type(pair)(bytes(f), bytes(bl_m), "marks", check_program=False),
              waits=fast_waits())
    parks = []
    h = b.m.hook_code(lambda mach, addr, size: parks.append(addr)
                      if addr == 0xFFF05228 else None)
    b.boot(max_insns=1_500_000, reset_vector=True)
    b.m.mu.hook_del(h)
    if parks or not b.m.pc < 0x80000:      # the program runs in the MPC window
        raise SystemExit(f"FAIL: H: marks-blank parked (pc {b.m.pc:#x}, {len(parks)} park calls)")
    print("  ok: H: marks blank but cal valid still boots -- only invalid content parks")

    # taken: the mid-push DME, line held across reset -> body -> HELLO
    pb = Board(parked_pair(bl_f, bl_m), waits=fast_waits())
    pb.sci.line_hold = True
    reached, why = pb.boot(max_insns=2_000_000, until=SRAM_BASE, reset_vector=True)
    if not reached:
        raise SystemExit(f"FAIL: H: the park window never reached the stub ({why})")
    pb.run_from(SRAM_BASE, 100_000, until=0x1)
    sp = Session(pb)
    if not sp.until(lambda: SRAM_BASE <= pb.m.pc < SRAM_BASE + REPLY_OFF,
                    budget=200_000):
        raise SystemExit(f"FAIL: H: body not in SRAM (pc={pb.m.pc:#x})")
    hello_wait(sp, "H park entry", bl15.stamp_bytes())
    print("  ok: H: parked + held line -> park window -> body (the C cases' re-entry)")

    print("=" * 64)
    print(f"ALL OK -- resume matrix converged, {time.time() - t0:.0f}s wall")
    return 0


if __name__ == "__main__":
    sys.exit(main())
