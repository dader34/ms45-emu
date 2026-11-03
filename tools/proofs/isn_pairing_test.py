"""The EEPROM-side ISN flows on the emulator (transport proof).

SUPERSEDED AS A PAIRING STORY (car, 2026-10-28): what pairs a used DME is
the flash triple at ext 0x1FB00 (isn_burn_test.py) plus the EWS start-value
sync; the EEPROM record this proof rewrites is a per-DME identity word that
two differently-valued DMEs both started the same car with. What this proof
still stands for: the v15 body's EEPROM read window and ee_write service
land byte-exact and the EWS DS2 client speaks its dialect. The EEPROM
matcher page it was written for is gone from BMWeb.

The ISN/EWS pairing proof (the matcher's capstone on the emulator):
both sides read, the match said, and both alignment flows driven over the
real wire -- the same session the app will run.

Run from the ms45-emu root:
.venv/bin/python -m tools.proofs.isn_pairing_test

The DME side is the v15 body (READ window + the ee_write module); the EWS
side is a mock in this file speaking the mined DS2 dialect (ews.js's, from
docs/EWS-ISN.md): job 0x60 answers the 2-byte ISN at [3..4], job 0x61
writes it, 63/62/67 sync the rolling code. The pairing logic itself
(client isn-pairing.js) is mock-proven in BMWeb (tools/verify/
test_pairing.js); what this proof adds is the flow against the protocol:
the used-DME story starts a mismatch, the DME<-EWS rewrite lands through
svc 0x0B with every write read back, the re-dump votes the car's ISN,
nothing outside the triple moves, and the blank-EWS story writes the
DME's ISN through the factory job without touching the DME at all.
"""
import struct
import sys
import time

from ms45emu.image import load_named, Pair
from ms45emu.board import Board
from tools.build.flasher_gate import build, ENTRY_CPU, stamp_bytes
from tools.build.flasher_body import SRAM_BASE, REPLY_OFF, EE_WINDOW, EE_SIZE
from tools.proofs.flasher_session_test import Session, frame, fast_waits, WATCHDOG_MS
from tools.proofs.ee_write_test import ee_write

S_EEWRITE = 0x0B

DONOR_ISN = 0x2F7F          # what the used DME's own car's EWS held
CAR_ISN = 0x1111            # what this car's EWS holds
OTHER_FIELD = 0xA55A        # another voting field in the stored-data block


def w16(img, at, v):
    img[at] = (v >> 8) & 0xFF
    img[at + 1] = v & 0xFF


def voting_triples(img):
    """The JS finder's mirror (isn-pairing.js): a 16-bit word kept
    straight / inverted / straight, the nearest second straight copy, the
    stride measured off the data."""
    out = []
    for p in range(0, len(img) - 1, 2):
        v = (img[p] << 8) | img[p + 1]
        if v in (0x0000, 0xFFFF):
            continue
        for q in range(p + 4, min(p + 33, len(img) - 1), 2):
            if ((img[q] << 8) | img[q + 1]) != v:
                continue
            m = next((t for t in range(p + 2, q, 2)
                      if ((img[t] << 8) | img[t + 1]) == v ^ 0xFFFF), -1)
            if m >= 0:
                out.append({"at": p, "straight": (p, q), "inverted": m, "val": v})
            break
    return out


def match_state(img, ews_isn):
    triples = voting_triples(img)
    hit = next((t for t in triples if t["val"] == ews_isn), None)
    others = [t for t in triples if t is not hit]
    state = "match" if hit else ("mismatch" if img is not None and ews_isn is not None else "unknown")
    return state, hit, others


class MockEws:
    """The EWS3 the app talks to (ews.js's dialect): DS2 frames at 0x44,
    the ISN two bytes at [3..4], the factory write job, the sync chain."""

    def __init__(self, isn):
        self.isn = isn
        self.writes = 0
        self.synced = []

    def transfer(self, payload):
        job = payload[0]
        if job == 0x60:
            return [0xA0, (self.isn >> 8) & 0xFF, self.isn & 0xFF]
        if job == 0x61:
            self.writes += 1
            self.isn = ((payload[1] & 0xFF) << 8) | (payload[2] & 0xFF)
            return [0xA0]
        if job == 0x63:
            self.synced.append("63")
            return [0xA0, 0x5A, 0xC3]
        if job == 0x62:
            self.synced.append("62")
            return [0xA0]
        if job == 0x67:
            self.synced.append("67")
            return [0xA0]
        raise SystemExit(f"FAIL: the mock EWS does not know job {job:#04x}")


def read_ews_isn(ews):
    a = ews.transfer([0x60])
    b = ews.transfer([0x60])          # two reads, both must agree (ews.js)
    if a != b:
        raise SystemExit(f"FAIL: two EWS reads disagree: {a} vs {b}")
    return ((a[1] & 0xFF) << 8) | (a[2] & 0xFF)


def write_ews_isn(ews, val):
    if not 0 <= val <= 0xFFFF:
        raise SystemExit("the ISN is two bytes")
    ews.transfer([0x61, (val >> 8) & 0xFF, val & 0xFF])
    back = read_ews_isn(ews)
    if back != val:
        raise SystemExit(f"FAIL: EWS read back {back:#06x}, wrote {val:#06x}")


def sync_dme(ews):
    code = ews.transfer([0x63])
    ews.transfer([0x62, code[1], code[2]])
    ews.transfer([0x67])
    return ews.synced


def main():
    t0 = time.time()
    pair = load_named("session1.livetune6-notraps")
    f, m = build(pair.flash, pair.mpc)
    board = Board(Pair(bytes(f), bytes(m), "isnpair", check_program=False),
                  waits=fast_waits() if "--fast-wait" in sys.argv else None)

    # the used DME's vault: the donor ISN as a voting triple, another
    # voting field beside it, an incidental copy of the value far away
    seed = bytearray(b"\xFF" * EE_SIZE)  # the part is 4 KB (v18)
    w16(seed, 0x3A, DONOR_ISN)
    w16(seed, 0x40, DONOR_ISN ^ 0xFFFF)
    w16(seed, 0x46, DONOR_ISN)
    w16(seed, 0x50, OTHER_FIELD)
    w16(seed, 0x56, OTHER_FIELD ^ 0xFFFF)
    w16(seed, 0x5C, OTHER_FIELD)
    w16(seed, 0x800, DONOR_ISN)       # an incidental occurrence, no vote
    board.load_eeprom(bytes(seed))

    s = Session(board)
    board.sci.line_hold = True
    reached, why = board.boot(max_insns=2_000_000, until=ENTRY_CPU + 4, reset_vector=True)
    assert reached, f"never reached the flasher entry: {why}"
    in_body = lambda: SRAM_BASE <= board.m.pc < SRAM_BASE + REPLY_OFF  # noqa: E731
    if not s.until(in_body, budget=2_000_000):
        raise SystemExit("FAIL: the body never reached SRAM")
    board.sci.line_hold = False
    if not s.until(lambda: len(board.sci.tx) >= 21):
        raise SystemExit("FAIL: no HELLO after the break released")
    if bytes(board.sci.tx[:21]) != frame(0x40, stamp_bytes(20, 0x1B)):
        raise SystemExit(f"FAIL: HELLO mismatch: {bytes(board.sci.tx[:21]).hex()}")
    board.watchdog_window()
    board.sci.model_overrun = True
    board.cmf.watch_hv_reads()

    writes0 = board.qspi.eeprom.writes

    # ---- both sides read, side by side ---------------------------------
    dump = bytearray()
    for at in range(0, EE_SIZE, 0x1000):
        dump += s.read(EE_WINDOW | at, 0x1000)
    ews = MockEws(CAR_ISN)             # this car's EWS; the DME is a donor
    ews_isn = read_ews_isn(ews)
    state, hit, others = match_state(bytes(dump), ews_isn)
    if state != "mismatch":
        raise SystemExit(f"FAIL: the used-DME story must start a mismatch ({state})")
    pick = next(t for t in others if t["val"] == DONOR_ISN)
    if len(others) != 2:
        raise SystemExit(f"FAIL: the picker sees {len(others)} candidates, want 2")
    vals = "/".join(f"{t['val']:04X}" for t in others)
    print(f"  ok: mismatch shown -- EWS {ews_isn:04X}, the dump votes {vals}")

    # ---- DME <- EWS: the triple rewritten, votes preserved -------------
    ops = [
        (pick["straight"][0], ews_isn),
        (pick["inverted"], ews_isn ^ 0xFFFF),
        (pick["straight"][1], ews_isn),
    ]
    for at, val in ops:
        ee_write(s, at, struct.pack(">H", val))    # each read back inside
    if board.qspi.eeprom.writes - writes0 != 3:
        raise SystemExit("FAIL: not exactly three WRITE transactions")

    after = bytearray()
    for at in range(0, EE_SIZE, 0x1000):
        after += s.read(EE_WINDOW | at, 0x1000)
    state, hit, others = match_state(bytes(after), ews_isn)
    if state != "match" or hit["at"] != 0x3A:
        raise SystemExit(f"FAIL: the re-dump must vote the car's ISN ({state})")
    if not any(t["val"] == OTHER_FIELD and t["at"] == 0x50 for t in others):
        raise SystemExit("FAIL: the other voting field moved")
    if (after[0x800] << 8 | after[0x801]) != DONOR_ISN:
        raise SystemExit("FAIL: the incidental copy of the value moved")
    moved = [i for i in range(EE_SIZE) if after[i] != dump[i]]
    if moved != [0x3A, 0x3B, 0x40, 0x41, 0x46, 0x47]:
        raise SystemExit(f"FAIL: bytes outside the triple moved: {moved}")
    print("  ok: DME<-EWS -- the triple rewritten, 6 bytes of 4 KB, everything else still")

    # ---- EWS <- DME: the factory job, the DME untouched -----------------
    donor = MockEws(0x0000)            # a blank EWS
    write_ews_isn(donor, DONOR_ISN)
    steps = sync_dme(donor)
    if read_ews_isn(donor) != DONOR_ISN or steps != ["63", "62", "67"]:
        raise SystemExit("FAIL: the blank-EWS story did not verify")
    if board.qspi.eeprom.writes != writes0 + 3:
        raise SystemExit("FAIL: the DME's part moved during the EWS flow")
    print("  ok: EWS<-DME -- the factory job verified, 63/62/67 synced, the DME untouched")

    # ---- both stories end in a match -----------------------------------
    # the EWS<-DME story pairs against the DME as it came (the donor
    # dump): a blank EWS fed the donor ISN agrees with the original vault
    state, _, _ = match_state(bytes(dump), read_ews_isn(donor))
    if state != "match":
        raise SystemExit("FAIL: the EWS<-DME pair does not match the DME as it came")
    print("  ok: both repairs end in a match (each against its own DME state)")

    gap = board.watchdog_gap_ms()
    if gap > WATCHDOG_MS:
        raise SystemExit(f"FAIL: the watchdog went {gap:.0f} ms unserviced")
    print(f"  ok: longest watchdog gap {gap:.1f} ms (car limit {WATCHDOG_MS} ms)")

    r = s.xfer(6)
    if r[3] != 0x46:
        raise SystemExit(f"FAIL: RESET: {r.hex()}")
    print("reboot: the loader starts the stock program (idle)")
    print(f"ALL OK -- {time.time() - t0:.0f}s wall")


if __name__ == "__main__":
    main()
