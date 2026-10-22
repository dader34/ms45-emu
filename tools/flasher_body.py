"""The flasher body: the wire protocol that runs once the gate branches
(docs/fast-flasher.md). Assembled for SRAM -- it only ever runs relocated --
placed in ext at 0xFD500 by flasher_gate.build(), and copied to SRAM by the
relocate stub at 0xFD400 before the first flash op.

Memory plan (the machine is ours from the gate; the loader's and the
program's SRAM state is dead):
    0x3F9800  this code, then the NRV2B decoder, then the reply buffer
              (reply at code offset 0xC00)
    0x3FAFF0  BAUD_PROBE -- SET_BAUD's probation countdown (one word)
    0x3FB000  DRV_SDA  -- the CMF driver's r13 data block (0x87C bytes,
              rebuilt before every MPC job; r13 = DRV_R13 while it runs)
    0x3FB900  CRC_TABLE -- CRC-32/MPEG-2's 256 words, built at entry
    0x3FBFF0  stack top -- non-leaf routines (send_reply, send_bytes, nak,
              rx_telegram) push LR here; the calls nest at most 3 deep,
              a dozen bytes; the CMF driver's frames add a few hundred
              (0x2F0 is the room above CRC_TABLE)
    0x3FC000  RXBUF    -- telegrams land here (a CHUNK is ~4.6 KB)
    0x3FD800  DSTBUF   -- the decoded 4 KB of a chunk
    0x3FE800  DRV_CODE -- the loader's CMF driver, copied from the boot
              block before every MPC job (0x1778 bytes, to 0x3FFF78)

Registers (r14-r23 follow aif_wipe's flash-macro plan so program_halfword
drops straight in; r28-r31 hold the SCI):
    r3  scratch/arg          r17 SWSR (0x2FC00E)      r28 SC1SR
    r14 0xAA  r15 0x55       r18 0x556C               r29 SC1DR
    r16 0xA0                  r19 0xAA39               r30 SCC1R0
The decoder blob clobbers r3-r12 and r14 -- the CHUNK handler sets the
flash constants after the decode call, never before.

Wire (115200, KWP-shaped telegrams, polled I/O, stop-and-wait):
    [n][12][F1][svc][data...][cksum]  n = bytes after the length byte,
    cksum = sum(tgt..data) mod 256. A frame whose span exceeds 255 uses
    the escape: n = 00, then a u16be with the same span. Only the app
    ever needs it (CHUNK); the body accepts both and always replies short.
    Services: HELLO 00, SECTOR_QUERY 01, ERASE 02, CHUNK 03, VERIFY 04,
    MARKS 05, RESET 06, SET_BAUD 07, CHUNK_SET 08; ACK = svc|0x40, NAK =
    7F svc reason (1 perm,
    2 chunk-crc, 3 decode, 4 readback, 5 verify-mismatch, 6 malformed,
    7 cmf-driver: not found in the boot block, or its erase failed).
    Addresses on the wire are ext offsets; only >= 0x40000 is writable.
    V2: bit 31 of a wire offset selects the MPC window (the CMF, 448 KB
    at CPU 0x0): off = 0x80000000 | mpc_offset. ERASE on the window takes
    the one 32 KB CMF block containing the offset -- or, with a u16 block
    mask after the offset (bit n = block n), all those blocks in ONE
    erase job (v8); CHUNK CMF-programs 64-byte pages (a partial tail
    page is filled from the array itself); QUERY/VERIFY read the array
    directly.
    V8: CHUNK_SET programs PAGESETS -- the CMF programs one page in each
    selected block with the same pulses (the driver is NXP's
    ParallelProgram), so a pageset of up to 14 pages costs what one page
    did. Header: u16 mask (bit n = block n), u16 offset within the
    block (64-aligned), u16 declen, u16 clen, u32 crc, u8 pages, 3 pad;
    the decoded data is `pages` pagesets, each the 64-byte page of every
    selected block in ascending block order; declen = pages x blocks x
    64 <= 4096. SET_BAUD (u16 SCBR) answers at the old rate, then
    switches, on probation: only a SET_BAUD naming the rate it is already
    on -- the tester's confirmation that it HEARD an answer there -- ends
    the probation; anything else is served but does not count, and after
    ~120 loop turns without it (~2.4 s of silence, less with traffic) the
    body puts 115200 back by itself. (v8 ended the probation on any valid
    telegram: a rate the tester could drive but not hear stranded the car
    on 2026-10-21.) The CMF writes are the boot
    loader's own driver (docs/fast-flasher.md, "The MPC (CMF) writes on
    silicon"): a hand-written sequence reset the car, so the body copies
    the loader's position-independent driver out of the protected boot
    block, gives it an r13 data block, raises the EPEE pin (MPIOSMDR/
    MPIOSMDDR bit 0x40 -- the driver checks it and never touches it) and
    calls its erase_job / program_job; the driver services the watchdog
    itself. The block is found by its data signature at run time: the
    car's loader is another build than the donor's (same bytes, +0x24).
The single K line means the transmitter hears itself: every reply's
worth of echo bytes is read back and discarded after sending (the stock
driver uses that echo; we drop it). The ninth wire bit is the even
parity of the byte and is the sender's business (the SCI hands over
nine data bits): the body computes it on transmit and masks it on
receive.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aif_wipe import program_halfword                        # noqa: E402
from flasher_gate import GateAsm, STAMP_AT                   # noqa: E402
from nrv2b_dec import build_decoder                          # noqa: E402

SRAM_BASE = 0x3F9800
RXBUF, DSTBUF = 0x3FC000, 0x3FD800
STACK_TOP = 0x3FBFF0
CRC_TABLE = 0x3FB900                      # 256 words, built at entry
BAUD_PROBE = 0x3FAFF0                     # SET_BAUD probation: cmd-loop timeouts left
BAUD_PROBATION = 120                      # cmd-loop turns (x ~20 ms when silent) to be confirmed
ENTRY_AT, BODY_AT = 0xFD400, 0xFD500      # ext offsets; stub at ENTRY copies from BODY_AT
EXT = 0xFFF00000

# the MPC window: wire offsets with bit 31 set address the CMF (448 KB at
# CPU 0x0), in 32 KB blocks; the EPEE pin is the MIOS parallel port bit 0x40
MPC_WINDOW = 0x80000000
MPIOSMDR = 0x306100
EPEE_PIN = 0x40
# the loader's CMF driver: one image in the boot block, located by the three
# words at +4 of its data (module bases, first timing word; the word before
# them is zero). With S the data start (an ext offset: 0x14B04 in the
# donor, 0x14B28 on the car), the signature is at S+4 and:
#   S-8     block masks, 2 words        -> r13-0x77F8
#   S       bases + timing table, 0x7C  -> r13-0x77E8
#   S+0x7C  code, 0x1778 bytes          -> DRV_CODE
# Entry offsets from the code start: erase_job(r3 = block mask) and
# program_job(r3 = array address, r4 = source, r5 = length < 0x10000);
# both return 0 for success. The driver reads r13-0x7FE8 .. r13-0x776C
# and nothing else of ours; the body zeroes that span before each job.
DRV_SIG = (0x002FC800, 0x002FC840, 0x284F0000)
DRV_SCAN_LO, DRV_SCAN_HI = 0x14000, 0x16000  # ext offsets the signature scan covers
DRV_IMAGE_LEN, DRV_CODE_LEN = 0x7C, 0x1778
DRV_CODE = 0x3FE800                          # SRAM, above DSTBUF
DRV_SDA, DRV_SDA_LEN = 0x3FB000, 0x87C       # r13-0x7FE8 .. r13-0x776C
DRV_R13 = DRV_SDA + 0x7FE8
DRV_ERASE, DRV_PROGRAM = 0x148, 0x21C        # erase_job, program_job (the wrappers)
# the driver proper (NXP's ParallelProgram state machine): init(r3 = mode,
# 1 erase / 0 program), start(r3 = block mask, r4 = source, r5 = offset
# within the block, r6 = shadow flag), step (0x10/0x11 = busy), finish.
# The mask's bit 31 - n is block n; start latches the source's 64-byte
# pages into every selected block (ascending) at the same offset, and one
# pulse sequence programs them all.
DRV_INIT, DRV_START, DRV_STEP, DRV_FINISH = 0xC60, 0xDF0, 0x1048, 0x1638

SCC1R0, SCC1R1, SC1SR, SC1DR = 0x305008, 0x30500A, 0x30500C, 0x30500E
SWSR = 0x2FC00E
TE, RE, RDRF, TDRE, RAF = 0x08, 0x04, 0x40, 0x0100, 0x20
PE, M = 0x0400, 0x0200                     # SCC1R1: hardware parity, 9-bit frame
SCBR_115200 = 11                          # 40 MHz / (32*11) = 113.6 k, ~1.2 % fast
SETTLE = 100000                            # ~5 ms at 2 cycles per loop pass
# Real-cable accommodations (the K+DCAN adapter cannot hear while DTR, its
# transmit enable, is high; the stock loader's P2-delayed replies started
# only after the tester's DTR drop landed, the body answered in microseconds
# and was never heard):
REPLY_GAP = 50000                          # ~5 ms before EVERY reply (4 cycles a pass)
RX_TIMEOUT = 114000                        # ~20 ms per byte (7 cycles a pass): a frame
                                           # whose sender went silent mid-span is
                                           # dropped and the parser resyncs silently
RX_TIMEOUT_MARK = 0xFFFF                   # rx_byte's "no byte" return (a real byte
                                           # can be 0x00; the mark cannot be one)
MAX_SPAN = 4700                            # chunk worst case + headroom; a longer span
                                           # is garbage (a stray 0x00 swallows the next
                                           # two bytes as a u16) -- NAK and resync now

# wire services
S_HELLO, S_QUERY, S_ERASE, S_CHUNK, S_VERIFY, S_MARKS, S_RESET, S_SETBAUD, S_CHUNKSET = range(9)
# marks (board.VALID_MARKS): ext offset, value, as big-endian halfword pairs
CAL_MARKS = ((0x5FF80, 0x4824, 0x9042), (0x5FFC0, 0x9048, 0x2442))
PROG_MARKS = ((0xFFF80, 0x4290, 0x2448), (0xFFFC0, 0x4224, 0x4890))
REPLY_OFF = 0x1600                         # code+decoder must stay under this (v2:
                                            # the CMF driver outgrew the old 0xC00;
                                            # v8 the pageset path outgrew 0x1400)


class BodyAsm(GateAsm):
    def lbz(self, rD, d, rA):
        self.raw(0x88000000 | (rD << 21) | (rA << 16) | (d & 0xFFFF),
                 f"lbz    r{rD}, {d:#x}(r{rA})")

    def stb(self, rS, d, rA):
        self.raw(0x98000000 | (rS << 21) | (rA << 16) | (d & 0xFFFF),
                 f"stb    r{rS}, {d:#x}(r{rA})")

    # X-form register logicals: the DESTINATION is the rA field (bits
    # 11-15, << 16) and the source rS the << 21 field -- the other way
    # round from every D-form load/store. An earlier build encoded them
    # swapped and read "unicorn never writes the destination"; unicorn
    # executes the right encoding correctly (sandboxed 2026-10-21: or, xor,
    # and, nor all exact). The loader's own driver uses them freely.
    def _xform(self, xo, rA, rS, rB, name):
        self.raw(0x7C000000 | (rS << 21) | (rA << 16) | (rB << 11) | (xo << 1),
                 f"{name:6s} r{rA}, r{rS}, r{rB}")

    def xor_(self, rA, rS, rB):
        self._xform(316, rA, rS, rB, "xor")

    def or_(self, rA, rS, rB):
        self._xform(444, rA, rS, rB, "or")

    def and_(self, rA, rS, rB):
        self._xform(28, rA, rS, rB, "and")

    def xori(self, rA, imm):                # self-form only: rA ^= imm16
        self.raw(0x68000000 | (rA << 21) | (rA << 16) | (imm & 0xFFFF),
                 f"xori   r{rA}, {imm:#06x}")

    def xoris(self, rA, imm):               # self-form: rA ^= imm16 << 16
        self.raw(0x6C000000 | (rA << 21) | (rA << 16) | (imm & 0xFFFF),
                 f"xoris  r{rA}, {imm:#06x}")

    def mr(self, rA, rS):
        self.addi(rA, rS, 0)                # addi copies; `or rA,rS,rS` is the broken one

    def add(self, rA, rB, rC):             # rA = rB + rC
        self.raw(0x7C000214 | (rA << 21) | (rB << 16) | (rC << 11),
                 f"add    r{rA}, r{rB}, r{rC}")

    def subf(self, rA, rB, rC):            # rA = rC - rB (equality: zero iff equal)
        self.raw(0x7C000050 | (rA << 21) | (rB << 16) | (rC << 11),
                 f"subf   r{rA}, r{rB}, r{rC}")

    def andis_(self, rA, rS, imm):         # sets CR0
        self.raw(0x74000000 | (rS << 21) | (rA << 16) | (imm & 0xFFFF),
                 f"andis. r{rA}, r{rS}, {imm:#x}")

    def rlwinm(self, rA, rS, sh, mb, me):
        self.raw(0x54000000 | (rS << 21) | (rA << 16) | (sh << 11) | (mb << 6) | (me << 1),
                 f"rlwinm r{rA}, r{rS}, {sh},{mb},{me}")

    def bl(self, label):
        self.fixups.append((self.here(), "bl", label))
        self.raw(0x48000001, f"bl     {label}")

    def blr(self):
        self.raw(0x4E800020, "blr")

    # LR discipline: any routine that executes a `bl` destroys its own
    # return address (the callees are leafs that never save it). Non-leaf
    # routines push LR at entry and return via ret(); the stack is r1,
    # initialised to STACK_TOP at sram_entry. Cost this bug: the first
    # HELLO careened through op_marks code with a junk send pointer.
    # The SPR field of mflr/mtlr is 0x00080000 for LR -- 8 in the LOW
    # half at bits 11-15. An 8 at bits 16-20 (8<<16, the swapped-halves
    # reading) selects SPR 256, which does not exist: mflr loads garbage
    # and mtlr writes nowhere, so blr ran on whatever stale LR held and
    # the machine chased its own ret sequence up through unmapped RAM.
    def mflr(self, rD):
        self.raw(0x7C0002A6 | (rD << 21) | 0x00080000, f"mflr   r{rD}")

    def mtlr(self, rS):
        self.raw(0x7C0003A6 | (rS << 21) | 0x00080000, f"mtlr   r{rS}")

    def mtctr(self, rS):                   # SPR 9: 9 in the low half, bits 11-15
        self.raw(0x7C0003A6 | (rS << 21) | 0x00090000, f"mtctr  r{rS}")

    def bctrl(self):
        self.raw(0x4E800421, "bctrl")

    def stwu(self, rS, d, rA):
        self.raw(0x94000000 | (rS << 21) | (rA << 16) | (d & 0xFFFF),
                 f"stwu   r{rS}, {d:#x}(r{rA})")

    def push_lr(self):
        self.mflr(0)
        self.stwu(0, -4, 1)

    def ret(self):
        self.lwz(0, 0, 1)
        self.addi(1, 1, 4)
        self.mtlr(0)
        self.blr()

    def blt(self, label):
        self.fixups.append((self.here(), "blt", label))
        self.raw(0x41800000, f"blt    {label}")

    def bgt(self, label):
        self.fixups.append((self.here(), "bgt", label))
        self.raw(0x41810000, f"bgt    {label}")

    def resolve(self, base):
        # `b`/`bl` carry the offset in LI (bits 2-25); the bc forms in BD
        ops = {"beq": 0x41820000, "bne": 0x40820000,
               "blt": 0x41800000, "bgt": 0x41810000}
        for index, kind, label in self.fixups:
            rel = 4 * (self.labels[label] - index)
            if kind in ("b", "bl"):
                w = (0x48000000 | (1 if kind == "bl" else 0)) | (rel & 0x03FFFFFC)
            else:
                w = ops[kind] | (rel & 0xFFFC)
            self.words[index] = (w, self.words[index][1])


def _swsr(a):
    a.sth(18, 0, 17)                        # 0x556C / 0xAA39 to SWSR
    a.sth(19, 0, 17)


def _rx_byte(a):
    """r3 = one byte (bit 8 masked off), or RX_TIMEOUT_MARK when nothing
    arrives within ~20 ms: a sender that went silent mid-frame (a port
    reopen's stray bytes, a 9600 telegram into the 115200 body) must not
    wedge the parser waiting for a span it will never finish."""
    a.label("rx_byte")
    a.li32(3, RX_TIMEOUT)
    a.label("rx_wait")
    a.lhz(4, 0, 28)
    a.andi_(4, 4, RDRF)
    a.bne("rx_got")
    _swsr(a)
    a.addic_(3, -1)
    a.bne("rx_wait")
    a.li32(3, RX_TIMEOUT_MARK)              # the countdown ran out: no byte
    a.blr()
    a.label("rx_got")
    a.lhz(3, 0, 29)                         # SR-then-DR is what clears RDRF
    a.andi_(3, 3, 0xFF)
    a.blr()


def _rx_to(a, label):
    """After a bl rx_byte: branch to `label` when it was a timeout."""
    a.cmplwi(3, RX_TIMEOUT_MARK)
    a.beq(label)


def _tx_parity(a):
    """r6 = byte -> r6 |= even-parity << 8 (the ninth wire bit).

    A xor-fold would need the register xor unicorn does not implement;
    the low bit of (b + b>>1 + b>>2 + b>>4) is the same parity (carries
    only climb), so the fold is three adds on rlwinm shifts, and the
    merge is an add: bit 8 of r6 is clear coming in (a loaded byte).
    """
    a.rlwinm(9, 6, 28, 16, 31)              # r9 = r6 >> 4
    a.add(8, 6, 9)
    a.rlwinm(9, 8, 30, 16, 31)              # r9 = r8 >> 2
    a.add(8, 8, 9)
    a.rlwinm(9, 8, 28, 16, 31)              # r9 = r8 >> 4
    a.add(8, 8, 9)                          # bit 0 = parity of the byte
    a.rlwinm(9, 8, 31, 23, 23)              # bit 0 -> bit 8
    a.add(6, 6, 9)


def _send_bytes(a):
    """r3 = ptr, r4 = count; sends each byte and eats its echo before the next.

    v5 sent the whole reply and only then read the echoes back. The SCI
    holds one received byte (plus the one in the shifter), so on the car all
    but ~2 echoes overran, and the drain then sat out its inter-byte timeout
    once per missing echo -- long enough to eat the tester's next request as
    "echo" (the car answered a HELLO sent after a pause, nothing sent right
    after a reply). One byte out, its echo in: nothing piles up. A missing
    echo costs one timeout and no more. rx_byte takes r3/r4, so the pointer
    lives in r7 and the count in r27 (_tx_parity uses r6, r8, r9)."""
    a.label("send_bytes")
    a.push_lr()
    a.mr(7, 3)
    a.mr(27, 4)
    a.label("sb_next")
    a.cmplwi(27, 0)
    a.beq("sb_done")
    a.label("sb_wait")
    a.lhz(5, 0, 28)
    a.andi_(5, 5, TDRE)                     # bit 8 is inside andi.'s 16 bits
    a.bne("sb_ready")
    _swsr(a)
    a.b("sb_wait")
    a.label("sb_ready")
    a.lbz(6, 0, 7)
    _tx_parity(a)
    a.sth(6, 0, 29)
    a.addi(7, 7, 1)
    a.addi(27, 27, -1)
    a.bl("rx_byte")                         # its echo, before the next goes out
    a.b("sb_next")
    a.label("sb_done")
    a.ret()


def _send_reply(a):
    """r3 = payload length, r4 = service byte; payload sits at REPLY+4."""
    a.label("send_reply")
    a.push_lr()
    a.mr(9, 3)                              # payload length
    a.mr(10, 4)                             # service
    a.li32(31, SRAM_BASE + REPLY_OFF)
    a.addi(3, 9, 4)
    a.stb(3, 0, 31)                         # span byte (replies are short)
    a.li(3, 0x12)
    a.stb(3, 1, 31)
    a.li(3, 0xF1)
    a.stb(3, 2, 31)
    a.stb(10, 3, 31)
    a.addi(3, 31, 1)                        # checksum over [1, 3+plen]
    a.addi(4, 9, 3)
    a.li(5, 0)
    a.label("sr_cs")
    a.cmplwi(4, 0)
    a.beq("sr_stor")
    a.lbz(6, 0, 3)
    a.add(5, 5, 6)
    a.addi(3, 3, 1)
    a.addic_(4, -1)
    a.bne("sr_cs")
    a.label("sr_stor")
    a.rlwinm(5, 5, 0, 24, 31)
    a.addi(3, 31, 4)
    a.add(3, 3, 9)                          # &reply[4+plen]
    a.stb(5, 0, 3)
    a.addi(4, 9, 5)                         # total bytes
    a.li32(3, REPLY_GAP)                    # P2-like quiet before the first byte:
    a.label("reply_gap")                    # the tester raises DTR (its transmit
    _swsr(a)                                # enable) around the write and drops it
    a.addic_(3, -1)                         # with a USB control transfer that takes
    a.bne("reply_gap")                      # ms -- a microsecond reply leaves before
    a.mr(3, 31)                             # the drop lands and is never heard
    a.bl("send_bytes")
    a.ret()


def _nak(a):
    """r4 = reason; the service byte comes from RXBUF+3."""
    a.label("nak")
    a.push_lr()
    a.li32(5, SRAM_BASE + REPLY_OFF + 4)
    a.li32(6, RXBUF + 3)
    a.lbz(7, 0, 6)
    a.stb(7, 0, 5)
    a.stb(4, 1, 5)
    a.li(3, 2)
    a.li(4, 0x7F)
    a.bl("send_reply")
    a.ret()


def _rx_telegram(a):
    """Read one telegram into RXBUF (both length forms); r3 = span, 0 = bad.

    The buffer layout is normalised to the short form -- [.. 12][F1][svc]
    at RXBUF+1..+3 -- however the length arrived, so the handlers always
    parse from RXBUF+4.

    Desync discipline (real cables, not the ws transport): the span is
    bounded and the 12 F1 header is validated BEFORE the span is
    swallowed, so a stray byte in front of a frame (a port reopen glitch)
    costs that one frame plus a NAK, never the 65535 bytes a garbage 0x00
    escape used to wait for; a sender that goes silent mid-frame is timed
    out after ~20 ms per byte and dropped without a reply.
    """
    a.label("rx_telegram")
    a.push_lr()
    a.li32(24, RXBUF)
    a.bl("rx_byte")
    _rx_to(a, "rxt_silent")
    a.cmplwi(3, 0)
    a.bne("rxt_short")
    a.bl("rx_byte")                         # escape: u16be span
    _rx_to(a, "rxt_silent")
    a.rlwinm(7, 3, 8, 16, 31)               # hi << 8 (r3 <= 0xFF)
    a.bl("rx_byte")
    _rx_to(a, "rxt_silent")
    a.add(3, 3, 7)                          # disjoint bits: add is the merge
    a.label("rxt_short")
    a.stb(3, 0, 24)                         # (informational; low byte only)
    a.li32(7, MAX_SPAN)
    a.cmplw(3, 7)
    a.bgt("rxt_bad")                        # past the biggest legal frame: garbage
    a.cmplwi(3, 4)
    a.blt("rxt_bad")                        # tgt+src+svc+cksum is the minimum
    a.mr(25, 3)
    a.mr(8, 3)                              # the span lives in r8 from here to
                                            # rxt_ok -- r9 is the sum loop's
                                            # scratch, r8 stays the span
    a.addi(26, 24, 1)
    a.bl("rx_byte")                         # the header, taken before the rest
    _rx_to(a, "rxt_silent")                 # of the span so garbage dies here
    a.stb(3, 0, 26)
    a.addi(26, 26, 1)
    a.cmplwi(3, 0x12)
    a.bne("rxt_bad")
    a.bl("rx_byte")
    _rx_to(a, "rxt_silent")
    a.stb(3, 0, 26)
    a.addi(26, 26, 1)
    a.cmplwi(3, 0xF1)
    a.bne("rxt_bad")
    a.addic_(25, -2)
    a.label("rxt_loop")
    a.cmplwi(25, 0)
    a.beq("rxt_check")
    a.bl("rx_byte")
    _rx_to(a, "rxt_silent")
    a.stb(3, 0, 26)
    a.addi(26, 26, 1)
    a.addic_(25, -1)
    a.bne("rxt_loop")
    a.label("rxt_check")
    a.addi(26, 26, -1)                      # &cksum byte
    a.lbz(3, 0, 26)
    a.mr(7, 8)                              # the true span; the byte at [24]
                                            # is its low half only in the
                                            # escape form, too short by 0x100
    a.cmplwi(7, 4)                          # tgt+src+svc+cksum is the minimum
    a.blt("rxt_bad")
    a.addic_(7, -1)                         # bytes to sum
    a.addi(6, 24, 1)
    a.li(5, 0)
    a.label("rxt_cs")
    a.cmplwi(7, 0)
    a.beq("rxt_cmp")
    a.lbz(9, 0, 6)
    a.add(5, 5, 9)
    a.addi(6, 6, 1)
    a.addic_(7, -1)
    a.bne("rxt_cs")
    a.label("rxt_cmp")
    a.rlwinm(5, 5, 0, 24, 31)
    a.subf(3, 5, 3)                         # zero iff equal (xor would need the register form)
    a.cmplwi(3, 0)
    a.beq("rxt_ok")
    a.label("rxt_bad")
    a.li(4, 6)
    a.bl("nak")
    a.li(3, 0)
    a.ret()
    a.label("rxt_ok")
    a.mr(3, 8)                              # the true span (nonzero = good)
    a.ret()
    a.label("rxt_silent")                   # a timeout is not the tester's frame:
    a.li(3, 0)                              # drop it and listen for a fresh length
    a.ret()                                 # byte -- no NAK for silence


def _crc_table(a):
    """Build CRC-32/MPEG-2's table at CRC_TABLE (sram_entry; ~16k insns)."""
    a.li32(3, CRC_TABLE)
    a.li(4, 0)
    a.label("ct_entry")
    a.rlwinm(5, 4, 24, 0, 7)                # i << 24
    a.li(6, 8)
    a.label("ct_bit")
    a.rlwinm(7, 5, 1, 31, 31)               # the top bit
    a.rlwinm(5, 5, 1, 0, 30)                # << 1
    a.cmplwi(7, 0)
    a.beq("ct_keep")
    a.xoris(5, 0x04C1)                      # ^= 0x04C11DB7
    a.xori(5, 0x1DB7)
    a.label("ct_keep")
    a.addic_(6, -1)
    a.bne("ct_bit")
    a.stw(5, 0, 3)
    a.addi(3, 3, 4)
    a.addi(4, 4, 1)
    a.cmplwi(4, 256)
    a.blt("ct_entry")


def _crc32(a):
    """r3 = ptr, r4 = len -> r3 = CRC-32/MPEG-2 (poly 0x04C11DB7, init all-ones).

    Table-driven, ~12 instructions a byte (the bitwise v4-v7 loop was ~110:
    a 64 KB QUERY took 600 ms on the car; now ~60 ms). The watchdog is
    serviced every 256 bytes (~80 us) against the loader's 100 ms period.
    """
    a.label("crc32")
    a.li32(5, 0xFFFFFFFF)
    a.li32(11, CRC_TABLE)
    a.label("c3_byte")
    a.cmplwi(4, 0)
    a.beq("c3_done")
    a.andi_(12, 4, 0xFF)
    a.bne("c3_go")
    _swsr(a)
    a.label("c3_go")
    a.lbz(7, 0, 3)
    a.addi(3, 3, 1)
    a.addi(4, 4, -1)
    a.rlwinm(8, 5, 8, 24, 31)               # crc >> 24
    a.xor_(8, 8, 7)                         # the table index
    a.rlwinm(8, 8, 2, 22, 29)               # x4
    a.add(8, 8, 11)
    a.lwz(9, 0, 8)
    a.rlwinm(5, 5, 8, 0, 23)                # crc << 8
    a.xor_(5, 5, 9)
    a.b("c3_byte")
    a.label("c3_done")
    a.mr(3, 5)
    a.blr()


def _perm(a):
    """r3 = wire offset, r4 = length -> r3 = 0 if the range is writable.
    V2: bit 31 selects the MPC window (0x0-0x6FFFF, the CMF)."""
    a.label("perm")
    a.andis_(5, 3, 0x8000)
    a.bne("perm_mpc")
    a.li32(5, 0x40000)
    a.cmplw(3, 5)
    a.blt("perm_bad")
    a.li32(5, 0x100000)
    a.add(6, 3, 4)
    a.cmplw(6, 5)
    a.bgt("perm_bad")
    a.li(3, 0)
    a.blr()
    a.label("perm_mpc")
    a.rlwinm(3, 3, 0, 1, 31)               # strip the window bit (li would
                                            # sign-extend it right back)
    a.li32(5, 0x70000)
    a.cmplw(3, 5)
    a.bgt("perm_bad")
    a.add(6, 3, 4)
    a.cmplw(6, 5)
    a.bgt("perm_bad")
    a.li(3, 0)
    a.blr()
    a.label("perm_bad")
    a.li(3, 1)
    a.blr()


def _base(a):
    """r3 = wire offset -> r3 = the CPU address the offset lives at.
    MPC window offsets ARE CPU addresses (the array is mapped at 0x0)."""
    a.label("base")
    a.andis_(5, 3, 0x8000)
    a.beq("base_ext")
    a.rlwinm(3, 3, 0, 1, 31)
    a.blr()
    a.label("base_ext")
    a.li32(5, EXT)
    a.add(3, 5, 3)
    a.blr()


def _erase_at(a):
    """r3 = CPU address anywhere in the sector; the 6-cycle AMD erase + poll."""
    a.label("erase_at")
    a.mr(24, 3)
    a.li32(3, EXT)
    a.li(14, 0xAA)
    a.li(15, 0x55)
    a.li(22, 0x80)
    a.li(23, 0x30)
    a.sth(14, 0xAAA, 3)
    a.sth(15, 0x554, 3)
    a.sth(22, 0xAAA, 3)                     # erase setup
    a.sth(14, 0xAAA, 3)
    a.sth(15, 0x554, 3)
    a.sthx(23, 24)                          # 0x30 at the sector
    a.li(10, -1)
    a.li32(4, 0x0000FFFF)                   # lhzx zero-extends, and li would
                                            # sign-extend 0xFFFF right back to -1
    a.label("era_poll")
    a.lhzx(8, 24)
    a.cmplw(8, 4)
    a.beq("era_done")
    _swsr(a)
    a.addic_(10, -1)
    a.bne("era_poll")
    a.label("era_done")
    a.blr()


def _program_range(a):
    """r3 = src (SRAM), r4 = dst (CPU), r5 = halfword count."""
    a.label("program_range")
    a.mr(24, 3)
    a.mr(25, 4)
    a.mr(26, 5)
    a.li32(3, EXT)
    a.li(14, 0xAA)
    a.li(15, 0x55)
    a.li(16, 0xA0)
    a.label("prg_loop")
    a.lhzx(4, 24)                           # data halfword
    a.mr(6, 25)                             # destination
    # the proven cycle + poll + SWSR, bounded: the Am29BL802C programs a
    # word in ~7 us (hundreds of us at worst); 20,000 passes is >5 ms, so a
    # halfword still wrong after that is a chip that will not take it, and
    # the read-back compare after this loop answers NAK 4 instead of the
    # open-ended wait that hung the body for minutes
    program_halfword(a, "prg", polls=20000, fail="prg_fail")
    a.addi(24, 24, 2)
    a.addi(25, 25, 2)
    a.addic_(26, -1)
    a.bne("prg_loop")
    a.label("prg_fail")                     # one halfword would not take: stop here;
    a.blr()                                 # the read-back compare reports NAK 4


def _epee_on(a):
    """Raise the CMF's EPEE pin: bit 0x40 of MPIOSMDR and MPIOSMDDR."""
    a.label("epee_on")
    a.li32(3, MPIOSMDR)
    a.lhz(4, 0, 3)
    a.ori_rd(4, 4, EPEE_PIN)
    a.sth(4, 0, 3)
    a.addi(3, 3, 2)
    a.lhz(4, 0, 3)
    a.ori_rd(4, 4, EPEE_PIN)
    a.sth(4, 0, 3)
    a.blr()


def _drv_call(a, entry):
    """Call the driver at DRV_CODE + entry (r3.. are its arguments, r7 is
    scratch). The driver's compiled routines save their LR in the CALLER's
    frame, at r1+4 (EABI) -- which in the body's push_lr scheme is the
    enclosing routine's pushed LR, so a 16-byte gap is opened for it.
    (v7 got away without one: its callers sat one level up, where r1+4
    was the unused word above the stack top.)"""
    a.addi(1, 1, -16)
    a.li32(7, DRV_CODE + entry)
    a.mtctr(7)
    a.bctrl()
    a.addi(1, 1, 16)


def _copyw(a):
    """r3 = src, r4 = dst, r5 = word count (> 0); leaf, clobbers r3-r6."""
    a.label("copyw")
    a.lwz(6, 0, 3)
    a.stw(6, 0, 4)
    a.addi(3, 3, 4)
    a.addi(4, 4, 4)
    a.addic_(5, -1)
    a.bne("copyw")
    a.blr()


def _cmf_setup(a):
    """Stage the loader's CMF driver for one job: find it in the boot
    block by its data signature, copy the code to DRV_CODE, rebuild its
    r13 data block (zero, then the masks and the data image), raise EPEE,
    point r13 at the block. r3 = 0, or 7 (the NAK reason) when the boot
    block holds no driver -- nothing is written then. Keeps r24-r27."""
    a.label("cmf_setup")
    a.push_lr()
    a.li32(3, EXT + DRV_SCAN_LO)
    a.li32(4, EXT + DRV_SCAN_HI)
    a.li32(5, DRV_SIG[0])
    a.li32(6, DRV_SIG[1])
    a.li32(7, DRV_SIG[2])
    a.label("cs_scan")
    a.cmplw(3, 4)
    a.beq("cs_missing")
    a.lwz(8, 0, 3)
    a.cmplw(8, 5)
    a.bne("cs_next")
    a.lwz(8, 4, 3)
    a.cmplw(8, 6)
    a.bne("cs_next")
    a.lwz(8, 8, 3)
    a.cmplw(8, 7)
    a.beq("cs_found")
    a.label("cs_next")
    a.addi(3, 3, 4)
    a.b("cs_scan")
    a.label("cs_missing")
    a.li(3, 7)
    a.ret()
    a.label("cs_found")
    a.addi(9, 3, -4)                       # S, as a CPU address (the zero word first)
    a.addi(3, 9, DRV_IMAGE_LEN)            # the code
    a.li32(4, DRV_CODE)
    a.li32(5, DRV_CODE_LEN // 4)
    a.bl("copyw")
    a.li32(4, DRV_SDA)                     # the data block: zero it all
    a.li32(5, DRV_SDA_LEN // 4)
    a.li(6, 0)
    a.label("cs_zero")
    a.stw(6, 0, 4)
    a.addi(4, 4, 4)
    a.addic_(5, -1)
    a.bne("cs_zero")
    a.addi(3, 9, -8)                       # the block masks
    a.li32(4, DRV_R13 - 0x77F8)
    a.li(5, 2)
    a.bl("copyw")
    a.mr(3, 9)                             # bases and timing table
    a.li32(4, DRV_R13 - 0x77E8)
    a.li(5, DRV_IMAGE_LEN // 4)
    a.bl("copyw")
    a.bl("epee_on")
    a.li32(13, DRV_R13)
    a.li(3, 0)
    a.ret()


def _blocks_mask(a):
    """r3 = wire block mask (bit n = block n, 14 bits) -> r3 = the driver's
    (bit 31 - n = block n). Leaf, clobbers r3-r7."""
    a.label("blocks_mask")
    a.li(4, 0)
    a.li32(5, 0x80000000)
    a.li(6, 14)
    a.label("bm_loop")
    a.andi_(7, 3, 1)
    a.beq("bm_next")
    a.add(4, 4, 5)                          # disjoint bits
    a.label("bm_next")
    a.rlwinm(3, 3, 31, 1, 31)               # >> 1
    a.rlwinm(5, 5, 31, 1, 31)
    a.addic_(6, -1)
    a.bne("bm_loop")
    a.mr(3, 4)
    a.blr()


def _cmf_erase(a):
    """r3 = MPC address: erase the one 32 KB block holding it with the
    loader's erase_job. r3 = 0 done, 7 driver missing or refused."""
    a.label("cmf_erase")
    a.push_lr()
    a.rlwinm(3, 3, 17, 17, 31)             # >> 15: the block index, 0-13
    a.li32(4, 0x80000000)                  # block n's mask bit is 31 - n
    a.label("ce_shift")
    a.cmplwi(3, 0)
    a.beq("ce_go")
    a.rlwinm(4, 4, 31, 1, 31)              # >> 1
    a.addic_(3, -1)
    a.b("ce_shift")
    a.label("ce_go")
    a.mr(3, 4)
    a.bl("cmf_erase_mask")
    a.ret()


def _cmf_erase_mask(a):
    """r3 = the driver's block mask: erase all those blocks in one job (the
    CMF erases every selected block with the same pulses, so fourteen cost
    what one does). r3 = 0 done, 7 driver missing or refused."""
    a.label("cmf_erase_mask")
    a.push_lr()
    a.mr(24, 3)
    a.bl("cmf_setup")
    a.cmplwi(3, 0)
    a.bne("cem_out")
    a.mr(3, 24)
    _drv_call(a, DRV_ERASE)
    a.cmplwi(3, 0)
    a.beq("cem_out")
    a.li(3, 7)
    a.label("cem_out")
    a.ret()


def _cmf_chunkset(a):
    """r3 = the driver's block mask, r4 = offset within the block, r5 =
    pagesets, r6 = source (SRAM: each pageset is the 64-byte page of every
    selected block, ascending). Drives the driver proper: init, then per
    pageset start / step until done / read every page back, then finish --
    what program_job does for one block, over up to fourteen at once.
    r3 = 0 done, 4 a page would not take (or the driver refused), 7
    driver missing."""
    a.label("cmf_chunkset")
    a.push_lr()
    a.mr(24, 3)
    a.mr(25, 4)
    a.mr(26, 5)
    a.mr(27, 6)
    a.bl("cmf_setup")
    a.cmplwi(3, 0)
    a.bne("cs_out")
    a.li(3, 0)                              # init(program)
    _drv_call(a, DRV_INIT)
    _swsr(a)
    a.cmplwi(3, 0)
    a.bne("cs_fail")
    a.label("cs_pageset")
    a.mr(3, 24)
    a.mr(4, 27)
    a.mr(5, 25)
    a.li(6, 0)
    _drv_call(a, DRV_START)
    _swsr(a)
    a.cmplwi(3, 0)
    a.bne("cs_fail")
    a.label("cs_step")
    _drv_call(a, DRV_STEP)
    _swsr(a)
    a.cmplwi(3, 0x10)
    a.beq("cs_step")
    a.cmplwi(3, 0x11)
    a.beq("cs_step")
    a.cmplwi(3, 0)
    a.bne("cs_fail")
    # read every page of the pageset back, blocks ascending (the source
    # cursor r27 walks the pageset as the driver's copy did)
    a.mr(8, 24)
    a.li(9, 0)                              # block n's array base
    a.li32(10, 0x8000)
    a.label("cs_rb")
    a.rlwinm(11, 8, 1, 31, 31)              # the mask's top bit: this block?
    a.cmplwi(11, 0)
    a.beq("cs_rb_next")
    a.add(3, 9, 25)
    a.li(4, 64)
    a.label("cs_cmp")
    a.lbz(5, 0, 3)
    a.lbz(6, 0, 27)
    a.subf(5, 6, 5)                         # zero iff equal
    a.cmplwi(5, 0)
    a.bne("cs_fail")
    a.addi(3, 3, 1)
    a.addi(27, 27, 1)
    a.addic_(4, -1)
    a.bne("cs_cmp")
    a.label("cs_rb_next")
    a.add(9, 9, 10)
    a.rlwinm(8, 8, 1, 0, 30)                # << 1
    a.cmplwi(8, 0)
    a.bne("cs_rb")
    a.addi(25, 25, 64)
    a.addic_(26, -1)
    a.bne("cs_pageset")
    _drv_call(a, DRV_FINISH)
    _swsr(a)
    a.cmplwi(3, 0)
    a.beq("cs_ok")
    a.li(3, 4)
    a.b("cs_out")
    a.label("cs_fail")                      # close the sequence as the wrapper does
    _drv_call(a, DRV_FINISH)
    _swsr(a)
    a.li(3, 4)
    a.b("cs_out")
    a.label("cs_ok")
    a.li(3, 0)
    a.label("cs_out")
    a.ret()


def _cmf_program(a):
    """r3 = src (SRAM), r4 = dst (MPC address), r5 = byte count: the
    loader's program_job (64-byte pages, bytes outside the span kept from
    the array, every page read back). r3 = 0 done, 1 a page would not
    take, 7 driver missing."""
    a.label("cmf_program")
    a.push_lr()
    a.mr(24, 3)
    a.mr(25, 4)
    a.mr(26, 5)
    a.bl("cmf_setup")
    a.cmplwi(3, 0)
    a.bne("cp_out")
    a.mr(3, 25)
    a.mr(4, 24)
    a.mr(5, 26)
    _drv_call(a, DRV_PROGRAM)
    a.label("cp_out")
    a.ret()


def _hello_payload(a):
    """Stage the 16-byte stamp (read straight out of ext) at REPLY+4."""
    a.li32(31, SRAM_BASE + REPLY_OFF + 4)
    a.li32(3, EXT + STAMP_AT)
    a.li(4, 16)
    a.label("hello_copy")
    a.lbz(5, 0, 3)
    a.stb(5, 0, 31)
    a.addi(3, 3, 1)
    a.addi(31, 31, 1)
    a.addic_(4, -1)
    a.bne("hello_copy")


def _nak_r(a, reason, back):
    a.li(4, reason)
    a.bl("nak")
    a.b(back)


PARK_PC = None                     # filled in by build_body(): where RESET parks


def build_body():
    """Assemble the body. Returns (words, notes) resolved at SRAM_BASE."""
    global PARK_PC
    a = BodyAsm()

    # ---- sram entry: settle, SCI to 115200, HELLO -----------------------
    a.label("sram_entry")
    a.li32(1, STACK_TOP)
    a.li32(17, SWSR)
    a.li(18, 0x556C)
    a.li(19, 0xAA39)
    a.li32(28, SC1SR)
    a.li32(29, SC1DR)
    a.li32(30, SCC1R0)
    a.label("wait_release")                 # RAF until the tester lets go. The hold
    a.lhz(3, 0, 28)                         # can outlast the watchdog period (the
    a.andi_(3, 3, RAF)                      # tester holds the break ~1.5 s, SYPCR
    a.beq("released")                       # runs at 100 ms), so the wait pets
    _swsr(a)
    a.b("wait_release")
    a.label("released")
    a.label("drain_rx")                     # the break's pending byte, if any
    a.lhz(3, 0, 28)
    a.andi_(3, 3, RDRF)
    a.beq("drained")
    a.lhz(3, 0, 29)
    a.b("drain_rx")
    a.label("drained")
    a.li32(3, SETTLE)
    a.label("settle")
    a.addic_(3, -1)
    a.bne("settle")
    a.li(3, SCBR_115200)
    a.sth(3, 0, 30)
    a.li32(3, SCC1R1)
    # 8E1 like the stock program (its SCC1R1 is 0x062C = PE|M|RIE|TE|RE):
    # with M clear the SCI sent 8N1, dropping the ninth (parity) bit, and the
    # tester's 8E1 receiver read every reply garbled on the car
    a.li(4, PE | M | TE | RE)               # polled, no interrupts
    a.sth(4, 0, 3)
    _crc_table(a)
    a.li32(5, BAUD_PROBE)
    a.li(6, 0)
    a.stw(6, 0, 5)
    _hello_payload(a)
    a.li(3, 16)
    a.li(4, S_HELLO | 0x40)
    a.bl("send_reply")

    # ---- the command loop ----------------------------------------------
    a.label("cmd")
    a.bl("rx_telegram")
    # on probation after a SET_BAUD, every turn counts -- a telegram the
    # body can read says nothing about whether the tester hears its answers
    # -- and at zero the body goes back to 115200 on its own; only the
    # tester's confirmation (op_setbaud, the same rate) ends it
    a.mr(24, 3)
    a.li32(5, BAUD_PROBE)
    a.lwz(6, 0, 5)
    a.cmplwi(6, 0)
    a.beq("cmd_probed")
    a.addic_(6, -1)
    a.stw(6, 0, 5)
    a.bne("cmd_probed")
    a.li(3, SCBR_115200)
    a.sth(3, 0, 30)
    a.label("cmd_probed")
    a.cmplwi(24, 0)
    a.beq("cmd")                            # nothing, or garbage already NAKed
    a.li32(3, RXBUF)
    a.lbz(3, 3, 3)                          # the service byte
    a.cmplwi(3, S_HELLO)
    a.beq("op_hello")
    a.cmplwi(3, S_QUERY)
    a.beq("op_query")
    a.cmplwi(3, S_ERASE)
    a.beq("op_erase")
    a.cmplwi(3, S_CHUNK)
    a.beq("op_chunk")
    a.cmplwi(3, S_VERIFY)
    a.beq("op_verify")
    a.cmplwi(3, S_MARKS)
    a.beq("op_marks")
    a.cmplwi(3, S_RESET)
    a.beq("op_reset")
    a.cmplwi(3, S_SETBAUD)
    a.beq("op_setbaud")
    a.cmplwi(3, S_CHUNKSET)
    a.beq("op_chunkset")
    _nak_r(a, 6, "cmd")                     # unknown service

    a.label("op_hello")
    _hello_payload(a)
    a.li(3, 16)
    a.li(4, S_HELLO | 0x40)
    a.bl("send_reply")
    a.b("cmd")

    # ---- SECTOR_QUERY: crc32 of an ext range ---------------------------
    a.label("op_query")
    a.li32(3, RXBUF)
    a.lwz(24, 4, 3)                         # ext offset
    a.lwz(25, 8, 3)                         # length
    a.mr(3, 24)
    a.mr(4, 25)
    a.bl("perm")
    a.cmplwi(3, 0)
    a.bne("q_nak")
    a.mr(3, 24)
    a.bl("base")                            # ext or MPC window, v2
    a.mr(4, 25)
    a.bl("crc32")
    a.li32(5, SRAM_BASE + REPLY_OFF + 4)
    a.stw(3, 0, 5)
    a.li(3, 4)
    a.li(4, S_QUERY | 0x40)
    a.bl("send_reply")
    a.b("cmd")
    a.label("q_nak")
    _nak_r(a, 1, "cmd")

    # ---- ERASE: the sector containing the offset -----------------------
    a.label("op_erase")
    a.li32(3, RXBUF)
    a.lwz(24, 4, 3)
    a.mr(3, 24)
    a.li(4, 1)
    a.bl("perm")
    a.cmplwi(3, 0)
    a.bne("e_nak")
    a.andis_(5, 24, 0x8000)
    a.bne("e_mpc")                          # v2: the MPC window
    a.li32(3, EXT)
    a.add(3, 3, 24)
    a.bl("erase_at")
    a.li(3, 0)
    a.li(4, S_ERASE | 0x40)
    a.bl("send_reply")
    a.b("cmd")
    a.label("e_mpc")
    a.li32(3, RXBUF)
    a.lbz(5, 0, 3)                          # the span: 8 plain, 10 with a block mask
    a.cmplwi(5, 10)
    a.beq("e_mask")
    a.mr(3, 24)
    a.bl("base")                            # the array address of the block
    a.bl("cmf_erase")
    a.b("e_done")
    a.label("e_mask")
    a.lhz(3, 8, 3)                          # bit n = block n
    a.cmplwi(3, 0)
    a.beq("e_mal")
    a.andi_(5, 3, 0xC000)                   # fourteen blocks
    a.bne("e_mal")
    a.bl("blocks_mask")
    a.bl("cmf_erase_mask")
    a.label("e_done")
    a.cmplwi(3, 0)
    a.bne("e_drv")
    a.li(3, 0)
    a.li(4, S_ERASE | 0x40)
    a.bl("send_reply")
    a.b("cmd")
    a.label("e_nak")
    _nak_r(a, 1, "cmd")
    a.label("e_drv")
    _nak_r(a, 7, "cmd")
    a.label("e_mal")
    _nak_r(a, 6, "cmd")

    # ---- CHUNK: hdr at RXBUF+4, compressed bytes at RXBUF+16 -----------
    a.label("op_chunk")
    a.li32(3, RXBUF)
    a.lwz(24, 4, 3)                         # ext offset
    a.lhz(25, 8, 3)                         # declen
    a.lhz(26, 10, 3)                        # clen
    a.lwz(27, 12, 3)                        # crc of the compressed bytes
    a.rlwinm(3, 25, 0, 31, 31)              # declen must be even
    a.cmplwi(3, 0)
    a.bne("ck_mal")
    a.cmplwi(25, 4096)
    a.bgt("ck_mal")
    a.cmplwi(26, 4616)                        # all-literal worst case plus the
    a.bgt("ck_mal")                           # 8-byte EOF marker that closes it
    a.mr(3, 24)
    a.mr(4, 25)
    a.bl("perm")
    a.cmplwi(3, 0)
    a.bne("ck_perm")
    a.li32(3, RXBUF + 16)
    a.mr(4, 26)
    a.bl("crc32")
    a.cmplw(3, 27)
    a.bne("ck_crc")
    a.li32(3, RXBUF + 16)                   # decode (clobbers r3-r12, r14)
    a.li32(4, DSTBUF)
    a.mr(5, 25)
    a.bl("dec")
    a.cmplwi(3, 0)
    a.beq("ck_dec")
    a.andis_(5, 24, 0x8000)
    a.bne("ck_mpc")                         # v2: the MPC window
    a.li32(3, DSTBUF)                       # program from SRAM
    a.li32(4, EXT)
    a.add(4, 4, 24)
    a.rlwinm(5, 25, 31, 16, 31)             # halfwords = declen >> 1 (rotl 31
                                            # is the divide; 1 was the multiply
                                            # that overran every chunk 4x)
    a.bl("program_range")
    a.li32(3, RXBUF)                        # read back and compare
    a.lwz(24, 4, 3)
    a.lhz(25, 8, 3)
    a.li32(26, DSTBUF)
    a.li32(27, EXT)
    a.add(27, 27, 24)
    a.b("ck_cmp")
    a.label("ck_mpc")
    a.mr(3, 24)                             # the wire offset, bit 31 set
    a.bl("base")                            # -> the array address
    a.mr(4, 3)                              # dst
    a.li32(3, DSTBUF)                       # src: the decoded span in SRAM
    a.mr(5, 25)                             # declen in bytes
    a.bl("cmf_program")
    a.cmplwi(3, 7)
    a.beq("ck_drv")
    a.cmplwi(3, 0)
    a.bne("ck_ver")                         # a page would not take: readback
    a.li32(3, RXBUF)                        # read back and compare
    a.lwz(24, 4, 3)
    a.lhz(25, 8, 3)
    a.li32(26, DSTBUF)
    a.mr(3, 24)
    a.bl("base")
    a.mr(27, 3)
    a.label("ck_cmp")
    a.cmplwi(25, 0)
    a.beq("ck_ack")
    a.lbz(3, 0, 26)
    a.lbz(4, 0, 27)
    a.subf(3, 4, 3)                         # zero iff equal
    a.cmplwi(3, 0)
    a.bne("ck_ver")
    a.addi(26, 26, 1)
    a.addi(27, 27, 1)
    a.addic_(25, -1)
    a.bne("ck_cmp")
    a.label("ck_ack")
    a.li(3, 0)
    a.li(4, S_CHUNK | 0x40)
    a.bl("send_reply")
    a.b("cmd")
    a.label("ck_perm")
    _nak_r(a, 1, "cmd")
    a.label("ck_crc")
    _nak_r(a, 2, "cmd")
    a.label("ck_dec")
    _nak_r(a, 3, "cmd")
    a.label("ck_ver")
    _nak_r(a, 4, "cmd")
    a.label("ck_mal")
    _nak_r(a, 6, "cmd")
    a.label("ck_drv")
    _nak_r(a, 7, "cmd")

    # ---- SET_BAUD: ACK at the old rate, then switch, on probation --------
    a.label("op_setbaud")
    a.li32(3, RXBUF)
    a.lhz(24, 4, 3)                         # SCBR: 40 MHz / (32 x SCBR)
    a.cmplwi(24, 0)
    a.beq("sb_mal")
    a.cmplwi(24, 0x1FFF)
    a.bgt("sb_mal")
    a.lhz(25, 0, 30)                        # the rate the SCI is on now
    a.andi_(25, 25, 0x1FFF)
    a.li(3, 0)
    a.li(4, S_SETBAUD | 0x40)
    a.bl("send_reply")                      # its last echo read: the line is quiet
    a.li32(5, BAUD_PROBE)
    a.cmplw(24, 25)
    a.beq("sb_confirm")
    a.sth(24, 0, 30)                        # a new rate: switch, on probation
    a.li(6, BAUD_PROBATION)
    a.stw(6, 0, 5)
    a.b("cmd")
    a.label("sb_confirm")                   # the rate it is on: the tester heard us
    a.li(6, 0)
    a.stw(6, 0, 5)
    a.b("cmd")
    a.label("sb_mal")
    _nak_r(a, 6, "cmd")

    # ---- CHUNK_SET: pagesets over several MPC blocks at once -----------
    # hdr at RXBUF+4: mask u16, offset u16, declen u16, clen u16, crc u32,
    # pages u8, 3 pad; packed bytes at RXBUF+20
    a.label("op_chunkset")
    a.li32(3, RXBUF)
    a.lhz(24, 4, 3)                         # block mask, bit n = block n
    a.lhz(25, 6, 3)                         # offset within the block
    a.lhz(26, 8, 3)                         # declen
    a.lhz(27, 10, 3)                        # clen
    a.lwz(20, 12, 3)                        # crc of the packed bytes
    a.lbz(21, 16, 3)                        # pagesets
    a.cmplwi(24, 0)
    a.beq("cs_mal")
    a.andi_(5, 24, 0xC000)
    a.bne("cs_mal")
    a.andi_(5, 25, 0x3F)                    # 64-aligned
    a.bne("cs_mal")
    a.cmplwi(21, 0)
    a.beq("cs_mal")
    a.cmplwi(21, 64)
    a.bgt("cs_mal")
    a.rlwinm(5, 21, 6, 0, 25)               # pages x 64
    a.add(5, 5, 25)
    a.li32(6, 0x8000)
    a.cmplw(5, 6)                           # stays inside the block
    a.bgt("cs_mal")
    a.mr(5, 24)                             # blocks = popcount(mask)
    a.li(6, 0)
    a.label("cs_pop")
    a.andi_(7, 5, 1)
    a.beq("cs_pop_next")
    a.addi(6, 6, 1)
    a.label("cs_pop_next")
    a.rlwinm(5, 5, 31, 1, 31)
    a.cmplwi(5, 0)
    a.bne("cs_pop")
    a.rlwinm(7, 6, 6, 0, 25)                # blocks x 64
    a.li(8, 0)                              # x pages
    a.mr(9, 21)
    a.label("cs_mul")
    a.add(8, 8, 7)
    a.addic_(9, -1)
    a.bne("cs_mul")
    a.cmplw(8, 26)                          # declen = pages x blocks x 64
    a.bne("cs_mal")
    a.cmplwi(26, 4096)
    a.bgt("cs_mal")
    a.cmplwi(27, 4616)
    a.bgt("cs_mal")
    a.li32(3, RXBUF + 20)
    a.mr(4, 27)
    a.bl("crc32")
    a.cmplw(3, 20)
    a.bne("cs_crc")
    a.li32(3, RXBUF + 20)                   # decode (clobbers r3-r12, r14)
    a.li32(4, DSTBUF)
    a.mr(5, 26)
    a.bl("dec")
    a.cmplwi(3, 0)
    a.beq("cs_dec")
    a.mr(3, 24)
    a.bl("blocks_mask")
    a.mr(4, 25)
    a.mr(5, 21)
    a.li32(6, DSTBUF)
    a.bl("cmf_chunkset")
    a.cmplwi(3, 7)
    a.beq("cs_drv")
    a.cmplwi(3, 0)
    a.bne("cs_rb")
    a.li(3, 0)
    a.li(4, S_CHUNKSET | 0x40)
    a.bl("send_reply")
    a.b("cmd")
    a.label("cs_mal")
    _nak_r(a, 6, "cmd")
    a.label("cs_crc")
    _nak_r(a, 2, "cmd")
    a.label("cs_dec")
    _nak_r(a, 3, "cmd")
    a.label("cs_drv")
    _nak_r(a, 7, "cmd")
    a.label("cs_rb")
    _nak_r(a, 4, "cmd")

    # ---- VERIFY: crc32 of an ext range against a value ------------------
    a.label("op_verify")
    a.li32(3, RXBUF)
    a.lwz(24, 4, 3)
    a.lwz(25, 8, 3)
    a.lwz(26, 12, 3)
    a.mr(3, 24)
    a.mr(4, 25)
    a.bl("perm")
    a.cmplwi(3, 0)
    a.bne("v_nak")
    a.mr(3, 24)
    a.bl("base")                            # ext or MPC window, v2
    a.mr(4, 25)
    a.bl("crc32")
    a.cmplw(3, 26)
    a.bne("v_bad")
    a.li(3, 0)
    a.li(4, S_VERIFY | 0x40)
    a.bl("send_reply")
    a.b("cmd")
    a.label("v_bad")
    _nak_r(a, 5, "cmd")
    a.label("v_nak")
    _nak_r(a, 1, "cmd")

    # ---- MARKS: burn the valid marks (the commit point) -----------------
    a.label("op_marks")
    a.li32(3, RXBUF)
    a.lbz(24, 4, 3)                         # which set
    a.li32(3, EXT)                          # flash-constant registers
    a.li(14, 0xAA)
    a.li(15, 0x55)
    a.li(16, 0xA0)
    a.cmplwi(24, 1)
    a.beq("mk_prog")
    for i, (at, hi, lo) in enumerate(CAL_MARKS):
        a.li32(6, EXT + at)
        a.li32(4, hi)                       # li sign-extends: 0x9042 would
        program_halfword(a, f"mkc{i}a")     # arrive as 0xFFFF9042 and the
        a.li32(6, EXT + at + 2)             # completion poll would never match
        a.li32(4, lo)
        program_halfword(a, f"mkc{i}b")
    a.b("mk_ack")
    a.label("mk_prog")
    for i, (at, hi, lo) in enumerate(PROG_MARKS):
        a.li32(6, EXT + at)
        a.li32(4, hi)
        program_halfword(a, f"mkp{i}a")
        a.li32(6, EXT + at + 2)
        a.li32(4, lo)
        program_halfword(a, f"mkp{i}b")
    a.label("mk_ack")
    a.li(3, 0)
    a.li(4, S_MARKS | 0x40)
    a.bl("send_reply")
    a.b("cmd")

    # ---- RESET: reply, then starve the watchdog -------------------------
    a.label("op_reset")
    a.li(3, 0)
    a.li(4, S_RESET | 0x40)
    a.bl("send_reply")
    a.label("op_park")                      # no SWSR service in the loop
    a.b("op_park")

    # ---- the subroutines -------------------------------------------------
    _rx_byte(a)
    _send_bytes(a)
    _send_reply(a)
    _nak(a)
    _rx_telegram(a)
    _crc32(a)
    _perm(a)
    _base(a)
    _erase_at(a)
    _program_range(a)
    _epee_on(a)
    _copyw(a)
    _cmf_setup(a)
    _blocks_mask(a)
    _cmf_erase(a)
    _cmf_erase_mask(a)
    _cmf_chunkset(a)
    _cmf_program(a)

    # ---- the NRV2B decoder blob -----------------------------------------
    a.label("dec")
    for w in build_decoder():
        a.raw(*w) if isinstance(w, tuple) else a.raw(w, "dec")

    a.resolve(SRAM_BASE)
    PARK_PC = SRAM_BASE + 4 * a.labels["op_park"]     # for kline.py's watchdog stand-in
    global LABEL_ADDRS                                 # label -> SRAM address, for
    LABEL_ADDRS = {k: SRAM_BASE + 4 * v for k, v in a.labels.items()}   # post-mortems
    size = 4 * len(a.words)
    if size > REPLY_OFF:
        raise ValueError(f"body is {size:#x} bytes, over the reply buffer at +{REPLY_OFF:#x}")
    return a.words, size


def build_stub(nwords):
    """The relocate stub at ext 0xFD400: copy the blob to SRAM, jump."""
    a = GateAsm()
    a.li32(3, EXT + BODY_AT)
    a.li32(4, SRAM_BASE)
    a.li32(5, nwords)
    a.label("cp")
    a.lwz(6, 0, 3)
    a.stw(6, 0, 4)
    a.addi(3, 3, 4)
    a.addi(4, 4, 4)
    a.addic_(5, -1)
    a.bne("cp")
    a.ba(SRAM_BASE)
    a.resolve(0)
    return a.words


def build_parts():
    """(stub words, body words, body size) -- everything that goes in ext."""
    body_words, size = build_body()
    stub = build_stub(len(body_words))
    return stub, body_words, size


def pack(words):
    return struct.pack(">%dI" % len(words), *(w for w, _ in words))


if __name__ == "__main__":
    stub, body, size = build_parts()
    print(f"stub: {len(stub)} words at ext {ENTRY_AT:#x}")
    print(f"body: {len(body)} words ({size:#x} bytes) at ext {BODY_AT:#x} "
          f"(spans to {BODY_AT + size:#x}, budget {0xFFF40:#x})")
    print(f"reply buffer at SRAM {SRAM_BASE + REPLY_OFF:#x}; rx {RXBUF:#x}; dst {DSTBUF:#x}")
    print(f"CRC table at {CRC_TABLE:#x}; baud probation word at {BAUD_PROBE:#x}")
    print(f"CMF driver: code at {DRV_CODE:#x}-{DRV_CODE + DRV_CODE_LEN:#x}, "
          f"data {DRV_SDA:#x}-{DRV_SDA + DRV_SDA_LEN:#x} (r13 = {DRV_R13:#x})")
