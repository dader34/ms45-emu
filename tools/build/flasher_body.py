"""The flasher body: the wire protocol that runs once the gate branches
(docs/fast-flasher.md). Assembled for SRAM -- it only ever runs relocated --
placed in ext at 0xFD500 by flasher_gate.build(), and copied to SRAM by the
relocate stub at 0xFD400 before the first flash op.

Memory plan (the machine is ours from the gate; the loader's and the
program's SRAM state is dead):
    0x3F9800  this code, then the NRV2B decoder (v13 outgrew the old reply
              slot right above the code: the reply buffer moved to the top
              of RXBUF's tail, where no telegram reaches)
    0x3FD400  reply buffer -- REPLY_OFF (+0x3C00 from the code base; 112
              bytes), above RXBUF's longest telegram (a CHUNK is ~4.6 KB)
    0x3FB170  DRV_SDA  -- the CMF driver's r13 data block (0x87C bytes,
              rebuilt before every MPC job; r13 = DRV_R13 while it runs)
    0x3FB9F0  DRV_ENTRIES -- the driver's entries, resolved per job
    0x3FBA70  CRC_TABLE -- CRC-32/MPEG-2's 256 words, built at entry
    0x3FC160  stack top -- non-leaf routines (send_reply, send_bytes, nak,
              rx_telegram) push LR here; the calls nest at most 3 deep,
              a dozen bytes; the CMF driver's frames add a few hundred
              (0x2F0 is the room above CRC_TABLE)
    0x3FC170  RXBUF    -- telegrams land here (a CHUNK is ~4.6 KB)
    0x3FD800  DSTBUF   -- the decoded 4 KB of a chunk
    0x3FE800  DRV_CODE -- the window of the loader's CMF driver the body
              calls into, copied from the boot block before every MPC
              job (0x1800 bytes, to the end of SRAM)

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
    erase job (v8); CHUNK CMF-programs whole, page-aligned 64-byte pages
    (anything else is NAK 4 -- v19 dropped the partial-page staging);
    QUERY/VERIFY read the array directly.
    V8: CHUNK_SET programs PAGESETS -- the CMF programs one page in each
    selected block with the same pulses (the driver is NXP's
    ParallelProgram), so a pageset of up to 14 pages costs what one page
    did. Header: u16 mask (bit n = block n), u16 offset within the
    block (64-aligned), u16 declen, u16 clen, u32 crc, u8 pages, 3 pad;
    the decoded data is `pages` pagesets, each the 64-byte page of every
    selected block in ascending block order; declen = pages x blocks x
    64 <= 4096. SET_BAUD (u16 SCBR) answers at the old rate, then
    switches and holds the new rate: no probation since v14 (v8-v13 fell
    back to 115200 unless the tester confirmed the rate). A rate the tester
    cannot follow is recovered by a reset, which always boots at 115200;
    the app steps down a marginal rate itself. The CMF writes are the boot
    loader's own driver (docs/fast-flasher.md, "The MPC (CMF) writes on
    silicon"): a hand-written sequence reset the car, so the body copies
    the loader's position-independent driver out of the protected boot
    block, gives it an r13 data block, raises the EPEE pin (MPIOSMDR/
    MPIOSMDDR bit 0x40 -- the driver checks it and never touches it) and
    drives the driver proper (init / start / step / finish) the way its
    erase_job / program_job wrappers do; the driver services the watchdog
    itself. Nothing about it is fixed per build: the block is found by its
    data signature (builds A and B carry it at different offsets, same
    bytes), and since v19 the entries are read from the wrappers' calls at
    run time (build C's driver is a different, longer build).
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
from tools.experiments.aif_wipe import program_halfword
from tools.build.flasher_gate import GateAsm, STAMP_AT
from tools.build.nrv2b_dec import build_decoder

SRAM_BASE = 0x3F9800
RXBUF, DSTBUF = 0x3FC170, 0x3FD800        # v19: RXBUF and everything below it sit
STACK_TOP = 0x3FC160                      # 0x170 higher than v18 (room for the body);
CRC_TABLE = 0x3FBA70                      # RXBUF + MAX_SPAN + head (0x127C) ends at
                                          # 0x3FD3EC, still under the reply buffer
# SET_BAUD's probation countdown retired with v14: a switch the tester
# could not follow is recovered by a reset, which always boots at 115200.
ENTRY_AT, BODY_AT = 0xFD400, 0xFD500      # ext offsets; stub at ENTRY copies from BODY_AT
# Where _hello_payload reads the 16-byte HELLO stamp from. The gate layout
# keeps it at flasher_gate's STAMP_AT (next to the gate, in the program
# area); BL's ring points it at the ring's own stamp in the boot sector
# (tools/bl.py sets it for its body build), so the announcement is the
# loader's identity and survives any program reflash.
STAMP_SRC = STAMP_AT
EXT = 0xFFF00000

# The bench-era name for what every body since v12 carries (on the car
# too: BL's ring body is built with it): the boot-sector write window
# (PERM_LOW..0x20000, ERASE/CHUNK only while an AIF marker slot is armed),
# the AIF marker service, READ with the EEPROM window, and the EE_WRITE
# dispatch. False builds the old v9 body without any of them, which
# nothing ships any more.
ALLOW_BOOT_SECTOR = True

# The lower edge of that opened window. The shipped body keeps the stock
# 0x8000 (the 96 KB boot sector); the BL installer variant lowers it to
# 0x4000 (tools/bl_test.py) so the one patched handoff word at ext 0x4EBC,
# which lives in the 8 KB sector below, can be erased and rewritten too.
# Everything below PERM_LOW stays refused, as before.
PERM_LOW = 0x8000

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
#   S+0x7C  code, 0x1778 bytes (A, B) / 0x1878 (C); the window from
#           +DRV_FLOOR, DRV_WINDOW bytes -> DRV_CODE
# The wrappers sit at fixed offsets from the code start on every build:
# erase_job(r3 = block mask) and program_job(r3 = array address, r4 =
# source, r5 = length < 0x10000), both 0 for success. The body never runs
# them; drv_fwd reads the driver's entries out of their calls (below).
# The driver reads r13-0x7FE8 .. r13-0x776C
# and nothing else of ours; the body zeroes that span before each job.
DRV_SIG = (0x002FC800, 0x002FC840, 0x284F0000)
DRV_SCAN_LO, DRV_SCAN_HI = 0x14000, 0x16000  # ext offsets the signature scan covers
DRV_IMAGE_LEN = 0x7C
# v19: the driver is not one build. Three loader builds are known (tools/build/
# bootwrite.py): A and B carry the same driver (0x1778 bytes, step +0x1048,
# finish +0x1638), the early build C a longer one (0x1878 bytes, step
# +0x1088, finish +0x1738). The body copies the WINDOW the routines it
# calls live in -- code+DRV_FLOOR on, DRV_WINDOW bytes, which is every byte
# of SRAM left above DSTBUF -- and resolves the entries at run time from the
# wrappers' own forward calls (drv_fwd): nothing the body reaches lies below
# +0x4B4 on either build, and the wrappers themselves (erase_job +0x148,
# program_job +0x21C, both calling the watchdog stub at +0) stay in the
# boot block, read but never run.
DRV_FLOOR, DRV_WINDOW = 0x400, 0x1800
DRV_CODE_LEN = DRV_WINDOW
DRV_CODE = 0x3FE800                          # SRAM, above DSTBUF, to the end of SRAM
DRV_SDA, DRV_SDA_LEN = 0x3FB170, 0x87C       # r13-0x7FE8 .. r13-0x776C
DRV_R13 = DRV_SDA + 0x7FE8
DRV_ERASE, DRV_PROGRAM = 0x148, 0x21C        # erase_job, program_job (the wrappers)
# the resolved entries, SRAM addresses, filled by cmf_setup: program_job's
# forward calls (init, finish, start, finish, step), then erase_job's (init,
# finish, start-with-mask, finish, step)
DRV_ENTRIES = 0x3FB9F0
DRV_ENTRY = {"init": 0, "finish": 1, "start": 2, "step": 4, "startmask": 7}
# the driver proper (NXP's ParallelProgram state machine): init(r3 = mode,
# 1 erase / 0 program), start(r3 = block mask, r4 = source, r5 = offset
# within the block, r6 = shadow flag), step (0x10/0x11 = busy), finish.
# The mask's bit 31 - n is block n; start latches the source's 64-byte
# pages into every selected block (ascending) at the same offset, and one
# pulse sequence programs them all.
DRV_INIT, DRV_START, DRV_STEP, DRV_FINISH = 0xC60, 0xDF0, 0x1048, 0x1638   # builds A/B, for the record

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
# v20: every wait on the hardware is bounded, and a bound that runs out is a
# NAK, never a hang. Counted, not timed: the emulator serves `mftb` only at
# the trap sites it finds in the flash image, so a time base read in the
# body's SRAM copy is 0 there and a timed bound could never be proven. The
# body runs from internal SRAM, so a pass costs about what it costs here;
# the counts are hang-breakers, generous against the parts' worst cases.
ERASE_POLLS = 1 << 28                      # erase_at: >= ~30 s of status reads
                                           # (the Am29BL802C's worst sector, 15 s)
CMF_STEPS = 1 << 28                        # driver `step` calls while it says busy
MARK_POLLS = 20000                         # a mark halfword, as program_range's
AMD_RESET = 0xF0                           # back to read-array after a failed
                                           # op (DQ5 set leaves the chip in status)
MAX_SPAN = 4700                            # chunk worst case + headroom; a longer span
                                           # is garbage (a stray 0x00 swallows the next
                                           # two bytes as a u16) -- NAK and resync now

# wire services
(S_HELLO, S_QUERY, S_ERASE, S_CHUNK, S_VERIFY, S_MARKS, S_RESET, S_SETBAUD,
 S_CHUNKSET, S_AIF, S_READ, S_EEWRITE) = range(12)
READ_MAX = 4096                             # v13 READ: bytes per request

# v14 READ extension: offset bit 30 addresses the serial EEPROM (the
# 25-series part on QSPI PCS1, 4 KB, where the per-car stored-data blocks
# live -- the only identity store neither flash image carries; docs/
# protections.md "Next" 3 has wanted a read of it). ee_fill stages a page
# at DSTBUF and op_read streams it like any array; 03 addr16 READs only,
# never a write to the part.
EE_WINDOW = 0x40000000
EE_SIZE = 0x1000                            # v18: the part is 4 KB -- the car's
                                            # 64 KB read (2026-10-28) was one 4 KB
                                            # sixteen times, its address wrapping;
                                            # a write past 0xFFF would land on real
                                            # data, so both services bound it here
QSPCR1, QSPCR2, QSPCR3, QSPSR = 0x30501A, 0x30501C, 0x30501E, 0x30501F
QRX_RAM, QTX_RAM, QCMD_RAM = 0x305140, 0x305180, 0x3051C0
QSPI_SPE, QSPI_SPIF = 0x8000, 0x80
SPCR1_GO = QSPI_SPE | 0x0101                # SPE, DSCKL 1, DTL 1: each run stores
                                            # SPCR1 whole, as stock does (0x8101)
EE_CONT = 0x8D                              # CONT | PCS1: the EEPROM's select
EE_BARE = EE_CONT & 0x7F                    # a one-entry group: its own CS cycle
EE_WMAX = 25                                # v15 EE_WRITE: bytes per request -- one
                                            # queue (WREN + WRITE + WRDI = len+5
                                            # entries, 30 at the cap)
EE_MODULE_AT = 0xFF000                      # and its code lives HERE, in ext past
                                            # the body: SRAM is full to its DRV_SDA
                                            # ceiling, but the writer never runs a
                                            # flash op, so it executes from flash
                                            # like the stub does, reached by counter
                                            # jump (SRAM to 0xFFF00000 is past bl)
QSMCM = 0x305000

# AIF-wipe resume marker (only built when ALLOW_BOOT_SECTOR). It records the
# boot-sector wipe's phase in the loader's blank tail at ext 0x387EC, which
# survives the boot-sector erase (a different sector) and whose bit-clearing
# transitions program without an erase: 0xFFFF -> 0xA55A (armed) -> 0xA558
# (done). Arm-before-erase is enforced in op_erase, so an interrupted session
# always leaves a marker the host can read on reconnect and converge from.
# Same address and values as aif_wipe.py's reset-payload marker.
MARK_AT = 0x387EC
MARK_ARMED, MARK_DONE = 0xA55A, 0xA558
# v11: a row of marker slots from MARK_AT (the tail is blank to 0x40000). A
# slot reading MARK_DONE is spent; the current slot is the first that is not,
# so every wipe gets a fresh one (v10 had the one halfword: after its first
# wipe it read DONE for good and refused every boot-sector erase after).
MARK_SLOTS = 64
# AIF service subcommands (payload byte at RXBUF+4).
AIF_READ, AIF_ARM, AIF_DONE = 0, 1, 2
BOOT_SECTOR, BOOT_SECTOR_END = 0x8000, 0x20000
# marks (board.VALID_MARKS): ext offset, value, as big-endian halfword pairs
CAL_MARKS = ((0x5FF80, 0x4824, 0x9042), (0x5FFC0, 0x9048, 0x2442))
PROG_MARKS = ((0xFFF80, 0x4290, 0x2448), (0xFFFC0, 0x4224, 0x4890))
REPLY_OFF = 0x3C00                         # the reply buffer, at RXBUF+0x1400:
                                            # above the longest telegram (MAX_SPAN
                                            # 4700 + head, 0x127C) and below DSTBUF.
                                            # Replies are short (HELLO's 21 bytes,
                                            # the READ header 11), so 112 bytes are
                                            # plenty. (v2-v12 the replies lived just
                                            # above the code, and the reply slot
                                            # doubled as the code-size bound; v14's
                                            # EEPROM read outgrew it, and the code
                                            # ceiling is DRV_SDA now -- build_parts
                                            # asserts it. The v14 first cut sized
                                            # the body against THIS offset instead,
                                            # ran 0x38 bytes into DRV_SDA, and the
                                            # driver copy ate the body's tail.)


class BodyAsm(GateAsm):
    def __init__(self):
        super().__init__()
        self.aliases = {}

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

    def bctr(self):
        self.raw(0x4E800420, "bctr")

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

    def alias(self, name, target):
        """`name` resolves to wherever `target` is: a handler's failure label
        pointed straight at the shared NAK tail, no instruction of its own."""
        if name in self.labels or name in self.aliases:
            raise ValueError(f"label {name!r} defined twice")
        self.aliases[name] = target

    def label(self, name):
        if name in self.aliases:
            raise ValueError(f"label {name!r} defined twice")
        super().label(name)

    def resolve(self, base):
        # `b`/`bl` carry the offset in LI (bits 2-25); the bc forms in BD
        ops = {"beq": 0x41820000, "bne": 0x40820000,
               "blt": 0x41800000, "bgt": 0x41810000}
        for name, target in self.aliases.items():
            self.labels[name] = self.labels[target]
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
    if ALLOW_BOOT_SECTOR:
        # The boot-sector window, PERM_LOW..0x20000 (0x8000 in the ring,
        # 0x4000 in the installer, 0x0 in the swap ring). perm admits it;
        # op_erase and op_chunk then refuse it unless the current AIF
        # marker slot is armed (op_aif), so only a deliberate boot write
        # gets in. A cut while the loader's own sector is erased bricks
        # until a bench recovery (tools/experiments/aif_wipe_flasher.py).
        a.li32(5, PERM_LOW)
        a.cmplw(3, 5)
        a.blt("perm_std")                  # below the window: normal rules
        a.li32(5, 0x20000)
        a.add(6, 3, 4)
        a.cmplw(6, 5)
        a.bgt("perm_std")                  # spills past it: normal rules
        a.li(3, 0)                         # fully inside the boot sector: allow
        a.blr()
    a.label("perm_std")
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
    """r3 = CPU address anywhere in the sector; the 6-cycle AMD erase + poll.
    r3 = 0 erased, 1 the address never read 0xFFFF within ERASE_POLLS (the
    chip is put back to read-array then)."""
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
    a.li32(10, ERASE_POLLS)
    a.li32(4, 0x0000FFFF)                   # lhzx zero-extends, and li would
                                            # sign-extend 0xFFFF right back to -1
    a.label("era_poll")
    a.lhzx(8, 24)
    a.cmplw(8, 4)
    a.beq("era_done")
    _swsr(a)
    a.addic_(10, -1)
    a.bne("era_poll")
    a.li(5, AMD_RESET)                      # never finished: read-array, then say so
    a.sth(5, 0, 3)                          # (v7-v19 polled ~minutes and ACKed anyway)
    a.li(3, 1)
    a.blr()
    a.label("era_done")
    a.li(3, 0)
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
    a.li(5, AMD_RESET)                      # the read-back compare reports NAK 4. Read-
    a.sth(5, 0, 3)                          # array either way (a no-op after success)
    a.blr()


def _mark_half(a):
    """r6 = CPU address, r4 = the mark halfword (li32: 0x9042 must not sign-
    extend): program it, bounded, and read it back. r3 = 0 it took, 1 it did
    not (read-array put back). Needs r14-r16 = AA/55/A0; leaf, clobbers r3,
    r5, r8, r10."""
    a.label("mark_half")
    a.li32(3, EXT)
    program_halfword(a, "mh", polls=MARK_POLLS, fail="mh_bad")
    a.li(3, 0)
    a.blr()
    a.label("mh_bad")
    a.li(5, AMD_RESET)
    a.sth(5, 0, 3)
    a.li(3, 1)
    a.blr()


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


def _drv_call(a, which):
    """Call the driver routine `which` (init, start, startmask, step, finish)
    through its resolved entry (r3.. are its arguments, r7 is scratch). The
    driver's compiled routines save their LR in the CALLER's frame, at r1+4
    (EABI) -- which in the body's push_lr scheme is the enclosing routine's
    pushed LR, so a 16-byte gap is opened for it. (v7 got away without one:
    its callers sat one level up, where r1+4 was the unused word above the
    stack top.)"""
    a.li32(7, DRV_ENTRIES + 4 * DRV_ENTRY[which])
    a.bl("drv_go")


def _drv_go(a):
    """The one call sequence every driver call shares (r7 = the entry's
    slot): the 16-byte gap for the driver's LR save, the body's own return
    address kept above it, the result masked to a byte as the wrappers do.
    r8 is clobbered; no caller keeps r8-r12 across a driver call."""
    a.label("drv_go")
    a.mflr(8)
    a.addi(1, 1, -16)
    a.stw(8, 12, 1)
    a.lwz(7, 0, 7)
    a.mtctr(7)
    a.bctrl()
    a.lwz(8, 12, 1)
    a.mtlr(8)
    a.addi(1, 1, 16)
    a.rlwinm(3, 3, 0, 24, 31)                # the result byte, as the wrappers take it
    a.blr()


def _drv_fwd(a):
    """r3 = a wrapper (ext address), r4 = where to store, r5 = the window's
    source (ext): the targets of the wrapper's first five FORWARD `bl`s, as
    SRAM addresses in the copied window, after a check that each lies in
    the window and begins with the driver's `stwu r1` prologue. r3 = 0, or
    7 (the NAK reason) for anything else. Leaf, clobbers r3-r8, r11, r12 (r9 and r10 are left alone: cmf_setup keeps S in r9)."""
    a.label("drv_fwd")
    a.li(6, 0)                               # stored so far
    a.li32(7, 0x300 // 4)                    # words to look at
    a.label("df_loop")
    a.lwz(8, 0, 3)
    a.rlwinm(11, 8, 0, 0, 5)                  # the opcode field
    a.li32(12, 0x48000000)                   # b / bl
    a.cmplw(11, 12)
    a.bne("df_next")
    a.andi_(11, 8, 3)                         # AA|LK: bl rel is 1
    a.cmplwi(11, 1)
    a.bne("df_next")
    a.andis_(11, 8, 0x0200)                   # a backward call (the watchdog stub)
    a.bne("df_next")
    a.rlwinm(11, 8, 0, 6, 29)                 # li
    a.add(11, 3, 11)                           # the target, ext
    a.cmplw(11, 5)
    a.blt("df_bad")                          # below the window
    a.li32(12, DRV_WINDOW - 4)
    a.add(12, 5, 12)
    a.cmplw(11, 12)
    a.bgt("df_bad")                          # past it
    a.lhz(12, 0, 11)
    a.cmplwi(12, 0x9421)                     # stwu r1, -n(r1)
    a.bne("df_bad")
    a.subf(11, 5, 11)                          # into the window
    a.li32(12, DRV_CODE)
    a.add(11, 11, 12)
    a.stw(11, 0, 4)
    a.addi(4, 4, 4)
    a.addi(6, 6, 1)
    a.cmplwi(6, 5)
    a.beq("df_ok")
    a.label("df_next")
    a.addi(3, 3, 4)
    a.addic_(7, -1)
    a.bne("df_loop")
    a.label("df_bad")
    a.li(3, 7)
    a.blr()
    a.label("df_ok")
    a.li(3, 0)
    a.blr()


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
    a.addi(3, 9, DRV_IMAGE_LEN + DRV_FLOOR)   # the window of the code
    a.li32(4, DRV_CODE)
    a.li32(5, DRV_WINDOW // 4)
    a.bl("copyw")
    a.addi(5, 9, DRV_IMAGE_LEN + DRV_FLOOR)   # the entries, from the wrappers
    a.addi(3, 9, DRV_IMAGE_LEN + DRV_PROGRAM)
    a.li32(4, DRV_ENTRIES)
    a.bl("drv_fwd")
    a.cmplwi(3, 0)
    a.bne("cs_missing")
    a.addi(5, 9, DRV_IMAGE_LEN + DRV_FLOOR)
    a.addi(3, 9, DRV_IMAGE_LEN + DRV_ERASE)
    a.li32(4, DRV_ENTRIES + 4 * 5)
    a.bl("drv_fwd")
    a.cmplwi(3, 0)
    a.bne("cs_missing")
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
    a.li(3, 1)                              # init(erase)
    _drv_call(a, "init")
    _swsr(a)
    a.cmplwi(3, 0)
    a.bne("cem_fail")
    a.mr(3, 24)                             # start(mask)
    _drv_call(a, "startmask")
    _swsr(a)
    a.cmplwi(3, 0)
    a.bne("cem_fail")
    a.li32(22, CMF_STEPS)                   # busy answers allowed (the driver
    a.b("cem_step")                         # keeps r14-r31)
    a.label("cem_busy")
    a.addic_(22, -1)
    a.beq("cem_fail")                       # still busy: finish, NAK 7 (v20)
    a.label("cem_step")
    _drv_call(a, "step")
    _swsr(a)
    a.cmplwi(3, 0x10)
    a.beq("cem_busy")
    a.cmplwi(3, 0x11)
    a.beq("cem_busy")
    a.cmplwi(3, 0)
    a.bne("cem_fail")
    _drv_call(a, "finish")
    _swsr(a)
    a.cmplwi(3, 0)
    a.beq("cem_out")
    a.li(3, 7)
    a.b("cem_out")
    a.label("cem_fail")                     # close the sequence as the wrapper does
    _drv_call(a, "finish")
    _swsr(a)
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
    _drv_call(a, "init")
    _swsr(a)
    a.cmplwi(3, 0)
    a.bne("cs_fail")
    a.label("cs_pageset")
    a.mr(3, 24)
    a.mr(4, 27)
    a.mr(5, 25)
    a.li(6, 0)
    _drv_call(a, "start")
    _swsr(a)
    a.cmplwi(3, 0)
    a.bne("cs_fail")
    a.li32(22, CMF_STEPS)                   # busy answers allowed for this pageset
    a.b("cs_step")
    a.label("cs_busy")
    a.addic_(22, -1)
    a.beq("cs_fail")                        # still busy: finish, NAK 4 (v20)
    a.label("cs_step")
    _drv_call(a, "step")
    _swsr(a)
    a.cmplwi(3, 0x10)
    a.beq("cs_busy")
    a.cmplwi(3, 0x11)
    a.beq("cs_busy")
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
    _drv_call(a, "finish")
    _swsr(a)
    a.cmplwi(3, 0)
    a.beq("cs_ok")
    a.li(3, 4)
    a.b("cs_out")
    a.label("cs_fail")                      # close the sequence as the wrapper does
    _drv_call(a, "finish")
    _swsr(a)
    a.li(3, 4)
    a.b("cs_out")
    a.label("cs_ok")
    a.li(3, 0)
    a.label("cs_out")
    a.ret()


def _cmf_program(a):
    """r3 = src (SRAM), r4 = dst (MPC address, page-aligned), r5 = byte
    count (whole pages): one block's pages through cmf_chunkset, every page
    read back. r3 = 0 done, 1 not whole aligned pages, 4 a page would not
    take, 7 driver missing."""
    a.label("cmf_program")
    a.push_lr()
    a.andi_(6, 5, 63)                      # whole pages only, page-aligned (an MPC
    a.bne("cp_bad")                        # chunk is 4 KB; the wrapper's partial-page
    a.andi_(6, 4, 63)                      # staging went with v19 -- no SRAM for it)
    a.bne("cp_bad")
    a.mr(6, 3)                             # the source
    a.rlwinm(7, 4, 17, 17, 31)             # dst >> 15: the block
    a.li32(3, 0x80000000)
    a.label("cp_shift")
    a.cmplwi(7, 0)
    a.beq("cp_go")
    a.rlwinm(3, 3, 31, 1, 31)              # >> 1
    a.addi(7, 7, -1)
    a.b("cp_shift")
    a.label("cp_go")
    a.rlwinm(4, 4, 0, 17, 31)              # the offset within the block
    a.rlwinm(5, 5, 26, 6, 31)              # the pages
    a.bl("cmf_chunkset")                   # one block, pages consecutive
    a.ret()
    a.label("cp_bad")
    a.li(3, 1)
    a.ret()


def _hello_payload(a):
    """Stage the 16-byte stamp (read straight out of ext) at REPLY+4."""
    a.li32(31, SRAM_BASE + REPLY_OFF + 4)
    a.li32(3, EXT + STAMP_SRC)
    a.li(4, 16)
    a.label("hello_copy")
    a.lbz(5, 0, 3)
    a.stb(5, 0, 31)
    a.addi(3, 3, 1)
    a.addi(31, 31, 1)
    a.addic_(4, -1)
    a.bne("hello_copy")


def _nak_tails(a):
    """The shared NAK tails: `nakN` answers 7F svc N and goes back to cmd.
    Every handler's failure label is an alias of one (v20; until then each
    handler carried its own li/bl/b triple per reason -- 21 of them -- and
    only reason 1 was shared). Reason 1 falls through into the one call."""
    for reason in (2, 3, 4, 5, 6, 7):
        a.label(f"nak{reason}")
        a.li(4, reason)
        a.b("nak_go")
    a.label("nak1")
    a.li(4, 1)
    a.label("nak_go")
    a.bl("nak")
    a.b("cmd")


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
    a.b("op_hello")                         # the first HELLO is op_hello's

    # ---- the command loop ----------------------------------------------
    a.label("cmd")
    a.bl("rx_telegram")
    a.mr(24, 3)
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
    if ALLOW_BOOT_SECTOR:
        a.cmplwi(3, S_AIF)
        a.beq("op_aif")
        a.cmplwi(3, S_READ)
        a.beq("op_read")
        a.cmplwi(3, S_EEWRITE)
        a.beq("op_eewrite")
    a.b("nak6")                             # unknown service

    # ---- EE_WRITE (v15): the ISN rewrite, served from the boot image -----
    # The SRAM map is full to DRV_SDA, so the writer is a module assembled
    # by build_eewrite() into ext at EE_MODULE_AT and executed in place --
    # nothing of ours runs a flash op while it holds the CPU, so the array
    # stays readable and the stub's own run-from-flash proves the mapping.
    # The dispatch's counter jump is the whole body-side cost; the module
    # replies through this body's send_reply/nak and branches back to cmd,
    # both too far for bl (SRAM to 0xFFF00000 is ~200 MB).
    a.label("op_eewrite")
    a.li32(5, EXT + EE_MODULE_AT)
    a.mtctr(5)
    a.bctr()

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
    a.alias("q_nak", "nak1")
    _nak_tails(a)

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
    if ALLOW_BOOT_SECTOR:
        # A boot-sector erase takes the loader with it, so it is refused
        # unless the AIF-wipe resume marker is armed first (op_aif, AIF_ARM).
        # That couples arm-before-erase: an interrupt after this point always
        # leaves an armed marker the host finds on reconnect and converges.
        a.li32(5, BOOT_SECTOR)
        a.cmplw(24, 5)
        a.blt("e_do")                       # below the boot sector: no gate
        a.li32(5, BOOT_SECTOR_END - 1)
        a.cmplw(24, 5)
        a.bgt("e_do")                       # above it: no gate
        a.bl("aif_cur")                     # in the boot sector: the current
        a.cmplwi(6, 0)                      # marker slot must be armed
        a.beq("e_nak")                      # every slot spent
        a.lhz(6, 0, 6)
        a.li32(7, MARK_ARMED)               # li32: 0xA55A must not sign-extend
        a.cmplw(6, 7)
        a.bne("e_nak")                      # not armed -> perm NAK 1
    a.label("e_do")
    a.li32(3, EXT)
    a.add(3, 3, 24)
    a.bl("erase_at")
    a.cmplwi(3, 0)
    a.bne("e_era")                          # the sector never read erased: NAK 4
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
    a.alias("e_nak", "nak1")
    a.alias("e_era", "nak4")
    a.alias("e_drv", "nak7")
    a.alias("e_mal", "nak6")

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
    if ALLOW_BOOT_SECTOR:
        # v12: a CHUNK into the boot sector only while the current marker
        # slot is armed -- the window is shut to everything but the AIF wipe
        # (a v10 body took the old line test's CHUNKs over the loader)
        a.li32(5, BOOT_SECTOR)
        a.cmplw(24, 5)
        a.blt("ck_open")
        a.li32(5, BOOT_SECTOR_END - 1)
        a.cmplw(24, 5)
        a.bgt("ck_open")
        a.bl("aif_cur")
        a.cmplwi(6, 0)
        a.beq("ck_perm")
        a.lhz(6, 0, 6)
        a.li32(7, MARK_ARMED)
        a.cmplw(6, 7)
        a.bne("ck_perm")
        a.label("ck_open")
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
    a.bne("ck_ver")                         # a page would not take, or not whole pages
    a.b("ck_ack")                           # cmf_chunkset read every page back already
                                            # (v20; v7-v19 compared the span a second time)
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
    a.alias("ck_perm", "nak1")
    a.alias("ck_crc", "nak2")
    a.alias("ck_dec", "nak3")
    a.alias("ck_ver", "nak4")
    a.alias("ck_mal", "nak6")
    a.alias("ck_drv", "nak7")

    # ---- SET_BAUD: ACK at the old rate, then switch ----------------------
    # (the v14-era probation countdown is gone: a switch the tester could
    # not follow is recovered by a reset, which always boots at 115200)
    a.label("op_setbaud")
    a.li32(3, RXBUF)
    a.lhz(24, 4, 3)                         # SCBR: 40 MHz / (32 x SCBR)
    a.cmplwi(24, 0)
    a.beq("sb_mal")
    a.cmplwi(24, 0x1FFF)
    a.bgt("sb_mal")
    a.li(3, 0)
    a.li(4, S_SETBAUD | 0x40)
    a.bl("send_reply")                      # its last echo read: the line is quiet
    a.sth(24, 0, 30)                        # switch (same value: idempotent)
    a.b("cmd")
    a.alias("sb_mal", "nak6")

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
    a.bne("cs_take")
    a.li(3, 0)
    a.li(4, S_CHUNKSET | 0x40)
    a.bl("send_reply")
    a.b("cmd")
    a.alias("cs_mal", "nak6")
    a.alias("cs_crc", "nak2")
    a.alias("cs_dec", "nak3")
    a.alias("cs_drv", "nak7")
    a.alias("cs_take", "nak4")              # (named cs_rb until v20: the name
                                            # cmf_chunkset's readback loop also
                                            # used -- the last label won, and a
                                            # page that would not take jumped
                                            # into that loop and ran off to PC 0)

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
    a.alias("v_bad", "nak5")
    a.alias("v_nak", "nak1")

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

    def marks(table):
        # each halfword programmed and read back (v20: v1-v19 waited open-
        # endedly and ACKed whatever the chip held -- the commit point could
        # answer "done" over a mark that never took). li sign-extends: 0x9042
        # would arrive as 0xFFFF9042, hence li32 for the values.
        for at, hi, lo in table:
            for off, half in ((0, hi), (2, lo)):
                a.li32(6, EXT + at + off)
                a.li32(4, half)
                a.bl("mark_half")
                a.cmplwi(3, 0)
                a.bne("mk_fail")
    marks(CAL_MARKS)
    a.b("mk_ack")
    a.label("mk_prog")
    marks(PROG_MARKS)
    a.alias("mk_fail", "nak4")              # a mark would not take
    a.label("mk_ack")
    a.li(3, 0)
    a.li(4, S_MARKS | 0x40)
    a.bl("send_reply")
    a.b("cmd")

    # ---- AIF: the boot-wipe resume marker (built only with the window) --
    if ALLOW_BOOT_SECTOR:
        a.label("op_aif")
        a.li32(3, RXBUF)
        a.lbz(24, 4, 3)                     # subcommand
        a.cmplwi(24, AIF_READ)
        a.beq("aif_read")
        a.cmplwi(24, AIF_ARM)
        a.beq("aif_arm")
        a.cmplwi(24, AIF_DONE)
        a.beq("aif_done")
        a.b("nak6")                         # bad subcommand
        a.label("aif_read")                 # reply with the current slot
        a.bl("aif_cur")
        a.li32(5, MARK_DONE)                # every slot spent: DONE
        a.cmplwi(6, 0)
        a.beq("aif_read_r")
        a.lhz(5, 0, 6)
        a.label("aif_read_r")
        a.mr(6, 5)
        a.li32(5, SRAM_BASE + REPLY_OFF + 4)
        a.sth(6, 0, 5)
        a.li(3, 2)
        a.li(4, S_AIF | 0x40)
        a.bl("send_reply")
        a.b("cmd")
        a.label("aif_arm")                  # 0xFFFF -> 0xA55A, only on a blank slot
        a.li32(4, MARK_ARMED)
        a.li32(9, 0xFFFF)
        a.b("aif_prog")
        a.label("aif_done")                 # 0xA55A -> 0xA558, only on an armed one
        a.li32(4, MARK_DONE)
        a.li32(9, MARK_ARMED)
        a.label("aif_prog")
        a.bl("aif_cur")                     # r4, r9 survive it
        a.cmplwi(6, 0)
        a.beq("aif_fail")                   # every slot spent
        a.lhz(5, 0, 6)                      # the slot must hold what this step
        a.cmplw(5, 9)                       # follows: never program over
        a.bne("aif_fail")                   # anything else (another build's tail)
        a.li32(3, EXT)
        a.li(14, 0xAA)
        a.li(15, 0x55)
        a.li(16, 0xA0)
        program_halfword(a, "aifm", polls=20000, fail="aif_fail")
        a.li(3, 0)
        a.li(4, S_AIF | 0x40)
        a.bl("send_reply")
        a.b("cmd")
        a.alias("aif_fail", "nak4")         # the marker halfword would not take

        # ---- READ (v13): raw bytes of ext or the MPC window ---------------
        # Request: offset (u32, bit 31 = the MPC window), length (u16, 1..4096).
        # Reply: a long frame [00 span(2) 12 F1 svc] crc32(4) data sum -- the
        # data streams straight from the array (no buffer: the reply area
        # holds ~500 bytes), and its CRC lets the host check every block.
        # Any address reads: the whole chip and the whole MPC, boot included.
        a.label("op_read")
        # r28-r31 are the SCI registers (send_bytes needs them); r14-r19 are the
        # flash macros'. This handler keeps its live values in r22-r24, which
        # send_bytes and its callees (r3-r9, r27) never touch: r23 the array
        # pointer, r24 the length, r22 the running checksum; r31 the reply head.
        a.li32(3, RXBUF)
        a.lwz(23, 4, 3)                     # offset
        a.lhz(24, 8, 3)                     # length (checked here, kept in r24)
        a.cmplwi(24, 0)
        a.beq("rd_mal")
        a.cmplwi(24, READ_MAX)
        a.bgt("rd_mal")
        # bit 30 of the offset: the serial EEPROM -- validate against its
        # 4 KB, stage the page at DSTBUF, and join the stream path with
        # the buffer as the array (the flash/MPC checks below never run)
        a.andis_(5, 23, 0x4000)
        a.beq("rd_flash")
        a.rlwinm(3, 23, 0, 16, 31)          # the 16-bit EEPROM address
        a.add(6, 3, 24)                     # addr + len must not pass the part's
        a.li(7, EE_SIZE)                    # end -- a short read at 0xFFE is fine,
        a.cmplw(6, 7)                       # a page at 0x001 is not (the first cut
        a.bgt("rd_bad")                     # tested addr alone)
        a.mr(4, 24)                         # ee_fill(r3 = addr16, r4 = count)
        a.bl("ee_fill")                     # leaves r23 = the staged page
        a.b("rd_crc")
        a.label("rd_flash")
        a.andis_(5, 23, 0x8000)
        a.bne("rd_mpc")
        a.add(6, 23, 24)
        a.li32(7, 0x100000)
        a.cmplw(6, 7)
        a.bgt("rd_bad")
        a.b("rd_ok")
        a.label("rd_mpc")
        a.rlwinm(5, 23, 0, 1, 31)
        a.add(6, 5, 24)
        a.li32(7, 0x70000)
        a.cmplw(6, 7)
        a.bgt("rd_bad")
        a.label("rd_ok")
        a.mr(3, 23)                         # the offset
        a.bl("base")                        # r3 = the array address
        a.mr(23, 3)                         # r23 = array pointer (survives send)
        a.label("rd_crc")                   # the EEPROM path arrives with r23/r24 set
        a.mr(3, 23)                         # crc32 takes r3 (ptr): the array (the
        a.mr(4, 24)                         # flash path's r3 already is it; ee_fill
        a.bl("crc32")                       # leaves r3 at the END address instead)
        a.mr(25, 3)                         # r25 = crc (survives the stores below)
        a.li32(31, SRAM_BASE + REPLY_OFF)
        a.li(5, 0)
        a.stb(5, 0, 31)                     # long form
        a.addi(6, 24, 8)                    # span = tgt src svc + crc4 + data + sum
        a.rlwinm(5, 6, 24, 24, 31)
        a.stb(5, 1, 31)
        a.stb(6, 2, 31)
        a.li(5, 0x12)
        a.stb(5, 3, 31)
        a.li(5, 0xF1)
        a.stb(5, 4, 31)
        a.li(5, S_READ | 0x40)
        a.stb(5, 5, 31)
        a.rlwinm(5, 25, 8, 24, 31)          # crc, big-endian, byte by byte
        a.stb(5, 6, 31)                     # (no unaligned word store)
        a.rlwinm(5, 25, 16, 24, 31)
        a.stb(5, 7, 31)
        a.rlwinm(5, 25, 24, 24, 31)
        a.stb(5, 8, 31)
        a.stb(25, 9, 31)
        a.li(22, 0)                         # r22 = sum over [3, 9] and the data
        a.addi(20, 31, 3)
        a.addi(21, 31, 10)
        a.label("rd_hsum")
        a.lbz(5, 0, 20)
        a.add(22, 22, 5)
        a.addi(20, 20, 1)
        a.cmplw(20, 21)
        a.bne("rd_hsum")
        a.mr(20, 23)                        # over the data, from the array
        a.mr(21, 24)
        a.label("rd_dsum")
        a.lbz(5, 0, 20)
        a.add(22, 22, 5)
        a.addi(20, 20, 1)
        a.addic_(21, -1)
        a.bne("rd_dsum")
        a.stb(22, 10, 31)                   # the sum byte (low 8 bits)
        a.li32(3, REPLY_GAP)                # the same quiet as every reply
        a.label("rd_gap")
        _swsr(a)
        a.addic_(3, -1)
        a.bne("rd_gap")
        a.mr(3, 31)
        a.li(4, 10)
        a.bl("send_bytes")                  # header + crc
        a.mr(3, 23)
        a.mr(4, 24)
        a.bl("send_bytes")                  # the data, from the array
        a.addi(3, 31, 10)
        a.li(4, 1)
        a.bl("send_bytes")                  # the sum
        a.b("cmd")
        a.alias("rd_bad", "nak1")
        a.alias("rd_mal", "nak6")

        # r3 = EEPROM offset, r4 = byte count (>= 1, <= DSTBUF); stages the
        # span at DSTBUF and leaves r23 pointing at it, ready for the READ
        # stream -- READ queues of up to 32 entries: the 03 addr_hi addr_lo
        # head plus 29 data bytes, the last entry dropping CONT. Nothing
        # below calls out, so besides the caller's r23 (which we set) every
        # register is ours; r3 doubles as the running address and r10 holds
        # the QSMCM base (every register is one addi off it -- the v14 body
        # ran 0x38 bytes past here into DRV_SDA and the driver copy ate its
        # own tail, so ee_fill is written to the byte budget: 55 insns).
        a.label("ee_fill")
        a.li32(23, DSTBUF)                  # absolute, unlike REPLY_OFF
        a.mr(20, 23)
        a.li32(10, QSMCM)
        qsmcm_setup(a, 10, 5)               # master mode, pins, baud -- the loader
                                            # left the QSMCM at reset; EEPROM path
                                            # only (r5 scratch)
        a.label("ee_run")
        a.li(6, 32)                         # entries n = min(32, count + 3): the
        a.cmplwi(4, 29)                     # full queue whenever count covers it,
        a.bgt("ee_have")                    # count + 3 for the short tail run
        a.addi(6, 4, 3)
        a.label("ee_have")
        a.addi(7, 10, 0x180)                # TX RAM: the READ head (0x140 is RX)
        a.li(5, 0x03)
        a.sth(5, 0, 7)
        a.rlwinm(5, 3, 24, 24, 31)         # the address, high byte then low.
        a.sth(5, 2, 7)                     # sth stores the register's low
        a.rlwinm(5, 3, 0, 24, 31)          # halfword and an 8-bit entry sends
        a.sth(5, 4, 7)                     # that halfword's LOW-ORDER byte, so
                                            # the byte must sit at value bits
                                            # 0-7: m(24,31), the hi byte pulled
                                            # down by rotl 24, the lo byte not
                                            # shifted at all. Two earlier cuts
                                            # (m(8,15), m(16,23)) parked the
                                            # byte where sth's low half kept it
                                            # away from the model's [-1:] and
                                            # the part got 00 00 every run
        a.addi(7, 10, 0x1C0)                # CMD RAM: one COMMAND BYTE per entry
        a.addi(8, 6, -1)                    # (not halfword slots like TX/RX);
        a.mr(9, 8)                          # CONT|PCS1 through n-1, bare last
        a.li(5, EE_CONT)
        a.label("ee_cmd")
        a.stb(5, 0, 7)
        a.addi(7, 7, 1)
        a.addic_(9, -1)
        a.bne("ee_cmd")
        a.li(5, EE_CONT & 0x7F)
        a.stb(5, 0, 7)
        a.rlwinm(5, 8, 8, 16, 23)           # NEWQP 0, ENDQP n-1, SPIFIE clear
        a.addi(7, 10, 0x1F)                 # SPSR; SPCR2 is -3, SPCR1 -5
        a.sth(5, -3, 7)
        a.li(5, SPCR1_GO)                   # SPE on with the delays, whole: sth
        a.sth(5, -5, 7)                     # keeps li's low half. (An earlier
        a.label("ee_poll")                  # cut's two-register ori swapped its
        a.lbz(5, 0, 7)                      # fields, stored n (19 == 0x13), SPE
        a.andi_(5, 5, QSPI_SPIF)            # never set, and this hung)
        a.beq("ee_poll")
        a.li(5, 0)
        a.stb(5, 0, 7)                      # SPIF down for the next run
        a.addi(9, 8, -2)                    # r9 = n - 3 data bytes landed
        a.addi(7, 10, 0x147)                # RX entry 3's LOW byte (8-bit
        a.label("ee_copy")                  # entries land in the low half)
        a.lbz(5, 0, 7)
        a.stb(5, 0, 20)
        a.addi(7, 7, 2)
        a.addi(20, 20, 1)
        a.addic_(9, -1)
        a.bne("ee_copy")
        a.addi(5, 8, -2)                    # n - 3 delivered this run
        a.add(3, 3, 5)
        a.subf(4, 5, 4)
        a.cmplwi(4, 0)
        a.bne("ee_run")
        a.blr()

        # r6 = the current marker slot (the first not reading MARK_DONE), or 0
        # when all MARK_SLOTS are spent. Clobbers r5, r7, r8 only.
        a.label("aif_cur")
        a.li32(6, EXT + MARK_AT)
        a.li(7, MARK_SLOTS)
        a.li32(8, MARK_DONE)
        a.label("aif_cur_next")
        a.lhz(5, 0, 6)
        a.cmplw(5, 8)
        a.bne("aif_cur_ret")
        a.addi(6, 6, 2)
        a.addic_(7, -1)
        a.bne("aif_cur_next")
        a.li(6, 0)
        a.label("aif_cur_ret")
        a.blr()

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
    _mark_half(a)
    _epee_on(a)
    _copyw(a)
    _cmf_setup(a)
    _drv_fwd(a)
    _drv_go(a)
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


# The QSMCM as the stock program sets it up before its first EEPROM read
# (read off the emulated program, tools: docs/EWS-ISN.md): master mode,
# 8-bit entries, CPHA 1, SPBR 5 (4 MHz); the QSPI's pins its own, the
# outputs driven, the chip selects idle high; DSCKL/DTL 1; no wrap, no
# halt. The loader never touches the module, so a body entered from a
# reset finds it at ITS reset state -- slave mode, pins as GPIO -- and the
# v15 body, which set SPE alone, polled SPIF forever on the car
# (2026-10-28) until the watchdog reset the DME. Set at the head of each
# EEPROM op only. SPCR1 is not here: each run stores it whole (SPCR1_GO).
# SPCR3 is not either: 0 from reset, and the one stock write (0x02, HMIE)
# matters only with HALT, which nothing sets.
QSMCM_SETUP = ((0x305014, 0x0078),          # PORTQS: PCS0-3 idle high
               (0x305016, 0x7B7E),          # PQSPAR | DDRQS
               (0x305018, 0xA105))          # SPCR0: MSTR, BITS 8, CPHA, SPBR 5


def qsmcm_setup(a, base, scratch):
    """Emit the QSMCM setup (QSMCM_SETUP) through `base` (already = QSMCM),
    `scratch` the one working register. Run at the head of every EEPROM op
    (ee_fill, the ee_write module): the loader leaves the QSMCM at its reset
    state and a body entered from a reset must put master mode, the pins and
    the baud back before it drives a queue -- but ONLY on the EEPROM path, so
    a flash/MPC/AIF read or a Fast Read, which never touch the QSPI, do not
    reconfigure a module the stock program may be mid-use of (setting it up
    in the stub, on every entry, hung the DME before it could even read --
    2026-10-28)."""
    for at, v in QSMCM_SETUP:
        a.li(scratch, v)                    # sth stores li's low half: one word
        a.sth(scratch, at - QSMCM, base)    # each, even past 0x7FFF


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


def build_eewrite(labels):
    """The EEPROM writer module, for ext at EE_MODULE_AT (v15's ISN rewrite).

    Entered by the body's op_eewrite counter jump after the dispatcher saw
    S_EEWRITE; everything else is its own. Request shape mirrors READ --
    [offset u32][len u16][data...] -- with the same bit-30 window and the
    part's 4 KB bound (EE_SIZE), plus two write-only rules: the data fits
    one queue (<= EE_WMAX) and the span stays inside one 32-byte block,
    because the real part wraps a page write inside its page while the
    emulator's part wraps the whole 4 KB -- a span that cannot cross a 32
    boundary is safe under any page size the part may be.

    The whole job is ONE QSMCM queue pass: WREN as its own chip-select
    cycle, then WRITE chained with the address and data, then WRDI -- so
    write-enable is live for exactly the one WRITE, exactly as long as it
    takes. Replies and NAKs go through the body's own send_reply/nak; the
    module ends by branching back to the body's cmd loop. It sets the QSMCM
    up first (qsmcm_setup), as ee_fill does: the EEPROM path is the only one
    that touches the QSPI. The register doorbell sequence (CMD RAM, SPCR2,
    SPE, poll, SPIF clear) is ee_fill's, proven by the dump.
    """
    a = BodyAsm()
    cmd, nak, send = labels["cmd"], labels["nak"], labels["send_reply"]

    def call_body(target):
        a.li32(11, target)
        a.mtctr(11)
        a.bctrl()

    def back_to_cmd():
        a.li32(11, cmd)
        a.mtctr(11)
        a.bctr()

    a.li32(3, RXBUF)
    a.lwz(23, 4, 3)                        # offset: bit 30 selects the part
    a.lhz(24, 8, 3)                        # length
    a.cmplwi(24, 0)
    a.beq("w_mal")
    a.cmplwi(24, EE_WMAX)
    a.bgt("w_bad")                         # one queue: len + 5 <= 30 entries
    a.andis_(5, 23, EE_WINDOW >> 16)
    a.beq("w_bad")                         # not the EEPROM window
    a.rlwinm(3, 23, 0, 16, 31)             # the 16-bit address
    a.add(6, 3, 24)
    a.li(7, EE_SIZE)
    a.cmplw(6, 7)
    a.bgt("w_bad")                         # addr + len must not pass the end
    a.rlwinm(5, 3, 0, 27, 31)              # (addr & 31) + len <= 32: the span
    a.add(5, 5, 24)                        # stays inside one page whatever the
    a.cmplwi(5, 32)                        # part's page size is
    a.bgt("w_bad")
    a.li32(10, QSMCM)
    qsmcm_setup(a, 10, 5)                  # master mode, pins, baud: the loader
                                            # left the QSMCM at reset (r5 scratch,
                                            # reloaded just below). r3 (the addr)
                                            # is untouched
    a.addi(7, 10, QTX_RAM - QSMCM)
    a.li(5, 0x06)
    a.sth(5, 0, 7)                         # slot 0: WREN, its own CS cycle
    a.li(5, 0x02)
    a.sth(5, 2, 7)                         # slot 1: WRITE
    a.rlwinm(5, 3, 24, 24, 31)             # slot 2: address hi, then lo -- each
    a.sth(5, 4, 7)                         # in its slot's low-order byte, the
    a.rlwinm(5, 3, 0, 24, 31)              # half an 8-bit entry sends
    a.sth(5, 6, 7)
    a.li32(3, RXBUF + 10)                  # the data, from the telegram itself
    a.addi(20, 7, 9)                       # slot 4's data byte is the odd one
    a.mr(25, 24)
    a.label("w_cp")
    a.lbz(5, 0, 3)
    a.stb(5, 0, 20)
    a.addi(3, 3, 1)
    a.addi(20, 20, 2)
    a.addic_(25, -1)
    a.bne("w_cp")
    a.li(5, 0x04)
    a.stb(5, 0, 20)                        # slot 4 + len: WRDI, its own cycle
    a.addi(7, 10, QCMD_RAM - QSMCM)        # command RAM: WREN bare; CONT through
    a.li(5, EE_BARE)                       # the WRITE group but NOT the last data
    a.stb(5, 0, 7)                         # byte -- CONT on entry i holds the chip
    a.addi(7, 7, 1)                        # select through entry i+1, so a CONT on
    a.addi(6, 24, 5)                       # the last data byte would drag WRDI's
    a.addi(8, 6, -3)                       # 0x04 into the WRITE (the first cut did
    a.li(5, EE_CONT)                       # exactly that and every 4-byte write
    a.label("w_cmd")                       # landed 5); the last data byte and the
    a.stb(5, 0, 7)                         # WRDI are both bare, three cycles total
    a.addi(7, 7, 1)
    a.addic_(8, -1)
    a.bne("w_cmd")
    a.li(5, EE_BARE)
    a.stb(5, 0, 7)                         # the last data byte: bare
    a.addi(7, 7, 1)
    a.stb(5, 0, 7)                         # WRDI: bare too, its own cycle
    a.addi(8, 6, -1)
    a.rlwinm(5, 8, 8, 16, 23)              # SPCR2 = NEWQP 0 | ENDQP n-1
    a.addi(7, 10, QSPSR - QSMCM)           # SPSR; SPCR2 is -3, SPCR1 is -5
    a.sth(5, -3, 7)
    a.li(5, SPCR1_GO)
    a.sth(5, -5, 7)                        # SPE on with the delays, whole
    a.label("w_poll")
    a.lbz(5, 0, 7)
    a.andi_(5, 5, QSPI_SPIF)
    a.beq("w_poll")
    a.li(5, 0)
    a.stb(5, 0, 7)                         # SPIF down
    a.li(3, 0)
    a.li(4, S_EEWRITE | 0x40)
    call_body(send)
    back_to_cmd()
    a.label("w_mal")
    a.li(4, 6)
    call_body(nak)
    back_to_cmd()
    a.label("w_bad")
    a.li(4, 1)
    call_body(nak)
    back_to_cmd()
    a.resolve(EXT + EE_MODULE_AT)
    return a.words


def build_parts():
    """(stub, body, body size, ee_write module) -- everything that goes in ext."""
    body_words, size = build_body()
    # the hard SRAM ceiling: DRV_SDA is copied over whatever sits at 0x3FB000
    # on every CMF driver call. v14 grew past it by 0x38 bytes and the MPC
    # chunk push executed driver data -- REPLY_OFF no longer bounds the code,
    # so this does (the old 0x1780 reply slot happened to, with 0x80 slack)
    sram_ceiling = DRV_SDA - SRAM_BASE
    if size > sram_ceiling:
        raise ValueError(
            f"body {size:#x} bytes overruns DRV_SDA: the driver copy would "
            f"eat its last {size - sram_ceiling} bytes (ceiling {sram_ceiling:#x})"
        )
    module = build_eewrite(LABEL_ADDRS)
    if 4 * len(module) > 0xFFF40 - EE_MODULE_AT:
        raise ValueError(
            f"ee_write module {4 * len(module):#x} bytes overruns the ext "
            f"range end {0xFFF40:#x} (base {EE_MODULE_AT:#x})"
        )
    stub = build_stub(len(body_words))
    return stub, body_words, size, module


def pack(words):
    return struct.pack(">%dI" % len(words), *(w for w, _ in words))


if __name__ == "__main__":
    stub, body, size, module = build_parts()
    print(f"stub: {len(stub)} words at ext {ENTRY_AT:#x}")
    print(f"ee_write module: {len(module)} words ({4 * len(module):#x} bytes) "
          f"at ext {EE_MODULE_AT:#x} (CPU {EXT + EE_MODULE_AT:#x})")
    print(f"body: {len(body)} words ({size:#x} bytes) at ext {BODY_AT:#x} "
          f"(spans to {BODY_AT + size:#x}, budget {0xFFF40:#x}; SRAM ends "
          f"{SRAM_BASE + size:#x}, ceiling {DRV_SDA:#x})")
    print(f"reply buffer at SRAM {SRAM_BASE + REPLY_OFF:#x}; rx {RXBUF:#x}; dst {DSTBUF:#x}")
    print(f"CRC table at {CRC_TABLE:#x}; EEPROM reads stage at {DSTBUF:#x}")
    print(f"CMF driver: code at {DRV_CODE:#x}-{DRV_CODE + DRV_CODE_LEN:#x}, "
          f"data {DRV_SDA:#x}-{DRV_SDA + DRV_SDA_LEN:#x} (r13 = {DRV_R13:#x})")
