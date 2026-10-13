"""The live-tune overlay (docs/livetune-design.md, milestone 2): new bodies
for the sixteen lookup-entry hooks.

The table-lookup routines (`dme.LOOKUP_ENTRIES`) are entered with the table
pointer in r3. The car's pair carries an older map-switch generation that
hooks every entry: the first instruction branches to a stub in the MPC tail
(0x6E550-0x6E78F) that may add +0xA0000 to the pointer, runs the stock
first instruction and branches back to entry+4.

`build` gives those hooks new bodies, written to the blank tail from 0x6E904
(0x6F000 onward stays free for the boot-PoC payload). A body first consults
a descriptor table in SRAM: each descriptor is (base, end, delta) — a
pointer inside [base, end) gets delta added, moving the read into a mirror
in SRAM. The descriptors end in a null entry. With the magic absent (SRAM
as the program leaves it) or no match, the stock path runs unchanged, and
the old generation's redirect is preserved before the stock instruction.

Everything runs on r0, r11, r12 and cr0, as the diagnostic stubs do; none
of the sixteen stock first instructions reads those. The stubs are built
idempotently: the stock first instructions live in the old stubs, which are
never touched, so a rebuild just retargets the entries again.
"""
import struct

from . import dme
from .checksums import fix_program
from .diagpatch import BEQ, BNE, BLT, _branch, _d, _x
from .image import Pair

R13 = 0x4017F0
OLD_BASE, OLD_STRIDE = 0x6E550, 0x24       # the old generation's sixteen stubs
CODE, CODE_END = 0x6E904, 0x6F400          # our stubs. 0x6F400+ is the boot-PoC
                                           # payload's transient slot, used only
                                           # during a flash update; the overlay
                                           # runs in normal operation, so the two
                                           # are time-disjoint and share the tail
SLOTS = 36                                 # tables (and single values) open at once
DESC = 0x3F9C48                            # the descriptor table: r13-relative, the whole of
DESC_SPACE = 4 + 12 * SLOTS + 4            # a 440-byte never-written gap -- the magic, the
                                           # triples and the null base that ends them
BITMAP = 0x3F9858                          # one bit per 256 bytes of calibration that holds
BLOCK_SHIFT = 8                            # any part of an open table, so a lookup of an
BLOCKS = dme.CAL_LENGTH >> BLOCK_SHIFT     # untouched table never walks the descriptors
BITMAP_SPACE = 60                          # (58 bytes, rounded up to words)
SAVE_ARMED = BITMAP + 58                   # one of the bitmap space's two spare bytes: SAVE_ASKED
SAVE_ASKED = 0x5A                          # here and the key-off folds the open tables in
                                           # (transport op 08); anything else and the edits
                                           # go with the power, as nobody asked to keep them
STATE = 0x3F9E74                           # the transport's 0x24-byte state block
POOLS = ((0x3F9E98, 0x3FA0A0),             # RAM for mirrors, the other never-written gaps
         (0x3F9B48, 0x3F9C40),             # (milestone-1 profile and the KWP writer map: the
         (0x3F9E10, 0x3F9E74),             # receive interrupt and its response echo write
         (BITMAP + BITMAP_SPACE, 0x3F98B0))  # 0x3F983C-50 and 0x3F99DC-0x3F9A64, none of it
                                           # here). 520, 248, 100 and 28 bytes; only the
                                           # first fits the biggest tables. The tester
                                           # decides what goes where (transport op 07)
SINGLES_POOL = (0x3FF580, 0x3FF900)        # the top of the program's heap, which it leaves
                                           # unallocated (singles.py lowers the heap's limit
                                           # to make that a fact): the single values the
                                           # program reads often live here for good, and a
                                           # mirror may be placed on one of them
SHELF = (0x1D000, 0x1FF80)                 # calibration offsets: the sector's blank end, past
                                           # what the run-time CRC covers and below the
                                           # loader's valid marks. A mirror may be programmed
                                           # here instead (transport op 06): blank flash takes
                                           # a word without an erase, and every save erases
                                           # the sector, so the shelf empties itself
SCAN = CODE + 4                            # the shared descriptor scan (see _emit_scan)
MAGIC = 0x6C690000                         # "li": lis alone builds it, so one
                                           # instruction still buys a 32-bit check
ENTRY_WORDS = 3                            # base, end, delta
BGE = (4, 0)                               # branch if cr0.LT clear

# The stock first instructions, as the map-switch builder lists them
# (mapswitch.js MS_LOOKUP_STOCK); asserted against the old stubs.
LOOKUP_STOCK = (
    0x89830000, 0x88E30000, 0xA1830000, 0xA0E30000, 0x88A30000, 0x88A30000,
    0xA0A30000, 0xA0A30000, 0x898DD7C6, 0x898DD7C6, 0x898DD7C6, 0x898DD7C6,
    0x38E30000, 0x38E30000, 0x88ADD7C4, 0x88ADD7C4,
)

# The lookup library's binary-search wrappers read their table(s) through data
# pointers they load from 4(r3) and 8(r3) -- NOT through r3 -- so the entry
# hooks (which redirect r3) never touch them, and a mirrored table is read stale
# from flash at these sites (proven at run time, tools/livetune_overlay.py:
# fn_E054 and family stay flash=y after a mirror is installed). The 1-D wrappers
# (D-series) read one axis from 4(r3); the 2-D wrappers (E/F-series) read a
# first axis from 4(r3) and a second from 8(r3), each in its own branch, so
# every such load is a separate hook. 0(r3) is the element count, not a
# pointer, and is left alone. Each hook replaces its one `lwz rReg, disp(r3)`
# with a branch to a wrapper stub that runs the load, redirects rReg through the
# descriptors, and returns. Enumerated statically over the library window
# 0xC328-0x11000 and confirmed against the run-time bypass set; the RTOS
# lookalikes above 0xF25C (os_tick, os_pit_start) use a different offset and
# never read the cal, so they are excluded.
# (pc of the lwz, pointer register, displacement off r3).
LOOKUP_WRAPPERS = (
    (0x0D810, 6, 4), (0x0D874, 6, 4), (0x0D8E0, 6, 4), (0x0D94C, 6, 4),
    (0x0D9BC, 7, 4), (0x0DA74, 7, 4), (0x0DB34, 7, 4), (0x0DBF4, 7, 4),
    (0x0DCBC, 6, 4), (0x0DD94, 6, 4), (0x0DE7C, 6, 4), (0x0DF60, 6, 4),
    (0x0E058, 7, 4), (0x0E0D0, 6, 8), (0x0E2E0, 7, 4), (0x0E358, 6, 8),
    (0x0E570, 7, 4), (0x0E5F0, 6, 8), (0x0E800, 7, 4), (0x0E880, 6, 8),
    (0x0EA98, 7, 4), (0x0EB10, 6, 8), (0x0ED2C, 7, 4), (0x0EDA4, 6, 8),
    (0x0EFC4, 7, 4), (0x0F044, 6, 8), (0x0F260, 7, 4), (0x0F2E0, 6, 8),
)


def _wrap_lwz(reg, disp):
    """The stock word a wrapper hook displaces: `lwz rReg, disp(r3)`."""
    return (32 << 26) | (reg << 21) | (3 << 16) | (disp & 0xFFFF)


def _rlwinm(rs, ra, sh, mb, me):
    # M-form: the bits-6-10 field is the SOURCE (rs), bits 11-15 the DEST (ra).
    return (21 << 26) | (rs << 21) | (ra << 16) | (sh << 11) | (mb << 6) | (me << 1)


def _word(mpc, at):
    return struct.unpack_from(">I", mpc, at)[0]


def _btarget(at, word):
    """Where a plain `b` at `at` goes, or None if the word is not one."""
    if word >> 26 != 18 or word & 1:
        return None
    li = word & 0x03FFFFFC
    if li & 0x02000000:
        li -= 0x04000000
    return (at + li) & 0xFFFFFFFF


class _Asm:
    """The diagnostic patch's assembler, plus an unconditional branch to a
    label (its `bc` tuples resolved the same way)."""

    def __init__(self, base):
        self.base, self.items, self.labels = base, [], {}

    def here(self):
        return self.base + 4 * len(self.items)

    def label(self, name):
        self.labels[name] = self.here()

    def emit(self, *words):
        self.items.extend(words)

    def b(self, name):
        return ("b", name)

    def bc(self, cond, name):
        return (cond, name)

    def lis_lbl(self, rd, name):
        """lis rd, HI16(&name) -- the label's absolute address, resolved late."""
        return ("lis", rd, name)

    def ori_lbl(self, rd, name):
        """ori rd, rd, LO16(&name) -- pairs with lis_lbl for a 32-bit address."""
        return ("ori", rd, name)

    def bytes(self):
        out = []
        for i, it in enumerate(self.items):
            if isinstance(it, int):
                out.append(it)
                continue
            at = self.base + 4 * i
            if it[0] == "b":
                out.append(_branch(at, self.labels[it[1]]))
            elif it[0] == "lis":
                _, rd, name = it
                # a label just above an address boundary needs the +0x8000 carry
                # the ori's signed add undoes; our tail is far from any such edge
                out.append((15 << 26) | (rd << 21) | ((self.labels[name] >> 16) & 0xFFFF))
            elif it[0] == "ori":
                _, rd, name = it
                out.append((24 << 26) | (rd << 21) | (rd << 16) | (self.labels[name] & 0xFFFF))
            else:
                (bo, bi), target = it[0], self.labels[it[1]]
                out.append((16 << 26) | (bo << 21) | (bi << 16) | ((target - at) & 0xFFFC))
        return struct.pack(f">{len(out)}I", *out)


_BCTR = (19 << 26) | (20 << 21) | (528 << 1)                    # bctr


def _mtctr(rs):
    return (31 << 26) | (rs << 21) | (9 << 16) | (467 << 1)     # mtspr CTR, rs


def _mr(rd, rs):
    return (31 << 26) | (rs << 21) | (rd << 16) | (rs << 11) | (444 << 1)   # or rd,rs,rs


def _emit_scan(a):
    """The shared descriptor redirect, emitted once at label 'scan'.

    A pointer in r12 that lands in a mirrored descriptor range gets its delta
    added in place; otherwise r12 is left untouched. The bitmap is consulted
    first: most lookups are of tables nobody opened, and they leave after a
    dozen instructions however many descriptors there are. The caller puts its return
    address in CTR (so r11/r12/r0 stay free here) and branches to 'scan'; scan
    returns with `bctr`. Registers: r12 the pointer, r11 the descriptor cursor,
    r0 scratch, CTR the return, cr0 -- all in the stubs' free set. The magic
    gate reads only the high half (MAGIC's low half is zero and no live pointer
    is 0x6C69xxxx), so one `cmplwi` suffices without a second scratch."""
    a.label("scan")
    a.emit(_d(32, 0, 13, DESC - R13),                        # lwz r0, magic
           _rlwinm(0, 0, 16, 16, 31),                        # srwi r0, r0, 16
           _d(10, 0, 0, MAGIC >> 16), a.bc(BNE, "scan_ret"),  # cmplwi r0, 0x6c69
           # the block bitmap: nothing open in this pointer's 256 bytes of
           # calibration (or the pointer is not into the calibration) -- out
           _d(15, 11, 12, -(dme.CAL_BASE >> 16) & 0xFFFF),   # addis r11, r12, -CAL: the offset
           _rlwinm(11, 11, 32 - BLOCK_SHIFT, BLOCK_SHIFT, 31),  # srwi r11, r11, 8: the block
           _d(10, 0, 11, BLOCKS), a.bc(BGE, "scan_ret"),     # cmplwi r11, BLOCKS
           _rlwinm(11, 0, 0, 29, 31),                        # r0 = block & 7
           _rlwinm(11, 11, 29, 3, 31),                       # srwi r11, r11, 3
           _x(11, 11, 13, 266),                              # add r11, r11, r13
           _d(34, 11, 11, BITMAP - R13),                     # lbz r11, bitmap byte
           _x(11, 11, 0, 536),                               # srw r11, r11, r0
           _d(28, 11, 0, 1), a.bc(BEQ, "scan_ret"),          # andi. r0, r11, 1
           _d(14, 11, 13, DESC + 4 - R13))                   # addi r11, r13, entries
    a.label("scan_loop")
    a.emit(_d(32, 0, 11, 0),                                 # lwz r0, base
           _d(11, 0, 0, 0), a.bc(BEQ, "scan_ret"),           # 0 base: end of table
           _x(0, 12, 0, 0), a.bc(BLT, "scan_next"),          # r12 below the range
           _d(32, 0, 11, 4),                                 # lwz r0, end
           _x(0, 12, 0, 0), a.bc(BGE, "scan_next"),          # r12 at/past the end
           _d(32, 0, 11, 8),                                 # lwz r0, delta
           _x(12, 12, 0, 266), a.b("scan_ret"))              # r12 += delta
    a.label("scan_next")
    a.emit(_d(14, 11, 11, ENTRY_WORDS * 4), a.b("scan_loop"))
    a.label("scan_ret")
    a.emit(_BCTR)
    return a


def _emit_entry(a, i, entry, stock, old=True):
    """One lookup-entry hook (entered with the table pointer in r3). Redirect r3
    through the shared scan, then the old generation's map-switch redirect (on a
    program that carries that generation), then the displaced stock first
    instruction, then back to entry+4."""
    a.label(f"entry{i}")
    cont = f"entry{i}_ret"
    a.emit(a.lis_lbl(0, cont), a.ori_lbl(0, cont), _mtctr(0),  # CTR = &continuation
           _mr(12, 3), a.b("scan"))                            # r12 = r3; redirect
    a.label(cont)
    a.emit(_mr(3, 12))                                         # r3 = redirected pointer
    if old:
        # The old generation's redirect, unchanged: flag bit 0 of 0x3FA195 and a
        # pointer ending in 0x7FF2 (r2+2) move by +0xA0000.
        a.emit(_d(34, 0, 13, dme.RAM_FLAG - R13),                 # lbz r0, flag
               _d(28, 0, 0, 1), a.bc(BEQ, f"entry{i}_stock"),     # andi. r0, r0, 1
               _rlwinm(3, 0, 15, 17, 31),                         # r0 = r3 & 0xFFFF
               _d(10, 0, 0, 0x7FF2), a.bc(BNE, f"entry{i}_stock"),  # cmplwi
               _d(15, 3, 3, 0xA))                                 # addis r3, r3, 0xA
    a.label(f"entry{i}_stock")
    a.emit(stock, _branch(a.here() + 4, entry + 4))


def _emit_wrap(a, i, pc, reg, disp):
    """One library-wrapper hook (replacing `lwz rReg, disp(r3)`). Run the load,
    then redirect rReg through the shared scan so the wrapper's own reads fall
    in the mirror, then back to the instruction after the one we displaced."""
    a.label(f"wrap{i}")
    cont = f"wrap{i}_ret"
    a.emit(_wrap_lwz(reg, disp),                             # lwz rReg, disp(r3)
           a.lis_lbl(0, cont), a.ori_lbl(0, cont), _mtctr(0),  # CTR = &continuation
           _mr(12, reg), a.b("scan"))                         # r12 = rReg; redirect
    a.label(cont)
    a.emit(_mr(reg, 12), _branch(a.here() + 4, pc + 4))       # rReg = redirected; back


def _old_stub(i):
    return OLD_BASE + OLD_STRIDE * i


def is_patched(pair):
    return all(CODE <= (_btarget(e, _word(pair.mpc, e)) or -1) < CODE_END
               for e in dme.LOOKUP_ENTRIES)


def carries_old(pair):
    """Whether the program carries the old map-switch generation (its sixteen
    lookup stubs in the MPC tail). The car's own does; BMW's program does not."""
    return bool(bytes(pair.mpc[OLD_BASE:_old_stub(len(dme.LOOKUP_ENTRIES))]).strip(b"\xff"))


def _build_tail(code, old=True):
    """Assemble the whole tail at `code` in one unit: the shared scan
    subroutine, then the sixteen entry hooks, then the twenty wrapper hooks.
    Returns (bytes, entry_targets, wrap_targets) -- the absolute address each
    hooked site must branch to."""
    a = _Asm(code)
    a.emit(a.b("scan"))                                      # skip over the subroutine
    _emit_scan(a)
    entry_targets, wrap_targets = [], []
    for i, (entry, stock) in enumerate(zip(dme.LOOKUP_ENTRIES, LOOKUP_STOCK)):
        entry_targets.append(a.here())
        _emit_entry(a, i, entry, stock, old)
    for i, (pc, reg, disp) in enumerate(LOOKUP_WRAPPERS):
        wrap_targets.append(a.here())
        _emit_wrap(a, i, pc, reg, disp)
    return a.bytes(), entry_targets, wrap_targets


def build(pair, code=CODE):
    """The pair with the overlay hooks, re-signed. Hooks both the sixteen
    lookup-entry stubs (redirecting the r3 table pointer) and the twenty
    library wrappers that read through a 4(r3) data pointer the entry hooks
    never see. On the car's program the old generation's stubs are there and
    their redirect is kept; on BMW's own program (no map switch) the entries
    still hold their stock first instructions and are hooked directly. Either
    way the stock instructions are known (LOOKUP_STOCK) and the wrapper ones are
    the fixed `lwz rX,4(r3)`, so building twice is safe."""
    mpc, flash = bytearray(pair.mpc), bytearray(pair.flash)
    if is_patched(pair):
        mpc[code:CODE_END] = b"\xff" * (CODE_END - code)      # our own stubs, rebuilt below
    if mpc[code:CODE_END].strip(b"\xff"):
        raise ValueError(f"the MPC tail is not empty from 0x{code:X}")
    old = carries_old(pair)
    for i, entry in enumerate(dme.LOOKUP_ENTRIES):
        word = _word(mpc, entry)
        target = _btarget(entry, word)
        ours = target is not None and CODE <= target < CODE_END
        if not old:
            if word != LOOKUP_STOCK[i] and not ours:
                raise ValueError(f"the lookup entry at 0x{entry:X} is neither stock nor our hook: 0x{word:08X}")
            continue
        if _word(mpc, _old_stub(i) + 0x1C) != LOOKUP_STOCK[i]:
            raise ValueError(f"the old stub at 0x{_old_stub(i):X} does not carry the expected first instruction")
        if not (ours or (target is not None
                         and _old_stub(0) <= target < _old_stub(len(dme.LOOKUP_ENTRIES)))):
            raise ValueError(f"the lookup entry at 0x{entry:X} is not hooked")
    for pc, reg, disp in LOOKUP_WRAPPERS:
        w = _word(mpc, pc)
        if w != _wrap_lwz(reg, disp) and _btarget(pc, w) is None:
            raise ValueError(f"the wrapper load at 0x{pc:X} is neither the stock "
                             f"lwz r{reg},{disp}(r3) nor an existing hook: 0x{w:08X}")

    stubs, entry_targets, wrap_targets = _build_tail(code, old)
    if code + len(stubs) > CODE_END:
        raise ValueError(f"the overlay stubs need 0x{len(stubs):X} bytes, "
                         f"more than the tail's 0x{CODE_END - code:X}")
    mpc[code:code + len(stubs)] = stubs
    for entry, target in zip(dme.LOOKUP_ENTRIES, entry_targets):
        struct.pack_into(">I", mpc, entry, _branch(entry, target))
    for (pc, _reg, _disp), target in zip(LOOKUP_WRAPPERS, wrap_targets):
        struct.pack_into(">I", mpc, pc, _branch(pc, target))
    fix_program(flash, mpc)
    return Pair(bytes(flash), bytes(mpc), pair.name + "+overlay")


# ---- the runtime side: descriptors and mirrors, as the tester writes them --------

def blocks(offset, length):
    """The bitmap blocks a calibration range touches."""
    return range(offset >> BLOCK_SHIFT, ((offset + length - 1) >> BLOCK_SHIFT) + 1)


def free_ram(taken, length):
    """Where a mirror of `length` bytes fits beside the ones in `taken`
    [(address, length)]: first fit over POOLS, or None."""
    for lo, hi in POOLS:
        at = lo
        for a, n in sorted(t for t in taken if lo <= t[0] < hi):
            if a - at >= length:
                break
            at = max(at, a + n)
        if at + length <= hi and all(at + length <= a or a + n <= at for a, n in taken):
            return at
    return None


def placement(ranges):
    """Where `install` puts each range: [(cal offset, length)] ->
    [(cal offset, length, mirror address)], without writing anything, so a
    watcher can cover the mirrors before they are seeded."""
    if not 1 <= len(ranges) <= SLOTS:
        raise ValueError(f"the overlay serves one to {SLOTS} tables")
    out = []
    for offset, length in ranges:
        at = free_ram([(a, n) for _, n, a in out], length)
        if at is None:
            raise ValueError(f"cal 0x{offset:X} ({length} B) fits no free span")
        out.append((offset, length, at))
    return out


def install(m, ranges):
    """Mirror calibration ranges into the free SRAM spans and point the
    overlay at them: [(cal offset, length)] -> [(cal offset, length, mirror
    address)]. The mirrors are seeded with the stock bytes first, so there is
    no moment a descriptor points at a mirror that is not filled."""
    out = placement(ranges)
    for offset, length, at in out:
        m.write(at, m.read(dme.CAL_BASE + offset, length))
    bitmap = bytearray(BITMAP_SPACE)
    words = [MAGIC]
    for offset, length, address in out:
        base = dme.CAL_BASE + offset
        words += [base, base + length, (address - base) & 0xFFFFFFFF]
        for block in blocks(offset, length):
            bitmap[block >> 3] |= 1 << (block & 7)
    words += [0]
    m.write(BITMAP, bytes(bitmap))
    m.write(DESC, struct.pack(f">{len(words)}I", *words))
    return out


def remove(m):
    """Leave the overlay inactive: the magic goes, the stubs take the stock path."""
    m.write(DESC, struct.pack(">II", 0, 0))
    m.write(BITMAP, bytes(BITMAP_SPACE))
