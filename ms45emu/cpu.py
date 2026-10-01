"""CPU facilities Unicorn does not expose directly: SRR0/SRR1, the time base
and the decrementer, and raising an exception the way the hardware does.

Unicorn gives no handle on SRR0/SRR1, TB or DEC, and leaves TB at zero and
DEC static, so they are driven from here through tiny code stubs in a
scratch page: a stub that writes SRR0/SRR1 and jumps to the vector, and
stubs that read or write DEC and TB.

MPC5xx detail: `mtspr EID/EIE` (SPR 81/80) are no-ops under Unicorn, so
MSR[EE] does not follow the program's critical sections; callers should
also respect the program's own interrupt-nesting counter.
"""
import struct

from unicorn import UC_PROT_READ, UC_PROT_EXEC
from unicorn.ppc_const import UC_PPC_REG_0, UC_PPC_REG_PC, UC_PPC_REG_MSR

SCRATCH = 0x00100100            # inside the sentinel page, after the return address
MSR_EE = 0x8000

# Vector table in the MPC's first 0x100 bytes: entry n at 8*n is `ba handler`.
VECTOR_STRIDE = 8
VEC_MACHINE_CHECK, VEC_EXTERNAL, VEC_DECREMENTER, VEC_SYSCALL = 2, 5, 9, 12


def _asm(words):
    return b"".join(struct.pack(">I", w) for w in words)


MSR_RI = 0x2
MSR_FP = 0x2000
SPR_EIE, SPR_EID, SPR_NRI = 80, 81, 82


def find_rfi(image, base):
    """Addresses of every `rfi` in an image."""
    out = set()
    for off in range(0, len(image) - 3, 4):
        if image[off:off + 4] == b"\x4c\x00\x00\x64":
            out.add((base + off) & 0xFFFFFFFF)
    return out


SPR_TBL_R, SPR_TBU_R, SPR_TBL_W, SPR_TBU_W = 268, 269, 284, 285
SPR_DEC = 22


def find_trap_sites(image, base):
    """Instructions Unicorn cannot run faithfully, to be replaced by `sc`:
    `mtspr EIE/EID/NRI` (no-ops under Unicorn), and time base access
    (`mftb`, `mfspr/mtspr TBL/TBU`: the time base reads zero and cannot be
    written). Returns addr -> ("msr", spr) | ("tb_read", reg, spr) | ("tb_write", reg, spr)."""
    out = {}
    for off in range(0, len(image) - 3, 4):
        w = struct.unpack(">I", image[off:off + 4])[0]
        if w >> 26 != 31:
            continue
        xo = (w >> 1) & 0x3FF
        reg = (w >> 21) & 31
        spr = ((w >> 16) & 31) | (((w >> 11) & 31) << 5)
        addr = (base + off) & 0xFFFFFFFF
        if xo == 467 and spr in (SPR_EIE, SPR_EID, SPR_NRI):
            out[addr] = ("msr", spr)
        elif xo == 339 and spr == SPR_DEC:
            out[addr] = ("dec_read", reg)
        elif xo == 467 and spr == SPR_DEC:
            out[addr] = ("dec_write", reg)
        elif xo == 371 or (xo == 339 and spr in (SPR_TBL_R, SPR_TBU_R)):
            out[addr] = ("tb_read", reg, spr)
        elif xo == 467 and spr in (SPR_TBL_W, SPR_TBU_W):
            out[addr] = ("tb_write", reg, spr)
    return out


def find_msr_sprs(image, base):
    return {a: v[1] for a, v in find_trap_sites(image, base).items() if v[0] == "msr"}


SC = 0x44000002
MSR_STUB_BASE, MSR_STUB_SIZE, MSR_STUB_STRIDE = 0x00200000, 0x10000, 32


def _ba(target):
    """ba target: absolute branch, target within +-32 MB of 0."""
    assert target < 0x02000000 or target >= 0xFE000000
    return 0x48000002 | (target & 0x03FFFFFC)


def _rlwinm(ra, rs, sh, mb, me):
    return (21 << 26) | (rs << 21) | (ra << 16) | (sh << 11) | (mb << 6) | (me << 1)


class Cpu:
    def __init__(self, m):
        self.m = m
        self.tb = 0
        self.dec = 0                 # the decrementer, kept here: its sites are trapped
        self._build_stubs()
        # MPC5xx EIE/EID/NRI are no-ops under Unicorn. Every such site is
        # replaced in the loaded image by `sc`, whose exception hook applies
        # the MSR change; this costs nothing on other instructions, unlike
        # code hooks. The program's checksums are then recomputed over the
        # patched image, see checksums.py.
        self.trap_sites = find_trap_sites(m.pair.mpc, 0)
        self.trap_sites.update(find_trap_sites(m.pair.flash, 0xFFF00000))
        self.msr_sprs = {a: v[1] for a, v in self.trap_sites.items() if v[0] == "msr"}
        self.rfi_sites = find_rfi(m.pair.mpc, 0) | find_rfi(m.pair.flash, 0xFFF00000)
        self.sc_sites = {}                    # pc after the sc -> site description
        self._patch_trap_sites()

    def _patch_trap_sites(self):
        m = self.m
        # EIE/EID/NRI sites become a branch to a native stub each (no
        # Python involved: the kernel hits them every ~60 instructions);
        # time base sites stay `sc` traps.
        self.msr_stub_base = MSR_STUB_BASE
        m.mu.mem_map(MSR_STUB_BASE, MSR_STUB_SIZE, UC_PROT_READ | UC_PROT_EXEC)
        self._next_stub = MSR_STUB_BASE
        for pc, site in self.trap_sites.items():
            sites = [pc] + ([pc - 0x100000] if pc >= 0xFFF00000 else [])   # and the 0xFFExxxxx mirror
            for at in sites:
                if site[0] == "msr":
                    m.write32(at, _ba(self._msr_stub(site[1], at + 4)))
                else:
                    m.write32(at, SC)
                    self.sc_sites[(at + 4) & 0xFFFFFFFF] = site
        self.siu_window_sites, self.sipend_store_sites = relocate_siu_window(m, self.sc_sites)
        from .checksums import refresh_program_sums
        refresh_program_sums(m)

    def _msr_stub(self, spr, back):
        """mtspr SPRG0,r3; mfmsr r3; <edit>; mtmsr r3; mfspr r3,SPRG0; ba back.
        SPRG0 is the scratch: the firmware only uses SPRG3."""
        # rlwinm with a wrapping mask MB..ME clears one bit: MB=17, ME=15
        # clears bit 16 (EE, 0x8000); MB=31, ME=29 clears bit 30 (RI, 0x2).
        if spr == SPR_EIE:
            edit = [0x60638002]                                    # ori r3,r3,0x8002 (EE|RI)
        elif spr == SPR_EID:
            edit = [_rlwinm(3, 3, 0, 17, 15)]
        else:
            edit = [_rlwinm(3, 3, 0, 17, 15), _rlwinm(3, 3, 0, 31, 29)]
        code = [0x7C7043A6, 0x7C6000A6] + edit + [0x7C600124, 0x7C7042A6, _ba(back)]
        at = self._next_stub
        self._next_stub += MSR_STUB_STRIDE
        assert self._next_stub <= MSR_STUB_BASE + MSR_STUB_SIZE
        self.m.write(at, _asm(code))
        return at

    def handle_trap(self, site):
        """Emulate a trapped instruction. Returns the spr for an MSR site."""
        kind = site[0]
        if kind == "nop":
            return None
        if kind == "msr":
            self.apply_msr_spr_value(site[1])
            return site[1]
        if kind == "dec_read":
            self.m.set_reg(site[1], self.dec)
            return None
        if kind == "dec_write":
            self.dec = self.m.reg(site[1]) & 0xFFFFFFFF
            return None
        _, reg, spr = site
        if kind == "tb_read":
            self.m.set_reg(reg, (self.tb >> 32) if spr == SPR_TBU_R else (self.tb & 0xFFFFFFFF))
        else:
            v = self.m.reg(reg)
            if spr == SPR_TBU_W:
                self.tb = (v << 32) | (self.tb & 0xFFFFFFFF)
            else:
                self.tb = (self.tb & 0xFFFFFFFF00000000) | v
        return None

    def apply_msr_spr_value(self, spr):
        mu = self.m.mu
        msr = mu.reg_read(UC_PPC_REG_MSR)
        if spr == SPR_EIE:
            msr |= MSR_EE | MSR_RI
        elif spr == SPR_EID:
            msr &= ~MSR_EE
        else:
            msr &= ~(MSR_EE | MSR_RI)
        mu.reg_write(UC_PPC_REG_MSR, msr)

    def apply_msr_spr(self, pc):
        """Call from a code hook; returns True when pc was one of them."""
        spr = self.msr_sprs.get(pc)
        if spr is None:
            return False
        mu = self.m.mu
        msr = mu.reg_read(UC_PPC_REG_MSR)
        if spr == SPR_EIE:
            msr |= MSR_EE | MSR_RI
        elif spr == SPR_EID:
            msr &= ~MSR_EE
        else:
            msr &= ~(MSR_EE | MSR_RI)
        mu.reg_write(UC_PPC_REG_MSR, msr)
        return True

    def _build_stubs(self):
        m = self.m
        # One raise stub per exception vector, 0x20 bytes apart from SCRATCH:
        # r3 = SRR0 value, r4 = SRR1 value on entry; both are restored from
        # scratch+0x184.. and the stub ends with the vector's own `ba`
        # instruction copied out of the compressed table, so neither CTR
        # nor LR is disturbed (the program's handler saves whatever it finds
        # in them, so a clobbered CTR would survive the rfi).
        self.saved_regs = 0x00100184       # r3, r4 saved here
        self.raise_stubs = {}
        for i, vector in enumerate((VEC_MACHINE_CHECK, VEC_EXTERNAL, VEC_DECREMENTER, VEC_SYSCALL)):
            stub = SCRATCH + 0x20 * i
            ba = m.read32(vector * VECTOR_STRIDE)
            assert ba >> 26 == 18 and ba & 2, f"vector {vector}: not a ba"
            m.write(stub, _asm([
                0x7C7A03A6,             # mtspr SRR0, r3
                0x7C9B03A6,             # mtspr SRR1, r4
                0x3C600010,             # lis r3, 0x10
                0x80830188,             # lwz r4, 0x188(r3)
                0x80630184,             # lwz r3, 0x184(r3)
                ba,                     # ba handler
            ]))
            self.raise_stubs[vector] = stub

        # read DEC into r3, then stop (the caller runs until the nop after).
        self.read_dec_stub = SCRATCH + 0xA0
        m.write(self.read_dec_stub, _asm([0x7C7602A6, 0x60000000]))        # mfspr r3,DEC ; nop
        # write DEC from r3
        self.write_dec_stub = SCRATCH + 0xB0
        m.write(self.write_dec_stub, _asm([0x7C7603A6, 0x60000000]))       # mtspr DEC,r3 ; nop
        # write TB from r3 (low) and r4 (high)
        self.write_tb_stub = SCRATCH + 0xC0
        m.write(self.write_tb_stub, _asm([0x7C9D03A6, 0x7C7C03A6, 0x60000000]))  # mtspr TBU,r4 ; mtspr TBL,r3 ; nop

    # ---- helpers that run a stub without disturbing the program ----------
    def _run_stub(self, addr, n, r3=None, r4=None):
        m = self.m
        mu = m.mu
        save = (mu.reg_read(UC_PPC_REG_PC), m.reg(3), m.reg(4))
        if r3 is not None:
            m.set_reg(3, r3)
        if r4 is not None:
            m.set_reg(4, r4)
        mu.emu_start(addr, addr + 4 * n, count=n)
        out = m.reg(3)
        mu.reg_write(UC_PPC_REG_PC, save[0])
        m.set_reg(3, save[1])
        m.set_reg(4, save[2])
        return out

    def read_dec(self):
        return self.dec

    def write_dec(self, value):
        self.dec = value & 0xFFFFFFFF

    def write_tb(self, value):
        self.tb = value                        # served to the program by the trapped mftb sites

    @property
    def msr(self):
        return self.m.mu.reg_read(UC_PPC_REG_MSR)

    def interrupts_enabled(self):
        return bool(self.msr & MSR_EE)

    def in_stub(self, pc):
        return SCRATCH <= pc < SCRATCH + 0x100 or MSR_STUB_BASE <= pc < MSR_STUB_BASE + MSR_STUB_SIZE

    def raise_exception(self, vector):
        """Enter the program's exception vector as the hardware would: SRR0 =
        current pc, SRR1 = MSR, MSR[EE] cleared, pc = vector entry. The
        program returns with rfi on its own; the caller just keeps running."""
        m = self.m
        mu = m.mu
        pc = mu.reg_read(UC_PPC_REG_PC)
        msr = self.msr
        m.write32(self.saved_regs, m.reg(3))
        m.write32(self.saved_regs + 4, m.reg(4))
        m.set_reg(3, pc)
        m.set_reg(4, msr)
        mu.reg_write(UC_PPC_REG_MSR, msr & ~MSR_EE)
        stub = self.raise_stubs[vector]
        mu.reg_write(UC_PPC_REG_PC, stub)
        return stub


# ---- the SIU interrupt window --------------------------------------------
SIU_WINDOW = 0x2FC010              # SIPEND, SIMASK, SIEL, SIVEC: 0x2FC010-0x2FC01F
SIU_SHADOW_LIS = 0x11              # the sites compute (lis << 16) - 0x3FF0 ...
SIU_SHADOW = (SIU_SHADOW_LIS << 16) - 0x3FF0        # ... = 0x10C010, in a RAM page of its own
SIU_SHADOW_PAGE = SIU_SHADOW & ~0xFFF


def find_siu_window_sites(image, base):
    """`lis rX, 0x30` instructions whose every use of rX, until rX is
    redefined, addresses 0x2FC010-0x2FC01F (directly, or through
    `addi rX, rX, -0x3FF0` and small offsets). The kernel writes SIMASK in
    every critical section; moving the window into RAM makes those plain
    stores instead of MMIO callbacks."""
    n = len(image) // 4
    words = [struct.unpack(">I", image[4 * i:4 * i + 4])[0] for i in range(n)]
    sites = []
    sipend_stores = []             # stores to SIPEND (write-1-to-clear): become no-ops
    for i, w in enumerate(words):
        if not (w >> 26 == 15 and (w >> 16) & 31 == 0 and w & 0xFFFF == 0x30):
            continue
        rx = (w >> 21) & 31
        ok, used = True, False
        offset = 0                     # what rx holds beyond 0x300000
        for j in range(i + 1, min(n, i + 80)):
            v = words[j]
            op, rd, ra, d = v >> 26, (v >> 21) & 31, (v >> 16) & 31, v & 0xFFFF
            if d & 0x8000:
                d -= 0x10000
            if op == 14 and rd == rx and ra == rx:          # addi rx, rx, d
                offset += d
                if not (0x2FC010 <= 0x300000 + offset <= 0x2FC01F):
                    ok = False
                    break
                continue
            if op in (32, 34, 36, 38, 40, 44, 33, 37) and ra == rx:   # lwz lbz stw stb lhz sth lwzu stwu
                addr = 0x300000 + offset + d
                if not (0x2FC010 <= addr <= 0x2FC01F):
                    ok = False
                    break
                used = True
                if addr < 0x2FC014 and op in (36, 38, 44):
                    sipend_stores.append(base + 4 * j)
                if op in (33, 37):
                    ok = False
                    break
                if rd == rx and op in (32, 34, 40):           # the load redefines rx
                    break
                continue
            if op == 31 and (v >> 1) & 0x3FF in (23, 151, 87, 215, 279, 407) and ra == rx:   # indexed forms
                ok = False
                break
            if op == 18 or op == 16 or op == 19:            # a branch: stop tracking
                if op == 18 and not v & 1:                  # b (not bl) leaves the block
                    break
                continue
            if rd == rx and op not in (36, 38, 44, 37, 31):   # redefined by a non-store
                break
            if op == 31 and rd == rx and (v >> 1) & 0x3FF not in (151, 215, 407, 183):
                break
        if ok and used:
            sites.append(base + 4 * i)
        else:
            sipend_stores = [a for a in sipend_stores if a < base + 4 * i]
    return sites, sipend_stores


def relocate_siu_window(m, sc_sites):
    """Patch the `lis rX, 0x30` sites so the window lives at SIU_SHADOW,
    and make the program's SIPEND stores `sc` no-ops (they clear edge
    requests on hardware; in RAM they would stick)."""
    a1, s1 = find_siu_window_sites(m.pair.mpc, 0)
    a2, s2 = find_siu_window_sites(m.pair.flash, 0xFFF00000)
    m.mu.mem_map(SIU_SHADOW_PAGE, 0x1000)
    for at in a1 + a2:
        for a in ([at, at - 0x100000] if at >= 0xFFF00000 else [at]):
            w = m.read32(a)
            m.write32(a, (w & 0xFFFF0000) | SIU_SHADOW_LIS)
    for at in s1 + s2:
        for a in ([at, at - 0x100000] if at >= 0xFFF00000 else [at]):
            m.write32(a, SC)
            sc_sites[(a + 4) & 0xFFFFFFFF] = ("nop",)
    return a1 + a2, s1 + s2
