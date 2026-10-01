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
        elif xo == 371 or (xo == 339 and spr in (SPR_TBL_R, SPR_TBU_R)):
            out[addr] = ("tb_read", reg, spr)
        elif xo == 467 and spr in (SPR_TBL_W, SPR_TBU_W):
            out[addr] = ("tb_write", reg, spr)
    return out


def find_msr_sprs(image, base):
    return {a: v[1] for a, v in find_trap_sites(image, base).items() if v[0] == "msr"}


SC = 0x44000002


class Cpu:
    def __init__(self, m):
        self.m = m
        self.tb = 0
        self.dec_base = 0
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
        for pc, site in self.trap_sites.items():
            m.write32(pc, SC)
            self.sc_sites[(pc + 4) & 0xFFFFFFFF] = site
            if pc >= 0xFFF00000:
                m.write32(pc - 0x100000, SC)          # the 0xFFExxxxx mirror
                self.sc_sites[(pc - 0x100000 + 4) & 0xFFFFFFFF] = site
        from .checksums import refresh_program_sums
        refresh_program_sums(m)

    def handle_trap(self, site):
        """Emulate a trapped instruction. Returns the spr for an MSR site."""
        kind = site[0]
        if kind == "msr":
            self.apply_msr_spr_value(site[1])
            return site[1]
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
        return self._run_stub(self.read_dec_stub, 1)

    def write_dec(self, value):
        self._run_stub(self.write_dec_stub, 1, r3=value & 0xFFFFFFFF)

    def write_tb(self, value):
        self.tb = value                        # served to the program by the trapped mftb sites

    @property
    def msr(self):
        return self.m.mu.reg_read(UC_PPC_REG_MSR)

    def interrupts_enabled(self):
        return bool(self.msr & MSR_EE)

    def in_stub(self, pc):
        return SCRATCH <= pc < SCRATCH + 0x100

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
