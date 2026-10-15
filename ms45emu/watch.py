"""The MPC555's L-bus data breakpoint, as far as the live-tune transport uses
it (transport.py, op 09): comparators E and F bracket one address range, the
first L-bus watchpoint is a breakpoint on reads of it, taken after the load
with the address in BAR.

Unicorn has no model of the development-support registers: an mtspr to SPR
148-159 stores nothing and an mfspr leaves the register as it was. So the
stub's own SPR instructions become `sc` probes -- the board's way of
emulating an instruction without a code hook on the whole program -- which
keep the registers here; arming puts a bounded read hook on the range, and
a hit enters the vector from inside the hook (Cpu.enter_breakpoint). The
hook runs before the access and the exit after it, which is the hardware's
order, except that unicorn leaves the instruction at its memory access: an
update-form load's rA is written here instead, and a load the handler would
not act on anyway (it keeps what it loaded) is not interrupted at all.
"""
from unicorn import UC_HOOK_MEM_READ
from unicorn.ppc_const import UC_PPC_REG_PC, UC_PPC_REG_MSR

from . import transport
from .cpu import SC, MSR_RI

LOADS = {32, 34, 40, 42}                  # lwz lbz lhz lha
UPDATE_LOADS = {33, 35, 41, 43}           # and with update
X_LOADS = {23, 87, 279, 343}              # lwzx lbzx lhzx lhax
X_UPDATE_LOADS = {55, 119, 311, 375}


class DataBreakpoint:
    def __init__(self, board, base):
        """`base`: where the transport stub starts (transport.stub_base)."""
        self.board = board
        self.sprs = {}
        self.bar = 0
        self.range = None
        self.hits = 0
        self._hook = None
        m = board.m
        for at in range(base, base + transport.STUB_SIZE, 4):
            w = m.read32(at)
            if w >> 26 != 31:
                continue
            xo, rs = (w >> 1) & 0x3FF, (w >> 21) & 31
            spr = ((w >> 16) & 31) | (((w >> 11) & 31) << 5)
            if not 148 <= spr <= 159 or xo not in (339, 467):
                continue
            if xo == 467:
                fn = lambda m, spr=spr, rs=rs: self._write(spr, m.reg(rs))      # mtspr
            else:
                fn = lambda m, rs=rs: m.set_reg(rs, self.bar)                   # mfspr (BAR)
            for site in (at, at - 0x100000):                                    # and the chip's lower window
                m.write32(site, SC)
                board.probes[(site + 4) & 0xFFFFFFFF] = (f"spr{spr}@{at:X}", fn)
        from .checksums import refresh_program_sums
        refresh_program_sums(m)

    def _write(self, spr, value):
        self.sprs[spr] = value
        armed = None
        if self.sprs.get(transport.LCTRL2, 0) & 0x80000000:
            # only the way the stub programs it: E greater-than, F less-than, reads
            if self.sprs.get(transport.LCTRL1) != transport.LCTRL1_RANGE or \
                    self.sprs[transport.LCTRL2] != transport.LCTRL2_ARM:
                raise ValueError("the breakpoint is programmed in a way this model does not know")
            armed = ((self.sprs[transport.CMPE] + 1) & 0xFFFFFFFF, self.sprs[transport.CMPF])
        if armed == self.range:
            return
        mu = self.board.m.mu
        if self._hook is not None:
            mu.hook_del(self._hook)
            self._hook = None
        self.range = armed
        if armed and armed[0] < armed[1]:
            self._hook = mu.hook_add(UC_HOOK_MEM_READ, self._read, begin=armed[0], end=armed[1] - 1)

    def _read(self, mu, access, addr, size, value, ud):
        if not mu.reg_read(UC_PPC_REG_MSR) & MSR_RI:        # masked mode: ignored
            return
        m, cpu = self.board.m, self.board.cpu
        pc = mu.reg_read(UC_PPC_REG_PC)
        if cpu.in_stub(pc):
            return
        w = m.read32(pc)
        op, xo = w >> 26, (w >> 1) & 0x3FF
        if op in UPDATE_LOADS or (op == 31 and xo in X_UPDATE_LOADS):
            m.set_reg((w >> 16) & 31, addr)
        elif op not in LOADS and not (op == 31 and xo in X_LOADS):
            return
        self.bar = addr
        self.hits += 1
        cpu.enter_breakpoint(pc + 4)
