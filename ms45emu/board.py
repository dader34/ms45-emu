"""The MS45.1 board around the CPU: open bus, watchdog, and whatever else the
boot needs. Built up one model at a time, each one added when the boot stopped
on it. See docs/full-boot.md for the order.
"""
import struct
from collections import Counter

from unicorn import (UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED,
                     UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ, UC_HOOK_CODE, UcError)

from .machine import Machine, RETURN_SENTINEL
from .qspi import Qspi
from .cpu import Cpu, VEC_EXTERNAL, VEC_DECREMENTER, MSR_FP
from .qadc import Qadc, QADC_A, QADC_B, SCAN_INSTRUCTIONS

RESET_ENTRY = 0xFFF717B4         # the boot code after the reset vector's setup
BOOT_IDLE = 0xFFF717FC           # `b .` at the end of the boot sequence

SWSR = 0x002FC00E                # software watchdog service register
SWSR_SEQUENCE = (0x556C, 0xAA39)


class OpenBus:
    """Addresses with nothing behind them: reads give 0xFF, writes vanish.

    The boot probes for development calibration RAM at 0xFFC40000 by writing
    a pattern and reading it back; on a production DME nothing answers and
    the probe fails, which is the path we want.
    """

    PAGE = 0x1000

    def __init__(self, m: Machine):
        self.m = m
        self.pages = set()
        self.touched = Counter()
        mu = m.mu
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self._unmapped)
        mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._fetch)

    def _unmapped(self, mu, access, addr, size, value, ud):
        page = addr & ~(self.PAGE - 1)
        if page not in self.pages:
            mu.mem_map(page, self.PAGE)
            mu.mem_write(page, b"\xff" * self.PAGE)
            mu.hook_add(UC_HOOK_MEM_WRITE, self._written, begin=page, end=page + self.PAGE - 1)
            self.pages.add(page)
        self.touched[page] += 1
        return True                              # retry the access, it is mapped now

    def _written(self, mu, access, addr, size, value, ud):
        # Writes land, then are undone, so the next read sees the floating bus.
        mu.mem_write(addr, b"\xff" * size)

    def _fetch(self, mu, access, addr, size, value, ud):
        return False                             # executing nothing is a real fault


class Watchdog:
    """Counts services; does not reset the machine (yet)."""

    def __init__(self, m: Machine):
        self.m = m
        self.services = 0
        self.bad = 0
        self._expect = 0
        m.mu.hook_add(UC_HOOK_MEM_WRITE, self._write, begin=SWSR, end=SWSR + 1)

    def _write(self, mu, access, addr, size, value, ud):
        if value == SWSR_SEQUENCE[self._expect]:
            self._expect ^= 1
            if self._expect == 0:
                self.services += 1
        else:
            self.bad += 1
            self._expect = 0


class TpuStub:
    """The TPU acknowledges every host service request at once.

    The boot sets up TPU channels and spins until the host service request
    bits (HSRR0/1 of each TPU) clear, which the TPU microcode does on the
    real part. With the engine stopped nothing else is needed from it.
    """

    HSRR = [0x304018, 0x30401A, 0x304418, 0x30441A]    # TPU A (0x304000) and B (0x304400): HSRR1, HSRR0

    def __init__(self, m: Machine):
        self.m = m
        self.requests = 0
        for reg in self.HSRR:
            m.mu.hook_add(UC_HOOK_MEM_WRITE, self._write, begin=reg, end=reg + 1)
            m.mu.hook_add(UC_HOOK_MEM_READ, self._read, begin=reg, end=reg + 1)

    def _write(self, mu, access, addr, size, value, ud):
        if value:
            self.requests += 1

    def _read(self, mu, access, addr, size, value, ud):
        # A write hook runs before the store lands, so the request is
        # cleared here instead: the first read back sees it serviced.
        mu.mem_write(addr & ~1, b"\x00\x00")


MIOS_SR0, MIOS_ER0, MIOS_RPR0 = 0x306C00, 0x306C04, 0x306C06
MIOS_SR1, MIOS_ER1, MIOS_RPR1 = 0x306C40, 0x306C44, 0x306C46
SOFT_EVENT_BIT = 0x40          # MIOS1 bank 1, bit 6: the OS's "events posted" interrupt


class MiosInterrupts:
    """The MIOS1 interrupt request logic, as far as the OS uses it.

    Completed QSPI jobs (and other things) are posted as events, and the
    poster enables MIOS1 bank-1 interrupt bit 6, whose status flag is
    permanently asserted, so enabling it is a software interrupt. The MIOS
    handler (SIU level 6) reads the request-pending registers, which are
    status AND enable, and dispatches by bit.
    """

    def __init__(self, m: Machine, raise_interrupt):
        self.m = m
        self.raise_interrupt = raise_interrupt
        self.pending = False
        self.posted = 0
        mu = m.mu
        mu.hook_add(UC_HOOK_MEM_WRITE, self._er1_write, begin=MIOS_ER1, end=MIOS_ER1 + 1)
        mu.hook_add(UC_HOOK_MEM_READ, self._rpr_read, begin=MIOS_RPR0, end=MIOS_RPR0 + 1)
        mu.hook_add(UC_HOOK_MEM_READ, self._rpr_read, begin=MIOS_RPR1, end=MIOS_RPR1 + 1)
        mu.hook_add(UC_HOOK_MEM_READ, self._sr1_read, begin=MIOS_SR1, end=MIOS_SR1 + 1)

    def _sr1_read(self, mu, access, addr, size, value, ud):
        m = self.m
        m.write16(MIOS_SR1, m.read16(MIOS_SR1) | SOFT_EVENT_BIT)

    def _rpr_read(self, mu, access, addr, size, value, ud):
        m = self.m
        sr1 = m.read16(MIOS_SR1) | SOFT_EVENT_BIT
        m.write16(MIOS_RPR1, sr1 & m.read16(MIOS_ER1))
        m.write16(MIOS_RPR0, m.read16(MIOS_SR0) & m.read16(MIOS_ER0))

    def _er1_write(self, mu, access, addr, size, value, ud):
        if value & SOFT_EVENT_BIT and not (self.m.read16(MIOS_ER1) & SOFT_EVENT_BIT):
            self.pending = True

    def service(self):
        if self.pending:
            self.pending = False
            self.posted += 1
            self.raise_interrupt(None)


# SIU interrupt levels, as bit positions from the MSB of SIPEND/SIMASK:
# IRQ0=0, LVL0=1, IRQ1=2, LVL1=3, ... LVL7=15. The program's external
# interrupt prologue picks the highest set bit of SIPEND & SIMASK and
# dispatches through its table at MPC 0xB4C4.
SIPEND, SIMASK = 0x2FC010, 0x2FC014
LEVEL_TPU, LEVEL_QADC, LEVEL_QSPI, LEVEL_MIOS = 3, 7, 9, 13

# One emulated instruction counts as one system clock; TB and DEC run at
# sysclk/4 on the MPC555.
CLOCKS_PER_TICK = 4
SLICE = 20_000

# The OS tick is MIOS PWM submodule 2's period interrupt (MIOS1 bank 0,
# bit 2): PERR 0x8235 at the MIOS clock gives about 10 ms. In emulated time
# that is this many instructions.
TICK_INSTRUCTIONS = 400_000
PWM2_BIT = 0x0004
INTERRUPT_NEST = 0x3FA0E4        # the program's own EID/EIE nesting counter


class WriteZeroToClear:
    """Status registers where software clears a flag by writing 0 to it and
    1s leave the other flags alone (TPU CISR, MIOS status). A write hook
    sees the value before it lands, so the correction is applied at the
    next instruction."""

    REGS = [0x304020, 0x304420, 0x306C00, 0x306C40, 0x304810, 0x304C10]

    def __init__(self, m: Machine):
        self.m = m
        self.fixups = []
        for reg in self.REGS:
            m.mu.hook_add(UC_HOOK_MEM_WRITE, self._write, begin=reg, end=reg + 1)

    def _write(self, mu, access, addr, size, value, ud):
        if size == 2:
            self.fixups.append((addr, self.m.read16(addr) & value))

    def service(self):
        for addr, v in self.fixups:
            self.m.write16(addr, v)
        self.fixups.clear()


class Board:
    def __init__(self, pair):
        self.m = Machine(pair)
        self.bus = OpenBus(self.m)
        self.watchdog = Watchdog(self.m)
        self.tpu = TpuStub(self.m)
        self.w0c = WriteZeroToClear(self.m)
        self.adc_a = Qadc(self.m, QADC_A, "A")
        self.adc_b = Qadc(self.m, QADC_B, "B")
        self._next_scan = SCAN_INSTRUCTIONS
        self.cpu = Cpu(self.m)
        self.pending_levels = set()
        self.qspi = Qspi(self.m, lambda _id: self._raise())
        self.mios = MiosInterrupts(self.m, lambda _id: self._raise())
        self.interrupts_taken = Counter()
        self.dec_exceptions = 0
        self.fp_enables = 0
        self.dec_pending = False
        self.irq_check = False
        self.instructions = 0
        self.ticks = 0
        self._next_tick = TICK_INSTRUCTIONS
        self.visits = Counter()
        self.trail = []
        self.m.mu.hook_add(UC_HOOK_CODE, self._code)
        self.m.mu.hook_add(UC_HOOK_MEM_READ, self._sipend_read, begin=SIPEND, end=SIPEND + 3)

    def _code(self, mu, pc, size, ud):
        self.visits[pc] += 1
        if pc in self.cpu.msr_sprs:
            self.cpu.apply_msr_spr(pc)
            self.irq_check = True
        elif pc in self.cpu.rfi_sites:
            self.irq_check = True                  # EE comes back with the rfi
        elif self.irq_check:
            # Interrupts are taken here, at instruction boundaries, the way
            # the CPU does it: as soon as EE allows and a level is pending.
            self.irq_check = False
            if self._can_interrupt():
                if self.dec_pending:
                    self.dec_pending = False
                    self.cpu.raise_exception(VEC_DECREMENTER)
                    self.dec_exceptions += 1
                    return
                pend = self.pending_external() & self.m.read32(SIMASK)
                if pend:
                    level = 32 - pend.bit_length()
                    self.cpu.raise_exception(VEC_EXTERNAL)
                    self.interrupts_taken[level] += 1
        self.trail.append(pc)
        if len(self.trail) > 64:
            self.trail.pop(0)
        if self.w0c.fixups:
            self.w0c.service()
        if self.qspi.pending:
            self.qspi.service()
        if self.mios.pending:
            self.mios.service()

    # ---- interrupts, raised between slices ----------------------------
    def _can_interrupt(self):
        return self.cpu.interrupts_enabled() and self.m.read32(INTERRUPT_NEST) == 0

    def _raise(self):
        self.irq_check = True

    def _sipend_read(self, mu, access, addr, size, value, ud):
        self.m.write32(SIPEND, self.pending_external())

    def pending_external(self):
        """SIPEND as the devices drive it: level interrupts stay asserted
        while their source does."""
        m = self.m
        pend = 0
        from .qspi import SPSR, SPCR2, SPIF, SPIFIE
        if m.read8(SPSR) & SPIF and m.read16(SPCR2) & SPIFIE:
            pend |= 0x80000000 >> LEVEL_QSPI
        sr1 = m.read16(MIOS_SR1) | SOFT_EVENT_BIT
        if (sr1 & m.read16(MIOS_ER1)) or (m.read16(MIOS_SR0) & m.read16(MIOS_ER0)):
            pend |= 0x80000000 >> LEVEL_MIOS
        if (m.read16(0x304020) & m.read16(0x30400A)) or (m.read16(0x304420) & m.read16(0x30440A)):
            pend |= 0x80000000 >> LEVEL_TPU
        if self.adc_a.interrupt_pending() or self.adc_b.interrupt_pending():
            pend |= 0x80000000 >> LEVEL_QADC
        return pend

    def _raise_external(self, level):
        self.cpu.raise_exception(VEC_EXTERNAL)
        self.interrupts_taken[level] += 1

    def _advance_clocks(self, instructions):
        """Time base and decrementer move with instruction count."""
        ticks = instructions // CLOCKS_PER_TICK
        self.cpu.tb += ticks
        self.cpu.write_tb(self.cpu.tb)
        dec = self.cpu.read_dec()
        new = (dec - ticks) & 0xFFFFFFFF
        self.cpu.write_dec(new)
        return dec < 0x80000000 and new >= 0x80000000      # crossed from positive to negative

    def boot(self, max_insns=5_000_000, until=BOOT_IDLE):
        """Run the reset path in slices, raising interrupts between them.
        Returns (reached_idle, reason)."""
        pc = RESET_ENTRY
        self.m.mu.reg_write(__import__("unicorn.ppc_const", fromlist=["x"]).UC_PPC_REG_MSR, 0)
        return self.run_from(pc, max_insns, until)

    def run_from(self, pc, max_insns, until=BOOT_IDLE):
        done = 0
        try:
            while done < max_insns:
                self.m.run(pc, until, max_insns=SLICE)
                pc = self.m.pc
                done += SLICE
                self.instructions += SLICE
                if pc == until:
                    return True, "idle"
                if self._advance_clocks(SLICE):
                    self.dec_pending = True
                # A software-started ADC scan takes real time (a few hundred
                # microseconds), so it completes at the slice boundary, not
                # at the next instruction.
                self.adc_a.service()
                self.adc_b.service()
                if self.adc_a.queue2_started or self.adc_b.queue2_started:
                    # The first scan of a freshly enabled queue completes
                    # within the slice; later ones keep the period.
                    self.adc_a.queue2_started = self.adc_b.queue2_started = False
                    self._next_scan = self.instructions
                if self.instructions >= self._next_scan:
                    self._next_scan += SCAN_INSTRUCTIONS
                    self.adc_a.periodic()
                    self.adc_b.periodic()
                if self.instructions >= self._next_tick:
                    self._next_tick += TICK_INSTRUCTIONS
                    self.ticks += 1
                    if self.m.read16(MIOS_ER0) & PWM2_BIT:
                        self.m.write16(MIOS_SR0, self.m.read16(MIOS_SR0) | PWM2_BIT)
                self.irq_check = True
        except UcError as e:
            # The program uses the FPU and relies on the "FP unavailable"
            # exception to switch it on. Unicorn stops on that exception
            # instead of vectoring, so it is handled here the same way:
            # set MSR[FP] and resume the instruction.
            if "exception" in str(e).lower() and not (self.cpu.msr & MSR_FP):
                from unicorn.ppc_const import UC_PPC_REG_MSR
                self.m.mu.reg_write(UC_PPC_REG_MSR, self.cpu.msr | MSR_FP)
                self.fp_enables += 1
                return self.run_from(self.m.pc, max_insns - done, until)
            return False, f"{e} at pc=0x{self.m.pc:X}"
        return False, f"ran out of instructions at pc=0x{self.m.pc:X}"

    def report(self):
        hot = ", ".join(f"0x{p:X}x{n}" for p, n in self.visits.most_common(6))
        tail = " ".join(f"{p:X}" for p in self.trail[-10:])
        return (f"watchdog services={self.watchdog.services} bad={self.watchdog.bad}; "
                f"tpu requests={self.tpu.requests}; qspi transfers={self.qspi.transfers} "
                f"(eeprom reads={self.qspi.eeprom.reads} writes={self.qspi.eeprom.writes}); "
                f"events posted={self.mios.posted}; ticks={self.ticks}; fp enables={self.fp_enables}; adc scans={self.adc_a.scans}/{self.adc_b.scans}; interrupts={dict(self.interrupts_taken)} dec={self.dec_exceptions}; "
                f"open-bus pages={sorted(hex(p) for p in self.bus.pages)}\n"
                f"hot: {hot}\ntrail: {tail}")
