"""The MS45.1 board around the CPU: the peripherals the boot needs, and
interrupt delivery. See docs/full-boot.md for what is modelled and why.

Performance note: nothing here runs on every instruction. Peripheral
registers are MMIO (Python is called only on register access), the few
hundred EIE/EID/rfi sites have their own code hooks, and interrupts are
delivered at those sites and at slice boundaries.
"""
from collections import Counter

from unicorn import (UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_WRITE_PROT, UC_PROT_EXEC,
                     UC_HOOK_MEM_WRITE, UC_HOOK_INTR, UC_PROT_READ, UC_PROT_WRITE, UcError)
from unicorn.ppc_const import UC_PPC_REG_MSR, UC_PPC_REG_PC

from .machine import Machine, MPC_BASE, MPC_MAP, EXT_BASE, EXT_SIZE
from .periph import MmioPage, write_zero_to_clear
from .qspi import Qspi
from .qadc import Qadc, QADC_A, QADC_B
from .toucan import TouCan
from .sci import Sci
from .cpu import Cpu, VEC_EXTERNAL, VEC_DECREMENTER, VEC_SYSCALL, MSR_FP, MSR_IP, SPR_EIE, SIU_SHADOW, BBCMCR_ETRE

RESET_ENTRY = 0xFFF717B4         # the boot code after the reset vector's setup
RESET_VECTOR = 0xFFF00100        # the real one, in the boot loader: starts the program only if it is marked valid
BOOT_IDLE = 0xFFF717FC           # `b .` at the end of the boot sequence

# Peripheral pages (MPC555, IMMR = 0x2F0000).
SIU_PAGE = 0x2FC000              # SIU, memory controller, timers
TPU_QADC_QSMCM_PAGE = 0x304000   # TPU A/B, QADC A/B, QSMCM: 0x304000-0x305FFF
MIOS_PAGE = 0x306000
CAN_PAGE = 0x307000              # TouCAN A at +0x80, B at +0x480

SWSR = 0x2FC00E
TBSCR, TBREF0, TBREF1 = 0x2FC200, 0x2FC204, 0x2FC208
TB_REFA, TB_REFB, TB_REFAE, TB_REFBE = 0x80, 0x40, 0x08, 0x04
SWSR_SEQUENCE = (0x556C, 0xAA39)
SIPEND, SIMASK = 0x2FC010, 0x2FC014
# Periodic interrupt timer. The boot loader's main loop (programming mode)
# has no OS: it polls PISCR[PS] for its 1 ms tick. PITC = 999 there, so the
# PIT counts at 1 MHz (the 4 MHz crystal / 4).
PISCR, PITC = 0x2FC240, 0x2FC244
PLPRCR, PLL_LOCKED = 0x2FC284, 0x00010000
PIT_PS, PIT_PIE, PIT_PTE = 0x80, 0x04, 0x01
PIT_HZ = 1_000_000
BR0, OR0 = 0x2FC100, 0x2FC104

TPU_HSRR = [0x304018, 0x30401A, 0x304418, 0x30441A]    # TPU A (0x304000), B (0x304400): HSRR1, HSRR0
TPU_CISR = [0x304020, 0x304420]
TPU_CIER = [0x30400A, 0x30440A]

MPIOSMDR, MPIOSMDDR = 0x306100, 0x306102      # MIOS parallel port: data, direction
FLASH_ENABLE_PIN = 0x0040
MMCSM22_COUNTER = 0x3060B0       # MIOS modulus counter 22: the time base of the MIOS PWM outputs
MIOS_SR0, MIOS_ER0, MIOS_RPR0 = 0x306C00, 0x306C04, 0x306C06
MIOS_SR1, MIOS_ER1, MIOS_RPR1 = 0x306C40, 0x306C44, 0x306C46
SOFT_EVENT_BIT = 0x40            # MIOS1 bank 1 bit 6: the OS's "events posted" interrupt
PWM2_BIT = 0x0004                # MIOS1 bank 0 bit 2: the OS tick

# SIU interrupt levels as bit positions from the MSB of SIPEND/SIMASK:
# IRQ0=0, LVL0=1, IRQ1=2, LVL1=3, ... LVL7=15.
LEVEL_TPU, LEVEL_QADC, LEVEL_QSPI, LEVEL_MIOS = 3, 7, 9, 13

INTERRUPT_NEST = 0x3FA0E4        # the program's own EID/EIE nesting counter (looked up per program, see find_interrupt_nest)
KL15_CHANNEL = 55                # QADC B: ignition sense
# What the loader leaves in the external flash once a part is complete and
# its signature checked: program (0xFFF80, 0xFFFC0), calibration (0x5FF80, 0x5FFC0).
VALID_MARKS = ((0xFFF80, 0x42902448), (0xFFFC0, 0x42244890), (0x5FF80, 0x48249042), (0x5FFC0, 0x90482442))
BATTERY_CHANNEL = 50             # QADC B: supply voltage; the loader refuses to flash below 0x218
BATTERY_OK = 0x320
KL15_FLAG = 0x3FD853             # the DME's "KL15 on" state byte
RAM_START, RAM_END = 0x3F8000, 0x400000

# TB and DEC clock. The kernel tick is 2500 time-base units, the scheduler
# runs every 5 ticks and the 10 ms CAN frame 0x316 every 10, so a tick is
# 1 ms and the time base runs at 2.5 MHz: the 40 MHz core clock divided by
# 16. 1 instruction = 1 clock here.
TB_HZ = 2_500_000                # 16 instructions per unit at the default 40 MIPS
SLICE = 20_000
HURRY_SLICE = 256                # while an interrupt waits for the program to allow it
HURRY_LIMIT = 200                # ... unless it keeps them off (the boot loader never enables them)
BUSY_SLICE, BUSY_SLICES = 2000, 10   # after interrupt activity, this many short slices


class OpenBus:
    """Addresses with nothing behind them: reads give 0xFF, writes vanish.
    The boot probes for development calibration RAM at 0xFFC40000; on a
    production DME nothing answers and the probe fails, as wanted."""

    PAGE = 0x1000

    def __init__(self, m: Machine):
        self.m = m
        self.pages = set()
        mu = m.mu
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self._unmapped)
        mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, lambda *a: False)

    def _unmapped(self, mu, access, addr, size, value, ud):
        page = addr & ~(self.PAGE - 1)
        if page not in self.pages:
            # Plain RAM, not executable, with writes undone so reads stay 0xFF.
            mu.mem_map(page, self.PAGE, UC_PROT_READ | UC_PROT_WRITE)
            mu.mem_write(page, b"\xff" * self.PAGE)
            mu.hook_add(UC_HOOK_MEM_WRITE, lambda uc, a, ad, sz, v, u: uc.mem_write(ad, b"\xff" * sz),
                        begin=page, end=page + self.PAGE - 1)
            self.pages.add(page)
        return True


class Board:
    def __init__(self, pair, patch_program=True, mips=40):
        """patch_program=False prepares only the boot loader for emulation
        and leaves the program's bytes alone (see Cpu): for a DME that
        will stay in the loader.

        mips is how many million instructions make a second of the DME's
        time. 40 counts an instruction as one clock of the 40 MHz CPU. The
        program keeps its schedule down to 10, where the emulator is faster
        than real time, which is what a tester on a real clock needs."""
        self.m = Machine(pair, periph_ram=False)
        m = self.m
        self.mips = mips
        self.ips = mips * 1_000_000                       # instructions per second
        self.clocks_per_tick = self.ips // TB_HZ          # instructions per time base unit
        self.tick_instructions = self.ips // 100          # the MIOS PWM2 period, 10 ms
        self.scan_instructions = self.ips // 100          # a periodic ADC scan, 10 ms
        self.pit_clock_instructions = self.ips // PIT_HZ
        assert self.clocks_per_tick >= 1 and self.pit_clock_instructions >= 1
        self.cpu = Cpu(m, program=patch_program)
        self.interrupt_nest = (self.find_interrupt_nest() if patch_program else None) or (INTERRUPT_NEST if m.pair.traced else None)
        self.bus = OpenBus(m)

        self.siu = MmioPage(m, SIU_PAGE, 0x1000)
        # Memory controller: CS0 is the external flash, 2 MB at 0xFFE00000
        # from the reset configuration; the firmware only ORs bits into it.
        self.siu.poke32(BR0, 0xFFE00001)
        self.siu.poke32(OR0, 0xFFE00000)
        self.imb = MmioPage(m, TPU_QADC_QSMCM_PAGE, 0x2000)
        self.mios = MmioPage(m, MIOS_PAGE, 0x1000)

        # watchdog
        self.watchdog_services = 0
        self.watchdog_bad = 0
        self._wd_expect = 0
        self.siu.on_write(SWSR, self._swsr_write)
        # TBSCR status bits are write-1-to-clear; the rest is a control register.
        self.siu.on_write(TBSCR, lambda a, size, value: (self.siu.peek16(TBSCR) & ~(value & (TB_REFA | TB_REFB))) & 0xFF3F | (value & 0xFF3F) if size == 2 else None)
        self.tb_interrupts = 0
        self.tb_late_refs = 0
        self.tb_irq_enabled = True
        # A reference written already behind TB would only match after a
        # wrap; the kernel checks for that itself (mftb after the write) and
        # moves on, so it is only counted here.
        for ref, flag in ((TBREF0, TB_REFA), (TBREF1, TB_REFB)):
            self.siu.on_write(ref, lambda a, size, value, flag=flag: self._tbref_write(size, value, flag))
        self.siu.on_read(SIPEND, lambda a, s: self.pending_external())   # for sites not relocated
        # The reset path waits for the PLL to report lock before it sets the clocks.
        self.siu.on_read(PLPRCR, lambda a, s: self.siu.peek32(PLPRCR) | PLL_LOCKED if s == 4 else None)
        self.pit_expiries = 0
        self._next_pit = None
        self.siu.on_write(PISCR, self._piscr_write)

        # TPU: host service requests are acknowledged at once; CISR is write-0-to-clear
        from .tpu import Tpu, Crank
        self.tpu_a = Tpu(self.imb, 0x304000, "A")
        self.tpu_b = Tpu(self.imb, 0x304400, "B")
        self.tpu_requests = 0
        self.crank = Crank(self)
        for reg in TPU_HSRR:
            self.imb.on_write(reg, self._hsrr_write)
            self.imb.on_read(reg, lambda a, s: 0)
        for reg in TPU_CISR:
            write_zero_to_clear(self.imb, reg)

        # QSPI with the EEPROM, ADCs
        self.qspi = Qspi(self.imb, lambda: self.instructions, self.ips)
        self.adc_a = Qadc(self.imb, QADC_A, "A", lambda: self.instructions, self.ips)
        self.adc_b = Qadc(self.imb, QADC_B, "B", lambda: self.instructions, self.ips)
        self.ignition(True)
        self.adc_b.channels[BATTERY_CHANNEL] = BATTERY_OK

        # CAN: A is the vehicle bus, B the second module
        self.canp = MmioPage(m, CAN_PAGE, 0x1000)
        self.can_a = TouCan(self.canp, CAN_PAGE + 0x80, "A", lambda: self.instructions)
        self.can_b = TouCan(self.canp, CAN_PAGE + 0x480, "B", lambda: self.instructions)
        # K-line
        self.sci = Sci(self.imb, lambda: self.instructions, self.ips)
        # The flash is read-only to the program; writes are commands to the
        # chips (or stray) and go to the flash models through the hook.
        m.mu.mem_protect(MPC_BASE, MPC_MAP, UC_PROT_READ | UC_PROT_EXEC)
        m.mu.mem_protect(EXT_BASE, EXT_SIZE, UC_PROT_READ | UC_PROT_EXEC)
        self.flash_writes = []
        from .flashchip import FlashChip
        from .cmf import Cmf
        self.flash = FlashChip(m)
        # The internal flash only takes program/erase with its EPEE pin
        # high. The loader's flash-init raises MPIO pin 6 (0x306100 bit
        # 0x40) before anything else and the reset path never touches it,
        # so that pin is taken to be the enable.
        self.cmf = Cmf(m, self.siu, lambda: bool(self.mios.peek16(MPIOSMDR) & self.mios.peek16(MPIOSMDDR) & FLASH_ENABLE_PIN))
        m.mu.hook_add(UC_HOOK_MEM_WRITE_PROT, self._flash_write)
        # A dump read over diagnostics comes without the loader's "valid"
        # marks. A DME that runs its program has them, so put them back.
        if patch_program:
            for at, mark in VALID_MARKS:
                if self.flash.image[at:at + 4] == b"\xff\xff\xff\xff":
                    self.flash.store(at, mark.to_bytes(4, "big"))

        # MIOS interrupts: status registers write-0-to-clear, request = status & enable,
        # bank-1 bit 6 always asserted (the OS's software interrupt).
        for reg in (MIOS_SR0, MIOS_SR1):
            write_zero_to_clear(self.mios, reg)
        self.mios.on_read(MIOS_SR1, lambda a, s: self.mios.peek16(MIOS_SR1) | SOFT_EVENT_BIT)
        self.mios.on_read(MIOS_RPR0, lambda a, s: self.mios.peek16(MIOS_SR0) & self.mios.peek16(MIOS_ER0))
        self.mios.on_read(MIOS_RPR1, lambda a, s: (self.mios.peek16(MIOS_SR1) | SOFT_EVENT_BIT) & self.mios.peek16(MIOS_ER1))
        self.events_posted = 0
        self.mios.on_write(MIOS_ER1, self._er1_write)
        # The PWM duty update (0x1B538, used once the engine runs) waits
        # for this counter to be clear of the old pulse width before it
        # writes the new one, so it has to count. Each read moves it on as
        # well: the instruction count only advances between slices.
        self._counter_reads = 0
        self.mios.on_read(MMCSM22_COUNTER, self._mmcsm_read)

        # interrupt bookkeeping
        self.interrupts_taken = Counter()
        self.dec_exceptions = 0
        self.dec_pending = False
        self._hurry = False
        self._hurried = 0
        self._busy = 0
        self.fp_enables = 0
        self.instructions = 0
        self.ticks = 0
        self._next_tick = self.tick_instructions
        self._next_scan = self.scan_instructions

        # The only hook on the instruction stream: the exception raised by
        # the `sc` that replaced each EIE/EID/NRI, and any real `sc`.
        self.syscalls = 0
        self.other_exceptions = Counter()
        self.probes = {}
        self.probe_counts = Counter()
        m.mu.hook_add(UC_HOOK_INTR, self._intr)

    # ---- probes -----------------------------------------------------------
    def probe(self, addr, name=None, on_hit=None):
        """Count executions of the instruction at addr without a code hook:
        it is replaced by `sc` and emulated in the exception hook. Only the
        usual function-entry instructions are supported (stwu r1,..(r1),
        mflr r0, and simple li/lbz/lhz/lwz/addi forms). on_hit(board) is
        called before the instruction is emulated, with the registers as
        they were on entry."""
        from unicorn.ppc_const import UC_PPC_REG_LR
        w = self.m.read32(addr)
        op = w >> 26
        rt, ra, d = (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
        if d & 0x8000:
            d -= 0x10000
        if w == 0x7C0802A6:
            fn = lambda m: m.set_reg(0, m.mu.reg_read(UC_PPC_REG_LR))
        elif op == 37 and rt == 1 and ra == 1:                    # stwu r1,d(r1)
            def fn(m, d=d):
                sp = (m.reg(1) + d) & 0xFFFFFFFF
                m.write32(sp, m.reg(1)); m.set_reg(1, sp)
        elif op == 14:                                              # addi / li
            fn = lambda m, rt=rt, ra=ra, d=d: m.set_reg(rt, (m.reg(ra) if ra else 0) + d)
        elif op == 15:                                              # addis / lis
            fn = lambda m, rt=rt, ra=ra, d=d: m.set_reg(rt, (m.reg(ra) if ra else 0) + (d << 16))
        elif op in (32, 34, 40):                                    # lwz / lbz / lhz
            size = {32: 4, 34: 1, 40: 2}[op]
            fn = lambda m, rt=rt, ra=ra, d=d, size=size: m.set_reg(rt, int.from_bytes(m.read(((m.reg(ra) if ra else 0) + d) & 0xFFFFFFFF, size), "big"))
        else:
            raise ValueError(f"probe at 0x{addr:X}: unsupported instruction {w:08X}")
        self.m.write32(addr, 0x44000002)
        if on_hit is not None:
            inner = fn
            def fn(m, inner=inner, on_hit=on_hit):
                on_hit(self)
                inner(m)
        self.probes[(addr + 4) & 0xFFFFFFFF] = (name or f"0x{addr:X}", fn)
        self.probe_counts[name or f"0x{addr:X}"] = 0

    def _flash_write(self, mu, access, addr, size, value, ud):
        if len(self.flash_writes) < 10000:
            self.flash_writes.append((addr, size, value, self.m.pc))
        # External flash: a command to the chip. Internal flash: program
        # data or the erase interlock for the CMF.
        if any(base <= addr < base + self.flash.size for base in self.flash.windows):
            self.flash.write(addr, size, value)
        elif addr < self.cmf.size:
            self.cmf.array_write(addr, size, value)
        return True                                   # the raw store is still dropped

    # ---- register handlers -----------------------------------------------
    def _tbref_write(self, size, value, flag):
        if size == 4 and self.siu.peek16(TBSCR) & 0x1:
            behind = (self.cpu.tb - value) & 0xFFFFFFFF
            if 0 < behind < 0x80000000:
                self.tb_late_refs += 1
        return None

    def _piscr_write(self, addr, size, value):
        if size != 2:
            return None
        old = self.siu.peek16(PISCR)
        # The application leaves PITC at 0 and never looks at PS; only a
        # real period is worth cutting slices for.
        if value & PIT_PTE and self.siu.peek32(PITC) >> 16:
            if self._next_pit is None:
                self._next_pit = self.instructions + self._pit_period()
        else:
            self._next_pit = None
        return (old & PIT_PS & ~value) | (value & ~PIT_PS)       # PS is write-1-to-clear

    def _pit_period(self):
        return ((self.siu.peek32(PITC) >> 16) + 1) * self.pit_clock_instructions

    def _swsr_write(self, addr, size, value):
        if value == SWSR_SEQUENCE[self._wd_expect]:
            self._wd_expect ^= 1
            if self._wd_expect == 0:
                self.watchdog_services += 1
        else:
            self.watchdog_bad += 1
            self._wd_expect = 0
        return None

    def _hsrr_write(self, addr, size, value):
        if value:
            self.tpu_requests += 1
            # Each channel's request is "serviced": the DME's own microcode
            # reports completion in parameter word 7 (bit 13) of the channel,
            # which some drivers wait for. HSRR1 holds channels 15-8, HSRR0
            # channels 7-0, two bits per channel.
            tpu = 0x304000 if addr < 0x304400 else 0x304400
            first = 8 if addr in (0x304018, 0x304418) else 0
            for i in range(8):
                if (value >> (2 * i)) & 3:
                    ch = first + i
                    w7 = tpu + 0x100 + ch * 16 + 0xE
                    self.imb.poke16(w7, self.imb.peek16(w7) | 0x2000)
                    (self.tpu_a if tpu == 0x304000 else self.tpu_b).on_service(ch, self.instructions, (value >> (2 * i)) & 3)
        return 0                                  # serviced before it can be read back

    def _mmcsm_read(self, addr, size):
        if size != 2:
            return None
        self._counter_reads += 1
        return (self.instructions // self.clocks_per_tick + self._counter_reads) & 0xFFFF

    def _er1_write(self, addr, size, value):
        if value & SOFT_EVENT_BIT and not (self.mios.peek16(MIOS_ER1) & SOFT_EVENT_BIT):
            self.events_posted += 1
        return None

    # ---- interrupts ---------------------------------------------------------
    def pending_external(self):
        """SIPEND as the devices drive it: level interrupts stay asserted
        while their source does."""
        pend = 0
        if self.qspi.interrupt_pending():
            pend |= 0x80000000 >> LEVEL_QSPI
        mios = self.mios
        if ((mios.peek16(MIOS_SR1) | SOFT_EVENT_BIT) & mios.peek16(MIOS_ER1)) or \
                (mios.peek16(MIOS_SR0) & mios.peek16(MIOS_ER0)):
            pend |= 0x80000000 >> LEVEL_MIOS
        imb = self.imb
        if (imb.peek16(TPU_CISR[0]) & imb.peek16(TPU_CIER[0])) or (imb.peek16(TPU_CISR[1]) & imb.peek16(TPU_CIER[1])):
            pend |= 0x80000000 >> LEVEL_TPU
        if self.adc_a.interrupt_pending() or self.adc_b.interrupt_pending():
            pend |= 0x80000000 >> LEVEL_QADC
        for dev in (self.can_a, self.can_b, self.sci):
            level = dev.interrupt_level()
            if level is not None:
                pend |= 0x80000000 >> (2 * level + 1)
        tbscr = self.siu.peek16(TBSCR)
        if self.tb_irq_enabled and ((tbscr & TB_REFA and tbscr & TB_REFAE) or (tbscr & TB_REFB and tbscr & TB_REFBE)):
            level = self._tb_level(tbscr)
            if level is not None:
                pend |= 0x80000000 >> (2 * level + 1)
        return pend

    @staticmethod
    def _tb_level(tbscr):
        """TBIRQ (bits 15-8) is one-hot; bit value 0x80 selects level 0,
        0x40 level 1, ... 0x01 level 7."""
        irq = (tbscr >> 8) & 0xFF
        for level in range(8):
            if irq & (0x80 >> level):
                return level
        return None

    def _can_interrupt(self):
        # Not while a raise stub is still pending: it has yet to load SRR0/
        # SRR1 for the previous exception, and a second raise would clobber
        # them.
        if self.cpu.in_stub(self.m.pc):
            return False
        nest = self.interrupt_nest
        return self.cpu.interrupts_enabled() and (nest is None or self.m.read32(nest) == 0)

    def find_interrupt_nest(self):
        """The address of the program's interrupt nesting counter, or None.

        Its critical sections are `mtspr EID` followed at once by a load
        and a store of the counter, r13-relative: the word most of the
        program's EID sites touch right after is the counter. Found by
        looking rather than known by address, so that another program of
        the family runs as well (it turns out to keep it in the same place)."""
        from collections import Counter
        from .cpu import SPR_EID
        from .machine import R13
        touched = Counter()
        for addr, site in self.cpu.trap_sites.items():
            if site[0] != "msr" or site[1] != SPR_EID:
                continue
            for k in (1, 2, 3):
                w = self.m.read32(addr + 4 * k)
                if w >> 26 in (32, 36) and (w >> 16) & 31 == 13:          # lwz / stw rX, d(r13)
                    d = w & 0xFFFF
                    touched[(R13 + (d - 0x10000 if d & 0x8000 else d)) & 0xFFFFFFFF] += 1
        if not touched:
            return None
        addr, count = touched.most_common(1)[0]
        return addr if count >= 50 else None

    def _deliver(self):
        """Raise the highest pending interrupt if the CPU will take it.
        Returns True when one was raised (pc now points at the stub)."""
        if not self._can_interrupt():
            return False
        if self.dec_pending:
            self.dec_pending = False
            self.cpu.raise_exception(VEC_DECREMENTER)
            self.dec_exceptions += 1
            return True
        pend = self.pending_external() & self.m.read32(SIU_SHADOW + 4)
        if pend:
            level = 32 - pend.bit_length()
            self.m.write32(SIU_SHADOW, self.pending_external())      # SIPEND, as the prologue reads it
            self.cpu.raise_exception(VEC_EXTERNAL)
            self.interrupts_taken[level] += 1
            return True
        return False

    EXCP_FPU, EXCP_SYSCALL = 7, 8                 # QEMU's PowerPC exception numbers

    def _intr(self, mu, intno, ud):
        pc = self.m.pc
        if intno == self.EXCP_FPU:
            # The program relies on the FP-unavailable exception to switch
            # the FPU on. Do that and re-run the instruction.
            mu.reg_write(UC_PPC_REG_MSR, self.cpu.msr | MSR_FP)
            self.fp_enables += 1
            w = self.m.read32(pc - 4)
            if (w >> 26) in (48, 49, 50, 51, 52, 53, 54, 55, 59, 63) or ((w >> 26) == 31 and ((w >> 1) & 0x3FF) in (535, 567, 599, 631, 663, 695, 727, 759)):
                mu.reg_write(UC_PPC_REG_PC, pc - 4)
            return
        if intno != self.EXCP_SYSCALL:
            self.other_exceptions[intno] += 1
            return
        site = self.cpu.sc_sites.get(pc)            # pc is already past the sc
        if site is None:
            probe = self.probes.get(pc)
            if probe is not None:
                self.probe_counts[probe[0]] += 1
                probe[1](self.m)
                return
            # A real system call: vector it as the hardware would.
            self.syscalls += 1
            self.cpu.raise_exception(VEC_SYSCALL)
            return
        if self.cpu.handle_trap(site) == SPR_EIE:
            self._deliver()

    # ---- time ---------------------------------------------------------------
    def _advance_clocks(self, instructions):
        ticks = instructions // self.clocks_per_tick
        self.cpu.tb += ticks
        dec = self.cpu.read_dec()
        new = (dec - ticks) & 0xFFFFFFFF
        self.cpu.write_dec(new)
        return dec < 0x80000000 and new >= 0x80000000      # crossed from positive to negative

    def _slice_length(self):
        """Instructions until the decrementer reaches zero, capped at SLICE,
        so its exception lands close to the right moment: the kernel reads
        DEC afterwards as the (small, negative) overshoot."""
        dec = self.cpu.read_dec()
        # Interrupts are only delivered at slice boundaries. While one is
        # pending that could not be taken (EE off, a critical section), keep
        # the slices short so it is taken soon after the program allows it,
        # as it would be on hardware.
        # Right after interrupt activity the drivers chain more requests
        # (QSPI transfer -> event -> next transfer), so stay fine-grained for
        # a while; otherwise take long slices.
        n = HURRY_SLICE if self._hurry else (BUSY_SLICE if self._busy else SLICE)
        if dec < 0x80000000 and dec * self.clocks_per_tick < n:
            n = dec * self.clocks_per_tick + self.clocks_per_tick
        # Likewise the time base reference compares, so their status bit is
        # set at the right instruction rather than at the end of a slice.
        tbscr = self.siu.peek16(TBSCR)
        if tbscr & 0x1:
            tb = self.cpu.tb & 0xFFFFFFFF
            for ref, enable in ((TBREF0, TB_REFAE), (TBREF1, TB_REFBE)):
                if tbscr & enable:
                    ahead = (self.siu.peek32(ref) - tb) & 0xFFFFFFFF
                    if ahead * self.clocks_per_tick < n:
                        n = ahead * self.clocks_per_tick + self.clocks_per_tick
        event = self.crank.next_event()
        if event is not None:
            n = min(n, max(int(event) - self.instructions, 0) + self.clocks_per_tick)
        if self._next_pit is not None:
            n = min(n, max(self._next_pit - self.instructions, 0) + self.clocks_per_tick)
        if self.qspi.done_at is not None:
            n = min(n, max(self.qspi.done_at - self.instructions, 0) + self.clocks_per_tick)
        # Hand the K line's receiver each byte when the byte is due: the
        # loader polls for it, and at 115200 baud a byte is shorter than
        # the slices the program is otherwise run in, so a telegram would
        # arrive stretched past the DME's inter-byte timeout.
        if self.sci.rx_queue:
            n = min(n, max(self.sci.rx_next_at - self.instructions, 0) + self.clocks_per_tick)
        return max(n, 64)

    def _slice_boundary(self, ran):
        self.instructions += ran
        if self._advance_clocks(ran):
            self.dec_pending = True
        self.sci.service()
        self.qspi.service()
        self.crank.service()
        # A software-started ADC scan takes real time, so it completes here.
        self.adc_a.service()
        self.adc_b.service()
        if self.adc_a.queue2_started or self.adc_b.queue2_started:
            self.adc_a.queue2_started = self.adc_b.queue2_started = False
            self._next_scan = self.instructions          # first scan of a fresh queue is immediate
        if self.instructions >= self._next_scan:
            self._next_scan += self.scan_instructions
            self.adc_a.periodic()
            self.adc_b.periodic()
        # Time base reference compare: TB low word passing TBREF0/1.
        tbscr = self.siu.peek16(TBSCR)
        if tbscr & 0x1:                                   # TBE
            tbl = self.cpu.tb & 0xFFFFFFFF
            prev = (self.cpu.tb - ran // self.clocks_per_tick) & 0xFFFFFFFF
            for ref, flag in ((TBREF0, TB_REFA), (TBREF1, TB_REFB)):
                r = self.siu.peek32(ref)
                if (prev < r <= tbl) or (prev > tbl and (r > prev or r <= tbl)):
                    self.siu.poke16(TBSCR, self.siu.peek16(TBSCR) | flag)
                    self.tb_interrupts += 1
        if self._next_pit is not None and self.instructions >= self._next_pit:
            self._next_pit += self._pit_period()
            self.pit_expiries += 1
            self.siu.poke16(PISCR, self.siu.peek16(PISCR) | PIT_PS)
        if self.instructions >= self._next_tick:
            self._next_tick += self.tick_instructions
            self.ticks += 1
            if self.mios.peek16(MIOS_ER0) & PWM2_BIT:
                self.mios.poke16(MIOS_SR0, self.mios.peek16(MIOS_SR0) | PWM2_BIT)
        # What _deliver() does, with the device state looked at once: raising
        # an exception changes none of it, and the CPU is only asked whether
        # it will take an interrupt when there is one to take.
        pend = self.pending_external()
        masked = pend & self.m.read32(SIU_SHADOW + 4)
        delivered = False
        if (self.dec_pending or masked) and self._can_interrupt():
            delivered = True
            if self.dec_pending:
                self.dec_pending = False
                self.cpu.raise_exception(VEC_DECREMENTER)
                self.dec_exceptions += 1
            else:
                self.m.write32(SIU_SHADOW, pend)                 # SIPEND, as the prologue reads it
                self.cpu.raise_exception(VEC_EXTERNAL)
                self.interrupts_taken[32 - masked.bit_length()] += 1
        else:
            self.m.write32(SIU_SHADOW, pend)
        waiting = self.dec_pending or bool(masked)
        self._hurried = self._hurried + 1 if (waiting and not delivered) else 0
        self._hurry = waiting and self._hurried < HURRY_LIMIT
        self._busy = BUSY_SLICES if (delivered or self._hurry) else max(0, self._busy - 1)
        return delivered

    # ---- running ------------------------------------------------------------
    # ---- the car around the DME ----------------------------------------------
    def ignition(self, on):
        """KL15 is an analogue input: QADC B channel 55, found by switching
        channels low one at a time and watching the DME's KL15 flag."""
        self.adc_b.channels[KL15_CHANNEL] = 0x3C0 if on else 0x40

    @property
    def kl15(self):
        """The DME's own "KL15 on" flag; None for a program its address is not known in."""
        return bool(self.m.read8(KL15_FLAG)) if self.m.pair.traced else None

    @property
    def powered_down(self):
        """After the after-run the DME parks in a loop copied to RAM and
        waits for the main relay to drop."""
        return RAM_START <= self.m.pc < RAM_END

    @property
    def in_loader(self):
        """Whether the boot loader has the CPU (programming mode, or
        nothing valid to start): exceptions at 0xFFF00000, as
        Cpu.raise_exception tells the two apart."""
        return bool(self.cpu.msr & MSR_IP) and not self.cpu.bbcmcr & BBCMCR_ETRE

    def eeprom_image(self):
        return bytes(self.qspi.eeprom.data)

    def load_eeprom(self, image):
        self.qspi.eeprom.data[:len(image)] = image

    def run(self, max_insns):
        """Keep running from where the program is."""
        return self.run_from(self.m.pc, max_insns)

    def boot(self, max_insns=5_000_000, until=BOOT_IDLE, reset_vector=False):
        """Run the reset path in slices. Returns (reached_idle, reason).

        By default this starts at the program's own reset entry. With
        reset_vector it starts where the CPU does, in the boot loader,
        which starts the program only when both the program and the
        calibration carry the "signature checked" marks it writes after a
        flash (dumps read over diagnostics do not include them) and
        otherwise stays in programming mode.

        The reset entry is one program's (image.PROGRAM_ID); any other is
        always started from the reset vector, which is in the boot loader
        and the same for all of them."""
        if reset_vector or not self.m.pair.traced:
            self.m.mu.reg_write(UC_PPC_REG_MSR, MSR_IP)
            return self.run_from(RESET_VECTOR, max_insns, until)
        self.m.mu.reg_write(UC_PPC_REG_MSR, 0)
        return self.run_from(RESET_ENTRY, max_insns, until)

    def flash_pair(self):
        """What the two flash memories hold now, without the emulator's patches."""
        from .image import Pair
        return Pair(bytes(self.flash.image), bytes(self.cmf.image), self.m.pair.name, check_program=False)

    def program_valid(self):
        """Whether the loader will start the program at the next reset:
        the marks it writes after its checksum and signature checks of the
        program and of the calibration are both there."""
        image = self.flash.image
        return all(int.from_bytes(image[at:at + 4], "big") == mark for at, mark in VALID_MARKS)

    def reset(self):
        """The DME after a reset: a new board on the flash contents as
        they are now, with this one's EEPROM and inputs. Boot it with
        reset_vector=True to have the loader decide what runs."""
        b = Board(self.flash_pair(), patch_program=self.program_valid(), mips=self.mips)
        b.load_eeprom(self.eeprom_image())
        b.adc_a.channels.update(self.adc_a.channels)
        b.adc_b.channels.update(self.adc_b.channels)
        return b

    def run_from(self, pc, max_insns, until=BOOT_IDLE):
        done = 0
        while done < max_insns:
            n = self._slice_length()
            try:
                pc = self.m.run(pc, until, max_insns=n)
            except UcError as e:
                # The program relies on the FP-unavailable exception to switch
                # the FPU on; Unicorn stops instead of vectoring, so do it here.
                if "exception" in str(e).lower() and not (self.cpu.msr & MSR_FP):
                    self.m.mu.reg_write(UC_PPC_REG_MSR, self.cpu.msr | MSR_FP)
                    self.fp_enables += 1
                    pc = self.m.pc
                    continue
                return False, f"{e} at pc=0x{self.m.pc:X}"
            done += n
            if pc == until:
                return True, "idle"
            if self._slice_boundary(n):
                pc = self.m.pc                # an exception was raised: on to its stub
        return False, f"ran out of instructions at pc=0x{self.m.pc:X}"

    def report(self):
        return (f"watchdog services={self.watchdog_services} bad={self.watchdog_bad}; "
                f"tpu requests={self.tpu_requests}; qspi transfers={self.qspi.transfers} "
                f"(eeprom reads={self.qspi.eeprom.reads} writes={self.qspi.eeprom.writes}); "
                f"events posted={self.events_posted}; ticks={self.ticks}; tb compares={self.tb_interrupts} (late refs {self.tb_late_refs}); fp enables={self.fp_enables}; "
                f"adc scans={self.adc_a.scans}/{self.adc_b.scans} single={self.adc_a.single_scans}; "
                f"can A tx={self.can_a.tx_count} rx={self.can_a.rx_count} B tx={self.can_b.tx_count} rx={self.can_b.rx_count}; "
                f"interrupts={dict(self.interrupts_taken)} dec={self.dec_exceptions} "
                f"syscalls={self.syscalls} other exceptions={dict(self.other_exceptions)}; "
                f"open-bus pages={sorted(hex(p) for p in self.bus.pages)}")
