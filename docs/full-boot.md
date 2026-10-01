# The full boot

Status as of 2026-10-01. The reset path (`0xFFF717B4`) runs under `Board`
in `ms45emu/board.py`, with the board models listed below. Each was added
when the boot stopped on it, so the order is the order the boot needs them.

## How far it gets

All the way into normal operation, engine off. Hardware setup, the RAM
test, the EEPROM load through the DME's own QSPI driver, the init chain
with its floating-point code and flash checksum, StartOS, and then the OS
proper: the kernel tick from the time-base reference interrupt (1 ms), the
scheduler task every 5 ms, the periodic application tasks (the 0x316 CAN
frame builder every 10 ms, the stored-data task, brake plausibility, ...),
and the background task chaining itself. With the ignition channel high the
DME reports KL15 on.

On the map-switch build the hook in the 0x316 builder runs every frame:
the power-up indication shows the map on the tach for 3 s, the pedal+brake
gesture toggles the map after 5 s and requests the save, and the DME's own
stored-data task takes the request. Switching KL15 off starts the after-run:
the stored data is compared with and written to the EEPROM (about 1200
writes on a blank part), then the CPU parks in a loop copied to RAM
(`Board.powered_down`) waiting for the main relay. Booting a new board on
that EEPROM image brings the DME up on the saved map, with the 2000 rpm
indication. `tests/test_boot.py` covers all of it; the ignition-off round
trip is behind `MS45_SLOW=1`.

Not yet: anything the engine needs (TPU microcode, crank/cam), CAN in
either direction, the monitoring processor. The CAN-receive task never
runs, so "message missing" faults are to be expected in the fault memory.

Speed: a simulated second is 40 M instructions and takes about 4 s of wall
time; most of that is Python handling interrupts and QSPI transfers, not
Unicorn. Nothing runs on every instruction: peripherals are MMIO, EIE/EID/
NRI and time-base instructions are replaced by `sc` and emulated in the
exception hook, and the program's checksums are recomputed over the patched
image (`checksums.py`).

## Time

- 1 instruction = 1 core clock at 40 MHz. The time base and decrementer
  count at 2.5 MHz (`CLOCKS_PER_TICK = 16`), fixed from the program's own
  constants: the kernel tick is 2500 TB units, the scheduler runs every
  5 ticks and the 10 ms frame 0x316 every 10 ticks, so a tick is 1 ms.
  (SCCR is never written, so this is the reset clock source.)
- Slices end where the decrementer reaches zero and where TB reaches an
  enabled TBREF, so both exceptions land at the right instruction. The
  kernel tick handler (`0x1085C`) walks the schedule table, writes TBSCR
  (W1C REFA | REFAE) and TBREF0 = next, then re-reads TB and loops if the
  reference is already behind; `Board.tb_late_refs` counts those.
- `TICK_INSTRUCTIONS` (MIOS PWM2) and `SCAN_INSTRUCTIONS` (ADC queue 2)
  are still instruction-count periods.

## What is modelled

| Piece | Model | Notes |
|---|---|---|
| Absent hardware (dev-RAM probe at `0xFFC40000`) | `OpenBus`: reads 0xFF, writes vanish, not executable | Makes the probe fail the production way |
| Watchdog | counts the 0x556C/0xAA39 service pairs | Does not reset the machine |
| TPU | host service requests acknowledged at once; parameter word 7 bit 0x2000 set for the channel | TPU A at `0x304000`, B at `0x304400`; the DME loads its own microcode into DPTRAM (`0x302000`), so engine functions are out of reach |
| Serial EEPROM | `Qspi` + `Eeprom25` on PCS1 | 32-entry queue; entries are 16-bit when BITSE is set (SPCR0[BITS]=0) and 8-bit otherwise, which is how WREN/WRDI go out; READ/WRITE are `op addr16` + 3 data bytes |
| OS event interrupt | MIOS1 bank 1 bit 6 (MMCSM22), enabled by the event poster | The drain is `0x1CC7C` |
| MIOS PWM2 interrupt (bank 0 bit 2) | periodic, `TICK_INSTRUCTIONS` | Its handler toggles an output pin; it is not the OS tick |
| OS tick | time-base reference A, SIU level 2 (`TBSCR` 0x20xx), dispatcher `0x109C0` to the RAM handler pointer `0x3FB654` = `0x1085C` | |
| ADC | `Qadc` x2 | Periodic queue 2 and software-started queue 1 (takes `Q1_SCAN_INSTRUCTIONS`); resting values, 10 bit; interrupt level 3. KL15 is QADC B channel 55 (`Board.ignition`) |
| Status registers | write-zero-to-clear | TPU CISR, MIOS SR, QADC QASR; TBSCR status is write-one-to-clear |
| Exceptions | `Cpu.raise_exception` | SRR0/SRR1 via a per-vector stub ending in the vector's own `ba`, so CTR/LR are untouched (the handler saves whatever it finds in them); return by the program's rfi |
| EIE / EID / NRI, mftb, mttb | replaced by `sc`, emulated in the exception hook | Unicorn ignores these SPRs and keeps TB at zero |
| Interrupt levels | `pending_external()` derives SIPEND from device state, masked by SIMASK | Level-triggered, taken at instruction boundaries when EE allows and the program's nesting counter is zero |
| Time base, decrementer | advanced from the instruction count; see Time | |
| FPU | FP-unavailable exception handled by enabling MSR[FP] and re-running the instruction | |
| Probes | `Board.probe(addr, name, on_hit)` | Entry instruction replaced by `sc` and emulated; counts calls at no per-instruction cost; `on_hit` sees the registers on entry |

## Things learned about the firmware

- Exception vectors are a compressed table in the first 0x100 bytes of the
  MPC, 8 bytes per vector (`ba target; nop`): reset `0xFFF717B4`, external
  interrupt `0x105F4`, decrementer `0x20918`, FP unavailable `0xFFF7209C`.
- The external-interrupt prologue (`0x105F4`) picks the highest bit of
  SIPEND & SIMASK and dispatches through the table at MPC `0xB4C4`:
  LVL1 TPU, LVL2 time base, LVL3 QADC, LVL4 QSPI, LVL6 MIOS, with an RTOS
  underneath (task control blocks at `0x3FB5F0`, interrupt nesting counter
  `0x3FA0E4`, ready queues per priority at TCB+0x60, 12 bytes each).
- Kernel critical sections mask levels through SIMASK (saved on a stack at
  `-0x6204(r13)`), with EID/EIE only around the SIMASK write.
- The QSPI command RAM is fixed at boot; PCS1 is the EEPROM, PCS0/2/3 are
  other devices, still answered as an open bus.
- The init chain's "wait for first tick" (`0x1156C`) sets TBSCR[TBF] with a
  read-modify-write (which also acknowledges a pending REFA) and then waits
  for the first periodic ADC scan; the scan must complete before the wait
  starts, as it does on hardware.
- KL15 is an analogue reading (logical ADC channel 0x1E, via the tick
  handler `0x10F44`), not a digital pin.
- OS tasks: table at MPC `0xB5C0` (0x24 bytes each: entry, wrapper
  `0x10550`, self, priority, 2, state byte, id). `0xFF7C` activates,
  `0xF5F8` terminates/chains, `0x10450` dispatches. The crank-synchronous
  tasks are activated through TPU channels 10/12 at the angles listed at
  `0xFFFF8B1C`; the time-based ones through the scheduler task `0x3B38C`.
- The stored data is written to the EEPROM in the after-run only, each
  record twice, with a read-back; the EEPROM is otherwise read at boot.
- The kernel also programs the PIT (PISCR 0x105 / 0x1 from `0x101BC` /
  `0x1094C`); it is not modelled and nothing has needed it.

## Not modelled yet

| Piece | Why it matters |
|---|---|
| CAN (TouCAN at `0x307000`) | No frames leave or arrive; needed for a bench DME on a real bus |
| Monitoring processor (SPI, not PCS1) | Its handshake will be needed before the DME considers itself healthy |
| SCI (K-line) | Diagnostics |
| Realistic ADC values per channel | All channels read mid-scale; pedal/brake/speed are forced at the hook in the tests |
| Watchdog reset | Services are counted but a missed one does nothing |
| Crank and cam (TPU microcode) | Engine running only |
