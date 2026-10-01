# The full boot

Status as of 2026-09-30. The reset path (`0xFFF717B4`) runs under `Board`
in `ms45emu/board.py`, with the board models listed below. Each was added
when the boot stopped on it, so the order is the order the boot needs them.

## How far it gets

Through hardware setup, the RAM test, the EEPROM load (69 reads via the
DME's own QSPI driver, interrupt handler and OS event queue), the first
ADC scan the init chain waits for, the whole init chain including the
floating-point code and the flash checksum, StartOS, and into the OS: the
init-complete markers (`0x3FEB26/27`) are set, the background task runs
(it chains itself and computes the flash checksum), kernel alarms fire,
and with the ignition channel high the DME reports KL15 on (`0x3FD853`).

Not yet: the periodic application tasks (the 17 descriptors at MPC
`0xB68C`, run through the scheduler task `0x3B38C`) are never activated,
so no CAN frames are built and the map-switch gesture code never runs.
The scheduler task is activated by the OS schedule table at MPC `0xBA94`
(entries of handler + 2500 counter units); what drives that table has not
been found. The time base reference interrupt was tried at both plausible
SIU levels and neither handler acknowledges it, so it is not that.

Speed: about 200 M instructions/s. Nothing runs on every instruction:
peripherals are MMIO, EIE/EID/NRI and time-base instructions are replaced
by `sc` and emulated in the exception hook, and the program's checksums
are recomputed over the patched image (`checksums.py`).

## What is modelled

| Piece | Model | Notes |
|---|---|---|
| Absent hardware (dev-RAM probe at `0xFFC40000`) | `OpenBus`: reads 0xFF, writes vanish | Makes the probe fail the production way |
| Watchdog | counts the 0x556C/0xAA39 service pairs | Does not reset the machine |
| TPU | host service requests acknowledged at once | TPU A at `0x304000`, B at `0x304400`; the DME loads its own microcode into DPTRAM (`0x302000`), so engine functions are out of reach |
| Serial EEPROM | `Qspi` + `Eeprom25` on PCS1 | 32-entry QSPI queue, READ/WRITE/WREN/RDSR; blank unless given an image |
| OS event interrupt | MIOS1 bank 1 bit 6 (MMCSM22), enabled by the event poster | The drain is `0x1CC7C` |
| MIOS PWM2 interrupt (bank 0 bit 2) | periodic, `TICK_INSTRUCTIONS` | Its handler toggles an output pin; it is not the OS tick |
| ADC | `Qadc` x2 | Periodic queue 2 and software-started queue 1; resting values, 10 bit; interrupt level 3 |
| Status registers | write-zero-to-clear | TPU CISR, MIOS SR, QADC QASR; TBSCR status is write-one-to-clear |
| Exceptions | `Cpu.raise_exception` | SRR0/SRR1 via a stub, vector from the compressed table in MPC `0x00-0xFF`, return by the program's rfi |
| EIE / EID / NRI, mftb, mttb | replaced by `sc`, emulated in the exception hook | Unicorn ignores these SPRs and keeps TB at zero |
| Interrupt levels | `pending_external()` derives SIPEND from device state | Level-triggered, taken at instruction boundaries when EE allows |
| Time base, decrementer | advanced from the instruction count; slices end where DEC crosses zero | 1 instruction = 1 clock, TB/DEC at sysclk/4; the kernel reads DEC as the overshoot |
| FPU | FP-unavailable exception handled by enabling MSR[FP] and re-running the instruction | |
| KL15 / battery | ADC channels (0x1E, 0x13 logical) | `Qadc.default` of 0x3C0 reads as ignition on |

## Things learned about the firmware

- Exception vectors are a compressed table in the first 0x100 bytes of the
  MPC, 8 bytes per vector (`ba target; nop`): reset `0xFFF717B4`, external
  interrupt `0x105F4`, decrementer `0x20918`, FP unavailable `0xFFF7209C`.
- The external-interrupt prologue (`0x105F4`) picks the highest bit of
  SIPEND & SIMASK and dispatches through the table at MPC `0xB4C4`:
  LVL1 TPU, LVL3 QADC, LVL4 QSPI, LVL6 MIOS, with an RTOS underneath
  (task control blocks at `0x3FB5F0`, interrupt nesting counter `0x3FA0E4`).
- The QSPI command RAM is fixed at boot; PCS1 is the EEPROM (READ is
  `03 addr16`, two data bytes per transfer), PCS0/2/3 are other devices,
  still answered as an open bus.
- The init chain's "wait for first tick" (`0x1156C`) actually waits for the
  first periodic ADC scan, and its loop does not reload the flag, so the
  scan must complete before the wait starts, as it does on hardware.
- KL15 is an analogue reading (logical ADC channel 0x1E, via the tick
  handler `0x10F44`), not a digital pin.
- OS tasks: table at MPC `0xB5C0` (0x24 bytes each: entry, wrapper
  `0x10550`, self, priority, 2, state byte, id). `0xFF7C` activates,
  `0xF5F8` terminates/chains, `0x10450` dispatches. The crank-synchronous
  tasks are activated through TPU channels 10/12 at the angles listed at
  `0xFFFF8B1C`; the time-based ones through the scheduler task `0x3B38C`.

## Not modelled yet

| Piece | Why it matters |
|---|---|
| Monitoring processor (SPI, not PCS1) | Its handshake will be needed before the DME considers itself healthy |
| CAN, SCI (K-line) | Silent so far; "message missing" faults are expected |
| Realistic ADC values per channel | All channels read mid-scale |
| Watchdog reset | Services are counted but a missed one does nothing |
| Crank and cam (TPU microcode) | Engine running only |
