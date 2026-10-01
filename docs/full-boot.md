# The full boot

Status as of 2026-09-30. The reset path (`0xFFF717B4`) runs under `Board`
in `ms45emu/board.py`, with the board models listed below. Each was added
when the boot stopped on it, so the order is the order the boot needs them.

## How far it gets

Through hardware setup, the RAM test, the EEPROM load (69 reads via the
DME's own QSPI driver, interrupt handler and OS event queue), the first
ADC scan the init chain waits for, and into the init chain proper,
including the floating-point code. The last known stop is the program
checksum the init computes over the whole flash, which is just long, not
blocked.

## What is modelled

| Piece | Model | Notes |
|---|---|---|
| Absent hardware (dev-RAM probe at `0xFFC40000`) | `OpenBus`: reads 0xFF, writes vanish | Makes the probe fail the production way |
| Watchdog | `Watchdog`: counts the 0x556C/0xAA39 service pairs | Does not reset the machine |
| TPU | `TpuStub`: acknowledges host service requests at once | TPU A at `0x304000`, B at `0x304400`; nothing engine-related |
| Serial EEPROM | `Qspi` + `Eeprom25` on PCS1 | 32-entry QSPI queue, READ/WRITE/WREN/RDSR; blank unless given an image |
| OS event interrupt | `MiosInterrupts` | MIOS1 bank 1 bit 6, enabled by the event poster; the drain is `0x1CC7C` |
| OS tick | MIOS PWM2 period interrupt (bank 0 bit 2) | `TICK_INSTRUCTIONS`, about 10 ms |
| ADC | `Qadc` x2 | Periodic queue 2 and software-started queue 1; resting values, 10 bit; interrupt level 3 |
| Status registers | `WriteZeroToClear` | TPU CISR, MIOS SR, QADC QASR |
| Exceptions | `Cpu.raise_exception` | SRR0/SRR1 via a stub, vector from the compressed table in MPC `0x00-0xFF`, return by the program's rfi |
| EIE / EID / NRI | code hook applying them to MSR | Unicorn treats these MPC5xx SPRs as no-ops |
| Interrupt levels | `pending_external()` derives SIPEND from device state | Level-triggered, taken at instruction boundaries when EE allows |
| Time base, decrementer | advanced from the instruction count | 1 instruction = 1 clock, TB/DEC at sysclk/4 |
| FPU | FP-unavailable exception handled by enabling MSR[FP] | Unicorn stops on the exception instead of vectoring |

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

## Not modelled yet

| Piece | Why it matters |
|---|---|
| Monitoring processor (SPI, not PCS1) | Its handshake will be needed before the DME considers itself healthy |
| CAN, SCI (K-line) | Silent so far; "message missing" faults are expected |
| Realistic ADC values per channel | All channels read mid-scale |
| Watchdog reset | Services are counted but a missed one does nothing |
| Crank and cam (TPU microcode) | Engine running only |
