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

CAN runs too (`ms45emu/toucan.py`): module A is the vehicle bus, where
the DME sends DME1-4 (0x316 every 10 ms with the rpm the cluster shows,
0x329, 0x545, and 0x338 on events) and receives ASC, cluster and gearbox
frames; `ms45emu/e46.py` plays those partners, and `tools/bench.py` puts
the DME on a real bus through a python-can adapter.

Not yet: anything the engine needs (TPU microcode, crank/cam), the
monitoring processor, K-line.

Speed: a simulated second is 40 M instructions and takes about 4 s of wall
time; most of that is Python handling interrupts and QSPI transfers, not
Unicorn. Nothing runs on every instruction: peripherals are MMIO, EIE/EID/
NRI and time-base instructions are replaced by `sc` and emulated in the
exception hook, and the program's checksums are recomputed over the patched
image (`checksums.py`).

## Time

- By default 1 instruction = 1 core clock at 40 MHz. The time base and
  decrementer count at 2.5 MHz (16 instructions per unit), fixed from the
  program's own constants: the kernel tick is 2500 TB units, the scheduler
  runs every 5 ticks and the 10 ms frame 0x316 every 10 ticks, so a tick
  is 1 ms. (SCCR is never written on the program's own reset entry, so
  this is the reset clock source.)
- `Board(pair, mips=10)` makes a second of DME time 10 M instructions
  instead of 40 M: a CPU a quarter as fast. The program still keeps its
  schedule there (it does not at 5), and the emulator then runs faster
  than real time, which a tester with real-time timeouts needs
  (`tools/kline.py` uses it and waits for the wall clock). All periods
  below scale with it. One thing does not: a software-started ADC scan
  takes at least 8000 instructions, because the program restarts it from
  its completion interrupt and a slower CPU would otherwise never get to
  the interrupt levels below.
- Slices end where the decrementer reaches zero and where TB reaches an
  enabled TBREF, so both exceptions land at the right instruction. The
  kernel tick handler (`0x1085C`) walks the schedule table, writes TBSCR
  (W1C REFA | REFAE) and TBREF0 = next, then re-reads TB and loops if the
  reference is already behind; `Board.tb_late_refs` counts those.
- The MIOS PWM2 period and the ADC queue 2 scan are plain 10 ms periods
  (`Board.tick_instructions`, `Board.scan_instructions`).

## What is modelled

| Piece | Model | Notes |
|---|---|---|
| Absent hardware (dev-RAM probe at `0xFFC40000`) | `OpenBus`: reads 0xFF, writes vanish, not executable | Makes the probe fail the production way |
| Watchdog | counts the 0x556C/0xAA39 service pairs | Does not reset the machine |
| TPU | host service requests acknowledged; `ms45emu/tpu.py` classifies each channel by its CFSR function and captures output servicing | TPU A at `0x304000`, B at `0x304400`; microcode is custom so function numbers are mapped by role, not the Motorola ROM set |
| Crank wheel | `Crank` (`board.crank.rpm = 800`): the crank channel's states and tooth counter, and the angle matches the program times its segments with | The program synchronises and its engine speed, and the tach on CAN, follow. See below |
| MIOS modulus counter 22 | counts | The PWM duty update waits on it once the engine runs |
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
| CAN | `TouCan` x2 on `0x307000` | Message buffers with codes, acceptance masks, IFLAG/ESTAT write-0-to-clear, interrupt level from ICR (module B, level 5), 16-bit timer. Transmit is immediate; frames go to `tx_log`/`on_tx`, `receive()` lands a frame in the first matching empty buffer |
| K line | `Sci` (SCI1, 9-bit frames with the parity done in software) | Interrupt driven in the program, polled in the boot loader |
| PIT | status bit every period when PITC is set | The boot loader's 1 ms tick; the program leaves PITC at 0 |
| Flash memories | `FlashChip` (external, AMD command set), `Cmf` (internal) | Programmed and erased by the DME's own drivers, see `flashing.md` |
| Reset vector | `boot(reset_vector=True)`, `Board.reset()` | The loader starts the program only when it is marked valid; exceptions follow `BBCMCR[ETRE]` |
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
- OS tasks: table at MPC `0xB5C0` (0x24 bytes each: priority, 1, TCB,
  id, 0, a pointer, entry, wrapper `0x10550`, a pointer; `ms45emu/funcmap.py`
  reads it). `0xFF7C` activates,
  `0xF5F8` terminates/chains, `0x10450` dispatches. The crank-synchronous
  segment task (`0x3223C`) is activated from the angle-match channel
  (below); the time-based ones through the scheduler task `0x3B38C`.
- Engine speed. The crank is TPU A channel 13 (handler `0x17FE8`), the two
  cam sensors are A10 and A12 (`0x16AF4`). The crank channel's microcode
  keeps a tooth counter (0..119) and reports its state in a parameter
  byte, with an interrupt on each change: no signal, teeth seen, gap
  found, synchronised. At "gap found" the program writes the tooth number
  the wheel is at; once synchronised it arms TPU B channel 14 (handler
  `0x168D4`) to capture the time at a tooth, every 20 teeth for each of
  two offsets (table `0xFFFF8B0C`). The difference of two captures is the
  segment time X in 0.8 us units; the handler posts an OS event that runs
  `0x1174C` and activates the segment task, which computes
  rpm = 5,000,000 / (X / 5) (`0x31000`) once the engine state manager
  (`0x552BC`, state at `0x3F9C43`: 0 stopped, 2 running) has seen the
  crank driver synchronised. The driver object is at `0xFFFF8A14`, its
  mode setter `0x17B64`.
- With the cam sensors silent the sensor diagnosis (`0x43A8C`) gives up on
  both after about 0.45 s of running and from then on restarts the crank
  search every 10 ms. `Crank` goes along with that (it resynchronises
  each time), and the engine speed keeps being measured.
- The stored data is written to the EEPROM in the after-run only, each
  record twice, with a read-back; the EEPROM is otherwise read at boot.
- CAN A message buffers: 0-10 receive 0x43F, 0x613, 0x615, 0x153, 0x1F3,
  (unused), 0x1F5, 0x43B, 0x1F8, (unused), 0x43D; 11-14 transmit 0x545,
  0x338, 0x329, 0x316. CAN B carries 0x7E8-0x7ED and a few others, with
  interrupts enabled. Module A is polled: the application calls the
  receive routine `0x2A8D8` per message handle every 10 ms, reads the
  buffer through `0x2B598` and stores the frame byte-reversed (0x153 at
  `0x3FDCAC`), so little-endian fields read naturally on the PowerPC.
- Vehicle speed (`-0x3F95`) is a TPU-measured pulse input, not CAN, unless
  `-0x3D1E` selects the CAN value; brake is MIOS pin state (DASM 12/15);
  the pedal is ADC.
- The kernel also programs the PIT (PISCR 0x105 / 0x1 from `0x101BC` /
  `0x1094C`) but leaves its count at 0 and nothing in the program has
  needed it; the boot loader runs on it (`flashing.md`).

## Not modelled yet

| Piece | Why it matters |
|---|---|
| Monitoring processor (SPI, not PCS1) | Its handshake will be needed before the DME considers itself healthy |
| Vehicle speed pulse (TPU) | Stays at 0 km/h |
| Realistic ADC values per channel | All channels read mid-scale; pedal/brake/speed are forced at the hook in the tests |
| Watchdog reset | Services are counted but a missed one does nothing |
| Cam sensors, ignition and injection timing (TPU microcode) | The crank is modelled; with no cam signal the program flags both cam sensors, and the output channels are only acknowledged |
