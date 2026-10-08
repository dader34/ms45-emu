# ms45-emu

Runs routines of the Siemens MS45.1 DME (MPC555, program `0044570LO02S`)
under Unicorn, straight from a flash pair, so firmware patches can be tested
before they go near a car.

What it can do today:

- run the DME's own safety-monitor code sum ("ROM test level 2") and compare
  it with the stored value - the check that reset the DME when a map-switch
  build left it stale;
- run the hooked table-lookup routines against map 1 and the maps stored as blocks beside it;
- drive the map-switch gesture / tach stub tick by tick, and the stored-data
  init / restore / save routines, exactly as the DME would call them.

It also boots the whole program under `Board` (`ms45emu/board.py`), with
models of the hardware around the CPU: open bus, watchdog, TPU
acknowledgement, QSPI with a serial EEPROM, the MIOS interrupts the OS runs
on, the ADC, the time base and real exception delivery. The boot runs
through the reset path, the EEPROM load and the init chain into the OS,
whose periodic tasks then run on a 1 ms tick: the 10 ms CAN frame builder,
the stored-data task, the map-switch hook. Switch the ignition off and the
after-run writes the EEPROM and parks the CPU; boot again on that EEPROM
and the DME comes up on the map that was saved. `docs/full-boot.md` has the
state of each piece and what is still missing (the monitoring
processor, anything the engine needs).

    from ms45emu import load_pair
    from ms45emu.board import Board
    b = Board(load_pair("stock"))
    b.probe(0x3B38C, "scheduler task")
    print(b.boot(max_insns=20_000_000), b.report(), dict(b.probe_counts))
    b.ignition(False)                      # KL15 off: the after-run starts

A simulated second is 40 M instructions and takes about four seconds;
`Board(pair, mips=10)` clocks the CPU four times slower, which the program
still keeps up with and which runs faster than real time.

The DME is on its CAN bus as well: it sends the real DME1-4 frames
(0x316 with the rpm the cluster shows, every 10 ms) and takes the ASC,
cluster and gearbox frames in; `ms45emu/e46.py` plays those partners.
`tools/bench.py` puts the emulated DME on a real bus through a USB-CAN
adapter (python-can), so a cluster on the bench, or the car with its DME
unplugged, follows the emulator.

Turn the crank (`board.crank.rpm = 800`) and the program synchronises to
the 60-2 wheel and measures its engine speed, which the tach frame on CAN
then carries.

It can be flashed, too. The K line is modelled (`ms45emu/sci.py`) and the
DME's diagnostics run on it: identification, the RSA authentication, and
programming mode, where the DME's own boot loader erases and programs the
external flash chip and the MPC555's internal flash, checks its checksums
and signatures, and after a reset starts what it was given. See
`docs/flashing.md`. `tools/kline.py` puts that K line where a tester can
reach it: a pseudo-terminal, a real USB serial adapter (`--port`), a Unix
socket for a virtual machine's serial port (`--socket`), or a WebSocket
with a Web Serial stand-in for testers that run in a browser (`--ws`,
`tools/webserial-emu.js`).

Logging is the other use of the K line. The stock program already goes to
115200 baud and a shorter timing in its default session and reads a packet
the tester defines, 50 times a second instead of 10; `docs/logging.md` has
the requests. `ms45emu/diagpatch.py` (`tools/diagpatch.py`) builds a patch
that doubles that again, adds a log frame on CAN every 10 ms and a buffer
with a record per crank segment, and it is tested here the way the map
switch is.

## Other programs

The full boot, the K line and flashing are not tied to one program: any
MS45.1 program (`0044570L...`) is taken, started from the reset vector by
the DME's own boot loader, and the one thing the board takes from the
program, its interrupt nesting counter, is found by looking at its
critical sections. Checked with the five programs of SP-Daten's `MDS451` folder
(`0044570LL01S`, `LL30S`, `LM00S`, `LN00S` and `LO02S` itself), each on a
stock boot loader with one of its own calibrations: they boot into their
OS, send their CAN frames and identify with their own part numbers.

BMW's data files are taken as they are. A program (`.0PA`) and a
calibration (`.0DA`) have no boot loader, so they are written over a
read's, the way a tester would write them (`ms45emu/daten.py`):

    MS45_FLASH=read_Flash.bin .venv/bin/python tools/kline.py --pair stock --program MDS451/7549388A.0PA

A program brings the whole MPC flash, so the read needs only its external
flash, and of that only the boot loader: with its first 256 KB kept as
`images/stock_boot.bin` (`python -m ms45emu.daten keep-boot READ_Flash.bin`),
`--program` alone starts a DME. The boot loader's part of the flash also
holds the programming log (the AIF, from `0x1FB34`), each entry with the
VIN of the car the DME was in; it is emptied in what is kept, so such a
DME has been in no car. Without `--calibration` the read's calibration is kept when it is
made for the program, and otherwise the first `.0DA` in the program's
folder that is gets used; the choice is printed. MS45.0 programs
(`0044560B...`, SP-Daten's `MDS450`) are refused: on an MS45.1 boot
loader they did not get as far as setting up a peripheral.

What does belong to `0044570LO02S` alone: the routine and variable
addresses in `ms45emu/dme.py` and everything built on them (the ROM test
sum, the lookup and gesture tests, the diagnostics patch), the `kl15`
flag, the direct reset entry `boot()` uses for it, and the map switch and
EWS delete themselves. The crank model has only been watched with that
program.

    MS45_OTHER_FLASH=... MS45_OTHER_MPC=... .venv/bin/pytest tests/test_other_program.py

## Setup

    python3.11 -m venv .venv            # or newer
    .venv/bin/pip install -e '.[test]'

Images are BMW-derived and are not in the repo; see `images/README.md`.
The patched pair is what the BMWeb Flasher's Map Switch view saves with the
pedals as the trigger, the shifter pair what it saves with the gear lever.

    MS45_FLASH=... MS45_MPC=... MS45_PATCHED_FLASH=... MS45_PATCHED_MPC=... .venv/bin/pytest
    MS45_SHIFTER_FLASH=... MS45_SHIFTER_MPC=... .venv/bin/pytest tests/test_shifter.py

## Layout

- `ms45emu/machine.py`  the machine: memory map, registers, `call()` a routine
- `ms45emu/image.py`    finding and validating a pair
- `ms45emu/daten.py`    BMW's .0PA / .0DA files, written onto a pair's boot loader
- `ms45emu/dme.py`      traced addresses and helpers for this program
- `ms45emu/board.py`    the board around the CPU: peripherals, interrupts, the boot loop
- `ms45emu/cpu.py`      SRR0/SRR1, TB/DEC and EIE/EID, which Unicorn does not expose
- `ms45emu/qspi.py`, `ms45emu/qadc.py`, `ms45emu/toucan.py`, `ms45emu/tpu.py`  the QSPI/EEPROM, ADC, CAN and TPU models
- `ms45emu/flashchip.py`, `ms45emu/cmf.py`  the external flash chip and the MPC555's internal flash
- `ms45emu/sci.py`, `ms45emu/kwp.py`  the K line and a KWP tester (diagnostics, flashing)
- `ms45emu/diagpatch.py`  the diagnostic patch: faster K-line logging, CAN log frame, capture buffer
- `ms45emu/e46.py`      the other modules on the E46's bus
- `tools/bench.py`      the DME on a real CAN adapter
- `tools/diagpatch.py`  builds the diagnostic patch onto a pair
- `tools/xref.py`       who reads and writes an address, asked of the running program (`ms45emu/xref.py`)
- `tools/funcmap.py`    the program's functions: a sweep of the code, coverage from a run, names from `ms45emu/names/`, a Ghidra symbol export (`ms45emu/funcmap.py`)
- `tools/protections.py` what a custom program trips that the stock one does not: faults (`ms45emu/faults.py`), limp home, a reset; and the static table of every check (`ms45emu/protections.py`, `docs/protections.md`)
- `tools/explain.py`    a routine's calibration items by XDF name (`ms45emu/xdf.py`; the XDF goes in `images/` or `MS45_XDF`), RAM variables and callees, from a scan of its code and, with `--run`, from watching it run (`ms45emu/explain.py`)
- `tools/kline.py`      the DME's K line on a serial port, socket or WebSocket (`tools/webserial-emu.js` is the browser side)
- `tests/`              the checks, one file per subject (`test_boot.py` is the full boot; the ignition-off round trip and the full program flash need `MS45_SLOW=1`)
- `docs/`               notes on the full boot, flashing and logging

Related: the map-switch trace notes in `~/Desktop/e46bins/MS45-DME/Research`
and the builder in `~/Development/code/projects/BMWeb-Flasher` (`MapSwitch.cs`).
