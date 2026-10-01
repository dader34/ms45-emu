# ms45-emu

Runs routines of the Siemens MS45.1 DME (MPC555, program `0044570LO02S`)
under Unicorn, straight from a flash pair, so firmware patches can be tested
before they go near a car.

What it can do today:

- run the DME's own safety-monitor code sum ("ROM test level 2") and compare
  it with the stored value - the check that reset the DME when a map-switch
  build left it stale;
- run the hooked table-lookup routines against map 1 and map 2;
- drive the map-switch gesture / tach stub tick by tick, and the stored-data
  init / restore / save routines, exactly as the DME would call them.

It also boots the whole program under `Board` (`ms45emu/board.py`), with
models of the hardware around the CPU: open bus, watchdog, TPU
acknowledgement, QSPI with a blank serial EEPROM, the MIOS interrupts the
OS runs on, the ADC, and real exception delivery. The boot currently gets
through the EEPROM load and into the init chain; `docs/full-boot.md` has
the state of each piece and what is still missing.

    from ms45emu import load_pair
    from ms45emu.board import Board
    b = Board(load_pair("stock"))
    print(b.boot(max_insns=100_000_000), b.report())

## Setup

    python3.11 -m venv .venv            # or newer
    .venv/bin/pip install -e '.[test]'

Images are BMW-derived and are not in the repo; see `images/README.md`.
The patched pair is what the BMWeb Flasher's Map Switch view saves.

    MS45_FLASH=... MS45_MPC=... MS45_PATCHED_FLASH=... MS45_PATCHED_MPC=... .venv/bin/pytest

## Layout

- `ms45emu/machine.py`  the machine: memory map, registers, `call()` a routine
- `ms45emu/image.py`    finding and validating a pair
- `ms45emu/dme.py`      traced addresses and helpers for this program
- `ms45emu/board.py`    the board around the CPU: peripherals, interrupts, the boot loop
- `ms45emu/cpu.py`      SRR0/SRR1, TB/DEC and EIE/EID, which Unicorn does not expose
- `ms45emu/qspi.py`, `ms45emu/qadc.py`  the QSPI/EEPROM and ADC models
- `tests/`              the checks, one file per subject
- `docs/`               notes on what a full boot would need

Related: the map-switch trace notes in `~/Desktop/e46bins/MS45-DME/Research`
and the builder in `~/Development/code/projects/BMWeb-Flasher` (`MapSwitch.cs`).
