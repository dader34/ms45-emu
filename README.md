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
acknowledgement, QSPI with a serial EEPROM, the MIOS interrupts the OS runs
on, the ADC, the time base and real exception delivery. The boot runs
through the reset path, the EEPROM load and the init chain into the OS,
whose periodic tasks then run on a 1 ms tick: the 10 ms CAN frame builder,
the stored-data task, the map-switch hook. Switch the ignition off and the
after-run writes the EEPROM and parks the CPU; boot again on that EEPROM
and the DME comes up on the map that was saved. `docs/full-boot.md` has the
state of each piece and what is still missing (CAN, the monitoring
processor, anything the engine needs).

    from ms45emu import load_pair
    from ms45emu.board import Board
    b = Board(load_pair("stock"))
    b.probe(0x3B38C, "scheduler task")
    print(b.boot(max_insns=20_000_000), b.report(), dict(b.probe_counts))
    b.ignition(False)                      # KL15 off: the after-run starts

A simulated second is 40 M instructions and takes about four seconds.

The DME is on its CAN bus as well: it sends the real DME1-4 frames
(0x316 with the rpm the cluster shows, every 10 ms) and takes the ASC,
cluster and gearbox frames in; `ms45emu/e46.py` plays those partners.
`tools/bench.py` puts the emulated DME on a real bus through a USB-CAN
adapter (python-can), so a cluster on the bench, or the car with its DME
unplugged, follows the emulator.

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
- `ms45emu/qspi.py`, `ms45emu/qadc.py`, `ms45emu/toucan.py`, `ms45emu/tpu.py`, `ms45emu/flashchip.py`  the QSPI/EEPROM, ADC, CAN, TPU and flash-chip models
- `ms45emu/sci.py`, `ms45emu/kwp.py`  the K line and a KWP tester
- `ms45emu/e46.py`      the other modules on the E46's bus
- `tools/bench.py`      the DME on a real CAN adapter
- `tests/`              the checks, one file per subject (`test_boot.py` is the full boot; the ignition-off round trip needs `MS45_SLOW=1`)
- `docs/`               notes on what a full boot would need

Related: the map-switch trace notes in `~/Desktop/e46bins/MS45-DME/Research`
and the builder in `~/Development/code/projects/BMWeb-Flasher` (`MapSwitch.cs`).
