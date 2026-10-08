# Flashing the emulated DME

The emulated DME can be flashed over its K line the way the real one is:
calibration only, or the whole program (external flash and the MPC555's
internal flash). The tester only speaks KWP2000*; erasing, programming,
the checksums, the RSA signature checks and the decision what to start
after a reset are all the DME's own boot loader running against models of
the two flash memories.

`ms45emu/kwp.py` (`Tester`) drives it from Python; `tools/kline.py` puts
the K line on a serial port for EDIABAS, INPA or the flasher app.

    from ms45emu import load_pair
    from ms45emu.board import Board
    from ms45emu.kwp import Tester

    b = Board(load_pair("stock"))
    b.boot(max_insns=20_000_000)
    t = Tester(b)
    t.authenticate(); t.programming_mode()
    t.erase(0x02040000, 0x20000)                 # calibration sector
    t.write(0x02040000, calibration)             # 0x1D000 bytes
    t.default_mode()
    t.check_signature("data")                    # the DME marks it valid
    t.reset()
    b = b.reset()                                # a board on the new flash contents
    b.boot(max_insns=40_000_000, reset_vector=True)

`tests/test_flash.py` does this with the stock pair (half a minute), and
with `MS45_SLOW=1` the whole program (about five minutes).

## The job order

From a real `flash-program.log` of the flasher, and what the emulated DME
answers the same way:

    1A 89                                  seriennummer_lesen
    31 07 03 <user4>                       authentisierung_zufallszahl_lesen (seed)
    31 08 00 00 00 10 <key64>              authentisierung_start
    10 85 05                               diagnose_mode (ECUPM, 115200 baud)
    83 03 00 78 18 F0 00                   access timing (P3min 12 ms)
    31 02 06 00 00 02 0A 00 00             flash_loeschen: program, 0x02060000 + 0xA0000
    34 06 00 00 02 00 09 FF 40             flash_schreiben_adresse -> 74 FE
    36 <253 bytes>                         flash_schreiben -> 76 <block> 01, ...
    37 06 00 00 02 00 09 FF 40             flash_schreiben_ende
    34 00 00 00 06 00 07 00 00  36.. 37    the internal flash: 0x06000000 + 0x70000
    31 02 04 00 00 02 02 00 00             flash_loeschen: calibration, 0x02040000 + 0x20000
    34 04 00 00 02 00 01 D0 00  36.. 37    the calibration
    10 81 01                               diagnose_mode (default, 9600 baud); the loader keeps running
    31 0A                                  status: 05 = program signature not checked
    31 09 02                               FLASH_SIGNATUR_PRUEFEN program -> 71 09 01
    31 0A                                  status: 06 = data signature not checked
    31 09 04                               FLASH_SIGNATUR_PRUEFEN data -> 71 09 01
    31 0A                                  status: 01 = normal
    11 01                                  STEUERGERAETE_RESET

Addresses are bytes 2, 1, 0, then byte 3: external flash is
`0x02000000 + offset`, the internal flash `0x06000000 + offset`. A
calibration-only flash is the same with just the calibration's erase,
write and signature check. `7F xx 23` means ask again, `7F xx 78` means
the answer follows on its own. The second status of a block answer
(`76 <block> 02`) is a failed write.

There is no erase job for the internal flash: erasing the program region
erases the external program sectors and all of the internal flash.

## What the DME does, and what it needed

The first erase request is taken by the running program, which shuts
itself down and jumps into the boot loader (`0xFFF04EC4`: MSR with IP,
exception table relocation off, then the flash-init `0xFFF0367C`). The
request that triggered this gets no answer; the next one is served by the
loader. From then on there is no OS and no interrupts: the loader's main
loop (`0xFFF05228`) runs four tasks off a 1 ms tick.

| The loader uses | Model | |
|---|---|---|
| PIT, 1 ms (`PISCR`/`PITC` = 999) | `Board`: PS set every period, write-1-to-clear | Without it the main loop never ticks and the K line stays silent |
| SCI polled, 115200 baud | `Sci`, with slices ending at each byte time | |
| Supply voltage, QADC B channel 50 | `BATTERY_CHANNEL`, default `BATTERY_OK` | Erase answers `7F 31 22` below 0x218 counts; KL15 is channel 55 as before |
| External flash commands from a RAM copy of its driver (`0xFFF14BBC`...) | `FlashChip` | AMD command set; burst-mode configuration (`C0`) is accepted and ignored |
| Internal flash: `CMFMCR`/`CMFCTL` at `0x2FC800`/`0x2FC840`, EPEE pin | `Cmf` | Motorola's driver; refused with error 0x87 unless EPEE reads 1 |
| MIOS port pin 6 (`0x306100` bit 0x40) | taken to be the EPEE enable | The flash-init raises it first; it is plain GPIO, not a gate of its own |
| PLL lock (`PLPRCR`) | reads locked | Only on the path from the reset vector |

The external chip has the sector layout of an Am29BL802CB, which is also
how the DME is partitioned (the firmware's own sector-erase addresses show
it): boot loader below `0x40000`, calibration in the 128 KB sector at
`0x40000`, program in the 128 + 256 + 256 KB from `0x60000`.

Neither model times anything: an erase or program is done when the
command is, so the driver's first poll sees it finished. A word is
programmed by ANDing, as on the real parts. After an internal-flash
program pulse the array shows the program margin read (all zeros when
done) until the driver closes the sequence.

### What makes a flash valid

The loader works out the checksums in the background, ten bytes per pass:

- program: CRC-32/MPEG-2 over the internal flash and the external program,
  stored at `0x60000` and `0x60340`;
- calibration: the same CRC over `0x40200`-`0x5CFFF`, start, end and
  initial value from the header at `0x40104`, stored at `0x40100`.

`31 09` then checks the references (hardware, program, data, at
`0xFFF148E0`) and the RSA signature over the MD5 of the listed segments,
and on success writes marks into the last bytes of the sector:

| | complete | signature checked |
|---|---|---|
| program | `0xFFF80` = `42902448` | `0xFFFC0` = `42244890` |
| calibration | `0x5FF80` = `48249042` | `0x5FFC0` = `90482442` |

At a reset the loader (`0xFFF032CC`, from the reset vector `0xFFF00100`)
starts the program with `ba 8` only when the marks are there; otherwise
it stays in programming mode and reports the status that says why.

A dump read over diagnostics does not contain the marks (they read as
`FF`), so `Board` puts them back for a pair it is told to run.

### Reset

`11 01` is answered and nothing more happens in the emulator; the reset
itself is `Board.reset()`, which builds a new board from what the two
flash memories now hold (`flash.image`, `cmf.image`: the contents without
the emulator's patches) and the EEPROM. `boot(reset_vector=True)` then
starts where the CPU does. If the marks are missing the new board leaves
the program bytes untouched, so the loader's checksum and signature checks
still see what was flashed.

`tools/kline.py` does the same for an ignition cycle (`i`, or
`/ignition/off` and `/ignition/on` on its `--ws` port). A flash that was
interrupted leaves the loader in its programming session at 115200 baud,
status `07`, deaf to a tester that starts over at 9600; ignition off
takes its power, and on again it comes up from the reset vector at 9600
with status `0C` (program not complete) and takes a new flash. With the
program running, ignition off is the after-run first (35 s on a blank
EEPROM) and the power goes when it has parked.

The program is started with MSR[IP] still set; what moves its exceptions
to the compressed table at 0 is `BBCMCR[ETRE]`, which `Cpu` now follows.

## Limits

- A signature check of a program the emulator is running fails: its
  EIE/EID sites are patched in memory. Checks of what was just flashed in
  the same session, which is the only way the flasher uses them, see the
  real bytes.
- The image has to be right. The DME refuses a calibration whose stored
  CRC does not match (status `0F`, `71 09 00`), exactly as it should. Note
  that the copy the flasher saves under `flashed/` is the image *before*
  its write-time fix-ups: the CRC and signature it actually sends differ
  from the saved file.
- Timing is not modelled: erase and program are instant, so a flash is
  limited by the K line (about 5 KB/s at 115200 baud). Through
  `tools/kline.py` a tester's own pause after each answer comes on top
  (BMWeb: 25 ms, 77 ms a block in all); `--turbo` runs the DME ahead of
  the wall clock while a telegram is in flight, 47 ms a block.
- The AIF write (`3D`) after a flash has not been tried.
