# Flashing the emulated DME

Status as of 2026-10-01. The goal is to run BMWeb-Flasher / EDIABAS against
the emulated DME over the K line and have a program or calibration actually
land in the flash image.

## What works

The diagnostic transport and the whole pre-flash handshake run against the
real firmware, driven by `ms45emu/kwp.py` (`Tester`) or a real tester
through `tools/kline.py` (a pseudo-terminal EDIABAS can open):

- KWP2000* framing (`B8 <tgt> <src> <len> … <xor>`) over SCI1 (`ms45emu/sci.py`),
  including the 115200-baud switch the flasher makes for programming.
- Identification (`1A 80`), serial (`1A 89`).
- The RSA seed/key authentication (`31 07` / `31 08`) — the MD5+RSA the
  flasher's `Checksums_Signatures` does, reproduced in `kwp.py`.
- Programming mode (`10 85 05`) and the access-timing telegram (`83 …`).

The exact job order the flasher uses (from a real `flash-program.log`):

    1A 89                                  seriennummer_lesen
    31 07 03 <user4>                       authentisierung_zufallszahl_lesen (seed)
    31 08 00 00 00 10 <key64>              authentisierung_start
    10 85 05                               diagnose_mode (ECUPM, 115200)
    83 03 00 78 18 F0 00                   access timing
    31 02 <addr3b4><len3>                  flash_loeschen  (erase)
    34 <addr><len>                         flash_schreiben_adresse (request download)
    36 <data…>                             flash_schreiben (transfer data, 258 B blocks)

Addresses are the programming-window form: `0x02000000 + flash_offset`
(e.g. `0x02060000`, `len 0xA0000` for a full program; `0x02040000`,
`len 0x20000` for calibration only).

## What is missing

The erase/program jobs are accepted (`7F 31 23`, "routine not complete /
busy") but never execute, because the DME gates them behind a flash-enable
hardware handshake the board does not model:

- The erase job (`0xFFF0EC2C`) runs only when the flag at `-0x7FC9(r13)`
  (`0x3F9827`) is set. It is set by the flash-init routine `0xFFF03680`,
  which writes a port latch at `0x306100`/`0x306102` (Vpp / write-enable),
  copies a small routine into RAM and runs it, then sets the flag.
- Until then the job takes the `flag == 0` branch (`0xFFF0EEAC`): a
  multi-stage init handshake through a vtable at `0xFFF6010C`, sequenced by
  the flags `-0x7BAE` and `-0x7FD4`. Each poll should advance one step and
  eventually set `-0x7FC9`; in the emulator the steps do not advance
  because the port latch and device unlock behind them are not modelled.

So the remaining work is to model the flash-control port at `0x306100`
and let that init handshake complete; then the firmware's own driver
(`0xFFF14CC8` erase, its state machine at `0xFFF15BC8`) issues real chip
commands.

## The chip is ready

`ms45emu/flashchip.py` already models the external flash as an AMD/Spansion
command-set device: it watches the command cycles (`AA@555`, `55@2AA`,
`A0` program, `80…30` sector erase, `10` chip erase) through the board's
write-protect hook and applies program/erase to the backing image at once,
so the driver's first completion poll reads "done". Once the init handshake
lands, erase and program will write the image, verifiable by reading it
back over KWP.
