# Logging: what the DME can do, and the diagnostic patch

Everything here was measured on the emulated DME (program `0044570LO02S`,
40 MIPS, engine stopped unless said otherwise). Nothing has been on the car
yet; see the limits at the end.

## What the stock program already does

In the default session, with no authentication:

| Request | What it gives |
|---|---|
| `10 81 05` | The default session at 115200 baud (`03` is 38400). Answered at the old rate, then the line switches |
| `83 03 04 01 18 14 00` | Access timing set to the session's limits: the DME answers after 2 ms instead of 25, and takes the next request 12 ms after its answer instead of about 27. Only exactly these values are accepted; anything else is `7F 83 22`. `83 00` reads the limits, `83 01` goes back to the defaults |
| `2C F0` then `03 <pos> <size> <addr24>` per piece | Defines local identifier `F0` from memory. All pieces in one request (a second request replaces the first), `pos` is the 1-based byte position, up to 42 pieces. `2C F0 04` clears it |
| `21 F0` | The packet |
| `23 <addr24> <size>` | Memory: RAM from `0x3F9800` and the internal flash, up to 250 bytes. 251 to 254 get no answer at all; the external flash is refused (`7F 23 52`) |

The programming session (`10 85 05`, after authentication) has the same
timing limits with an immediate answer, but refuses `21`, `22`, `2C` and
`18`, so it is no use for logging.

A 30-byte packet (`21 F0`), one read after another:

| | ms a read | |
|---|---|---|
| 9600 baud, default timing | 103 | 10 Hz |
| 115200 baud, default timing | 57 | 17 Hz |
| 115200 baud and `83 03` | 20 | 50 Hz |
| the same, with the patch | 10 | 100 Hz |

`Tester.logging_mode()`, `define_packet()`, `read_packet()` and
`read_memory()` in `ms45emu/kwp.py` do this.

## The patch

`ms45emu/diagpatch.py` builds it, `tools/diagpatch.py` writes the files:

    .venv/bin/python tools/diagpatch.py --flash Flash.bin --mpc MPC.bin --out DIR

It replaces two `bl` instructions in the internal flash and puts 368 bytes
of code in the unused end of the external program area:

| | |
|---|---|
| `0x4BE9C` `bl 0x4B528` | the 10 ms task calling the 0x316 builder; now calls the frame stub, which ends in `b 0x4B528` |
| `0x3235C` `bl 0x32180` | the last call of the segment task; now calls the segment stub, which ends in `b 0x32180` |
| `0xFFFDC860` up (file `0xDC860`) | the two stubs. The area is empty from `0xDC854`; the map switch's header and blocks begin at `0xDCC00` |

The stubs use r0, r11, r12 and cr0 only. Neither hooked call is in a range
of the safety monitor's code sum; that sum, the program checksums and the
program signature are recomputed all the same (`checksums.fix_program`;
signing the stock pair gives the stock signature back, byte for byte).
`diagpatch.remove()` returns the pair to what it was.

The map switch is not in the way and does not mind: its builder checks the
internal flash's free area and its own hook sites, none of which this
touches. Either order works.

### Fast timing

The access-timing handler (`0xFFF0D1F4`) is boot-sector code, which a
K-line flash cannot replace, so its limits stay. The times it sets are RAM:
the answer delay at `0x3F9A34`, the pause before the next request at
`0x3F9A35`, both in ms. Every 10 ms the frame stub looks there, and when it
finds exactly the limits (2 and 12) it writes 0 and 2. A tester that never
sends `83 03` sees no change; one that does gets 100 Hz. Leaving the
session (`10 81 01`) or `83 01` restores the DME's own values.

About 9 ms a read is the floor for polling: the DME's diagnostic task does
not come round sooner.

### The log frame

The frame stub sends one frame every 10 ms through message buffer 15 of
CAN module A, which the program never configures (0-10 receive, 11-14
transmit its own four frames; the interrupt mask is 0, the module is
polled). Identifier `0x7A0` by default.

| Byte | |
|---|---|
| 0 | counter, +1 a frame |
| 1 | pedal, 0.39 % a count |
| 2-3 | engine speed, rpm, big endian |
| 4 | vehicle speed, km/h |
| 5 | the DME's KL15 state |
| 6 | brake input |
| 7 | map-switch flag (bits 4-6: the map index, 0 = map 1) |

`build(pair, can_id=..., can_fields=...)` takes other variables (any RAM
address; 16-bit ones at even offsets), `can_id=None` leaves the frame out.
`tools/bench.py` passes it to a real bus like the DME's own frames.

### The capture buffer

Polling, however fast, samples at its own times. The segment stub writes a
record each time the segment task has run, which is once per 120 degrees
of crank, into a ring a tester reads whole with one request:

    23 3F F7 80 F8        248 bytes at 0x3FF780

| Offset | |
|---|---|
| 0-1 | `D1 A6` once the frame stub has set the block up |
| 2 | 10 ms counter (the log frame's) |
| 3 | the slot written next, 0-29 |
| 4 | the last sequence number |
| 8 + 8 x slot | sequence number (1-255, 0 = never written), segment 0-5, segment time (16 bit, 4 us a count), engine speed (16 bit), pedal, spare |

`Layout.records()` puts a block in order and `Capture.feed()` gives the
records that are new since the last read. The slot about to be written is
never returned (the read may have caught it half done), which leaves 29 a
read. A read takes about 30 ms with the patch's timing, in which 6500 rpm
produces ten records, so nothing is lost up to the limiter.

The block sits in the program's heap (`0x3FF2A0`-`0x3FF900`), which is
handed out at start-up from the bottom (to `0x3FF4C0` with this
calibration) and, by the allocator's other mode, from the top (not used
here). Both stubs compare the heap's two pointers with the block first and
leave the block alone, CAN frame included, if the heap has reached it.

## Tests

`tests/test_diagpatch.py`: the images (only the two calls and the free
area change, sums and signature valid, removal gives the stock pair), the
program running as before with the frame on the bus, timing untouched
until asked for, 50 Hz stock and 100 Hz patched, the ring against a probe
on the segment task at 900, 3000 and 6500 rpm, the heap guard, and the
patch on top of the map switch (the cluster is told the same, frame for
frame). With `MS45_SLOW=1` the patched program is flashed through the
DME's own boot loader, which checks its checksum and signature, and is
started from the reset vector.

## Limits

- Emulator only so far. The CPU there has nothing to do for the engine;
  on the car the answer delay may stretch under load.
- A real K-line cable has to turn round in 2 ms. An FTDI adapter needs its
  latency timer at 1 ms for that (the default is 16).
- Message buffer 15 and an extra identifier on the car's bus have not been
  tried on hardware. `0x7A0` is not one the E46's modules are known to use.
- The heap figures are for the calibrations tried here (stock and the
  map-switch pairs on this machine); the guard is what covers the others.
- Above about 4000 rpm the emulated DME keeps restarting its crank search
  (no cam signal), so segment times there are irregular. The ring shows
  that faithfully; it is the emulation, not the patch.
