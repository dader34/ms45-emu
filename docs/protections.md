# The DME's protections

What the program does when something is wrong, found with the RE tools
(`tools/xref.py`, `tools/funcmap.py`, `tools/explain.py`) on program
`0044570LO02S`, so that a custom program can be checked against them on
the emulator before it goes near a car. State as of 2026-10-07: the
reactions are found; the checks that feed them are being enumerated.

## Reactions

Everything a check can do ends in one of these.

| Reaction | Where | How to see it on the emulator |
|---|---|---|
| A fault entry | `fault_report` (MPC `0x26170`): r3 = fault index, r4 = result bits (`0x10` plus the low bits of the verdict), r5-r7 details. 258 descriptors at MPC `0x45B8` (handler, counter byte at `0x3FDAA1`+i, calibration record at cal `0x8EF8`+0x12·i, status word at `0x3FD106`+4·i, flags). `fault_report_b` (`0x2657C`) is the same without a verdict; `fault_query` (`0x267E4`) asks | `Board.probe` on `fault_report` with `on_hit` reading r3/r4; `ms45emu/faults.py` turns the index into the DTC code (record bytes 10-11) and text |
| Limp home | the flag `limp_home_flag` (r13-0x4059) and `limp_home` (r13-0x406B), the limiter's limp limit `c_n_max_mtc_lih` | `xref.py 0x3FD797` lists the writers: each is a check |
| An ignition or injection cut | the ignition-fire sites gated in `ms45emu/protect.py`; the fuel path not yet traced | a run with `--rpm` and the TPU I/O capture |
| A reset | the watchdog. It is serviced unconditionally at the very end of `task24` (`0x55A7C`, the 10 ms chain: `0x55D40`/`0x55D4C` write `556C`/`AA39`); nothing in the program withholds it on purpose. A reset therefore means the chain did not finish: an unexpected exception (the handlers at `0xFFF71A9C`.. end in `b .`), a hang, or a jump into erased flash, which is what the earlier limiter hook did | `board.watchdog_services` stops growing; pc in one of the `b .` handlers; `board.other_exceptions` |

Fault indices are the program's own; BMW's DTC codes are the same across
programs. The research CSV (`ms45_dtc_table_7561533.csv`) is indexed by
another program and must only be used by code: `Faults(pair).describe(i)`.

## The self-tests

Found by their DTC code in this program's table, then the `li r3, index`
before a call of `fault_report`:

| DTC | Index | Reporter | What it checks (from `explain`) |
|---|---|---|---|
| 2830 P16A0 checksum | 38 | `selftest_checksum` `0xFFFCF2B0`, from task11 | drives the background CRC-32 walker (`fn_FFFD9E68`, the hottest function in coverage; `dme.FLASH_CRC_RETURN`) over the external flash and compares with the stored sums. The map switch's and the patches' sums are refreshed for this (`checksums.py`) |
| 2831 P3238 "Prozessorüberwachung" | 96 | `selftest_processor_monitor` `0x4375C`, from `fn_37FE8` and `fn_5B954` | reads `c_abc_max_eng_psn`, `c_abc_max_tooth_per`, `c_abc_max_tpu_syn` and the crank driver's state: it monitors the TPU, the MPC555's co-processor that runs the crank and the outputs, not an external watchdog chip |
| 2869 P16A3 RAM check | 206 | `selftest_ram_check` `0xFFFCF1D0` | compares RAM copies (`fn_FFF6969C`, the 287-caller helper) |
| 2777 ADC | 129 | | |
| 2779 P0604 RAM | 153 | | |
| 28FF / 2900 P3024 / P3025 | 246 / 247 | | |

The safety monitor's code sum ("ROM test level 2", `romtest_accumulate`,
`tests/test_romtest.py`) is separate from the CRC-32 above: its stored
value at `0xFFF60600` is what a map-switch build must correct.

## The SPI devices

The QSPI command RAM is fixed at boot: queues 0-3 PCS2 (16-bit pairs such
as `0404`, `8232`), 4-7 PCS1 (the EEPROM), 8-12 PCS3 (single bytes `35`,
`d1`, `40`, `e0`, `e1`, `94`, polled continuously), 13-20 PCS0 (8-byte
frames `3b3b0208ff0000f5`, `7e7e000000000000`, sent by
`spi_pcs0_frame_task` `0x213CC` from task22 every 10 ms; answers read by
`fn_21768` and `fn_2A3AC`), 21-26 with no chip select asserted. Driver:
`qspi_request` → `qspi_start_queue`; `qspi_fill_tx` / `qspi_read_rx`.
All but the EEPROM are answered as an open bus (`0xFF`) today. Which of
them is a monitoring device, and whether a wrong answer has a reaction,
is the next thing to establish; the self-test above suggests the
"processor monitoring" DTC is about the TPU, not about them.

## The checks

`tools/protections.py --table docs/protections-checks.md` lists every
check statically (`ms45emu/protections.py`, `Checks`): 124 routines that
report a fault (the `li r3, index` before a call of `fault_report`) or
write a limp-home flag or the engine state, with the OS task each runs
under, its calibration thresholds by XDF name, and the RAM it reads and
writes. Worth knowing from it: the vehicle-speed and engine-speed
limiter `fn_FFF961A0` (task28, `c_vs_max*`, `c_t_max_n_max_h_*`) is a
writer of `limp_home`; `brake_throttle_plausibility` (task22) is the
writer of `limp_home_flag`; the self-tests sit in the segment task
(processor monitoring), task11 (checksum) and the stored-data tasks.

## Checking a custom program

`tools/protections.py --pair X` (or `--flash/--mpc`) boots the pair and
runs a scenario (the crank at `--rpm`, the E46 peers on the bus,
`--key-off` for the after-run) with `Reactions` watching: the fault
reporter probed (index, verdict: `0x10` is "tested", a low bit is the
way it failed), the limp-home flags and the engine state hooked, the
watchdog checked every 20 ms once armed, exceptions and the `b .`
handlers watched. The stock pair is run the same way and the difference
printed. `tests/test_protections.py` does this for the map switch and a
protect build; a custom program is checked the same way.

What the stock pair itself fails on the emulator (0.5 s at 800 rpm),
which is the baseline and a list of what the board does not model yet:

| Faults | Why |
|---|---|
| 10, 11 (`271C`, `2724`), 44-47 (ASC/LWS messages) | the peers send zeroed frames; the DME wants content (alive counters) |
| 59-64 ignition cylinder 1-6, 53-58 coils | no coil feedback on the TPU outputs |
| 73 pedal signal, 65-72 throttle/pedal pots | ADC channels read mid-scale |
| 88-91 cam sensors, 94/97 crank | no cam model; the crank resynchronises |
| 173 `286B` output-stage IC | PCS0 (queues 13-20, 8-byte frames). Its self-test `fn_5BBD8` (task24) asks `fn_23284` for the error flag r13-0x766A, which the driver `fn_21768` sets at `0x21AA8` when bytes 16-17 of its receive buffer (on the heap, `0x3FF2FC`) are not `AA`. `fn_21768` is a generic sequence driver: a descriptor at r13-0x7668 (byte 0 = bytes per message, byte 2 = first queue entry), a message counter r13-0x763C against a count r13-0x763B, a transmit buffer r13-0x7650 and the receive buffer r13-0x7640, into which each message's answer is copied from the RX RAM (`0x217F4`, `0x21828`, `0x21858`) indexed by the counter. Answering `AA` on every chip select (codes B, E and F, singly and together; an echo on F) does not clear the fault: the slot it checks still holds the `FF` the driver put there, so the job that owns that slot never gets its transfer. Chip-select idle levels are all high (PORTQS `0x78`), so code F (queues 21-26, `78aa`/`5689`/`6caa`) selects nothing on paper and yet is part of the traffic. Left here; the baseline comparison is not affected |
| ~~174 `286A` knock IC~~ | passes since `qspi.py` models PCS3 (queues 8-12) as an echo: the self-test `fn_FFF9C4E0` (task28, with the engine running) asks `fn_11FC0`, and the driver `fn_11FEC` at `0x120B0` wants the five bytes it sent back unchanged |
| 164 BSD, 215 ambient sensor | the bit-serial interface to the alternator and the ambient sensor are not modelled |
| 206 `2869` RAM check | `selftest_ram_check` (`0xFFFCF1D0`) fails when r13-0x2AA0 or r13-0x3FF6 is set, and both are set by the stored-data restore in task10 at boot: block 3's restore (`fn_FFFCA290`: a word kept three times, two decoded through `fn_C6D0`, must agree two of three) finds no majority, and the block reader `fn_FFFC97FC` finds block 4 without a valid record. Both because the EEPROM is blank; a DME with its own EEPROM passes. The after-run's EEPROM image (`images/eeprom.bin`) does not carry them either |
| `limp_home` toggling every 100 ms, `engine_state` 5 → 0 → 2 (→ 3 at key off) | the stock program's own behaviour with these inputs |

A reset never happens on the stock pair: the watchdog is serviced 10 ms
after 10 ms, no exception, no hang.

## The ignition checks and the TPU

Faults 53-64 (coils, ignition per cylinder) come from `ignition_diagnosis`
(`0x34648`, segment task), which per cylinder takes `ignition_word4`
(word 4 of the cylinder's TPU channel, through the channel table at
r13-0x74D4) and `ignition_fired_flag` (bit per cylinder at r13-0x74AE,
cleared on reading). Nothing sets that bit on the emulator, because the
TPU's completion interrupts never come: `Tpu.on_service` only records
the host service request.

How they would come: the TPU interrupt (`tpu_interrupt`, SIU level 1)
calls `tpu_dispatch` (`0x1F12C`), which takes CISR & CIER of both
modules as 32 bits (A0-15 low, B0-15 high), clears each pending bit and
calls the handler from the table at RAM `0x3FB058` (32 pointers, a byte
argument each at +0x80): A0-5 `ignition_channel_handler` (arg = the
cylinder), A6/9/11/15 and B9/15 `fn_164D8` (PWM), A10/A12 `cam_handler`
(arg 0/1), A13 `crank_handler`, B14 `tpu_b14_capture_handler`, the rest
a stub. `ignition_channel_handler` reads the channel's parameter RAM:
byte 9 bit 0 as a status into r13-0x750C, word 5 as the angle the pulse
happened at (it must equal one of four expected values 0x78 apart, else
bit 2 of r13-0x74F4), word 6 as a duration summed into r13-0x7508. So an
ignition model has to run the pulse the program schedules (words 0 and
1, written by `fn_18870`/`fn_19058` from `ignition_fire_a`) against the
crank angle, and on completion leave the angle in word 5, the duration
in word 6, the status in byte 9 and raise the channel's CISR bit.
Injecting the interrupt alone, with made-up words, sets nothing.

The cam channels (A10, A12) never interrupt either: no edges are
generated, so `cam_handler` (3.5 KB) never runs and the cam checks
(`fn_FFF77EC4` in the segment task, `fn_FFFCD878`/`fn_FFFCDC94` in
task10) fail on duration and phase. A cam model needs the microcode
function D's parameter layout, from `cam_handler`.

## Why the earlier cold-start limiter reset the DME

The first cold-start protection lowered the limiter's own limit: a hook on
`sth r30,-0x4BD6(r13)` at `0xFFF96950` (`fn_FFF961A0`, task28, the only
writer of `N_max`) stored a lower value when cold. What the tools show:

- `N_max` itself is read by one routine only, the torque-path limiter
  `fn_52AD8` (task24 via `fn_68EE8`). Nothing in the safety monitor reads
  it, so a lower value is not caught by a comparison of the value.
- The safety monitor (`fn_FFF60788`, task22, 20 sub-monitors, each found
  by its `*_mon` calibration items) has its own rev-limiter check,
  `fn_FFF651AC`: with its gate r13-0x3D9F set, its **own** engine speed
  (r13-0x3D96, from the n_32 monitor `fn_FFF652EC`) above
  `c_n_max_mtc_lih_thd_mon` (raw 51 = 1632 rpm) and cylinders cut in the
  cut mask r13-0x6506 (low 6 bits; written by `fn_FFFCB5F0`, applied per
  cylinder in the segment task's `fn_32688`), it counts up with
  `c_abc_inc/max_tqi_n_max_mon` and, debounced, sets r13-0x3D97.
- r13-0x3D97 is read by `fn_FFF64EB0`, which packs the monitor's states
  into the reset record r13-0x7744..-0x773F (two bytes, each with its
  complement). At the next start `fn_FFF685F8` checks that record and
  reports fault 139 `28B2` "Drehzahlbegrenzung: Reset" (XDF
  `fmy_id_tqi_n_max_nvmy_mon`); fault 137 `28B1` "Drehzahlbegrenzung"
  (`tqi_n_max_mon_1`) is its running counterpart.

So the chain is: the lowered limit makes the main program cut cylinders
at a speed the monitor considers legitimate only in limp home; the
monitor sees a speed-limiter cut it did not expect, confirms it, records
the rev-limiter reaction in non-volatile memory and resets. The spark-cut
patch now in `protect.py` avoids exactly that: `N_max` and the cut mask
stay as stock computes them and only the ignition is withheld, which this
monitor does not watch.

On the emulator the trip does **not** reproduce yet, and the harness says
nothing different from stock with `N_max` forced to 500, 1000 or 3500:

- the cut mask stays 0: `fn_52AD8`'s cut decision needs torque-path
  inputs (pedal, torque request) that are not modelled;
- started straight at 1300-1400 rpm the crank does not synchronise
  (gap reported, never answered). Not a `Crank` bug: at "gap found"
  `crank_handler` compares the cam levels with the ones its segment table
  expects and restarts the search on a mismatch (`0x18154` →
  `crank_set_mode(0, 0)`); with no cam model the outcome depends on the
  phase. Synchronised at idle first, the speed then holds anywhere up to
  7000 rpm, so `Reactions.scenario` now ramps from 800 rpm. Ramped to
  3000 rpm the monitor sees 2976 rpm (above its 1632), but with `N_max`
  forced to 1000 the cut mask still stays clear and `n_max_limiter`'s
  outputs hardly change: its intervention is a torque reduction that the
  unmodelled pedal and torque request (fault 73, pedal signal) leave with
  nothing to reduce.

With pedal and torque request modelled, a test would replay the old hook
above 1632 rpm and expect r13-0x3D97 and the reset record to be set,
which is the regression test for any limiter-side protection.

## Next

1. The output-stage IC's protocol on PCS0 (above), so that its self-test
   passes and a custom program's SPI traffic can be judged.
2. Coils and cam signals on the TPU, so the segment task's checks run on
   real inputs.
3. An EEPROM image with stored-data blocks 3 and 4 valid (a read from a
   car, or an after-run that writes them), so the RAM check passes.
