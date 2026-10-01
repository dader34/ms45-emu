# What a full boot would need

Status of the pieces, as of 2026-09-30.

| Piece | Have | Notes |
|---|---|---|
| External flash (boot sector, program, calibration, init data) | yes | any full read; `MS45.1_7561382KNOWNGOOD_fullread.bin` is byte-identical to the donor stock program |
| MPC internal flash | yes | identical for every DME on this program |
| Boot path | traced | entry `0xFFF717B4` sets r1/r13/r2, RAM test `0xFFF71924`, data copy `0xFFF71800`, init chain `0xFFFC9068` |
| Memory map | traced | CS0 2 MB window, RAM `0x3F8000-0x400000`, keep-alive RAM `0x3FA0A0-0x3FA0DF`, IMMR `0x2F0000` |
| Serial EEPROM | missing | a separate chip; 69 stored-data blocks. Blank EEPROM = the "program changed" path = defaults, which is a real state (first boot after a flash) |
| Monitoring processor | missing | SPI question/answer; without it the DME resets ("ROM test level 2" is one of its reports) |
| Watchdog | model needed | SWSR at `0x2FC00E`, serviced with 0x556C / 0xAA39 |
| Timer interrupts | model needed | the 10 ms task that builds CAN 0x316 and runs the gesture |
| Sensors (QADC), CAN mailboxes (TouCAN at `0x3051C0`), SCI | model needed | resting values are enough for "ignition on, engine stopped" |
| Crank / cam (TPU) | model needed | only for engine running |

Realistic first target: ignition on, engine stopped, EEPROM blank, monitor
stubbed. That is the state the map switch operates in.
