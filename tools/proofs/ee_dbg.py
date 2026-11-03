"""One EEPROM read under the microscope: where the body sits when the
reply never comes, what the QSPI model saw, what the queue holds."""
import struct
import sys

from ms45emu.image import load_named, Pair
from ms45emu.board import Board
from ms45emu.checksums import crc32_mpeg2  # noqa: F401
from tools.build.flasher_gate import build, ENTRY_CPU, stamp_bytes
from tools.build.flasher_body import SRAM_BASE, REPLY_OFF, EE_WINDOW, build_body
from tools.build import flasher_body as fb
from tools.proofs.flasher_session_test import Session, frame, expect, fast_waits
from ms45emu.qspi import SPCR0, SPCR1, SPCR2, SPSR, RX_RAM, TX_RAM, CMD_RAM


def main():
    pair = load_named("session1.livetune6-notraps")
    f, m = build(pair.flash, pair.mpc)
    board = Board(Pair(bytes(f), bytes(m), "eedbg", check_program=False),
                  waits=fast_waits())
    pattern = bytes((i * 13 + 0x5A) & 0xFF for i in range(0x10000))
    board.load_eeprom(pattern)
    s = Session(board)

    board.sci.line_hold = True
    reached, why = board.boot(max_insns=2_000_000, until=ENTRY_CPU + 4, reset_vector=True)
    assert reached, f"never reached the flasher entry: {why}"
    in_body = lambda: SRAM_BASE <= board.m.pc < SRAM_BASE + REPLY_OFF   # noqa: E731
    if not s.until(in_body, budget=2_000_000):
        raise SystemExit("FAIL: the body never reached SRAM")
    board.sci.line_hold = False
    if not s.until(lambda: len(board.sci.tx) >= 21):
        raise SystemExit("FAIL: no HELLO after the break released")
    board.watchdog_window()
    board.sci.model_overrun = True
    board.cmf.watch_hv_reads()

    words, _ = build_body()
    la = {v: k for k, v in fb.LABEL_ADDRS.items()}

    # every access in the QSMCM block, from here on (head matters: the
    # poll floods the tail), and any exception inside the transfer hook
    # printed instead of swallowed by the unicorn binding
    qlog = []
    page = board.qspi.page
    page.trace = (lambda kind, addr, size, value:
                  qlog.append((kind, addr, size, value))
                  if 0x305000 <= addr <= 0x305200 else None)
    _orig_transfer = board.qspi._transfer

    def loud_transfer():
        try:
            _orig_transfer()
        except BaseException:
            import traceback
            traceback.print_exc()
            raise

    board.qspi._transfer = loud_transfer
    print(f"before: SPCR2 {page.peek16(SPCR1 + 2):#06x} transfers {board.qspi.transfers}")

    def dis(pc):
        i = (pc - SRAM_BASE) // 4
        if not 0 <= i < len(words):
            return "<outside the body>"
        return f"{words[i][1]:28s} {la.get(pc, '')}"

    q = board.qspi
    try:
        got = s.read(EE_WINDOW, 0x80, budget=20_000_000)
        want = pattern[:0x80]
        bad = next((i for i in range(0x80) if got[i] != want[i]), None)
        print("READ OK" if bad is None else f"READ differs at +{bad:#x}")
    except SystemExit as e:
        print("read failed:", e)
    print("queue outs (first 6):", [out for _, out, _ in q.log[:6]])
    print("eeprom reads:", q.eeprom.reads)

    # the proof's tail sequence: two NAKs, then the request that hung
    import struct
    for off, n, note in ((EE_WINDOW | 0xF001, 0x1000, "past the end"),
                         (EE_WINDOW, 0, "zero length"),
                         (0x50000000, 4, "bit 29 + bit 30")):
        try:
            f = s.xfer(10, struct.pack(">IH", off, n), budget=50_000_000)
            print(f"{note}: reply {bytes(f).hex()}")
        except SystemExit as e:
            print(f"{note}: {e}")
            print("  sci.tx tail:", bytes(board.sci.tx[-24:]).hex())
            for off2 in range(-4, 3):
                print(f"  {board.m.pc + 4 * off2:#x}  {dis(board.m.pc + 4 * off2)}")

    # v15 EE_WRITE smoke: 8 bytes at 0x140, then read them back
    data = bytes(range(0xA0, 0xA8))
    try:
        f = s.xfer(0x0B, struct.pack(">IH", EE_WINDOW | 0x140, len(data)) + data,
                   budget=50_000_000)
        print(f"WRITE ack: {bytes(f).hex()}")
    except SystemExit as e:
        print(f"WRITE: {e}")
        print("  sci.tx tail:", bytes(board.sci.tx[-24:]).hex())
        for off2 in range(-4, 3):
            print(f"  {board.m.pc + 4 * off2:#x}  {dis(board.m.pc + 4 * off2)}")
    got = s.read(EE_WINDOW | 0x140, 8, budget=20_000_000)
    print("readback:", got.hex(), "want", data.hex(),
          "OK" if got == data else "DIFFERS")
    print("eeprom writes:", q.eeprom.writes, "write_enabled:", q.eeprom.write_enabled)
    print("last queue:", q.log[-1])

    pc = board.m.pc

    # what actually moved: the part's answer, the staged page, the wire
    p = q.page
    print("expected :", pattern[:16].hex())
    print("RX low 3+:", bytes(p.peek8(RX_RAM + 7 + 2 * i) for i in range(16)).hex())
    staged = bytes(board.m.mu.mem_read(0x3FD800, 16))
    print("staged   :", staged.hex())
    print("sci.tx tail:", bytes(board.sci.tx[-32:]).hex())

    print(f"r10 {board.m.reg(10):#x} (QSMCM base)")
    print("first 40 QSMCM accesses of the read:")
    for k, a, sz, v in qlog[:40]:
        print(f"  {k} {a:#x} sz{sz} {v:#x}")
    print(f"last 24 QSMCM block accesses:")
    for k, a, sz, v in qlog[-24:]:
        print(f"  {k} {a:#x} sz{sz} {v:#x}")
    print(f"pc {pc:#x}:")
    for off in range(-8, 5):
        print(f"  {pc + 4 * off:#x}  {dis(pc + 4 * off)}")
    p = q.page
    print(f"SPCR0 {p.peek16(SPCR0):#06x}  SPCR1 {p.peek16(SPCR1):#06x}  "
          f"SPCR2 {p.peek16(SPCR2):#06x}  SPSR {p.peek8(SPSR):#04x}")
    print(f"done_at {q.done_at}  now {q.now()}  transfers {q.transfers}  "
          f"eeprom reads {q.eeprom.reads} writes {q.eeprom.writes}")
    print("TX 0-4:", [hex(p.peek16(TX_RAM + 2 * i)) for i in range(5)])
    print("CMD 0-4:", [hex(p.peek8(CMD_RAM + i)) for i in range(5)])
    print("RX 0-5:", [hex(p.peek16(RX_RAM + 2 * i)) for i in range(6)])
    print("log tail:", q.log[-3:])

    # step a little and watch the pc move (or not)
    pcs = []
    for _ in range(6):
        board.run_from(board.m.pc, 2000, until=0x1)
        pcs.append(board.m.pc)
    print("pcs after 6 slices:", [hex(x) for x in pcs])


if __name__ == "__main__":
    main()
