"""Where the vault's first blocks come from: boot the STOCK program on a
blank EEPROM and log every WRITE the program itself makes.

The question (2026-10-28): every saved emulator vault carries the same
opening -- the voting pairs at 0x4..0x1E (fb82 08ef | fb7d f7ef 0482 0810,
twice) and the six-word group at 0x3A (cccc caca cfce c8cb b2ac cbca,
three copies, "74MS45" after the third). The oldest file (images/
quickflash1.eeprom.bin, Oct 20) predates the v14 read window, so no
hardware source exists: either the program writes these blocks when the
vault is blank, or past tooling seeded them. bench.py boots blank and
saves at power-down, and nothing in the tree seeds those bytes -- so if
this boot writes them, the program is the author and the layout is the
real stored-data format, learned from the writer itself.

Run from the ms45-emu root:
.venv/bin/python -m tools.analysis.ee_origin [flash.bin mpc.bin]
(defaults to the donor pair in ~/Downloads/new_reads)
"""
import os
import sys
import time

from ms45emu.image import Pair
from ms45emu.board import Board

DONOR_DIR = os.path.expanduser("~/Downloads/new_reads")
DEFAULT_FLASH = os.path.join(DONOR_DIR, "NJ87379_0044570_Flash_new.bin")
DEFAULT_MPC = os.path.join(DONOR_DIR, "NJ87379_0044570_MPC_new.bin")

RUN_INSNS = int(os.environ.get("RUN_INSNS", "30000000"))


def main():
    flash = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FLASH
    mpc = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_MPC
    vault = os.environ.get("EE_VAULT")     # optional: seed a real dump
    pair = Pair(open(flash, "rb").read(), open(mpc, "rb").read(),
                os.path.basename(flash))
    board = Board(pair)
    qspi = board.qspi
    eeprom = qspi.eeprom
    if vault:
        img = open(vault, "rb").read()
        eeprom.data[:len(img)] = img
        print(f"vault seeded from {vault} ({len(img)} bytes)", flush=True)
    else:
        assert eeprom.data == bytearray(b"\xff" * len(eeprom.data)), "vault not blank"

    writes = []          # (insns, pc, addr, bytes)
    reads = {}           # addr -> first insn that read it
    orig = eeprom.transaction

    def traced(out: bytes) -> bytes:
        if out and out[0] == 0x02 and len(out) >= 3:
            addr = (out[1] << 8) | out[2]
            writes.append((qspi.now(), board.m.pc, addr, bytes(out[3:])))
        elif out and out[0] == 0x03 and len(out) >= 3:
            addr = (out[1] << 8) | out[2]
            reads.setdefault(addr, qspi.now())
        return orig(out)

    eeprom.transaction = traced

    t0 = time.time()
    print(f"booting {pair.name} on a blank vault (up to 20M insns)...", flush=True)
    board.boot(max_insns=20_000_000, reset_vector=True)
    print(f"boot done: {qspi.now():,} insns, "
          f"{len(writes)} WRITEs, {len(reads)} distinct READ addresses, "
          f"powered_down={board.powered_down}", flush=True)

    print(f"running {RUN_INSNS:,} more insns...", flush=True)
    board.run(RUN_INSNS)
    print(f"run done: {qspi.now():,} insns total, "
          f"{len(writes)} WRITEs, powered_down={board.powered_down}",
          flush=True)

    print("\nWRITE log (insn, pc, addr, bytes):")
    for ins, pc, addr, data in writes:
        print(f"  {ins:>12,}  pc={pc:08X}  {addr:04X}  {data.hex(' ')}")
    if not writes:
        print("  (none -- the program never wrote)")

    first = sorted(reads.items(), key=lambda kv: kv[1])[:24]
    print("\nfirst READ addresses (addr, insn):")
    for addr, ins in first:
        print(f"  {addr:04X}  {ins:>12,}")
    pages = sorted({a >> 12 for a in reads})
    print(f"\nREAD pages (addr>>12): {[f'{p:X}' for p in pages]}")
    per_page = {p: sum(1 for a in reads if a >> 12 == p) for p in pages}
    print(f"reads per page: { {f'{p:X}': n for p, n in per_page.items()} }")

    img = bytes(eeprom.data)
    nz = [i for i, b in enumerate(img) if b != 0xFF]
    print(f"\nvault now: {len(nz)} non-blank bytes" +
          (f", first at {nz[0]:#06x}, last at {nz[-1]:#06x}" if nz else ""))
    if nz:
        lo, hi = nz[0], min(nz[-1] + 1, nz[0] + 0x80)
        print(f"  {lo:#06x}..{hi:#06x}: {img[lo:hi].hex(' ')}")
    print(f"\n{time.time() - t0:.0f}s wall")


if __name__ == "__main__":
    main()
