"""Does the 4K serial-EEPROM pair block override the flash ring's ISN?

Static decode of fn_FFFDC1B0 (session1, 2026-10-30): gated by the ring
markers in RAM (0x3FD532 in {FEFE,ECEC,C8C8}) and suppressed by AA55 at
0x3FD52E, it calls fn_FFFC97FC(1)/(2) -- load pair-block record 1 (EEPROM
0x04) / record 2 (0x14) into staging 0x3F9E00 -- applies the mangA/mangB
arithmetic (workA bytes 0,3 / workB bytes 1,2 inverted) against ~accepted,
and on a MATCH-form block overwrites the comparison slots:

    isn 0x3FC9BC <- accepted      ~isn 0x3FC9B0 <- ~derived
    workA 0x3FD538 <- re-derived  workB 0x3FDC70 <- ~workA

On total failure (both records, twice each) it zeroes ~isn and raises
0x3FEFAB/0x3FEFAD.  No static pointer to it exists -- it is entered via a
RAM table, so only a run can say when it fires and who wins.

The question that decides the one-click pairing flow: Donor 2 (PL48740)
carried a MATCH-form block voting BD09, its ring said 2086, we burned A356
-- and the car started.  So on the car the ring (or the burn) beat the
block.  This runs the exact same contest in the emulator: ring A356
(session1) against each real 4K dump (A356 block, BD09 block, blank), with
hooks on fn_FFFDC1B0 and fn_FFFC97FC, watching the slots through boot,
ignition and crank.

    .venv/bin/python -m tools.experiments.ews_eeprom_seed
"""
import os
import sys

from unicorn import UC_HOOK_CODE
from unicorn.ppc_const import UC_PPC_REG_PC

from ms45emu.image import load_named
from ms45emu.board import Board
from ms45emu.kwp import Tester

DOWNLOADS = os.path.expanduser("~/Downloads")

SEED, LOAD_REC = 0xFFFDC1B0, 0xFFFC97FC
SLOTS = [("~isn  0x3FC9B0", 0x3FC9B0), ("isn   0x3FC9BC", 0x3FC9BC),
         ("acc   0x3FC9AC", 0x3FC9AC), ("workA 0x3FD538", 0x3FD538),
         ("workB 0x3FDC70", 0x3FDC70), ("hs    0x3F9E06", 0x3F9E06),
         ("flag  0x3FEFAB", 0x3FEFAB)]


def read16(b, at):
    return int.from_bytes(bytes(b.m.read8(a) for a in range(at, at + 2)), "big")


def show(b, label):
    print(f"  {label:26s} " + "  ".join(f"{name.split()[0]}={read16(b, at):04X}"
                                        for name, at in SLOTS))


def stage(b, label):
    print(f"\n== {label} ==")
    show(b, "slots now")
    t = Tester(b)                      # ring readable for ground truth
    r = t.request([0x23, 0x01, 0xFB, 0x00, 0x02, 0x06])
    body = bytes(r[1:]) if r and r[0] != 0x7F else b""
    print(f"  ring via 0x23: {body.hex(' ')}")


def run_case(name, eeprom):
    print(f"\n{'=' * 66}\ncase: {name}")
    b = Board(load_named("session1"))
    if eeprom is not None:
        b.load_eeprom(eeprom)
    hits = {"seed": 0, "load": 0}
    log = []

    def hook(mu, addr, size, ud):
        pc = mu.reg_read(UC_PPC_REG_PC) & 0xFFFFFFFF
        if pc == SEED:
            hits["seed"] += 1
            log.append(("seed", b.m.step_count if hasattr(b.m, "step_count") else -1,
                        tuple(read16(b, at) for _, at in SLOTS)))
        elif pc == LOAD_REC:
            hits["load"] += 1

    b.m.mu.hook_add(UC_HOOK_CODE, hook, begin=SEED, end=SEED)
    b.m.mu.hook_add(UC_HOOK_CODE, hook, begin=LOAD_REC, end=LOAD_REC)
    b.boot(max_insns=20_000_000)
    stage(b, "idle boot")
    b.ignition(True)
    b.run(200_000_000)
    stage(b, "ignition on, 5 s")
    from ms45emu import e46
    e46.running(b)
    b.run(200_000_000)
    stage(b, "engine running, 5 s idle")
    print(f"  fn_FFFDC1B0 entered {hits['seed']}x, fn_FFFC97FC {hits['load']}x")
    for tag, _, slots in log[:6]:
        print(f"    entry @{tag}: slots were "
              + " ".join(f"{v:04X}" for v in slots))
    print(f"  EEPROM reads={b.qspi.eeprom.reads} writes={b.qspi.eeprom.writes}")
    return b


def main():
    cases = [] if "-b" in sys.argv else [("blank EEPROM (baseline)", None)]
    for fn in ("NJ87379_0044570_EEPROM_4K.bin", "PL48740_0044570_EEPROM_4K.bin"):
        p = os.path.join(DOWNLOADS, fn)
        if os.path.exists(p):
            cases.append((fn, open(p, "rb").read()))
        else:
            print(f"missing {p}, skipped")
    for name, ee in cases:
        run_case(name, ee)
    return 0


if __name__ == "__main__":
    sys.exit(main())
