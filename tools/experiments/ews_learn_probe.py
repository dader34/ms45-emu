"""The EWS learn-branch probe: drive the real validator with crafted
telegrams and answer the one open question -- when the DME accepts a
value it was never taught (the learn branch at 0xFFFDB7D0), does
anything ever persist it to the flash ring or the EEPROM?

Validator semantics (fn_FFFDB734 / twin fn_FFFDB80C, r13 = 0x4017F0):
    workA = 0x3FD538, workB = 0x3FDC70, isn = 0x3FC9BC,
    accepted = 0x3FC9AC, reject byte = 0x3FEFAC
    mangA = workA with bytes 0 and 3 inverted
    mangB = workB with bytes 1 and 2 inverted
    ~isn == mangA or mangB  -> accepted = isn          (match)
    workA == ~workB         -> accepted = ~mangA        (LEARN: foreign)
    otherwise               -> reject = 1

Run from the ms45-emu root:
.venv/bin/python -m tools.experiments.ews_learn_probe
"""
import sys

from ms45emu.image import load_named
from ms45emu.board import Board
from ms45emu.kwp import Tester
from ms45emu.machine import R13, RETURN_SENTINEL
from unicorn.ppc_const import UC_PPC_REG_LR

WORKA, WORKB, ISN, ACCEPTED, REJECT = 0x3FD538, 0x3FDC70, 0x3FC9BC, 0x3FC9AC, 0x3FEFAC
GATE, SYNCSTATE = 0x3FDC79, 0x3FDC6E
RING = 0x1FB00
VALIDATOR, VALIDATOR2, WRAPPER = 0xFFFDB734, 0xFFFDB80C, 0xFFFC1FD0

ISN_CAR = 0x0000A356                    # what the ring decodes to (slot 0)


def inv(word, *byte_offs):
    for off in byte_offs:
        word ^= 0xFF << (24 - 8 * off)
    return word & 0xFFFFFFFF


def rd(b, addr, size=4):
    return int.from_bytes(bytes(b.m.read8(addr + i) for i in range(size)), "big")


def snapshot(b):
    return dict(worka=rd(b, WORKA), workb=rd(b, WORKB), isn=rd(b, ISN),
                accepted=rd(b, ACCEPTED), reject=rd(b, REJECT, 1),
                gate=rd(b, GATE, 1), sync=rd(b, SYNCSTATE, 1))


def show(s, label):
    print(f"  {label:26s} workA={s['worka']:08X} workB={s['workb']:08X} isn={s['isn']:04X} "
          f"accepted={s['accepted']:08X} reject={s['reject']} gate={s['gate']} sync={s['sync']}")


def call_validator(b, use):
    m = b.m
    assert m.reg(13) == R13, f"r13 is {m.reg(13):X} at idle, not {R13:X}"
    m.mu.reg_write(UC_PPC_REG_LR, RETURN_SENTINEL)
    m.set_reg(3, 1)                       # for the wrapper: r3==1 -> validator #2
    m.mu.emu_start(use & 0xFFFFFFFF, RETURN_SENTINEL, count=5_000_000)
    if m.pc != RETURN_SENTINEL:
        raise RuntimeError(f"validator 0x{use:X} did not return (pc 0x{m.pc:X})")


def flash_diff(before, after):
    runs, at = [], None
    for i in range(len(before)):
        if before[i] != after[i]:
            at = i if at is None else at
        elif at is not None:
            runs.append((at, i)); at = None
    if at is not None:
        runs.append((at, len(before)))
    return runs


def main():
    b = Board(load_named("session1"))
    b.boot(max_insns=20_000_000)
    t = Tester(b)

    flash0 = bytes(b.flash.image)
    ee0 = b.eeprom_image()

    print("== sync mode via the INPA jobs (EWS-Startwertabgleich) ==")
    print("   31 83 01 ->", t.request([0x31, 0x83, 0x01]).hex())
    print("   31 83 00 ->", t.request([0x31, 0x83, 0x00]).hex())
    print("   21 06    ->", t.request([0x21, 0x06]).hex(), "(Empfangsstatus)")
    show(snapshot(b), "after sync jobs")

    print("\n== case MATCH: mangled telegram equals ~isn ==")
    b.m.write32(ISN, ISN_CAR)                       # the ring's value, as a filled slot
    b.m.write32(WORKA, inv(0xFFFF5CA9, 0, 3))       # mangA == ~isn -> 0xFFFF5CA9
    b.m.write32(WORKB, 0)
    call_validator(b, VALIDATOR)
    show(snapshot(b), "match")

    print("\n== case LEARN: foreign self-consistent telegram ==")
    learn_a = 0x12345678
    b.m.write32(WORKA, learn_a)
    b.m.write32(WORKB, inv(learn_a, 0, 1, 2, 3))    # ~workA
    call_validator(b, VALIDATOR)
    s = snapshot(b)
    show(s, "learn")
    want = inv(learn_a ^ 0xFFFFFFFF, 0, 3)          # ~mangA
    print(f"  learn store predicted ~mangA = {want:08X}: "
          f"{'CONFIRMED' if s['accepted'] == want else 'NOT TAKEN'}")

    print("\n== case REJECT: neither form ==")
    b.m.write32(WORKA, 0x11111111)
    b.m.write32(WORKB, 0x11111110)
    call_validator(b, VALIDATOR)
    show(snapshot(b), "reject")

    print("\n== after the learn: does anything persist? ==")
    b.m.write32(WORKA, learn_a)
    b.m.write32(WORKB, inv(learn_a, 0, 1, 2, 3))
    call_validator(b, VALIDATOR)
    show(snapshot(b), "learn again")
    b.run(150_000_000)                              # ~4 s of DME time with the OS live
    show(snapshot(b), "after 150M insns")
    runs = flash_diff(flash0, bytes(b.flash.image))
    print("  flash writes so far:", runs or "none")

    print("\n== key off, full after-run ==")
    b.ignition(False)
    for _ in range(900):                              # up to 9 s of after-run, 10 ms slices
        b.run(4_000_000)
        if b.powered_down:
            break
    print("  powered down:", b.powered_down,
          " eeprom writes:", b.qspi.eeprom.writes)
    runs = flash_diff(flash0, bytes(b.flash.image))
    print("  flash writes:", runs or "none")
    print("  ring now:", bytes(b.flash.image[RING:RING + 0x18]).hex())
    diff = flash_diff(ee0, b.eeprom_image())
    if not diff:
        print("  EEPROM: unchanged")
    for at, end in diff:
        print(f"  EEPROM {at:#06x}-{end:#06x}: was {ee0[at:at+16].hex()} now {b.eeprom_image()[at:at+16].hex()}")
    learned = rd(b, ACCEPTED)
    print(f"\n  accepted slot still: {learned:08X} "
          f"({'foreign learn survived in RAM' if learned == want else 'cleared/changed'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
