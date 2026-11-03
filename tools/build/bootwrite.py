"""The boot overwrite: a DME's whole boot region written from a file.

The boot region is ext 0x0-0x1FFFF, four chip sectors (16 KB, 8 KB, 8 KB,
96 KB): the loader, its variant tag, and the tail with the boot block's
CRC word, the sector table, the hardware-number triple, the ISN and the
programming log. `region(file)` takes a full external-flash read (1 MB) or
a bare boot-region dump (128 KB) and gives those four sectors as they are
in the file. Nothing is spliced in or kept from the DME: the DME ends up
with the file's boot region exactly -- the file's loader build, the
file's tail, and a flasher ring only if the file carries one.

What it is for: putting a loader build no unit on hand carries (there are
three, see BUILDS) on the bench DME to prove the ring on it, and putting
the DME's own read back afterwards. The write goes through the ring's
SWAP variant (bl.build(swap=True): its body's write window opens at ext
0x0), which has to be on the DME first; the 96 KB rewrite then replaces
that ring with whatever the file has there. While the 16 KB sector is
erased nothing boots and nothing resumes: a cut there is a BDM job. Bench
only.

    python -m tools.build.bootwrite FILE        # what the file would put on
"""
import argparse
import hashlib
import struct

from ms45emu.checksums import crc32_mpeg2

REGION_END = 0x20000
SECTORS = ((0x0, 0x4000), (0x4000, 0x6000), (0x6000, 0x8000), (0x8000, 0x20000))
LOADER_END = 0x1F800                 # the tail begins here
TAG_AT, TAG_LEN = 0x2208, 3          # the variant tag: `1C` MS45.1, `CE` MS45.0
HW_AT = 0x1F9F4                      # the hardware-number triple
CRC_AT, CRC_RANGE_AT, CRC_SEED_AT = 0x1F800, 0x1F808, 0x1F9F0
AIF_AT, AIF_SLOT, AIF_SLOTS = 0x1FB34, 64, 14

# sha1 of ext 0x0-0x1F7FF with the tag zeroed -> the loader build. 24 full
# reads from four sources (2026-10-30), MS45.0 and MS45.1 alike: the build
# follows the production era, not the hardware number.
BUILDS = {
    "62c6262b": "A",         # 2003-on, park call at 0x3828 (the donor in the car)
    "5742c1fd": "B",         # 2003-on, park call at 0x3828, driver +0x24 (most MS45.0s)
    "69b86cba": "C",         # 2002-03, park call at 0x377C
}


def region(file):
    """The boot region in a full read or a boot-region dump, as bytes."""
    if len(file) < REGION_END:
        raise ValueError(f"a boot region is {REGION_END:#x} bytes; the file has {len(file):#x}")
    return bytes(file[:REGION_END])


def sectors(reg):
    """[(base, bytes)] of the four sectors, in the order they are written."""
    return [(lo, bytes(reg[lo:hi])) for lo, hi in SECTORS]


def loader_id(reg):
    """(build name or None, the loader's 8-char fingerprint)."""
    loader = bytearray(reg[:LOADER_END])
    loader[TAG_AT:TAG_AT + TAG_LEN] = b"\0" * TAG_LEN
    loader[0x17000:0x1F700] = b"\xff" * 0x8700          # a ring, if any, does not count
    for at in (0x4EBC, 0x5228):                          # nor its two patched words
        loader[at:at + 4] = b"\0\0\0\0"
    h = hashlib.sha1(bytes(loader)).hexdigest()[:8]
    return BUILDS.get(h), h


def crc_ok(reg):
    """Whether the file's CRC word matches its own boot block (the program
    walks 0x0-0x1EFFF against it every ~5 s and resets the DME on a
    mismatch), or None when the table is blank."""
    start, end = struct.unpack_from(">II", reg, CRC_RANGE_AT)
    if start == 0xFFFFFFFF:
        return None
    lo, hi = start & 0xFFFFF, (end & 0xFFFFF) + 1
    seed = struct.unpack_from(">I", reg, CRC_SEED_AT)[0]
    return crc32_mpeg2(reg[lo:hi], seed) == struct.unpack_from(">I", reg, CRC_AT)[0]


def describe(reg):
    """What a file would put on a DME, one line per fact."""
    build, h = loader_id(reg)
    hw = reg[HW_AT:HW_AT + 7].decode("latin1", "replace")
    used = sum(1 for i in range(AIF_SLOTS) if reg[AIF_AT + AIF_SLOT * i] != 0xFF)
    ring = reg[0x17140:0x17146] == b"MS45BL" or reg[0x17080:0x17086] == b"MS45BL"
    ok = crc_ok(reg)
    return [f"loader build {build or '?'} ({h}), tag {reg[TAG_AT:TAG_AT + TAG_LEN]!r}",
            f"hardware number {hw}, {used} of {AIF_SLOTS} log entries used, "
            f"flasher ring {'present' if ring else 'none'}",
            "boot CRC word " + ("matches" if ok else "blank (no check)" if ok is None
                                else "DOES NOT MATCH: the DME would reset every ~5 s")]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("file", help="a full flash read or a boot-region dump")
    args = ap.parse_args()
    for line in describe(region(open(args.file, "rb").read())):
        print(line)


if __name__ == "__main__":
    main()
