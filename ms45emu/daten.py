"""BMW's data files for an MS45.1: a program (.0PA) and a calibration (.0DA).

These are what a dealer's tester writes into a DME, and what SP-Daten
holds for every release (the MDS451 folder). Both are Intel HEX with
segment and linear address records and one record type of BMW's own,
0x10, which carries data like type 0. A program is the whole MPC flash
at 0 and the external flash from 0x60000 at 0x2060000; a calibration is
the external flash from 0x40000 at 0x2040000. Neither has the boot
loader in the external flash below that, as no write touches it, so a
pair is made of them on the boot loader of a read: its regions are
erased and written the way a tester would, and the rest of it is kept.

A program runs with a calibration made for it: the six characters at
0x60302 of the program are at 8 in the calibration. With a program and
no calibration named, the read's own is kept when it carries them, and
otherwise the folder the program came from is searched for one that
does, which in SP-Daten finds one.

A program brings the whole MPC flash with it, so the read it goes on
needs only its external flash, and of that only the boot loader: the
first 256 KB of a read, kept as images/stock_boot.bin (BMW's code like
the rest of that folder, and as little committed), is enough for any
.0PA to be started without a read being named.
"""
import glob
import os

from .image import (Pair, load_pair, find_pair, MPC_SIZE, FLASH_SIZE,
                    ENV_NAMES, DEFAULT_NAMES, IMAGES_DIR)

EXTERNAL = 0x2000000                 # where the files put the external flash
CALIBRATION = (0x40000, 0x5D000)     # the regions a write erases, in the external flash
PROGRAM = (0x60000, 0xFFF40)
PROGRAM_TOKEN, CALIBRATION_TOKEN, TOKEN_SIZE = 0x60302, 0x40008, 6
BOOT_SIZE = 0x40000                  # the boot loader: the external flash below the calibration
BOOT_NAME, BOOT_ENV = "stock_boot.bin", "MS45_BOOT"
# The programming log (AIF) is in the boot loader's part of the flash: 64 bytes
# an entry from here to the end of the sector, each with the VIN of the car the
# DME was in when it was written. The hardware data below it is not the car's.
AIF = (0x1FB34, 0x20000)


def records(path):
    """(address, data) for every data record of the file, in its order."""
    linear = segment = 0
    with open(path, "r", errors="replace") as f:
        for number, line in enumerate(f, 1):
            line = line.strip()
            if not line.startswith(":"):
                continue
            try:
                rec = bytes.fromhex(line[1:])
            except ValueError:
                raise ValueError(f"{path}, line {number}: not a hex record") from None
            if len(rec) < 5 or len(rec) != rec[0] + 5 or sum(rec) & 0xFF:
                raise ValueError(f"{path}, line {number}: record length or checksum is wrong")
            kind, data = rec[3], rec[4:-1]
            if kind in (0x00, 0x10):
                yield linear + segment + ((rec[1] << 8) | rec[2]), data
            elif kind == 0x01:
                return
            elif kind == 0x02:
                segment = int.from_bytes(data, "big") << 4
            elif kind == 0x04:
                linear = int.from_bytes(data, "big") << 16
            else:
                raise ValueError(f"{path}, line {number}: record type 0x{kind:02X}")


def _write(buf, start, end, at, recs):
    """Erases buf[start:end] and writes the records that fall in it, `at` being
    the address the files have for buf[0]. Returns how many bytes were written."""
    buf[start:end] = b"\xff" * (end - start)
    covered = 0
    for address, data in recs:
        lo, hi = max(address, at + start), min(address + len(data), at + end)
        if lo < hi:
            buf[lo - at:hi - at] = data[lo - address:hi - address]
            covered += hi - lo
    return covered


def token(flash, at):
    return bytes(flash[at:at + TOKEN_SIZE])


def calibration_token(path):
    """The program a calibration file is for, read from its first records."""
    at = EXTERNAL + CALIBRATION_TOKEN
    got = bytearray(TOKEN_SIZE)
    have = 0
    for address, data in records(path):
        lo, hi = max(address, at), min(address + len(data), at + TOKEN_SIZE)
        if lo < hi:
            got[lo - at:hi - at] = data[lo - address:hi - address]
            have += hi - lo
            if have >= TOKEN_SIZE:
                return bytes(got)
    return None


def find_calibration(want, folder):
    """The first .0DA in a folder made for the program with this token, or None."""
    for path in sorted(glob.glob(os.path.join(glob.escape(folder), "*.0[dD][aA]")), key=lambda p: os.path.basename(p).upper()):
        try:
            if calibration_token(path) == want:
                return path
        except ValueError:
            continue
    return None


def build(base, program=None, calibration=None, say=print):
    """The pair `base` after a write of a .0PA and/or a .0DA. `say` is told
    which calibration was chosen when one had to be."""
    flash, mpc = bytearray(base.flash), bytearray(base.mpc)
    parts = []
    if program:
        recs = list(records(program))
        in_mpc = _write(mpc, 0, MPC_SIZE, 0, recs)
        in_flash = _write(flash, PROGRAM[0], PROGRAM[1], EXTERNAL, recs)
        if not in_mpc or not in_flash:
            raise ValueError(f"{os.path.basename(program)}: nothing in it for the "
                             f"{'MPC flash' if not in_mpc else 'external flash at 0x%X' % (EXTERNAL + PROGRAM[0])}, "
                             f"so it is not an MS45 program")
        parts.append(os.path.basename(program))
        want = token(flash, PROGRAM_TOKEN)
        if not calibration and token(flash, CALIBRATION_TOKEN) != want:
            calibration = find_calibration(want, os.path.dirname(os.path.abspath(program)))
            if calibration:
                say(f"calibration: {os.path.basename(calibration)}, the first one next to the program that is "
                    f"made for it (name another with --calibration)")
            else:
                say(f"no calibration for {os.path.basename(program)}: {base.name}'s is for another program "
                    f"and no .0DA next to it is for this one; name one with --calibration")
    if calibration:
        if not _write(flash, CALIBRATION[0], CALIBRATION[1], EXTERNAL, records(calibration)):
            raise ValueError(f"{os.path.basename(calibration)}: nothing in it at 0x{EXTERNAL + CALIBRATION[0]:X}, "
                             f"so it is not an MS45 calibration")
        parts.append(os.path.basename(calibration))
        if token(flash, CALIBRATION_TOKEN) != token(flash, PROGRAM_TOKEN):
            say(f"{os.path.basename(calibration)} is made for another program "
                f"({token(flash, CALIBRATION_TOKEN).decode('latin1')}, the program is {token(flash, PROGRAM_TOKEN).decode('latin1')})")
    return Pair(bytes(flash), bytes(mpc), " + ".join(parts) + f" on the {base.name} boot loader")


def find_boot():
    """Path of a boot loader kept for programs that come without a read
    (MS45_BOOT, or images/stock_boot.bin), or None."""
    path = os.environ.get(BOOT_ENV) or os.path.join(IMAGES_DIR, BOOT_NAME)
    return path if os.path.isfile(path) else None


def without_aif(flash):
    """An external flash, or the boot loader at its start, with the programming
    log empty: the boot loader of a DME that has been in no car."""
    return bytes(flash[:AIF[0]]) + b"\xff" * (AIF[1] - AIF[0]) + bytes(flash[AIF[1]:])


def keep_boot(read, path=None):
    """Keeps the boot loader of an external flash read for programs that come
    without one, its programming log emptied. Returns where it was put."""
    with open(read, "rb") as f:
        data = f.read()
    if len(data) not in (FLASH_SIZE, BOOT_SIZE):
        raise ValueError(f"{read}: 0x{len(data):X} bytes; an external flash read (0x{FLASH_SIZE:X}) is wanted")
    path = path or os.path.join(IMAGES_DIR, BOOT_NAME)
    with open(path, "wb") as f:
        f.write(without_aif(data[:BOOT_SIZE]))
    return path


def _flash_only(path, name, kept=False):
    """A pair of an external flash alone, for a program to be written onto:
    a whole read, or just the boot loader that is its first 256 KB. The
    boot loader kept for this stands for no particular DME, so the
    programming log that came with it is never passed on."""
    with open(path, "rb") as f:
        data = f.read()
    if kept:
        data = without_aif(data)
    if len(data) == BOOT_SIZE:
        data += b"\xff" * (FLASH_SIZE - BOOT_SIZE)
    if len(data) != FLASH_SIZE:
        raise ValueError(f"{path}: 0x{len(data):X} bytes; an external flash read (0x{FLASH_SIZE:X}) "
                         f"or its boot loader (0x{BOOT_SIZE:X}) is wanted")
    return Pair(data, b"\xff" * MPC_SIZE, name, check_program=False)


def load(kind="stock", program=None, calibration=None, say=print):
    """The pair of a kind (as load_pair) after a write of these files.

    A program needs no more of a read than the boot loader in its external
    flash. So with a program, MS45_FLASH without MS45_MPC is the read it
    goes on, whatever pair there is in images/; and where there is no read
    of that kind at all, the boot loader kept for this (`find_boot`) is
    used, which makes a .0PA enough to start a DME on."""
    if program:
        env_flash, env_mpc = (os.environ.get(name) for name in ENV_NAMES[kind])
        default_flash = os.path.join(IMAGES_DIR, DEFAULT_NAMES[kind][0])
        if env_flash and not env_mpc:
            return build(_flash_only(env_flash, kind), program, calibration, say)
        if find_pair(kind) is None:
            if os.path.isfile(default_flash):
                return build(_flash_only(default_flash, kind), program, calibration, say)
            boot = find_boot()
            if boot is None:
                raise FileNotFoundError(
                    f"No boot loader to write {os.path.basename(program)} over: a .0PA has none. Set "
                    f"{ENV_NAMES[kind][0]} to an external flash read, or keep the first 0x{BOOT_SIZE:X} bytes "
                    f"of one as {os.path.join(IMAGES_DIR, BOOT_NAME)} (or {BOOT_ENV})")
            return build(_flash_only(boot, "kept", kept=True), program, calibration, say)
    return build(load_pair(kind), program, calibration, say)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3 or sys.argv[1] != "keep-boot":
        sys.exit("usage: python -m ms45emu.daten keep-boot READ_Flash.bin")
    print("boot loader kept, without its programming log, as", keep_boot(sys.argv[2]))
