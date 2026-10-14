#!/usr/bin/env python
"""Write out the flashable live-tune program pair.

The live-tune feature is four patches composed on a stock-generation pair
(docs/livetune-design.md): the RAM overlay that redirects table reads into
SRAM mirrors, the transport that rides the 2C define-packet handler, the
fold that saves the open tables into the calibration, and the single values
(the constants the program reads straight from the calibration) made live. The emulator builds
them on the fly for its tests; this writes the result to disk so it can be
flashed onto a DME (or booted by tools/kline.py --pair livetune).

    .venv/bin/python tools/livetune_build.py [--source session1] [--out-prefix images/livetune]
        [--stock FLASH MPC]

Produces <prefix>.flash.bin and <prefix>.mpc.bin. The source is the pair
whose calibration (the tune) the result carries; session1 is the car's own.

The car's own program carries the old map-switch generation (hooks on the
lookup entries, a handler table entry, a second calibration at 0xE0000).
--stock FLASH MPC builds without any of it: BMW's own program out of that
unpatched pair (the car's backup read), under the source's calibration and
boot sector. Live tune then stands on the stock program alone.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu import fold, overlay, singles, transport      # noqa: E402
from ms45emu.board import VALID_MARKS              # noqa: E402
from ms45emu.checksums import fix_program          # noqa: E402
from ms45emu.image import IMAGES_DIR, Pair, load_named   # noqa: E402

PROGRAM_FILE = (0x60000, 0x100000)                 # the program's part of the external flash
MAPS_FILE = 0xE0000                                # from here the old generation keeps its second map


def clean_base(pair, stock_flash, stock_mpc):
    """The pair's calibration and boot sector under the stock program: BMW's
    MPC image, and the external flash's program without the old generation's
    map data, with the marks that tell the loader the program is whole and
    its sums and signature redone.

    The map switch lives wholly in the MPC image and in the data from
    0xE0000. Anything ELSE the source changed in the external program is the
    owner's own and stays: on the car that is the immobiliser (EWS) delete, two
    instructions in ews_lock, without which the engine would not start.
    Returns (pair, [(offset, length)] of what was kept)."""
    stock = load_named(stock_flash, stock_mpc)
    if stock.program_id != pair.program_id:
        raise ValueError(f"the stock pair is program {stock.program_id!r}, the source {pair.program_id!r}")
    if overlay.carries_old(stock):
        raise ValueError("the stock pair carries the map switch itself")
    flash = bytearray(pair.flash)
    lo, hi = PROGRAM_FILE
    flash[MAPS_FILE:hi] = stock.flash[MAPS_FILE:hi]
    kept, at = [], lo
    while at < MAPS_FILE:                           # runs where the source's program is not BMW's
        if flash[at] != stock.flash[at]:
            end = at
            while end < MAPS_FILE and flash[end:end + 8] != stock.flash[end:end + 8]:
                end += 1
            kept.append((at, end - at))
            at = end
        else:
            at += 1
    for at, mark in VALID_MARKS:                    # a read does not always carry them
        flash[at:at + 4] = mark.to_bytes(4, "big")
    mpc = bytearray(stock.mpc)
    fix_program(flash, mpc)
    # the sums and the signature differ of course; they are not patches
    sums = lambda a: a < 0x60700                    # noqa: E731
    return (Pair(bytes(flash), bytes(mpc), pair.name + "+stockprogram"),
            [(a, n) for a, n in kept if not sums(a)])


def build(source="session1", stock=None, traps=False):
    pair = load_named(source)
    if stock:
        pair, _kept = clean_base(pair, *stock)
    return singles.build(fold.build(transport.build(overlay.build(pair))), traps=traps)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", default="session1",
                    help="the stock-generation pair to patch (default session1)")
    ap.add_argument("--stock", nargs=2, metavar=("FLASH", "MPC"),
                    help="build on the stock program out of this unpatched pair (no map switch)")
    ap.add_argument("--base-prefix", default=None, metavar="PREFIX",
                    help="with --stock: also write the unpatched base pair here")
    ap.add_argument("--out-prefix", default=None,
                    help="output path prefix (default images/<source>.livetune)")
    ap.add_argument("--traps", action="store_true",
                    help="add the single-value trap tier (resets the car's DME at 3 krpm: experiments only)")
    args = ap.parse_args()
    prefix = args.out_prefix or os.path.join(IMAGES_DIR, f"{args.source}.livetune")

    built = build(args.source, args.stock, args.traps)
    if args.stock:
        print(f"built on the stock program: map-switch generation present = {overlay.carries_old(built)}")
        if args.base_prefix:
            base, kept = clean_base(load_named(args.source), *args.stock)
            for at, n in kept:
                print(f"kept from the source's program: {n} bytes at 0x{at:X} ({base.flash[at:at + n].hex()})")
            with open(args.base_prefix + ".flash.bin", "wb") as f:
                f.write(base.flash)
            with open(args.base_prefix + ".mpc.bin", "wb") as f:
                f.write(base.mpc)
    assert fold.is_patched(built) and overlay.is_patched(built) and transport.is_patched(built) \
        and singles.is_patched(built), \
        "the built pair is not fully patched"

    with open(prefix + ".flash.bin", "wb") as f:
        f.write(built.flash)
    with open(prefix + ".mpc.bin", "wb") as f:
        f.write(built.mpc)
    print(f"wrote {prefix}.flash.bin ({len(built.flash)} bytes) "
          f"and {prefix}.mpc.bin ({len(built.mpc)} bytes)")
    print(f"golden calibration preserved: {fold.golden(built) == built.flash[fold.CAL_FILE:fold.CAL_FILE + fold.LENGTH]}")


if __name__ == "__main__":
    main()
