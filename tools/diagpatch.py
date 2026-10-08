#!/usr/bin/env python
"""Build the diagnostic patch onto a pair (see ms45emu/diagpatch.py and
docs/logging.md).

    .venv/bin/python tools/diagpatch.py --flash Flash.bin --mpc MPC.bin --out DIR
    .venv/bin/python tools/diagpatch.py --pair stock --out DIR [--can-id 0x7A0 | --no-can]
    .venv/bin/python tools/diagpatch.py --flash ... --mpc ... --out DIR --remove

Writes <name>_diag_Flash.bin and <name>_diag_MPC.bin; the inputs are never
changed. The pair may already carry the map switch. The output has its
safety-monitor sum, program checksums and signature brought up to date,
so it can be flashed as a program (external and internal flash).
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu import diagpatch, load_pair      # noqa: E402
from ms45emu.image import Pair                # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair", help="a pair by name, as ms45emu/image.py finds it (stock, patched)")
    ap.add_argument("--flash")
    ap.add_argument("--mpc")
    ap.add_argument("--out", required=True)
    ap.add_argument("--can-id", type=lambda s: int(s, 0), default=diagpatch.CAN_ID)
    ap.add_argument("--no-can", action="store_true", help="leave the CAN log frame out")
    ap.add_argument("--remove", action="store_true", help="take the patch out instead")
    args = ap.parse_args()

    if args.flash and args.mpc:
        with open(args.flash, "rb") as f, open(args.mpc, "rb") as m:
            name = os.path.basename(args.flash).rsplit(".", 1)[0].replace("_Flash", "")
            pair = Pair(f.read(), m.read(), name)
    elif args.pair:
        pair = load_pair(args.pair)
    else:
        ap.error("give --pair, or --flash and --mpc")

    if args.remove:
        out, suffix = diagpatch.remove(pair), "nodiag"
    else:
        out, layout = diagpatch.build(pair, can_id=None if args.no_can else args.can_id)
        suffix = "diag"
    os.makedirs(args.out, exist_ok=True)
    for kind, data in (("Flash", out.flash), ("MPC", out.mpc)):
        path = os.path.join(args.out, f"{pair.name}_{suffix}_{kind}.bin")
        with open(path, "wb") as f:
            f.write(data)
        print("wrote", path)
    if args.remove:
        return

    print(f"stubs at 0x{layout.frame_stub:X} (10 ms) and 0x{layout.segment_stub:X} (segment), "
          f"{layout.code_end - layout.frame_stub} bytes")
    if layout.can_id is not None:
        fields = ", ".join(f"{f.name}({f.size})" for f in layout.can_fields)
        print(f"CAN 0x{layout.can_id:X} every 10 ms: counter(1), {fields}")
    fields = ", ".join(f"{f.name}({f.size})" for f in layout.capture_fields)
    print(f"capture block: 23 {layout.block >> 16:02X} {(layout.block >> 8) & 0xFF:02X} {layout.block & 0xFF:02X} {layout.block_size:02X}"
          f" -> header({diagpatch.HEADER}) + {diagpatch.SLOTS} records of seq(1), {fields}")
    print("fast timing: after 10 81 05 and 83 03 04 01 18 14 00 the DME answers at once and takes the next request after 2 ms")


if __name__ == "__main__":
    main()
