#!/usr/bin/env python
"""Build engine protection and the spark-cut rev limiter onto a pair
(ms45emu/protect.py). Everything is an ignition cut with the fuel kept; the
program's own rev limiter is never touched, so its safety monitor stays
quiet.

    .venv/bin/python tools/protect.py --flash Flash.bin --mpc MPC.bin --out DIR
    .venv/bin/python tools/protect.py --pair stock --out DIR
    .venv/bin/python tools/protect.py --flash ... --mpc ... --out DIR --remove

Defaults: spark cut at the program's own rev limit (pops & bangs; stands
down in limp home); cold start cut at 3500 rpm until coolant reaches 50 C;
oil >=130 C -> cut at 4500 rpm (+ oil-temp warning); coolant >=115 C -> cut
at 4500 rpm (the cluster gauge shows the overheat). Anything can be turned
off (--no-spark-cut / --no-oil / --no-coolant / --no-cold) or retuned. The
output has its sums and signature refreshed and flashes as a program; the
calibration is untouched, so it stacks with a tune and the map switch.
Verify temps read sanely and the oil warning lights your cluster on the car.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu import load_pair, protect          # noqa: E402
from ms45emu.image import Pair                  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair")
    ap.add_argument("--flash")
    ap.add_argument("--mpc")
    ap.add_argument("--out", required=True)
    ap.add_argument("--remove", action="store_true")
    d = protect.Config()
    ap.add_argument("--no-spark-cut", "--no-rev-cut", action="store_false", dest="spark_cut", default=d.spark_cut)
    ap.add_argument("--oil-c", type=int, default=d.oil_c, dest="oil_c")
    ap.add_argument("--oil-rpm", type=int, default=d.oil_rpm, dest="oil_rpm")
    ap.add_argument("--no-oil", action="store_const", const=None, dest="oil_c")
    ap.add_argument("--coolant-c", type=int, default=d.cool_c, dest="cool_c")
    ap.add_argument("--coolant-rpm", type=int, default=d.cool_rpm, dest="cool_rpm")
    ap.add_argument("--no-coolant", action="store_const", const=None, dest="cool_c")
    ap.add_argument("--cold-warm-c", type=int, default=d.cold_warm_c, dest="cold_warm_c")
    ap.add_argument("--cold-rpm", type=int, default=d.cold_rpm, dest="cold_rpm")
    ap.add_argument("--no-cold", action="store_const", const=None, dest="cold_warm_c")
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
        out, layout, suffix = protect.remove(pair), None, "noprotect"
    else:
        cfg = protect.Config(args.spark_cut, args.oil_c, args.oil_rpm, args.cool_c,
                             args.cool_rpm, args.cold_warm_c, args.cold_rpm)
        out, layout = protect.build(pair, cfg)
        suffix = "protect"

    os.makedirs(args.out, exist_ok=True)
    for kind, data in (("Flash", out.flash), ("MPC", out.mpc)):
        path = os.path.join(args.out, f"{pair.name}_{suffix}_{kind}.bin")
        with open(path, "wb") as f:
            f.write(data)
        print("wrote", path)
    if layout:
        c = layout.config
        print("protections:")
        if c.spark_cut:
            print("  spark cut      at the program's rev limit  (ignition cut, fuel kept -> pops & bangs)")
        if c.oil_c is not None:
            print(f"  oil temp       >= {c.oil_c} C -> spark cut at {c.oil_rpm} rpm  (+ oil-temp warning)")
        if c.cool_c is not None:
            print(f"  coolant temp   >= {c.cool_c} C -> spark cut at {c.cool_rpm} rpm  (cluster gauge warns)")
        if c.cold_warm_c is not None:
            print(f"  cold start     spark cut at {c.cold_rpm} rpm until coolant reaches {c.cold_warm_c} C")
        print("VERIFY ON THE CAR: temps read sanely; the oil warning lights your cluster")


if __name__ == "__main__":
    main()
