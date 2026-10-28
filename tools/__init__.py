"""ms45-emu's tools, by kind: build, export, proofs, bench, analysis, experiments.

Run any of them from the repo root as a module, e.g.

    .venv/bin/python -m tools.proofs.bl14_test
    .venv/bin/python -m tools.bench.kline --ws 6802

`make proofs`, `make export` and `make test` run the sets (see Makefile).
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES = os.path.join(ROOT, "images")
BMWEB = os.path.normpath(os.path.join(ROOT, "..", "inpa-mac-bridge"))
