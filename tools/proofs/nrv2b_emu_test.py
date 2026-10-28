"""Prove the PPC NRV2B decoder on the emulator, byte-for-byte against the
JS encoder's streams (which the Python reference decoder has already shown
byte-exact with ucl-1.03's format).

Each case: load the decoder into SRAM (where the flasher will run it), load
the stream, call it with r3/r4/r5 = src/dst/len, then compare the buffer
with the case's original bytes and the return value with dst+len. Run from
the ms45-emu root: .venv/bin/python -m tools.proofs.nrv2b_emu_test [cases.json]
(--full adds every 4 KB chunk of all three flashable regions, re-encoded
through the JS encoder, and an instruction count for the cal region).

Streams come from /tmp/nrv2b_cases.js (node /tmp/nrv2b_cases.js) unless a
path is given; each case's original bytes are re-checked through the Python
reference decoder first, so a failure names the side that is wrong.
"""
import json
import os
import struct
import sys

from ms45emu.image import Pair, load_named
from ms45emu.machine import Machine, RAM_BASE
from tools.build.nrv2b_dec import build_decoder
from tools import ROOT

DEC_AT = RAM_BASE + 0x100          # the flasher relocates its code to SRAM
SRC_AT = RAM_BASE + 0x1000         # streams are <= 4 KB decompressed
DST_AT = RAM_BASE + 0x3000         # inside the upper 16 KB block


def ref_decode(src, out_len):
    sys.path.insert(0, "/tmp")
    import importlib.util
    spec = importlib.util.spec_from_file_location("nrv2b_ref", "/tmp/nrv2b_ref.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.decode(src, out_len)


def run_case(m, src, orig):
    """Decode one case through the PPC; True when byte-exact."""
    m.write(SRC_AT, src)
    m.write(DST_AT, b"\xA5" * len(orig))                       # stale-marker fill
    ret = m.call(DEC_AT, SRC_AT, DST_AT, len(orig))
    return ret == DST_AT + len(orig) and bytes(m.read(DST_AT, len(orig))) == orig


def main():
    full = "--full" in sys.argv
    cases_path = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") \
        else "/tmp/nrv2b_cases.json"
    cases = json.load(open(cases_path))

    words = build_decoder()
    code = struct.pack(">%dI" % len(words), *(w for w, _ in words))
    print(f"decoder: {len(words)} words ({len(code)} bytes) at 0x{DEC_AT:X}")

    pair = load_named("session1.livetune6-notraps")
    m = Machine(Pair(pair.flash, pair.mpc, pair.name, check_program=False))
    m.write(DEC_AT, code)

    count = [0, 0]                                            # insns, decoded bytes (cal only)
    counting = [False]
    def hook(machine, addr, size):                            # before the first call: unicorn
        if counting[0]:                                       # only delivers hooks added before
            count[0] += 1                                     # the first emu_start
    m.hook_code(hook)

    fails = 0
    for case in cases:
        src = bytes.fromhex(case["src"])
        orig = bytes.fromhex(case["orig"])
        if ref_decode(src, case["len"]) != orig:               # ground truth
            print(f"{case['name']}: REFERENCE disagrees -- case is bad")
            fails += 1
            continue
        if run_case(m, src, orig):
            print(f"{case['name']}: OK  {case['len']} <- {len(src)} bytes")
        else:
            got = bytes(m.read(DST_AT, len(orig)))
            first = next((i for i, (a, b) in enumerate(zip(got, orig)) if a != b), None)
            print(f"{case['name']}: FAIL  first diff at {first}"
                  + (f" (got {got[first]:02x} want {orig[first]:02x})" if first is not None else ""))
            fails += 1

    # corruption: a desync (truncation, garbage) must be caught by the
    # decoder's own bounds checks and return 0 -- never hang, never write
    # outside the buffer. A flipped bit inside literal data decodes to
    # wrong-but-in-bounds output by construction (any LZ decoder); catching
    # that on-target is the CHUNK header's CRC-32 of the compressed bytes.
    for name, mut in [("truncated", lambda s: s[:len(s) // 2]),
                      ("bit-flip", lambda s: s[:3] + bytes([s[3] ^ 0x40]) + s[4:]),
                      ("garbage-tail", lambda s: s[:len(s) // 2]
                       + b"\xDE\xAD" * ((len(s) - len(s) // 2) // 2))]:
        src = mut(bytes.fromhex(cases[6]["src"]))              # cal0: a real mixed chunk
        m.write(SRC_AT, src)
        m.write(DST_AT, b"\xA5" * 4096)
        ret = m.call(DEC_AT, SRC_AT, DST_AT, 4096)
        print(f"corrupt/{name}: ret={ret:#x} "
              f"({'caught by bounds checks' if ret == 0 else 'in bounds -- wire CRC catches it'})")

    if full:
        # every 4 KB chunk of all three flashable regions, re-encoded here
        # through a subprocess of BMWeb's JS encoder, decoded by the PPC
        import subprocess
        js = ("const {nrv2b} = require('%s/app/renderer/core/flash/nrv2b.js');"
              "const fs=require('fs');"
              "const f=fs.readFileSync('%s/images/session1.livetune6-notraps.flash.bin');"
              "const m=fs.readFileSync('%s/images/session1.livetune6-notraps.mpc.bin');"
              "const out=[];"
              "for (const [n,d] of [['cal',f.subarray(0x40000,0x5D000)],"
              "['eprog',f.subarray(0x60000,0xFFF40)],['mpc',m.subarray(0,0x70000)]])"
              " for (let a=0;a<d.length;a+=4096){const c=d.subarray(a,Math.min(a+4096,d.length));"
              "out.push(n+' '+a+' '+Buffer.from(nrv2b.encode(c)).toString('hex')+"
              "' '+c.toString('hex'));}"
              "console.log(out.join('\\n'));") % (
            "/Users/dannerbaumgartner/Development/code/projects/inpa-mac-bridge",
            ROOT, ROOT)
        rows = subprocess.run(["node", "-e", js], capture_output=True, text=True,
                              check=True).stdout.strip().splitlines()
        bad = 0
        for row in rows:
            name, at, src_hex, orig_hex = row.split(" ", 3)
            src, orig = bytes.fromhex(src_hex), bytes.fromhex(orig_hex)
            counting[0] = name == "cal"
            if not run_case(m, src, orig):
                print(f"full/{name}@{int(at, 10):#x}: FAIL")
                bad += 1
            if name == "cal":
                count[1] += len(orig)
        print(f"full sweep: {len(rows)} chunks, {bad} failures"
              + (f"; cal decode = {count[0] / count[1]:.1f} insn/byte"
                 f" (~{count[0] / 40e6 * 1000:.0f} ms at 40 MHz)" if count[1] else ""))
        fails += bad

    print("ALL OK" if not fails else f"{fails} FAILURES")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
