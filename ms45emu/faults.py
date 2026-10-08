"""The program's fault table: fault index -> DTC code -> text.

The diagnosis reports a fault by index (`fault_report`, 0x26170, r3 =
index, r4 = result bits). Each index has a 0x14-byte descriptor in the
MPC (handler, counter byte, calibration record, status word, flags) and
the calibration record it points at holds the DTC code at bytes 10-11.
Indices are the program's own and differ between programs; codes are
BMW's and the same everywhere, so a code list (the DTC CSV of the
research notes, `MS45_DTC_CSV`) gives the text.

    f = Faults(pair)
    f.code(44)        # 0x280B
    f.text(44)        # 'Botschaft (ASC 1) vom ASC-Steuergerät fehlt'
    f.index(0x2831)   # the index of the processor-monitoring self-test, or None
"""
import csv
import os
import struct

DESCRIPTORS = 0x45B8              # MPC: the first fault descriptor
DESCRIPTOR_SIZE = 0x14
RECORD_SIZE = 0x12
CODE_AT = 10
CAL_BASE = 0xFFE40000
ENV = "MS45_DTC_CSV"
DEFAULT_CSV = os.path.expanduser("~/Desktop/e46bins/MS45-DME/Research/ms45_dtc_table_7561533.csv")


class Faults:
    def __init__(self, pair, csv_path=None):
        self.pair = pair
        mpc, flash = pair.mpc, pair.flash
        self.records = []             # index -> calibration offset of the record
        self.status = []              # index -> RAM address of the status word
        at = DESCRIPTORS
        while True:
            handler, counter, record, status, flags = struct.unpack(">5I", mpc[at:at + DESCRIPTOR_SIZE])
            if not (CAL_BASE <= record < CAL_BASE + 0x20000 and 0x3F8000 <= status < 0x400000):
                break
            self.records.append(record - CAL_BASE)
            self.status.append(status)
            at += DESCRIPTOR_SIZE
        self.codes = [int.from_bytes(flash[0x40000 + r + CODE_AT:0x40000 + r + CODE_AT + 2], "big") for r in self.records]
        self.texts = {}
        path = csv_path or os.environ.get(ENV) or DEFAULT_CSV
        if os.path.isfile(path):
            with open(path, newline="") as f:
                for row in csv.DictReader(f):
                    try:
                        self.texts[int(row["inpa_code"], 16)] = (row.get("pcode_1") or "", row.get("sgbd_text_de") or "")
                    except ValueError:
                        pass

    def __len__(self):
        return len(self.records)

    def code(self, index):
        return self.codes[index] if 0 <= index < len(self.codes) else None

    def index(self, code):
        try:
            return self.codes.index(code)
        except ValueError:
            return None

    def text(self, index):
        code = self.code(index)
        if code is None:
            return None
        pcode, text = self.texts.get(code, ("", ""))
        return text or None

    def describe(self, index):
        code = self.code(index)
        if not code:
            return f"fault {index}"
        pcode, text = self.texts.get(code, ("", ""))
        return f"fault {index} ({code:04X}" + (f" {pcode}" if pcode else "") + (f": {text}" if text else "") + ")"

    def status_of(self, m, index):
        """The fault's 32-bit status word in RAM, as the program keeps it."""
        return m.read32(self.status[index])
