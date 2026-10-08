"""Calibration item names from a TunerPro XDF.

The MS4X group's XDF for a program names every constant, table and axis
of the calibration with its offset into the calibration (`mmedaddress`:
the 1024K file carries BASEOFFSET 0x40000 so that address + base is the
file offset; the 116K file is the calibration alone with the same
addresses). The emulator addresses the calibration at 0xFFE40000 +
offset.

    x = Xdf.find(pair)             # MS45_XDF, or images/*<program short id>*.xdf
    x.at(0x4395)                   # the item holding this offset, or None
    x.items_in(0x4000, 0x4400)     # every item overlapping a range
"""
import bisect
import glob
import os
import xml.etree.ElementTree as ET

from .image import IMAGES_DIR

CAL_BASE = 0xFFE40000
ENV = "MS45_XDF"


class Item:
    __slots__ = ("name", "kind", "offset", "size", "units", "equation", "description", "table")

    def __init__(self, name, kind, offset, size, units="", equation="", description="", table=None):
        self.name = name
        self.kind = kind              # constant | table | axis
        self.offset = offset
        self.size = size
        self.units = units
        self.equation = equation
        self.description = description
        self.table = table            # the table an axis belongs to

    @property
    def end(self):
        return self.offset + self.size

    @property
    def address(self):
        return CAL_BASE + self.offset

    def __repr__(self):
        return f"<{self.kind} {self.name} 0x{self.offset:X}+{self.size}>"


class Xdf:
    def __init__(self, path):
        self.path = path
        self.items = []
        root = ET.parse(path).getroot()
        header = root.find("XDFHEADER")
        self.title = header.findtext("deftitle", "") if header is not None else ""
        for c in root.iter("XDFCONSTANT"):
            e = c.find("EMBEDDEDDATA")
            if e is None:
                continue
            bits = int(e.get("mmedelementsizebits", "8"))
            self.items.append(Item(c.findtext("title", "").strip(), "constant", int(e.get("mmedaddress"), 16), max(bits // 8, 1),
                                   c.findtext("units", ""), _equation(c), c.findtext("description", "")))
        for t in root.iter("XDFTABLE"):
            name = t.findtext("title", "").strip()
            for axis in t.findall("XDFAXIS"):
                e = axis.find("EMBEDDEDDATA")
                if e is None or e.get("mmedaddress") is None:
                    continue
                bits = int(e.get("mmedelementsizebits", "8"))
                axis_id = axis.get("id")
                if axis_id == "z":
                    rows = int(e.get("mmedrowcount", "1"))
                    cols = int(e.get("mmedcolcount", "1"))
                    count = rows * cols
                    kind, label = "table", name
                else:
                    count = int(axis.findtext("indexcount", "1"))
                    kind, label = "axis", f"{name}.{axis_id}"
                self.items.append(Item(label, kind, int(e.get("mmedaddress"), 16), max(count * bits // 8, 1),
                                       axis.findtext("units", ""), _equation(axis), t.findtext("description", ""),
                                       table=name if kind == "axis" else None))
        self.items.sort(key=lambda i: (i.offset, -i.size))
        self._starts = [i.offset for i in self.items]

    def at(self, offset):
        """The item holding this calibration offset (the smallest, when
        an axis and its table share bytes), or None."""
        i = bisect.bisect_right(self._starts, offset)
        best = None
        while i > 0:
            i -= 1
            item = self.items[i]
            if item.offset <= offset < item.end and (best is None or item.size < best.size):
                best = item
            if offset - item.offset > 0x2000:          # no item is that long
                break
        return best

    def items_in(self, start, end):
        return [i for i in self.items if i.offset < end and i.end > start]

    def by_name(self, name):
        for i in self.items:
            if i.name == name:
                return i
        return None

    @classmethod
    def find(cls, pair=None):
        """The XDF for the pair's program: MS45_XDF, or a file in images/
        whose name holds the program's short id (LO02S). None without one."""
        path = os.environ.get(ENV)
        if path:
            return cls(path)
        short = pair.program_id[-5:].decode("latin1") if pair is not None else ""
        for p in sorted(glob.glob(os.path.join(IMAGES_DIR, "*.xdf"))):
            if short in os.path.basename(p):
                return cls(p)
        return None


def _equation(node):
    m = node.find("MATH")
    return m.get("equation", "") if m is not None else ""
