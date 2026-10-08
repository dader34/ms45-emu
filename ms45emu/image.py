"""Loading a matching MPC + external flash pair.

Images are BMW-derived and never committed. They are found through
environment variables, or in ./images/ under the names below.
"""
import os
from dataclasses import dataclass

MPC_SIZE = 0x70000          # 448 KB internal flash
FLASH_SIZE = 0x100000       # 1 MB external flash
# The program whose routines and variables dme.py knows by address, and which
# the patches (map switch, EWS delete) are written for.
PROGRAM_ID = b"0044570LO02S"
PROGRAM_ID_OFFSET = 0x6031C
# Any MS45.1 program boots under Board and answers diagnostics: the board is
# the hardware, and what it takes from the program it finds by looking
# (checked with 0044570LN00S, the 7549388A.0PA of SP-Daten). Only the
# addresses in dme.py and the tests built on them belong to PROGRAM_ID.
PROGRAM_FAMILY = b"0044570L"

DEFAULT_NAMES = {
    "stock": ("stock_Flash.bin", "stock_MPC.bin"),
    "patched": ("patched_Flash.bin", "patched_MPC.bin"),
    "shifter": ("shifter_Flash.bin", "shifter_MPC.bin"),
    "three": ("three_Flash.bin", "three_MPC.bin"),
    "seven": ("seven_Flash.bin", "seven_MPC.bin"),
    "other": ("other_Flash.bin", "other_MPC.bin"),
}
ENV_NAMES = {
    "stock": ("MS45_FLASH", "MS45_MPC"),
    "patched": ("MS45_PATCHED_FLASH", "MS45_PATCHED_MPC"),
    "shifter": ("MS45_SHIFTER_FLASH", "MS45_SHIFTER_MPC"),
    "three": ("MS45_THREE_FLASH", "MS45_THREE_MPC"),         # the map switch with three maps, DSC x4
    "seven": ("MS45_SEVEN_FLASH", "MS45_SEVEN_MPC"),         # the map switch with all seven maps, DSC x4
    "other": ("MS45_OTHER_FLASH", "MS45_OTHER_MPC"),       # an MS45.1 program that is not PROGRAM_ID
}

IMAGES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "images")


@dataclass
class Pair:
    flash: bytes
    mpc: bytes
    name: str = ""
    check_program: bool = True      # off for what a board holds mid-flash (erased, half written)

    def __post_init__(self):
        if len(self.flash) != FLASH_SIZE:
            raise ValueError(f"{self.name}: external flash must be 0x{FLASH_SIZE:X} bytes")
        if len(self.mpc) != MPC_SIZE:
            raise ValueError(f"{self.name}: MPC must be 0x{MPC_SIZE:X} bytes")
        if not self.check_program:
            return
        if not self.program_id.startswith(PROGRAM_FAMILY):
            raise ValueError(f"{self.name}: program is {self.program_id!r}, not an MS45.1 program ({PROGRAM_FAMILY.decode()}...)")

    @property
    def program_id(self):
        """The program reference in the external flash, such as b"0044570LO02S"."""
        return bytes(self.flash[PROGRAM_ID_OFFSET:PROGRAM_ID_OFFSET + len(PROGRAM_ID)])

    @property
    def traced(self):
        """Whether this is the program the addresses in dme.py (and a few in board.py) were traced in."""
        return self.program_id == PROGRAM_ID


def find_pair(kind="stock"):
    """Paths for a pair, or None when it is not on this machine."""
    env_flash, env_mpc = ENV_NAMES[kind]
    flash, mpc = os.environ.get(env_flash), os.environ.get(env_mpc)
    if not (flash and mpc):
        f, m = DEFAULT_NAMES[kind]
        flash, mpc = os.path.join(IMAGES_DIR, f), os.path.join(IMAGES_DIR, m)
    if os.path.isfile(flash) and os.path.isfile(mpc):
        return flash, mpc
    return None


def load_pair(kind="stock"):
    paths = find_pair(kind)
    if paths is None:
        raise FileNotFoundError(
            f"No {kind} pair. Set {ENV_NAMES[kind][0]} and {ENV_NAMES[kind][1]}, "
            f"or put {DEFAULT_NAMES[kind]} in {IMAGES_DIR}")
    with open(paths[0], "rb") as f:
        flash = f.read()
    with open(paths[1], "rb") as f:
        mpc = f.read()
    return Pair(flash, mpc, kind)
