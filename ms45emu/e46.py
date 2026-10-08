"""The E46's side of the DME's CAN bus.

The DME listens for these identifiers on module A (its receive buffers
0-10) and sends DME1-4 (0x316, 0x329, 0x338, 0x545). `Peers` plays the
other modules: it emits each frame at its period so the DME sees a live
bus instead of logging every partner as missing.

Payload layouts are the published E46 ones where known; everything else is
zeros, which the DME takes as "nothing requested".
"""
from .board import Board

# DME transmit
DME1, DME2, DME3, DME4 = 0x316, 0x329, 0x338, 0x545
# received: ASC/DSC, instrument cluster, gearbox
ASC1, ASC3, ASC4, STEERING = 0x153, 0x1F3, 0x1F8, 0x1F5
KOMBI1, KOMBI2 = 0x613, 0x615
EGS1, EGS2, EGS3 = 0x43F, 0x43B, 0x43D

PERIOD_MS = {ASC1: 10, ASC3: 10, ASC4: 10, STEERING: 10, KOMBI1: 200, KOMBI2: 200, EGS1: 10, EGS2: 10, EGS3: 10}

FRAME_INSTRUCTIONS = 400_000           # 10 ms at the default 40 MIPS


# The program symbol the gearbox sends for the cluster, in the top three bits of EGS1 byte 2.
PROGRAM_MANUAL, PROGRAM_SPORT, PROGRAM_DRIVE = 1, 2, 5
PROGRAM_DRIVE_GEAR_DISPLAY = 4          # D as the GS20 gear-display program sends it
GEAR_PARK_NEUTRAL, GEAR_REVERSE = 0, 7


def egs1(gear, program, lever=5):
    """An EGS1 frame as the GS20 builds it: the gear (0 in P and N, 1-5, 7 in R),
    the cluster's lever symbol, the program symbol above five bits of torque data."""
    return bytes([gear & 7, lever & 0xF, (program & 7) << 5 | 0x0B, 0, 0, 0, 0, 0])


def rpm_of(frame):
    """Engine speed as DME1 carries it: bytes 2-3 little endian, 1/6.4 rpm."""
    return (frame.data[2] | frame.data[3] << 8) / 6.4


class Peers:
    def __init__(self, board: Board, automatic=False):
        self.board = board
        self.data = {ident: bytes(8) for ident in PERIOD_MS}
        if not automatic:
            for ident in (EGS1, EGS2, EGS3):
                del self.data[ident]
        self._due = {ident: 0 for ident in self.data}

    def set_speed(self, kmh):
        """Vehicle speed in ASC1, bytes 1-2 little endian, 1/8 km/h."""
        v = int(kmh * 8) & 0xFFFF
        d = bytearray(self.data[ASC1])
        d[1], d[2] = v & 0xFF, v >> 8
        self.data[ASC1] = bytes(d)

    def run(self, instructions):
        """Run the board, feeding the frames that fall due on the way."""
        b = self.board
        frame = b.ips // 100
        end = b.instructions + instructions
        while b.instructions < end:
            for ident, period in PERIOD_MS.items():
                if ident in self.data and b.instructions >= self._due[ident]:
                    b.can_a.receive(ident, self.data[ident])
                    self._due[ident] = b.instructions + period * frame // 10
            b.run(min(frame, end - b.instructions))
