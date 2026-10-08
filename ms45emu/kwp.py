"""A KWP2000* tester for the emulated DME, for tests and experiments.

Telegrams are B8 <target> <source> <len> <data> <xor>. `request()` sends
one and runs the board until the answer is complete, repeating while the
DME says "routine not complete" (0x23) or "response pending" (0x78), as
EDIABAS does. The RSA authentication is the one BMWeb-Flasher's
Checksums_Signatures does, in Python.
"""
import hashlib

DME, TESTER = 0x12, 0xF1
# Times, in instructions at the default 40 MIPS; a Tester scales them to
# its board's clock.
FRAME = 400_000                # 10 ms
GAP = 4 * FRAME                # 40 ms between telegrams
PROGRAMMING_GAP = 480_000      # P3min = 12 ms once the access timing is set
PROGRAMMING_STEP = 40_000
LOGGING_GAP = 500_000          # the same 12 ms in the default session, with a little over
PATCHED_LOGGING_GAP = 100_000  # 2 ms with the diagnostic patch (diagpatch.py), likewise
LOGGING_STEP = 10_000
PACKET = 0xF0                  # the local identifier a tester defines for itself

RSA_N = 8972339025878534711764289273376673716657892103603163846525142300863027035823902824753024958104010374518577719658056297243325957293507856591918471309133927
RSA_D = 3845288153947943447898981117161431592853382330115641648510775271798440158210161294390718397115404567798616968157688687573437683643982238798574542074351303


def telegram(data, target=DME, source=TESTER):
    t = bytes([0xB8, target, source, len(data)]) + bytes(data)
    cs = 0
    for x in t:
        cs ^= x
    return t + bytes([cs])


def auth_key(user_id, serial_tail, seed):
    """The 64-byte authentication block: RSA over the MD5 of user id +
    last 4 serial bytes + seed, 64 little-endian bytes with each 32-bit
    word byte-swapped, as the flasher sends it."""
    h = hashlib.md5(bytes(user_id) + bytes(serial_tail) + bytes(seed)).digest()
    m = int.from_bytes(h + b"\x00", "little")
    le = pow(m, RSA_D, RSA_N).to_bytes(64, "little")
    return b"".join(le[4 * i:4 * i + 4][::-1] for i in range(16))


class Tester:
    __test__ = False               # not a test class, whatever pytest makes of the name

    def __init__(self, board, timeout_frames=300, trace=False):
        self.b = board
        self.timeout = timeout_frames
        self.trace = trace
        self.log = []
        self.frame = FRAME * board.mips // 40
        self.gap = GAP * board.mips // 40          # P3: the DME wants a pause after its answer
        self.step = self.frame                     # how often to look for the answer

    def _receive(self, data, timeout_frames=None):
        """Run until the DME has sent a whole telegram; its data, or None."""
        b = self.b
        frames = 0
        while frames < (timeout_frames or self.timeout):
            b.run(self.step)
            frames += self.step / self.frame
            tx = bytes(b.sci.tx)
            if len(tx) >= 4 and len(tx) == tx[3] + 5:
                self.log.append((bytes(data), tx))
                if self.trace:
                    print(f"  > {bytes(data).hex()}  < {tx[4:-1].hex()}  ({frames:g} frames)")
                b.sci.tx.clear()
                return tx[4:-1]
        self.log.append((bytes(data), bytes(b.sci.tx)))
        if self.trace:
            print(f"  > {bytes(data).hex()}  < (no answer, {bytes(b.sci.tx).hex()})")
        return None

    def _exchange(self, data, timeout_frames=None):
        b = self.b
        b.run(self.gap)
        b.sci.tx.clear()
        b.sci.send(telegram(data))
        return self._receive(data, timeout_frames)

    def request(self, data, retries=30, timeout_frames=None, pending_frames=6000):
        """The positive response data, or the negative one (7F ...)/None.
        "Busy" (0x23) means ask again; "response pending" (0x78) means the
        answer will follow on its own, however long the job takes."""
        silent = 0
        for _ in range(retries):
            r = self._exchange(data, timeout_frames)
            while r is not None and len(r) == 3 and r[0] == 0x7F and r[2] == 0x78:
                r = self._receive(data, pending_frames)
            if r is None:
                silent += 1                       # busy (the RSA check takes seconds): ask again
                if silent > 5:
                    return None
                continue
            if len(r) == 3 and r[0] == 0x7F and r[2] == 0x23:
                continue
            return r
        return r

    # ---- the flasher's steps ------------------------------------------------
    def ident(self):
        return self.request([0x1A, 0x80])

    def serial(self):
        r = self.request([0x1A, 0x89])
        return bytes(r[2:]) if r and r[0] == 0x5A else None

    def authenticate(self, user_id=b"\x9B\x8E\xDA\xAE"):
        serial = self.serial()
        r = self.request([0x31, 0x07, 0x03] + list(user_id))
        if not r or r[0] != 0x71:
            return False
        seed = bytes(r[2:10])
        key = auth_key(user_id, serial[-4:], seed)
        r = self.request([0x31, 0x08, 0, 0, 0, 0x10] + list(key))
        return bool(r) and r[0] == 0x71

    def programming_mode(self):
        r = self.request([0x10, 0x85, 0x05])
        if not r or r[0] != 0x50:
            return False
        r = self.request([0x83, 0x03, 0x00, 0x78, 0x18, 0xF0, 0x00])
        if not r or r[0] != 0xC3:
            return False
        self.gap, self.step = PROGRAMMING_GAP * self.b.mips // 40, PROGRAMMING_STEP * self.b.mips // 40
        return True

    def default_mode(self):
        """Back to 9600 baud and the normal timing; the loader keeps running."""
        r = self.request([0x10, 0x81, 0x01])
        self.gap, self.step = 4 * self.frame, self.frame
        return bool(r) and r[0] == 0x50

    def programming_status(self):
        """1 = normal, 5 = program signature not checked yet, 6 = data
        signature not checked yet (FLASH_PROGRAMMIER_STATUS_LESEN)."""
        r = self.request([0x31, 0x0A])
        return r[2] if r and r[0] == 0x71 else None

    def check_signature(self, what):
        """The DME's RSA check of what was flashed: "program" or "data".
        A pass is what marks that part valid for the next reset."""
        r = self.request([0x31, 0x09, {"program": 0x02, "data": 0x04}[what]])
        return bool(r) and r[0] == 0x71 and r[2] == 0x01

    def reset(self):
        """STEUERGERAETE_RESET. The board itself is reset with Board.reset()."""
        r = self.request([0x11, 0x01])
        return bool(r) and r[0] == 0x51

    # ---- logging -------------------------------------------------------------
    def logging_mode(self, patched=False):
        """As fast as the default session goes, with no authentication:
        115200 baud, and the timing limits (answer after 2 ms, next request
        12 ms after it), which is the only timing that session accepts.
        With the diagnostic patch in the program the DME then goes on to
        0 and 2 ms by itself, and `patched` has the tester use that."""
        r = self.request([0x10, 0x81, 0x05])
        if not r or r[0] != 0x50:
            return False
        r = self.request([0x83, 0x03, 0x04, 0x01, 0x18, 0x14, 0x00])
        if not r or r[0] != 0xC3:
            return False
        self.gap = (PATCHED_LOGGING_GAP if patched else LOGGING_GAP) * self.b.mips // 40
        self.step = LOGGING_STEP * self.b.mips // 40
        if patched:
            self.b.run(2 * self.frame)                 # its 10 ms task has to come round first
        return True

    def read_memory(self, address, size):
        """Up to 250 bytes of RAM (0x3F9800 up) or internal flash, or None."""
        r = self.request([0x23, (address >> 16) & 0xFF, (address >> 8) & 0xFF, address & 0xFF, size])
        return bytes(r[1:]) if r and r[0] == 0x63 else None

    def define_packet(self, entries):
        """Define local identifier F0 as these (address, size) pieces of
        memory, in order; up to 42 of them. All in one request: a second
        one replaces the first."""
        req, position = [0x2C, PACKET], 1
        for address, size in entries:
            req += [0x03, position, size, (address >> 16) & 0xFF, (address >> 8) & 0xFF, address & 0xFF]
            position += size
        r = self.request(req)
        return bool(r) and r[0] == 0x6C

    def read_packet(self):
        r = self.request([0x21, PACKET])
        return bytes(r[2:]) if r and r[0] == 0x61 else None

    @staticmethod
    def _region(start, length):
        # As the SGBD encodes it: address bytes 2,1,0 then byte 3, then a 3-byte length.
        return [(start >> 16) & 0xFF, (start >> 8) & 0xFF, start & 0xFF, (start >> 24) & 0xFF,
                (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF]

    def erase(self, start, length):
        r = self.request([0x31, 0x02] + self._region(start, length), timeout_frames=60)
        return bool(r) and r[0] == 0x71 and r[2] == 0x01

    def write(self, start, data, progress=None):
        """Request download, transfer the data in the 253-byte blocks the
        DME asks for, transfer exit. True when every block was taken."""
        region = self._region(start, len(data))
        region[4:4] = [0x00]                      # data format: plain
        r = self.request([0x34] + region)
        if not r or r[0] != 0x74:
            return False
        size = r[1] - 1                           # the block length includes the service id
        for i, at in enumerate(range(0, len(data), size)):
            r = self.request([0x36] + list(data[at:at + size]))
            if not r or r[0] != 0x76:
                return False
            if progress is not None:
                progress(at + size, len(data))
        r = self.request([0x37] + region)
        return bool(r) and r[0] == 0x77
