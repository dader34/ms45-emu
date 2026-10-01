"""A KWP2000* tester for the emulated DME, for tests and experiments.

Telegrams are B8 <target> <source> <len> <data> <xor>. `request()` sends
one and runs the board until the answer is complete, repeating while the
DME says "routine not complete" (0x23) or "response pending" (0x78), as
EDIABAS does. The RSA authentication is the one BMWeb-Flasher's
Checksums_Signatures does, in Python.
"""
import hashlib

DME, TESTER = 0x12, 0xF1
FRAME = 400_000
GAP_FRAMES = 4                 # 40 ms between telegrams

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
    def __init__(self, board, timeout_frames=300, trace=False):
        self.b = board
        self.timeout = timeout_frames
        self.trace = trace
        self.log = []

    def _exchange(self, data, timeout_frames=None):
        b = self.b
        b.run(GAP_FRAMES * FRAME)                 # P3: the DME wants a pause after its answer
        b.sci.tx.clear()
        b.sci.send(telegram(data))
        frames = 0
        while frames < (timeout_frames or self.timeout):
            b.run(FRAME)
            frames += 1
            tx = bytes(b.sci.tx)
            if len(tx) >= 4 and len(tx) == tx[3] + 5:
                self.log.append((bytes(data), tx))
                if self.trace:
                    print(f"  > {bytes(data).hex()}  < {tx[4:-1].hex()}  ({frames} frames)")
                return tx[4:-1]
        self.log.append((bytes(data), bytes(b.sci.tx)))
        if self.trace:
            print(f"  > {bytes(data).hex()}  < (no answer, {bytes(b.sci.tx).hex()})")
        return None

    def request(self, data, retries=30, timeout_frames=None):
        """The positive response data, or the negative one (7F ...)/None."""
        silent = 0
        for _ in range(retries):
            r = self._exchange(data, timeout_frames)
            if r is None:
                silent += 1                       # busy (the RSA check takes seconds): ask again
                if silent > 5:
                    return None
                continue
            if len(r) == 3 and r[0] == 0x7F and r[2] in (0x23, 0x78):
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
        return bool(r) and r[0] == 0xC3

    @staticmethod
    def _region(start, length):
        # As the SGBD encodes it: address bytes 2,1,0 then byte 3, then a 3-byte length.
        return [(start >> 16) & 0xFF, (start >> 8) & 0xFF, start & 0xFF, (start >> 24) & 0xFF,
                (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF]

    def erase(self, start, length):
        return self.request([0x31, 0x02] + self._region(start, length), timeout_frames=3000)
