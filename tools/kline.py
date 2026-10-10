#!/usr/bin/env python
"""The emulated DME on a serial port, for INPA / EDIABAS / the flasher app.

    .venv/bin/python tools/kline.py [--pair patched] [--eeprom images/eeprom.bin]
    .venv/bin/python tools/kline.py --port /dev/cu.usbserial-XXXX

Without --port this prints a pseudo-terminal to point a tester on this
machine at (e.g. /dev/ttys012). With --port it uses a real serial device
instead, for a tester on another machine or in a VM: two USB serial
adapters back to back (TX to RX, RX to TX, ground to ground), one here
and one where the tester expects its K-line cable. The port follows the
baud rate the DME sets (9600, then 115200 while flashing), 8 data bits
and even parity.

--socket PATH adds a Unix socket next to either, for a tester in a virtual
machine: give the VM a serial port that is a named pipe on that path with
the VM as the client end (VMware: serial0.fileType = "pipe",
serial0.fileName = PATH, serial0.pipe.endPoint = "client"), and the guest
sees a COM port with the DME on it. A pipe has no baud rate to follow.

--ws PORT adds a WebSocket on localhost for testers that run in a browser
on Web Serial, whose port picker only lists real serial devices. It speaks
BMWeb's gateway protocol, so BMWeb takes it as its cable with
?gateway=ws://localhost:PORT on the page's URL, and its command line with
--gateway localhost:PORT. For any other Web Serial page the same port
serves tools/webserial-emu.js; load that into the page (DevTools console:
import('http://localhost:PORT/webserial-emu.js')) and its Web Serial hands
out the emulated DME as the port.

Either way this plays the K line: bytes the tester writes are echoed back
(a K-line cable hears its own transmission) and fed to the DME's SCI;
bytes the DME transmits go out to the tester. The DME runs with the
ignition on until the tester goes away or `q`.

The DME speaks KWP2000* (B8 12 F1 <len> <data> <xor>) through its own
diagnostic code, so anything EDIABAS can do with ms450ds0.prg works here
as far as the hardware behind it is modelled: identification, memory
reads, fault memory, and flashing (docs/flashing.md). STEUERGERAETE_RESET
resets the board onto whatever the flash then holds; on exit a changed
flash is saved next to the EEPROM image as <eeprom>.flash.bin / .mpc.bin.
--resume starts on those two instead of the pair, from the reset vector,
so a DME left half flashed is still half flashed the next time.

--program FILE.0PA and --calibration FILE.0DA start the DME on BMW's own
data files, as SP-Daten has them for every release: they are written onto
the pair the way a tester would write them, over its boot loader, which
they do not contain (ms45emu/daten.py). A program without --calibration
keeps the pair's calibration when that is made for it and otherwise gets
the first .0DA in its folder that is. A program brings the MPC flash with
it, so the pair then only needs its external flash (MS45_FLASH).

The ignition is on to begin with. `i` and Enter here toggles it, and so
do http://localhost:PORT/ignition/off, /on and /toggle on the --ws port
(/ignition shows it). A tester reads it where a K+DCAN cable has it, on
DSR. With the ignition off the program does its after-run, writes the
EEPROM and parks, and the DME is then without power; the boot loader
holds no main relay and is off at once. Ignition on starts a DME that
was off from its reset vector, on what its flash holds: the way out of
a flash that was interrupted, as in the car.

With nothing happening for an hour (no bytes from a tester on any line,
nothing typed, no ignition command) the bridge quits as `q` would, saving
the EEPROM and any flash it changed; --idle-timeout sets the seconds, 0
never.

The DME keeps real time: a tester's timeouts and pauses are in real
milliseconds, and so are the DME's. For that the emulated CPU is clocked
at 10 MIPS instead of 40 (--mips), which the program still keeps its
schedule on and the emulator can do faster than real time; the bridge
then waits for the wall clock.

--turbo stops that wait while a telegram is in flight: from the tester's
first byte until the DME's answer is out, the DME runs as fast as the
emulator can go, and it is back on the wall clock in the pauses between.
The DME itself sees the same line at the same baud rate in its own time;
the tester gets its answers sooner than a wire at that rate could carry
them, so this is for getting through a flash quickly, not for checking a
tester's timing.
"""
import argparse
import base64
import hashlib
import json
import os
import select
import socket
import sys
import termios
import time
import tty

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ms45emu import load_pair                 # noqa: E402
from ms45emu.board import Board, VALID_MARKS  # noqa: E402
from ms45emu.image import Pair                # noqa: E402

from ms45emu.sci import SCC1R0, CLOCK         # noqa: E402

SLICE_SECONDS = 0.0025   # DME time between looks at the line
PTY_ACTIVE_SECONDS = 120
RESET_ANSWER = bytes.fromhex("B8F11201510B")   # positive response to STEUERGERAETE_RESET (11 01)
TURBO_ANSWER_SECONDS = 0.1   # --turbo: DME time to wait for an answer to start (some requests get none)
TURBO_LIMIT_SECONDS = 2.0    # ... and to wait for one that has started to finish
AFTER_RUN_LIMIT_SECONDS = 90 # ignition off: DME time the after-run gets before the main relay drops anyway
PARKED_SLICES = 4            # ... and how many looks in a row have to find the program parked
IDLE_TIMEOUT_SECONDS = 3600 # quit after this long without a tester or a command (--idle-timeout)
BAUD_RATES = (9600, 10400, 19200, 38400, 57600, 115200, 125000)


class Pty:
    """A pseudo-terminal for a tester on this machine."""

    def __init__(self, link=None):
        self.fd, slave = os.openpty()
        tty.setraw(self.fd)
        os.set_blocking(self.fd, False)           # nobody may be reading the other end
        self.heard = 0.0                          # when the tester last sent something
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO                 # the DME side does the echo, not the tty
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        self.name = os.ttyname(slave)
        self.link = link
        if link:
            try:
                os.unlink(link)
            except FileNotFoundError:
                pass
            os.symlink(self.name, link)

    def fileno(self):
        return self.fd

    def read(self):
        try:
            data = os.read(self.fd, 4096)
        except BlockingIOError:
            return b""
        if data:
            self.heard = time.time()
        return data

    def active(self):
        """A pty cannot tell whether anyone has it open. Bytes written to
        one nobody reads pile up (and would greet the next tester), so the
        DME is only passed on while a tester has been talking."""
        return time.time() - self.heard < PTY_ACTIVE_SECONDS

    def write(self, data):
        try:
            os.write(self.fd, bytes(data))
        except BlockingIOError:
            pass                                  # its buffer is full: nobody is reading

    def set_baud(self, baud):
        pass

    def close(self):
        if self.link:
            try:
                os.unlink(self.link)
            except FileNotFoundError:
                pass


class Port:
    """A real serial device (a USB adapter wired to the tester's)."""

    def __init__(self, device):
        import serial                              # pyserial; only needed for --port
        self.ser = serial.Serial(device, 9600, bytesize=8, parity=serial.PARITY_EVEN, stopbits=1, timeout=0)
        self.name = device

    def fileno(self):
        return self.ser.fileno()

    def read(self):
        return self.ser.read(4096)

    def write(self, data):
        self.ser.write(bytes(data))

    def set_baud(self, baud):
        if self.ser.baudrate != baud:
            self.ser.flush()
            self.ser.baudrate = baud

    def close(self):
        self.ser.close()


class Socket:
    """A Unix socket for a virtual machine's serial port; one client at a time."""

    def __init__(self, path):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        self.name = path
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(path)
        self.server.listen(1)
        self.client = None

    def fileno(self):
        return (self.client or self.server).fileno()

    def read(self):
        if self.client is None:
            self.client, _ = self.server.accept()
            print(f"{self.name}: connected", flush=True)
            return b""
        try:
            data = self.client.recv(4096)
        except OSError:
            data = b""
        if not data:
            print(f"{self.name}: disconnected", flush=True)
            self.client.close()
            self.client = None
        return data

    def write(self, data):
        if self.client is not None:
            try:
                self.client.sendall(bytes(data))
            except OSError:
                pass

    def set_baud(self, baud):
        pass

    def close(self):
        if self.client is not None:
            self.client.close()
        self.server.close()
        try:
            os.unlink(self.name)
        except FileNotFoundError:
            pass


class WebSocket:
    """A WebSocket on localhost for a browser tester. One client at a time.

    Binary frames are the bytes on the line. Text frames are control, in
    either of two forms: BMWeb's gateway calls, {id, op: open | close |
    setSignals | getSignals, ...}, each answered {id, ok}, or the plain
    {baudRate, parity} webserial-emu.js sends (the same port serves that
    file over plain HTTP). Either way the client says which baud rate it
    has its port set to; `baud` is that.

    The port also takes the ignition switch over plain HTTP: /ignition/on,
    /off and /toggle are left in `commands` for the bridge, which keeps
    `ignition` at what the switch is."""

    GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    SHIM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webserial-emu.js")

    def __init__(self, port):
        self.name = f"ws://localhost:{port}"
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", port))
        self.server.listen(4)
        self.client = None
        self.buf = b""
        self.baud = None
        self.ignition = True
        self.commands = []                # ignition on (True) / off (False), as asked for over HTTP
        self.pending = []                 # [conn, request so far, since]: connections not yet served

    def fileno(self):
        return (self.client or self.server).fileno()

    def service(self):
        """Take what has come in on the listening socket (the ignition
        switch, or the tester again after a page reload, which then replaces
        the old one) and feed the connections whose request is still on its
        way, without ever waiting on one: a browser opens connections it
        may never use, and a wait here is the DME standing still, which a
        tester in the middle of a flash reads as a silent ECU."""
        while select.select([self.server], [], [], 0)[0]:
            conn, _ = self.server.accept()
            conn.setblocking(False)
            self.pending.append([conn, b"", time.time()])
        still = []
        for entry in self.pending:
            conn, request, since = entry
            try:
                chunk = conn.recv(4096)
            except BlockingIOError:
                chunk = None
            except OSError:
                chunk = b""
            if chunk:
                entry[1] = request = request + chunk
            if b"\r\n\r\n" in request or len(request) >= 8192:
                self._serve(conn, request)
            elif chunk == b"" or time.time() - since > 5:
                print(f"{time.strftime('%H:%M:%S')} {self.name}: a connection {'closed' if chunk == b'' else 'gave up on'} "
                      f"without a request after {time.time() - since:.1f} s", flush=True)
                conn.close()                              # gone, or never said what it wanted
            else:
                still.append(entry)
        self.pending = still

    def _ignition_page(self, path):
        want = {"on": True, "off": False, "toggle": not self.ignition}.get(path.rstrip("/").rpartition("/")[2])
        if want is not None:
            self.commands.append(want)
        state = "on" if (self.ignition if want is None else want) else "off"
        return (f"<!doctype html><title>ms45-emu ignition</title><p>Ignition is <b>{state}</b>.</p>"
                f'<p><a href="/ignition/on">on</a> | <a href="/ignition/off">off</a></p>\n').encode()

    def _serve(self, conn, request):
        """Answer one connection's request: a WebSocket upgrade makes it the
        tester, anything else is served over plain HTTP and closed."""
        try:
            head, _, rest = request.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            headers = {k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in lines[1:])}
            if headers.get("upgrade", "").lower() == "websocket":
                accept = base64.b64encode(hashlib.sha1(headers["sec-websocket-key"].encode() + self.GUID).digest())
                conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                             b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
                conn.setblocking(True)
                print(f"{time.strftime('%H:%M:%S')} {self.name}: tester connected"
                      f"{' (replacing the one before)' if self.client is not None else ''}", flush=True)
                if self.client is not None:
                    self._drop()
                self.client, self.buf, self.baud = conn, rest, None
                self._send(0x1, json.dumps({"event": "hello", "port": "ms45-emu"}).encode())
                return
            path = (lines[0].split(" ") + ["/"])[1]
            print(f"{time.strftime('%H:%M:%S')} {self.name}: {lines[0][:60]}", flush=True)
            if path.startswith("/ignition"):
                body, kind = self._ignition_page(path), b"text/html"
            elif "webserial-emu.js" in path:
                body, kind = open(self.SHIM, "rb").read(), b"text/javascript"
            else:
                body, kind = b"ms45-emu K line; see /webserial-emu.js and /ignition\n", b"text/plain"
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: " + kind + b"; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\n"
                         b"Cache-Control: no-store\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        except (OSError, KeyError):
            pass
        conn.close()

    def _drop(self):
        print(f"{time.strftime('%H:%M:%S')} {self.name}: tester disconnected", flush=True)
        self.client.close()
        self.client = None

    def _send(self, opcode, payload):
        n = len(payload)
        head = bytes([0x80 | opcode]) + (bytes([n]) if n < 126 else b"\x7e" + n.to_bytes(2, "big") if n < 65536
                                         else b"\x7f" + n.to_bytes(8, "big"))
        try:
            self.client.sendall(head + bytes(payload))
        except OSError:
            self._drop()

    def read(self):
        if self.client is None:
            self.service()
            if self.client is None or not self.buf:
                return b""
        else:
            try:
                data = self.client.recv(65536)
            except OSError:
                data = b""
            if not data:
                self._drop()
                return b""
            self.buf += data
        out = b""
        while self.client is not None and len(self.buf) >= 2:
            opcode, n, at = self.buf[0] & 0x0F, self.buf[1] & 0x7F, 2
            if n == 126:
                n, at = int.from_bytes(self.buf[2:4], "big"), 4
            elif n == 127:
                n, at = int.from_bytes(self.buf[2:10], "big"), 10
            masked = bool(self.buf[1] & 0x80)
            if len(self.buf) < at + 4 * masked + n:
                break
            mask = self.buf[at:at + 4] if masked else b"\0\0\0\0"
            at += 4 * masked
            payload = bytes(x ^ mask[i & 3] for i, x in enumerate(self.buf[at:at + n]))
            self.buf = self.buf[at + n:]
            if opcode == 0x2:
                out += payload
            elif opcode == 0x1:
                self._control(payload)
            elif opcode == 0x9:
                self._send(0xA, payload)
            elif opcode == 0x8:
                self._drop()
        return out

    def _control(self, payload):
        try:
            msg = json.loads(payload)
        except ValueError:
            return
        if not isinstance(msg, dict):
            return
        if "op" not in msg:                            # webserial-emu.js: the port's settings or its lines
            self.baud = msg.get("baudRate", self.baud)
            return
        reply = {"id": msg.get("id"), "ok": True}
        op = msg["op"]
        if op == "open":
            self.baud = (msg.get("config") or {}).get("baudRate", self.baud)
        elif op == "close":
            self.baud = None
        elif op == "getSignals":
            # the cable reports the ignition (KL15) on DSR/DCD
            reply["signals"] = {"dataSetReady": self.ignition, "dataCarrierDetect": self.ignition, "clearToSend": False}
        elif op != "setSignals":
            reply = {"id": msg.get("id"), "ok": False, "error": f"unknown call {op}"}
        self._send(0x1, json.dumps(reply).encode())

    def write(self, data):
        if self.client is not None:
            self._send(0x2, data)

    def set_baud(self, baud):
        pass

    def close(self):
        if self.client is not None:
            self.client.close()
        self.server.close()


def dme_baud(board):
    """The standard rate nearest to what the DME's SCI is set to."""
    scbr = board.imb.peek16(SCC1R0) & 0x1FFF
    if not scbr:
        return 9600
    rate = CLOCK / (32 * scbr)
    return min(BAUD_RATES, key=lambda r: abs(r - rate))


class Trace:
    """Prints the line's traffic, a run of bytes in one direction per line,
    with the real time and the DME's time in seconds: a tester that sends
    before the DME's time has caught up with the wall clock shows here."""

    IDLE = 0.03                    # a pause this long ends a run

    def __init__(self):
        self.who = None
        self.data = bytearray()
        self.started = self.last = 0.0
        self.zero = time.time()

    def add(self, who, data, dme_time):
        now = time.time() - self.zero
        if self.data and (who != self.who or now - self.last > self.IDLE):
            self.flush()
        if not self.data:
            self.who, self.started, self.dme_time = who, now, dme_time
        self.data += data
        self.last = now

    def flush(self):
        if self.data:
            print(f"{self.started:9.3f} (dme {self.dme_time:9.3f})  {self.who:>6}> {self.data.hex()}", flush=True)
            self.data.clear()

    def idle(self):
        if self.data and time.time() - self.zero - self.last > self.IDLE:
            self.flush()


class Adapter:
    """The K line behind a Deep OBD style WiFi adapter (the THOR and its
    kin), as EdiabasLib drives it: a byte stream on TCP, carrying

    - config telegrams, 8x F1 F1 <cmd> ... <sum>, which the adapter echoes and
      answers itself: FE ignition, FD type and version, FB serial, FC
      voltage, 06 escape mode, 82 CAN mode;
    - below 115200 baud, K-line telegrams wrapped 00 <type> <baud/2> <flags1>
      [<flags2> <interbyte> <kwp1281 timeout>] <len> <data> <sum>: the
      adapter puts the data on the line at that rate and parity, keeps the
      echo to itself, and sends back the ECU's bytes as they are;
    - at 115200, the telegrams raw, echoed as the line echoes.

    One client at a time, on a TCP port (what the dongle is to an app on the
    same network) or a WebSocket (for the app in a browser on this machine,
    binary frames). `baud` follows what the tester's telegrams say, so the
    DME hears nothing sent at a rate it is not listening on."""

    TYPE, VERSION = 0x0002, 0x000C          # what the adapter says it is: a Deep OBD adapter with long telegrams
    SERIAL = bytes.fromhex("4D53343545" "4D5500")   # "MS45EMU"
    IGNITION_ON = 0x01

    def __init__(self, port, websocket=False):
        self.ws = websocket
        self.name = f"{'ws' if websocket else 'tcp'}://localhost:{port} (adapter)"
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("0.0.0.0", port))
        self.server.listen(4)
        self.client = None
        self.buf = b""                    # bytes from the tester not yet parsed
        self.baud = None                  # the rate the tester's last telegram was for
        self.echoes = False               # whether the DME's line echo goes back (raw mode only)
        self.ignition = True
        self.commands = []
        self.pending = []
        self.wsbuf = b""

    def fileno(self):
        return (self.client or self.server).fileno()

    def service(self):
        while select.select([self.server], [], [], 0)[0]:
            conn, _ = self.server.accept()
            conn.setblocking(False)
            if not self.ws:
                print(f"{time.strftime('%H:%M:%S')} {self.name}: tester connected"
                      f"{' (replacing the one before)' if self.client is not None else ''}", flush=True)
                if self.client is not None:
                    self.client.close()
                conn.setblocking(True)
                self.client, self.buf, self.baud, self.wsbuf = conn, b"", None, b""
            else:
                self.pending.append([conn, b"", time.time()])
        still = []
        for entry in self.pending:
            conn, request, since = entry
            try:
                chunk = conn.recv(4096)
            except BlockingIOError:
                chunk = None
            except OSError:
                chunk = b""
            if chunk:
                entry[1] = request = request + chunk
            if b"\r\n\r\n" in request:
                head, _, rest = request.partition(b"\r\n\r\n")
                headers = {k.strip().lower(): v.strip() for k, _, v in
                           (line.partition(":") for line in head.decode("latin-1").split("\r\n")[1:])}
                if headers.get("upgrade", "").lower() == "websocket" and "sec-websocket-key" in headers:
                    accept = base64.b64encode(hashlib.sha1(headers["sec-websocket-key"].encode() + WebSocket.GUID).digest())
                    conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                 b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
                    conn.setblocking(True)
                    print(f"{time.strftime('%H:%M:%S')} {self.name}: tester connected"
                          f"{' (replacing the one before)' if self.client is not None else ''}", flush=True)
                    if self.client is not None:
                        self.client.close()
                    self.client, self.buf, self.baud, self.wsbuf = conn, b"", None, rest
                else:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\n"
                                 b"Connection: close\r\n\r\nms45-emu: a Deep OBD style adapter on a WebSocket\n")
                    conn.close()
            elif chunk == b"" or time.time() - since > 5:
                conn.close()
            else:
                still.append(entry)
        self.pending = still

    def _drop(self):
        print(f"{time.strftime('%H:%M:%S')} {self.name}: tester disconnected", flush=True)
        self.client.close()
        self.client, self.baud = None, None

    def _send(self, data):
        if self.client is None or not data:
            return
        try:
            if self.ws:
                n = len(data)
                head = bytes([0x82]) + (bytes([n]) if n < 126 else b"\x7e" + n.to_bytes(2, "big"))
                self.client.sendall(head + bytes(data))
            else:
                self.client.sendall(bytes(data))
        except OSError:
            self._drop()

    def _recv(self):
        """Bytes from the tester, unframed."""
        try:
            data = self.client.recv(65536)
        except OSError:
            data = b""
        if not data:
            self._drop()
            return b""
        if not self.ws:
            return data
        self.wsbuf += data
        out = b""
        while len(self.wsbuf) >= 2:
            opcode, n, at = self.wsbuf[0] & 0x0F, self.wsbuf[1] & 0x7F, 2
            if n == 126:
                n, at = int.from_bytes(self.wsbuf[2:4], "big"), 4
            elif n == 127:
                n, at = int.from_bytes(self.wsbuf[2:10], "big"), 10
            masked = bool(self.wsbuf[1] & 0x80)
            if len(self.wsbuf) < at + 4 * masked + n:
                break
            mask = self.wsbuf[at:at + 4] if masked else b"\0\0\0\0"
            at += 4 * masked
            payload = bytes(x ^ mask[i & 3] for i, x in enumerate(self.wsbuf[at:at + n]))
            self.wsbuf = self.wsbuf[at + n:]
            if opcode == 0x2:
                out += payload
            elif opcode == 0x9:
                self.client.sendall(bytes([0x8A, len(payload)]) + payload)
            elif opcode == 0x8:
                self._drop()
                break
        return out

    @staticmethod
    def _sum(data):
        return sum(data) & 0xFF

    def _answer_config(self, tel):
        """The adapter's own answer to a config telegram, after its echo."""
        cmd = tel[3]
        if cmd == 0xFE:                                        # ignition
            body = [0x82, 0xF1, 0xF1, 0xFE, self.IGNITION_ON if self.ignition else 0x00]
        elif cmd == 0xFD:                                      # type and version
            body = [0x85, 0xF1, 0xF1, 0xFD, self.TYPE >> 8, self.TYPE & 0xFF, self.VERSION >> 8, self.VERSION & 0xFF]
        elif cmd == 0xFB:                                      # serial
            body = [0x89, 0xF1, 0xF1, 0xFB] + list(self.SERIAL[:8].ljust(8, b"\0"))
        elif cmd == 0xFC:                                      # voltage, in 0.1 V
            body = [0x82, 0xF1, 0xF1, 0xFC, 138]
        elif cmd == 0x06:                                      # escape mode: none, whatever was asked
            body = [0x84, 0xF1, 0xF1, 0x06, 0x00 ^ 0x55, 0xFF ^ 0x55, 0x80 ^ 0x55]
        elif cmd == 0x82:                                      # CAN mode: taken as asked
            body = [0x82, 0xF1, 0xF1, 0x82, tel[4]]
        else:
            return
        self._send(bytes(tel) + bytes(body + [self._sum(body)]))

    def read(self):
        """What the DME is to hear now, at the rate the tester named."""
        if self.client is None:
            self.service()
            if self.client is None:
                return b""
            return b""
        self.buf += self._recv()
        heard = b""
        while self.buf:
            b0 = self.buf[0]
            if b0 == 0x00:                                     # a wrapped K-line telegram
                if len(self.buf) < 2:
                    break
                kind = self.buf[1]
                head = 8 if kind == 0x00 else 10
                if len(self.buf) < head + 1:
                    break
                n = int.from_bytes(self.buf[head - 2:head], "big")
                if len(self.buf) < head + n + 1:
                    break
                tel = self.buf[:head + n + 1]
                self.buf = self.buf[head + n + 1:]
                if self._sum(tel[:-1]) != tel[-1]:
                    print(f"{time.strftime('%H:%M:%S')} {self.name}: wrapped telegram with a bad sum, dropped", flush=True)
                    continue
                half = int.from_bytes(tel[2:4], "big")
                self.baud = 115200 if half == 0 else half * 2
                self.echoes = False                            # KLINEF1_NO_ECHO: the adapter keeps the echo
                heard += tel[head:head + n]
            elif 0x80 <= b0 <= 0x8F and len(self.buf) >= 3 and self.buf[1] == 0xF1 and self.buf[2] == 0xF1:
                n = (b0 & 0x3F) + 4                            # header, that many bytes, sum
                if len(self.buf) < n:
                    break
                tel = self.buf[:n]
                self.buf = self.buf[n:]
                if self._sum(tel[:-1]) == tel[-1]:
                    self._answer_config(tel)
            else:                                              # raw: the line at 115200, echoed
                # one telegram at a time, by its own framing (B8 <to> <from>
                # <len> ... or 8x <to> <from> ...), so a block split over two
                # segments is not mistaken for something wrapped
                if b0 == 0xB8:
                    if len(self.buf) < 4:
                        break
                    n = self.buf[3] + 5
                elif b0 & 0xC0 == 0x80:
                    n = (b0 & 0x3F) + 4
                else:
                    n = len(self.buf)                          # not a telegram we know: through as it is
                if len(self.buf) < n:
                    break
                tel = self.buf[:n]
                self.buf = self.buf[n:]
                self.baud = 115200
                self.echoes = True
                heard += tel
        return heard

    def write(self, data):
        self._send(data)

    def set_baud(self, baud):
        pass

    def close(self):
        if self.client is not None:
            self.client.close()
        self.server.close()


def listening(line):
    """Whether there is a tester on the line to pass the DME's bytes to."""
    active = getattr(line, "active", None)
    return active() if active else getattr(line, "client", True) is not None


def wrong_rate(line, baud):
    """A line that knows its tester's baud rate, set to another than `baud`."""
    own = getattr(line, "baud", None)
    return own is not None and min(BAUD_RATES, key=lambda r: abs(r - own)) != baud


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair", default="patched", choices=["stock", "patched"])
    ap.add_argument("--program", default=None, metavar="FILE.0PA",
                    help="one of BMW's program files, written onto the pair first (its boot loader is kept)")
    ap.add_argument("--calibration", default=None, metavar="FILE.0DA",
                    help="one of BMW's calibration files, likewise; without it a program gets one that is made for it")
    ap.add_argument("--eeprom", default="images/eeprom.bin")
    ap.add_argument("--port", default=None, help="a real serial device instead of a pseudo-terminal")
    ap.add_argument("--socket", default=None, help="also serve the line on this Unix socket (a VM's serial port)")
    ap.add_argument("--ws", type=int, default=None, metavar="PORT",
                    help="also serve the line on a WebSocket (browser testers; see webserial-emu.js)")
    ap.add_argument("--link", default=None, help="also create this symlink to the pty (a stable name)")
    ap.add_argument("--adapter", type=int, default=None, metavar="PORT",
                    help="also be a Deep OBD style WiFi adapter (THOR) on this TCP port, for an app on the network")
    ap.add_argument("--adapter-ws", type=int, default=None, metavar="PORT",
                    help="the same adapter protocol on a WebSocket, for the app in a browser on this machine")
    ap.add_argument("--attached", action="store_true",
                    help="quit when standard input closes (for a program that starts this one and may die)")
    ap.add_argument("--trace", action="store_true", help="print every telegram")
    ap.add_argument("--no-watch", dest="watch", action="store_false",
                    help="do not print the wall-clock side of the line (answers that took over 200 ms to start, "
                         "stretches the DME stood still, the connections the gateway takes); on by default")
    ap.add_argument("--rpm", type=float, default=0, help="turn the crank at this speed (default 0: ignition on, engine off)")
    ap.add_argument("--mips", type=int, default=10,
                    help="million instructions per second of DME time (default 10: real time; 40: a truer CPU, 4x slow)")
    ap.add_argument("--turbo", action="store_true",
                    help="do not wait for the wall clock while a telegram is being taken and answered")
    ap.add_argument("--diag", action="store_true",
                    help="build the diagnostic patch onto the pair first (ms45emu/diagpatch.py, docs/logging.md)")
    ap.add_argument("--resume", action="store_true",
                    help="start on the flash contents saved at the last exit (<eeprom>.flash.bin / .mpc.bin), from the reset vector")
    ap.add_argument("--idle-timeout", type=float, default=IDLE_TIMEOUT_SECONDS, metavar="SECONDS",
                    help=f"quit after this long with no tester bytes, typing or ignition command "
                         f"(default {IDLE_TIMEOUT_SECONDS}: an hour; 0 never)")
    args = ap.parse_args()

    lines = [Port(args.port) if args.port else Pty(args.link)]
    if args.socket:
        lines.append(Socket(args.socket))
    if args.ws:
        lines.append(WebSocket(args.ws))
    if args.adapter:
        lines.append(Adapter(args.adapter))
    if args.adapter_ws:
        lines.append(Adapter(args.adapter_ws, websocket=True))
    print("K line on " + ", ".join(line.name for line in lines)
          + (f" (also {args.link})" if args.link and not args.port else ""), flush=True)

    if args.program or args.calibration:
        from ms45emu import daten                # a .0PA / .0DA on the pair's boot loader (ms45emu/daten.py)
        pair = daten.load(args.pair, args.program, args.calibration, say=lambda text: print(text, flush=True))
        print(f"booting {pair.name}: program {pair.program_id.decode('latin1')}", flush=True)
    else:
        pair = load_pair(args.pair)
    if args.diag:
        from ms45emu import diagpatch
        pair, layout = diagpatch.build(pair)
        print(f"diagnostic patch built on: log frame 0x{layout.can_id:X} on CAN, capture block {layout.block_size} bytes at 0x{layout.block:X}", flush=True)
    saved = None
    if args.resume:
        try:
            saved = Pair(open(args.eeprom + ".flash.bin", "rb").read(), open(args.eeprom + ".mpc.bin", "rb").read(),
                         pair.name, check_program=False)
        except FileNotFoundError:
            print(f"nothing to resume from ({args.eeprom}.flash.bin / .mpc.bin): starting on the {args.pair} pair", flush=True)
    if saved:
        # As Board.reset() does it: the program is only prepared for
        # emulation when the loader is going to start it.
        valid = all(saved.flash[at:at + 4] == mark.to_bytes(4, "big") for at, mark in VALID_MARKS)
        board = Board(saved, patch_program=valid, mips=args.mips)
    else:
        board = Board(pair, mips=args.mips)
    slice_instructions = int(SLICE_SECONDS * board.ips)
    if os.path.exists(args.eeprom):
        board.load_eeprom(open(args.eeprom, "rb").read())
    # What the DME sends, each byte with the rate it went out at: it answers
    # the switch to 115200 at 9600 and changes its rate right after, so the
    # rate has to be the one at the moment of sending, not at delivery.
    out = []
    board.sci.on_tx = lambda byte: out.append((byte, dme_baud(board)))
    print("booting...", flush=True)
    if saved:
        print("resuming on the saved flash; the DME will start "
              + ("its program" if board.cpu.program else "the boot loader: nothing valid to run"), flush=True)
        board.boot(max_insns=board.ips // 2, reset_vector=True)
    else:
        board.boot(max_insns=board.ips // 2)
    board.crank.rpm = args.rpm
    print(f"DME running (ignition on, engine {'at %g rpm' % args.rpm if args.rpm else 'off'}); q to quit, i for the ignition", flush=True)

    trace = Trace() if args.trace else None
    sent = bytearray()                 # the DME's last bytes, to spot its answer to a reset request
    stdin_open = True
    epoch = (time.time(), board.instructions)      # real time and DME time, taken together
    in_flight = False                  # --turbo: a tester telegram is going in or its answer coming out
    # --watch: the wall-clock side of every exchange, for a tester that times
    # out on the line: when the request came in, how long the DME took to
    # start answering, and any stretch where this loop itself did not get
    # round (the DME standing still)
    watch = args.watch
    asked_at = None                    # wall time the latest tester bytes came in
    last_turn = time.time()
    def stamp():
        return time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"
    answer = bytearray()               # the DME's bytes since that telegram
    answer_by = None                   # DME times by which the answer has to have started, and finished
    ignition = True                    # KL15
    powered = True                     # False once the main relay has dropped: the CPU stands still
    off_at, parked = 0, 0              # DME time of ignition off, and looks in a row that found the program parked
    active_at = time.time()            # wall time of the latest tester bytes or command (--idle-timeout)

    def reset_board(why):
        """A new board on what the flash and the EEPROM hold now, started from the reset vector."""
        nonlocal board, epoch, in_flight, off_at, parked
        board = board.reset()
        board.ignition(ignition)
        board.sci.on_tx = lambda byte: out.append((byte, dme_baud(board)))
        state = "its program" if board.cpu.program else "the boot loader: nothing valid to run"
        print(f"{why}; it will start {state}", flush=True)
        board.boot(max_insns=slice_instructions, reset_vector=True)
        board.crank.rpm = args.rpm
        epoch = (time.time(), board.instructions)
        in_flight = False
        off_at, parked = 0, 0

    def power_off(why):
        nonlocal powered, in_flight
        powered, in_flight = False, False
        out.clear()
        board.sci.rx_queue.clear()
        print(f"DME off ({why})", flush=True)

    def set_ignition(on):
        nonlocal ignition, powered, off_at, parked
        if on == ignition:
            return
        ignition = on
        for line in lines:
            if hasattr(line, "ignition"):
                line.ignition = on
        if not on:
            board.ignition(False)
            off_at, parked = board.instructions, 0
            if board.in_loader:
                print("ignition off", flush=True)
                power_off("the boot loader holds no main relay")
            else:
                print("ignition off: the program starts its after-run", flush=True)
        elif powered:
            board.ignition(True)
            print("ignition on (the DME was still in its after-run)", flush=True)
        else:
            powered = True
            reset_board("ignition on: DME reset")

    try:
        while True:
            # Keep the DME on the wall clock: wait when it is ahead, and
            # when it has fallen behind (a slow stretch) start counting anew
            # rather than race to catch up.
            ahead = (board.instructions - epoch[1]) / board.ips - (time.time() - epoch[0])
            if ahead < -0.2 or in_flight:
                epoch = (time.time(), board.instructions)
                ahead = min(ahead, 0.0)
            wait = max(0.0, min(ahead, 0.05)) if powered else 0.05
            r, _, _ = select.select(lines + ([sys.stdin] if stdin_open else []), [], [], wait)
            for line in lines:
                if line in r:
                    data = line.read()
                    if data:
                        active_at = time.time()
                        if getattr(line, "echoes", True):
                            line.write(data)                  # the cable's echo
                        if not powered or wrong_rate(line, dme_baud(board)):
                            continue                          # nobody there, or the DME hears noise, not bytes
                        board.sci.send(data)
                        if watch:
                            asked_at = time.time()
                        if args.turbo:
                            in_flight, answer_by = True, None
                            answer.clear()
                        if trace:
                            trace.add("tester", data, board.instructions / board.ips)
            if sys.stdin in r:
                typed = sys.stdin.readline()
                if typed:
                    active_at = time.time()
                if typed.strip() == "q":
                    break
                if typed.strip() == "i":
                    set_ignition(not ignition)
                elif typed.strip() in ("ignition on", "ignition off"):       # for a program that drives this one
                    set_ignition(typed.strip().endswith("on"))
                if not typed and args.attached:
                    break                                     # whoever started this is gone
                stdin_open = bool(typed)                      # EOF: running detached
            for line in lines:
                if hasattr(line, "service"):
                    line.service()
                    while line.commands:
                        active_at = time.time()
                        set_ignition(line.commands.pop(0))
            if args.idle_timeout and time.time() - active_at > args.idle_timeout:
                idle = f"{args.idle_timeout / 60:g} min" if args.idle_timeout >= 60 else f"{args.idle_timeout:g} s"
                print(f"{stamp()} nothing from a tester for {idle}: quitting", flush=True)
                break
            if not powered:
                if trace:
                    trace.idle()
                continue
            if watch:
                turn = time.time()
                if turn - last_turn > 0.15:
                    print(f"{stamp()} watch: this loop did not get round for {(turn - last_turn) * 1000:.0f} ms"
                          f"{' with a request waiting' if asked_at else ''}", flush=True)
                last_turn = turn
            board.run(slice_instructions)
            if watch and time.time() - last_turn > 0.15:
                print(f"{stamp()} watch: one slice of the DME took {(time.time() - last_turn) * 1000:.0f} ms", flush=True)
            if not ignition:
                # The program parks in RAM when its after-run is done and
                # waits for the main relay to let go of it.
                parked = parked + 1 if board.powered_down else 0
                seconds = (board.instructions - off_at) / board.ips
                if parked >= PARKED_SLICES:
                    power_off(f"after-run done in {seconds:.1f} s")
                    continue
                if seconds > AFTER_RUN_LIMIT_SECONDS:
                    power_off(f"still running {AFTER_RUN_LIMIT_SECONDS} s after ignition off")
                    continue
            for line in lines:
                line.set_baud(dme_baud(board))
            if out:
                sending = bytes(byte for byte, _ in out)
                if watch and asked_at is not None:
                    took = time.time() - asked_at
                    if took > 0.2:
                        print(f"{stamp()} watch: the DME took {took * 1000:.0f} ms to start answering "
                              f"(DME time {board.instructions / board.ips:.1f} s)", flush=True)
                    asked_at = None
                for line in lines:
                    if listening(line):
                        heard = bytes(byte for byte, baud in out if not wrong_rate(line, baud))
                        if heard:
                            line.write(heard)
                if trace:
                    trace.add("dme", sending, board.instructions / board.ips)
                sent = (sent + sending)[-len(RESET_ANSWER):]
                if in_flight:
                    answer += sending
                out.clear()
                if sent == RESET_ANSWER:
                    sent.clear()
                    reset_board("DME reset")
            if in_flight:
                if len(answer) >= 4 and len(answer) >= answer[3] + 5:
                    in_flight = False                         # a whole telegram: B8 <to> <from> <len> <data> <xor>
                elif answer or not board.sci.rx_queue:        # the DME has taken the request
                    now = board.instructions
                    if answer_by is None:
                        answer_by = (now + int(TURBO_ANSWER_SECONDS * board.ips), now + int(TURBO_LIMIT_SECONDS * board.ips))
                    if now >= answer_by[1] or (not answer and now >= answer_by[0]):
                        in_flight = False                     # no answer to this one, or one that will not end
            if trace:
                trace.idle()
    finally:
        os.makedirs(os.path.dirname(args.eeprom) or ".", exist_ok=True)
        open(args.eeprom, "wb").write(board.eeprom_image())
        now = board.flash_pair()
        marks_only = Board(pair).flash_pair()          # what the pair is on a board, before any flashing
        if (now.flash, now.mpc) != (marks_only.flash, marks_only.mpc):
            open(args.eeprom + ".flash.bin", "wb").write(now.flash)
            open(args.eeprom + ".mpc.bin", "wb").write(now.mpc)
            print(f"flash changed: saved as {args.eeprom}.flash.bin / .mpc.bin", flush=True)
        if args.trace and board.flash_writes:
            print(f"{len(board.flash_writes)} flash writes; first 80:")
            for a, size, v, pc in board.flash_writes[:80]:
                print(f"  {a:08X}/{size} <- {v:0{2 * size}X}  pc={pc:X}")
        for line in lines:
            line.close()


if __name__ == "__main__":
    main()
