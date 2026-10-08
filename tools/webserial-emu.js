// The emulated DME as a Web Serial port, for web testers (Chrome's port
// picker only lists real serial devices, so a pseudo-terminal never shows
// up there). Served by `tools/kline.py --ws PORT`; load it into the page
// that uses Web Serial, before connecting:
//
//     import('http://localhost:8766/webserial-emu.js')
//
// from the DevTools console, a bookmarklet, or a <script type="module">.
// navigator.serial.requestPort() and getPorts() then hand out a port whose
// bytes go over a WebSocket to the emulator's K line. Reload the page to
// get the real ports back.
const WS_URL = new URL(import.meta.url).origin.replace(/^http/, 'ws');

class EmulatedPort extends EventTarget {
  constructor(url) {
    super();
    this.url = url;
    this.ws = null;
    this.readable = null;
    this.writable = null;
    this.calls = new Map(); // id -> resolve, for the answers to getSignals
    this.nextCall = 1;
  }

  // What a K+DCAN cable's FTDI chip reports.
  getInfo() {
    return { usbVendorId: 0x0403, usbProductId: 0x6001 };
  }

  async open(options) {
    if (this.ws) throw new DOMException('The port is already open.', 'InvalidStateError');
    const ws = new WebSocket(this.url);
    ws.binaryType = 'arraybuffer';
    await new Promise((resolve, reject) => {
      ws.onopen = resolve;
      ws.onerror = () =>
        reject(new DOMException('The emulator is not running (tools/kline.py --ws).', 'NetworkError'));
    });
    // The line has no baud rate; the emulator drops what is sent at a rate
    // the DME is not listening on, as the wire would.
    ws.send(JSON.stringify({ baudRate: options.baudRate, parity: options.parity || 'none' }));
    this.ws = ws;
    this.readable = new ReadableStream({
      start: (controller) => {
        ws.onmessage = (e) => {
          if (e.data instanceof ArrayBuffer) return controller.enqueue(new Uint8Array(e.data));
          let msg = null;
          try {
            msg = JSON.parse(e.data);
          } catch {
            /* not ours */
          }
          const answered = msg && this.calls.get(msg.id);
          if (answered) {
            this.calls.delete(msg.id);
            answered(msg);
          }
        };
        ws.onclose = () => {
          try {
            controller.close();
          } catch {
            /* already closed or cancelled */
          }
          if (this.ws === ws) {
            // not our close(): the emulator went away
            this.ws = null;
            this.dispatchEvent(new Event('disconnect'));
          }
        };
      },
    });
    this.writable = new WritableStream({
      write: (chunk) => {
        if (ws.readyState !== WebSocket.OPEN) throw new DOMException('The port is closed.', 'NetworkError');
        ws.send(chunk);
      },
    });
  }

  async close() {
    const ws = this.ws;
    this.ws = null;
    this.readable = null;
    this.writable = null;
    if (ws) ws.close();
  }

  async setSignals(signals) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify({ signals }));
  }

  // The cable reports the ignition (KL15) on DSR/DCD: the emulator's switch
  // (tools/kline.py: `i`, or /ignition/on and /off on this port).
  async getSignals() {
    let on = true;
    const ws = this.ws;
    if (ws && ws.readyState === WebSocket.OPEN) {
      const id = `signals-${this.nextCall++}`;
      const reply = await new Promise((resolve) => {
        this.calls.set(id, resolve);
        setTimeout(() => this.calls.delete(id) && resolve(null), 1000);
        ws.send(JSON.stringify({ id, op: 'getSignals' }));
      });
      if (reply && reply.signals) on = !!reply.signals.dataSetReady;
    }
    return { dataSetReady: on, dataCarrierDetect: on, clearToSend: false, ringIndicator: false };
  }

  async forget() {}
}

const port = new EmulatedPort(WS_URL);
const real = navigator.serial;
const serial = new EventTarget();
serial.requestPort = async () => port;
serial.getPorts = async () => [port];
serial.real = real;
Object.defineProperty(navigator, 'serial', { value: serial, configurable: true });
console.info(`[ms45-emu] Web Serial now hands out the emulated DME (${WS_URL}); reload the page to undo.`);
