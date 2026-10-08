// Builds the emulator's map switch pairs from the stock pair, checksummed and signed as the app does:
//   patched  pedals trigger, 2 maps (map 2 differs at the coolant curve 0x4395 and the scalar 0x5EBC)
//   shifter  gear lever trigger, the same 2 maps
//   three    DSC x4 trigger, 3 maps (map 3 differs at the same curve, another scalar and block 0x43)
//   seven    DSC x4 trigger, 7 maps (maps 4-7 each differ at the scalar, the curve and one block of their own)
const fs = require('fs');
const path = require('path');
const app = process.env.HOME + '/Development/code/projects/inpa-mac-bridge/app/renderer/core/';
const { mapSwitch } = require(app + 'mapswitch.js');
global.Settings = { get: () => 'no' };
const F = require(app + 'flasher.js');
global._md5 = F._md5;
global._modPow = F._modPow;
global._bytesLEToBigInt = (bytes) => {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
};
global._bigIntToBytesLE = (value, outLen) => {
  const o = new Uint8Array(outLen);
  let v = value;
  for (let i = 0; i < outLen; i++) {
    o[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return o;
};
const ms45 = require(app + 'ms45.js');
const [flashIn, mpcIn, outDir] = process.argv.slice(2);
const flash = new Uint8Array(fs.readFileSync(flashIn));
const mpc = new Uint8Array(fs.readFileSync(mpcIn));
const map1 = Uint8Array.from(flash.subarray(0x40000, 0x5d000));
const map2 = Uint8Array.from(map1);
for (let i = 0; i < 16; i++) map2[0x4395 + i] ^= 0x55;
map2[0x5ebc] = 0x12;
map2[0x5ebd] = 0x34;
const map3 = Uint8Array.from(map1);
for (let i = 0; i < 16; i++) map3[0x4395 + i] ^= 0xaa;
map3[0x5ebc] = 0x56;
map3[0x5ebd] = 0x78;
for (let i = 0; i < 64; i++) map3[0x10c40 + i] = i;
fs.writeFileSync(path.join(outDir, 'bench_map2.bin'), map2);
fs.writeFileSync(path.join(outDir, 'bench_map3.bin'), map3);
const more = [];
for (let n = 4; n <= 7; n++) {
  const m = Uint8Array.from(map1);
  for (let i = 0; i < 16; i++) m[0x4395 + i] ^= n * 0x11;
  m[0x5ebc] = n;
  m[0x5ebd] = 0x10 * n;
  for (let i = 0; i < 64; i++) m[0x8000 * (n & 1) + 0x2400 * (n >> 2) + 0x3000 + i] = n + i;
  more.push(m);
  fs.writeFileSync(path.join(outDir, `bench_map${n}.bin`), m);
}

function finish(built) {
  let cal = Uint8Array.from(built.flash.subarray(ms45.MS45_CAL_START, ms45.MS45_CAL_START + ms45.MS45_CAL_LENGTH));
  cal = ms45.ms45Checksums.signParameters(ms45.ms45Checksums.correctParameterChecksums(cal));
  built.flash.set(cal, ms45.MS45_CAL_START);
  built.flash = ms45.ms45Checksums.correctProgramChecksums(built.flash, built.mpc);
  built.flash = ms45.ms45Checksums.signProgram(built.flash, built.mpc);
  return built;
}
for (const [name, maps, trigger, presses] of [
  ['patched', [map2], 'pedals', 4],
  ['shifter', [map2], 'shifter', 4],
  ['three', [map2, map3], 'dsc', 4],
  ['seven', [map2, map3, ...more], 'dsc', 4],
]) {
  const built = finish(mapSwitch.build(flash, mpc, null, maps, trigger, presses));
  fs.writeFileSync(path.join(outDir, `${name}_Flash.bin`), built.flash);
  fs.writeFileSync(path.join(outDir, `${name}_MPC.bin`), built.mpc);
  console.log(`${name}: ${built.log.filter((l) => /^Map|^Maps/.test(l)).join(' | ')}`);
  console.log(`  code ${built.codeBytes} bytes, installed ${JSON.stringify(mapSwitch.installed(built.mpc))}`);
}
