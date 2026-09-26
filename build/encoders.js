// Encoders used only by the tests and the page examples, so fixtures are built
// from explicit values and decoded back, instead of being opaque blobs.
"use strict";

const crypto = require("node:crypto");

// -------------------------------------------------------------------- CBOR

function cborHead(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b;
}

function cbor(value) {
  if (value === false) return Buffer.from([0xf4]);
  if (value === true) return Buffer.from([0xf5]);
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === "number" && Number.isInteger(value)) return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  if (typeof value === "string") { const b = Buffer.from(value); return Buffer.concat([cborHead(3, b.length), b]); }
  if (value instanceof Uint8Array) return Buffer.concat([cborHead(2, value.length), Buffer.from(value)]);
  if (Array.isArray(value)) return Buffer.concat([cborHead(4, value.length), ...value.map(cbor)]);
  const entries = value instanceof Map ? [...value] : Object.entries(value);
  return Buffer.concat([cborHead(5, entries.length), ...entries.flatMap(([k, v]) => [cbor(k), cbor(v)])]);
}

// ---------------------------------------------------------------- protobuf

function varint(n) {
  let v = BigInt(n);
  if (v < 0n) v += 2n ** 64n;
  const out = [];
  do { let byte = Number(v & 0x7fn); v >>= 7n; if (v) byte |= 0x80; out.push(byte); } while (v);
  return Buffer.from(out);
}

/** fields: [[number, "varint"|"string"|"bytes"|"message"|"double"|"float"|"fixed32", value]] */
function protobuf(fields) {
  return Buffer.concat(fields.map(([n, type, value]) => {
    if (type === "varint") return Buffer.concat([varint(n * 8), varint(value)]);
    if (type === "double") { const b = Buffer.alloc(8); b.writeDoubleLE(value); return Buffer.concat([varint(n * 8 + 1), b]); }
    if (type === "float" || type === "fixed32") { const b = Buffer.alloc(4); type === "float" ? b.writeFloatLE(value) : b.writeUInt32LE(value); return Buffer.concat([varint(n * 8 + 5), b]); }
    const body = type === "message" ? protobuf(value) : type === "string" ? Buffer.from(value) : Buffer.from(value);
    return Buffer.concat([varint(n * 8 + 2), varint(body.length), body]);
  }));
}

// --------------------------------------------------------------------- DNS

function dnsNameBytes(name) {
  return Buffer.concat([...name.replace(/\.$/, "").split(".").filter(Boolean).map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);
}

const TYPE = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, SRV: 33, CAA: 257 };

function rdata(type, value) {
  if (type === "A") return Buffer.from(value.split(".").map(Number));
  if (type === "AAAA") return Buffer.from(value.split(":").flatMap((h) => [parseInt(h.padStart(4, "0").slice(0, 2), 16), parseInt(h.padStart(4, "0").slice(2), 16)]));
  if (type === "CNAME" || type === "NS") return dnsNameBytes(value);
  if (type === "MX") { const b = Buffer.alloc(2); b.writeUInt16BE(value[0]); return Buffer.concat([b, dnsNameBytes(value[1])]); }
  if (type === "TXT") return Buffer.concat([].concat(value).map((s) => Buffer.concat([Buffer.from([Buffer.byteLength(s)]), Buffer.from(s)])));
  if (type === "CAA") return Buffer.concat([Buffer.from([value[0], value[1].length]), Buffer.from(value[1]), Buffer.from(value[2])]);
  throw new Error(type);
}

/** Build a DNS message. The question name is written once; answers point back to it (compression). */
function dnsMessage({ id = 0, response = false, rd = true, ra = false, ad = false, rcode = 0, question, answers = [] }) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE((response ? 0x8000 : 0) | (rd ? 0x100 : 0) | (ra ? 0x80 : 0) | (ad ? 0x20 : 0) | rcode, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  const qtail = Buffer.alloc(4); qtail.writeUInt16BE(TYPE[question[1]], 0); qtail.writeUInt16BE(1, 2);
  const parts = [header, dnsNameBytes(question[0]), qtail];
  for (const [name, type, ttl, value] of answers) {
    const nameBytes = name === question[0] ? Buffer.from([0xc0, 12]) : dnsNameBytes(name);
    const data = rdata(type, value);
    const fixed = Buffer.alloc(10);
    fixed.writeUInt16BE(TYPE[type], 0); fixed.writeUInt16BE(1, 2); fixed.writeUInt32BE(ttl, 4); fixed.writeUInt16BE(data.length, 8);
    parts.push(nameBytes, fixed, data);
  }
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------- WebAuthn

const b64url = (b) => Buffer.from(b).toString("base64url");

/** A registration response for rpId with a fresh P-256 key, as navigator.credentials.create().toJSON() gives it. */
function webauthnRegistration({ rpId = "example.com", origin = "https://example.com", flags = 0x45 | 0x18, aaguid = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4", challenge = Buffer.alloc(32, 7), counter = 0, jwk = null } = {}) {
  if (!jwk) jwk = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" });
  const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]);
  const credId = crypto.createHash("sha256").update(rpId + origin).digest().subarray(0, 16);
  const count = Buffer.alloc(4); count.writeUInt32BE(counter);
  const idLen = Buffer.alloc(2); idLen.writeUInt16BE(credId.length);
  const authData = Buffer.concat([
    crypto.createHash("sha256").update(rpId).digest(), Buffer.from([flags]), count,
    Buffer.from(aaguid.replace(/-/g, ""), "hex"), idLen, credId, cbor(cose),
  ]);
  const clientData = { type: "webauthn.create", challenge: b64url(challenge), origin, crossOrigin: false };
  const attestationObject = cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
  return {
    jwk, authData, attestationObject,
    json: { id: b64url(credId), rawId: b64url(credId), type: "public-key", authenticatorAttachment: "platform",
      response: { clientDataJSON: b64url(Buffer.from(JSON.stringify(clientData))), attestationObject: b64url(attestationObject) } },
  };
}

module.exports = { cbor, protobuf, varint, dnsMessage, webauthnRegistration };
