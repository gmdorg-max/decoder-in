(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.DecoderTools = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // ---------------------------------------------------------------- bytes

  function base64ToBytes(value) {
    const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(padded) || padded.length % 4 === 1) throw new Error("Not Base64");
    const binary = typeof atob === "function" ? atob(padded) : Buffer.from(padded, "base64").toString("binary");
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  }

  function bytesToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
    return typeof btoa === "function" ? btoa(binary) : Buffer.from(binary, "binary").toString("base64");
  }

  function hex(bytes, separator = "") {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(separator);
  }

  function utf8(bytes, fatal = false) {
    return new TextDecoder("utf-8", { fatal }).decode(bytes);
  }

  function readable(text) {
    if (!text.length) return false;
    let good = 0;
    for (const char of text) {
      if (char !== "�" && !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(char)) good += 1;
    }
    return good / [...text].length > 0.92;
  }

  // ------------------------------------------------------------- hashing
  // Synchronous so certificate fingerprints stay part of the synchronous analysis.

  function sha256(bytes) {
    const K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]);
    const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const padded = pad(bytes, false);
    const W = new Uint32Array(64);
    const view = new DataView(padded.buffer);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let offset = 0; offset < padded.length; offset += 64) {
      for (let t = 0; t < 16; t += 1) W[t] = view.getUint32(offset + t * 4);
      for (let t = 16; t < 64; t += 1) {
        const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
        const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let t = 0; t < 64; t += 1) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[t] + W[t]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    return words(H);
  }

  function sha1(bytes) {
    const H = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
    const padded = pad(bytes, false);
    const W = new Uint32Array(80);
    const view = new DataView(padded.buffer);
    const rotl = (x, n) => (x << n) | (x >>> (32 - n));
    for (let offset = 0; offset < padded.length; offset += 64) {
      for (let t = 0; t < 16; t += 1) W[t] = view.getUint32(offset + t * 4);
      for (let t = 16; t < 80; t += 1) W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
      let [a, b, c, d, e] = H;
      for (let t = 0; t < 80; t += 1) {
        const f = t < 20 ? (b & c) | (~b & d) : t < 40 ? b ^ c ^ d : t < 60 ? (b & c) | (b & d) | (c & d) : b ^ c ^ d;
        const k = t < 20 ? 0x5a827999 : t < 40 ? 0x6ed9eba1 : t < 60 ? 0x8f1bbcdc : 0xca62c1d6;
        const temp = (rotl(a, 5) + f + e + k + W[t]) >>> 0;
        e = d; d = c; c = rotl(b, 30) >>> 0; b = a; a = temp;
      }
      H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e;
    }
    return words(H);
  }

  function pad(bytes) {
    const length = bytes.length;
    const total = Math.ceil((length + 9) / 64) * 64;
    const out = new Uint8Array(total);
    out.set(bytes);
    out[length] = 0x80;
    const view = new DataView(out.buffer);
    view.setUint32(total - 8, Math.floor((length * 8) / 2 ** 32));
    view.setUint32(total - 4, (length * 8) >>> 0);
    return out;
  }

  function words(H) {
    const out = new Uint8Array(H.length * 4);
    const view = new DataView(out.buffer);
    H.forEach((word, i) => view.setUint32(i * 4, word));
    return out;
  }

  // ------------------------------------------------------------- inflate
  // RFC 1951 decoder (after zlib's puff.c). Output is capped so a pasted
  // compression bomb cannot freeze the tab.

  const MAX_INFLATE = 8 * 1024 * 1024;
  const LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
  const LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
  const DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
  const DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
  const CLORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

  function huffman(lengths) {
    const count = new Uint16Array(16);
    for (const len of lengths) count[len] += 1;
    count[0] = 0;
    const offs = new Uint16Array(16);
    for (let len = 1; len < 16; len += 1) offs[len] = offs[len - 1] + count[len - 1];
    const symbol = new Uint16Array(lengths.length);
    lengths.forEach((len, sym) => { if (len) symbol[offs[len]++] = sym; });
    return { count, symbol };
  }

  let fixedTables = null;
  function fixed() {
    if (!fixedTables) {
      const lit = new Array(288).fill(8, 0, 144).fill(9, 144, 256).fill(7, 256, 280).fill(8, 280, 288);
      fixedTables = [huffman(lit), huffman(new Array(30).fill(5))];
    }
    return fixedTables;
  }

  function inflateRaw(data, start = 0) {
    let pos = start;
    let bitbuf = 0;
    let bitcnt = 0;
    // Start at 4x the input but never above the cap: a small gzip padded with
    // junk has a large data.length, and the old buffer skipped the cap check
    // until it needed to grow, which it never did.
    let out = new Uint8Array(Math.min(Math.max(1024, data.length * 4), MAX_INFLATE));
    let outLen = 0;

    function need(n) {
      while (bitcnt < n) {
        if (pos >= data.length) throw new Error("Compressed data ends early");
        bitbuf |= data[pos++] << bitcnt;
        bitcnt += 8;
      }
    }
    function bits(n) {
      need(n);
      const value = bitbuf & ((1 << n) - 1);
      bitbuf >>>= n;
      bitcnt -= n;
      return value;
    }
    function emit(byte) {
      if (outLen >= MAX_INFLATE) throw new Error("Decompressed output exceeds 8 MB");
      if (outLen === out.length) {
        const bigger = new Uint8Array(Math.min(out.length * 2, MAX_INFLATE));
        bigger.set(out);
        out = bigger;
      }
      out[outLen++] = byte;
    }
    function decode(h) {
      let code = 0;
      let first = 0;
      let index = 0;
      for (let len = 1; len < 16; len += 1) {
        code |= bits(1);
        const count = h.count[len];
        if (code - count < first) return h.symbol[index + (code - first)];
        index += count;
        first = (first + count) << 1;
        code <<= 1;
      }
      throw new Error("Invalid Huffman code");
    }
    function codes(lencode, distcode) {
      for (;;) {
        let symbol = decode(lencode);
        if (symbol < 256) { emit(symbol); continue; }
        if (symbol === 256) return;
        symbol -= 257;
        if (symbol >= 29) throw new Error("Invalid length symbol");
        const length = LBASE[symbol] + bits(LEXT[symbol]);
        const dsym = decode(distcode);
        if (dsym >= 30) throw new Error("Invalid distance symbol");
        const dist = DBASE[dsym] + bits(DEXT[dsym]);
        if (dist > outLen) throw new Error("Distance too far back");
        for (let i = 0; i < length; i += 1) emit(out[outLen - dist]);
      }
    }

    let last;
    do {
      last = bits(1);
      const type = bits(2);
      if (type === 0) {
        bitbuf = 0;
        bitcnt = 0;
        if (pos + 4 > data.length) throw new Error("Compressed data ends early");
        const len = data[pos] | (data[pos + 1] << 8);
        const nlen = data[pos + 2] | (data[pos + 3] << 8);
        pos += 4;
        if (len !== (~nlen & 0xffff)) throw new Error("Stored block length mismatch");
        if (pos + len > data.length) throw new Error("Compressed data ends early");
        for (let i = 0; i < len; i += 1) emit(data[pos++]);
      } else if (type === 1) {
        const [lit, dist] = fixed();
        codes(lit, dist);
      } else if (type === 2) {
        const nlen = bits(5) + 257;
        const ndist = bits(5) + 1;
        const ncode = bits(4) + 4;
        if (nlen > 286 || ndist > 30) throw new Error("Bad dynamic block counts");
        const clLengths = new Array(19).fill(0);
        for (let i = 0; i < ncode; i += 1) clLengths[CLORDER[i]] = bits(3);
        const clCode = huffman(clLengths);
        const lengths = [];
        while (lengths.length < nlen + ndist) {
          const symbol = decode(clCode);
          if (symbol < 16) lengths.push(symbol);
          else {
            let repeat;
            let value = 0;
            if (symbol === 16) {
              if (!lengths.length) throw new Error("Repeat with no previous length");
              value = lengths[lengths.length - 1];
              repeat = 3 + bits(2);
            } else if (symbol === 17) repeat = 3 + bits(3);
            else repeat = 11 + bits(7);
            if (lengths.length + repeat > nlen + ndist) throw new Error("Too many code lengths");
            for (let i = 0; i < repeat; i += 1) lengths.push(value);
          }
        }
        if (!lengths[256]) throw new Error("Missing end-of-block code");
        codes(huffman(lengths.slice(0, nlen)), huffman(lengths.slice(nlen)));
      } else throw new Error("Invalid block type");
    } while (!last);

    return { bytes: out.slice(0, outLen), end: pos };
  }

  /** Recognise gzip, zlib or raw deflate and return { format, bytes } or null. */
  function decompress(bytes) {
    if (bytes.length > 18 && bytes[0] === 0x1f && bytes[1] === 0x8b && bytes[2] === 8) {
      const flags = bytes[3];
      let pos = 10;
      if (flags & 4) pos += 2 + (bytes[pos] | (bytes[pos + 1] << 8));
      if (flags & 8) { while (pos < bytes.length && bytes[pos] !== 0) pos += 1; pos += 1; }
      if (flags & 16) { while (pos < bytes.length && bytes[pos] !== 0) pos += 1; pos += 1; }
      if (flags & 2) pos += 2;
      try { return { format: "gzip", bytes: inflateRaw(bytes, pos).bytes }; } catch { return null; }
    }
    if (bytes.length > 2 && (bytes[0] & 0x0f) === 8 && (bytes[0] >> 4) <= 7 && ((bytes[0] << 8) | bytes[1]) % 31 === 0 && !(bytes[1] & 0x20)) {
      try { return { format: "zlib", bytes: inflateRaw(bytes, 2).bytes }; } catch { /* fall through to raw */ }
    }
    try {
      const result = inflateRaw(bytes);
      // Raw deflate has no signature: accept it only when it consumed the input exactly.
      if (result.end === bytes.length && result.bytes.length) return { format: "deflate", bytes: result.bytes };
    } catch { /* not deflate */ }
    return null;
  }

  // ---------------------------------------------------------------- ASN.1

  const OIDS = {
    "2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "serialNumber", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.9": "street", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "title", "2.5.4.15": "businessCategory",
    "2.5.4.17": "postalCode", "2.5.4.42": "GN", "2.5.4.97": "organizationIdentifier",
    "0.9.2342.19200300.100.1.25": "DC", "1.2.840.113549.1.9.1": "emailAddress",
    "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC", "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
    "1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption", "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption", "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption", "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256", "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521", "1.3.132.0.10": "secp256k1",
    "2.5.29.14": "Subject key identifier", "2.5.29.15": "Key usage", "2.5.29.17": "Subject alternative names",
    "2.5.29.19": "Basic constraints", "2.5.29.31": "CRL distribution points", "2.5.29.32": "Certificate policies",
    "2.5.29.35": "Authority key identifier", "2.5.29.37": "Extended key usage",
    "1.3.6.1.5.5.7.1.1": "Authority information access", "1.3.6.1.4.1.11129.2.4.2": "Certificate transparency (SCTs)",
    "1.3.6.1.5.5.7.1.24": "OCSP must-staple",
    "1.3.6.1.5.5.7.3.1": "TLS server", "1.3.6.1.5.5.7.3.2": "TLS client", "1.3.6.1.5.5.7.3.3": "Code signing",
    "1.3.6.1.5.5.7.3.4": "Email protection", "1.3.6.1.5.5.7.3.8": "Time stamping", "1.3.6.1.5.5.7.3.9": "OCSP signing",
    "1.3.6.1.5.5.7.48.1": "OCSP", "1.3.6.1.5.5.7.48.2": "CA issuers",
    "2.23.140.1.2.1": "Domain validated (DV)", "2.23.140.1.2.2": "Organization validated (OV)",
    "2.23.140.1.2.3": "Individual validated (IV)", "2.23.140.1.1": "Extended validation (EV)",
    "1.2.840.113549.1.9.14": "extensionRequest",
  };

  function derNode(bytes, offset, end) {
    if (offset + 2 > end) throw new Error("Truncated DER");
    const tag = bytes[offset];
    let length = bytes[offset + 1];
    let header = 2;
    if (length & 0x80) {
      const count = length & 0x7f;
      if (count === 0 || count > 4) throw new Error("Unsupported DER length");
      length = 0;
      for (let i = 0; i < count; i += 1) length = length * 256 + bytes[offset + 2 + i];
      header += count;
    }
    const start = offset + header;
    if (start + length > end) throw new Error("DER length overruns input");
    const node = { tag, constructed: (tag & 0x20) !== 0, offset, start, end: start + length, bytes };
    if (node.constructed) {
      node.children = [];
      let cursor = start;
      while (cursor < node.end) {
        const child = derNode(bytes, cursor, node.end);
        node.children.push(child);
        cursor = child.end;
      }
    }
    return node;
  }

  function parseDer(bytes) {
    const node = derNode(bytes, 0, bytes.length);
    if (node.end !== bytes.length) throw new Error("Trailing data after DER");
    return node;
  }

  const content = (node) => node.bytes.subarray(node.start, node.end);
  const whole = (node) => node.bytes.subarray(node.offset, node.end);

  function oid(node) {
    const b = content(node);
    const parts = [Math.floor(b[0] / 40), b[0] % 40];
    let value = 0;
    for (let i = 1; i < b.length; i += 1) {
      value = value * 128 + (b[i] & 0x7f);
      if (!(b[i] & 0x80)) { parts.push(value); value = 0; }
    }
    return parts.join(".");
  }

  const oidName = (id) => OIDS[id] || id;

  function derString(node) {
    const b = content(node);
    if (node.tag === 0x1e) {
      let out = "";
      for (let i = 0; i + 1 < b.length; i += 2) out += String.fromCharCode((b[i] << 8) | b[i + 1]);
      return out;
    }
    if (node.tag === 0x14) return Array.from(b, (c) => String.fromCharCode(c)).join("");
    return utf8(b);
  }

  function derTime(node) {
    const text = utf8(content(node));
    const m = node.tag === 0x17
      ? text.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/)
      : text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/);
    if (!m) return null;
    let year = Number(m[1]);
    if (node.tag === 0x17) year += year >= 50 ? 1900 : 2000;
    return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] || 0)));
  }

  function derName(node) {
    const parts = [];
    for (const set of node.children || []) {
      for (const attr of set.children || []) {
        if (attr.children && attr.children.length >= 2) parts.push([oidName(oid(attr.children[0])), derString(attr.children[1])]);
      }
    }
    return parts;
  }

  const nameText = (parts) => parts.map(([k, v]) => `${k}=${v}`).join(", ");
  const nameValue = (parts, key) => (parts.find(([k]) => k === key) || [])[1];

  function bitLength(bytes) {
    let i = 0;
    while (i < bytes.length && bytes[i] === 0) i += 1;
    if (i === bytes.length) return 0;
    return (bytes.length - i - 1) * 8 + (32 - Math.clz32(bytes[i]));
  }

  function publicKeyInfo(spki) {
    const alg = oidName(oid(spki.children[0].children[0]));
    const params = spki.children[0].children[1];
    const keyBits = content(spki.children[1]).subarray(1);
    let description = alg;
    let size = null;
    if (alg === "RSA") {
      try {
        const rsa = parseDer(keyBits);
        size = bitLength(content(rsa.children[0]));
        description = `RSA ${size}-bit`;
      } catch { description = "RSA (unreadable modulus)"; }
    } else if (alg === "EC" && params && params.tag === 0x06) {
      description = `EC ${oidName(oid(params))}`;
    }
    const pin = bytesToBase64(sha256(whole(spki)));
    return { algorithm: alg, description, size, pin };
  }

  function generalNames(node) {
    const out = [];
    for (const child of node.children || []) {
      const b = content(child);
      if (child.tag === 0x82) out.push(utf8(b));
      else if (child.tag === 0x81) out.push(`email:${utf8(b)}`);
      else if (child.tag === 0x86) out.push(`URI:${utf8(b)}`);
      else if (child.tag === 0x87) {
        if (b.length === 4) out.push(`IP:${Array.from(b).join(".")}`);
        else if (b.length === 16) out.push(`IP:${hex(b).match(/.{4}/g).join(":").replace(/(^|:)0{1,3}/g, "$1")}`);
      }
    }
    return out;
  }

  function uris(node, out = []) {
    if (node.tag === 0x86) out.push(utf8(content(node)));
    for (const child of node.children || []) uris(child, out);
    return out;
  }

  function extensions(node) {
    const out = {};
    const wrapper = node.children && node.children[0];
    for (const ext of (wrapper && wrapper.children) || []) {
      const id = oid(ext.children[0]);
      const critical = ext.children.length === 3 && content(ext.children[1])[0] === 0xff;
      const valueNode = ext.children[ext.children.length - 1];
      let value;
      try {
        const inner = parseDer(content(valueNode));
        if (id === "2.5.29.17") value = generalNames(inner);
        else if (id === "2.5.29.19") {
          const ca = inner.children.length && inner.children[0].tag === 0x01 && content(inner.children[0])[0] === 0xff;
          const pathLen = inner.children.find((c) => c.tag === 0x02);
          value = ca ? `CA${pathLen ? `, path length ${content(pathLen)[0]}` : ""}` : "Not a CA";
        } else if (id === "2.5.29.15") {
          const names = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];
          const b = content(inner);
          value = names.filter((_, i) => b[1 + (i >> 3)] & (0x80 >> (i & 7)));
        } else if (id === "2.5.29.37") value = inner.children.map((c) => oidName(oid(c)));
        else if (id === "2.5.29.14") value = hex(content(inner), ":");
        else if (id === "2.5.29.35") {
          const keyId = inner.children.find((c) => c.tag === 0x80);
          value = keyId ? hex(content(keyId), ":") : "(no key identifier)";
        } else if (id === "1.3.6.1.5.5.7.1.1") {
          value = inner.children.map((ad) => `${oidName(oid(ad.children[0]))}: ${uris(ad.children[1]).join(", ")}`);
        } else if (id === "2.5.29.31") value = uris(inner);
        else if (id === "2.5.29.32") value = inner.children.map((p) => oidName(oid(p.children[0])));
        else if (id === "1.3.6.1.4.1.11129.2.4.2") value = "present";
      } catch { value = "(unreadable)"; }
      out[id] = { name: oidName(id), critical, value };
    }
    return out;
  }

  function formatDays(ms) {
    const days = Math.floor(Math.abs(ms) / 86400000);
    if (days >= 1) return `${days} day${days === 1 ? "" : "s"}`;
    const hours = Math.floor(Math.abs(ms) / 3600000);
    return `${hours} hour${hours === 1 ? "" : "s"}`;
  }

  function parseCertificate(der, now = Date.now()) {
    const cert = parseDer(der);
    const tbs = cert.children[0];
    let i = 0;
    let version = 1;
    if (tbs.children[0].tag === 0xa0) { version = content(tbs.children[0].children[0])[0] + 1; i = 1; }
    const serial = hex(content(tbs.children[i]), ":");
    const issuer = derName(tbs.children[i + 2]);
    const validity = tbs.children[i + 3];
    const notBefore = derTime(validity.children[0]);
    const notAfter = derTime(validity.children[1]);
    const subject = derName(tbs.children[i + 4]);
    const spki = tbs.children[i + 5];
    const extNode = tbs.children.slice(i + 6).find((c) => c.tag === 0xa3);
    const ext = extNode ? extensions(extNode) : {};
    const signature = oidName(oid(cert.children[1].children[0]));
    const key = publicKeyInfo(spki);
    const san = (ext["2.5.29.17"] && ext["2.5.29.17"].value) || [];
    const ca = ext["2.5.29.19"] && /^CA/.test(ext["2.5.29.19"].value);
    return {
      version, serial, issuer, subject, notBefore, notAfter, signature, key, extensions: ext, san, ca,
      selfSigned: nameText(issuer) === nameText(subject),
      spkiDer: whole(spki),
      sha256: hex(sha256(der), ":").toUpperCase(),
      sha1: hex(sha1(der), ":").toUpperCase(),
      status: statusFor(notBefore, notAfter, now),
    };
  }

  function statusFor(notBefore, notAfter, now) {
    if (!notBefore || !notAfter) return { state: "unknown", text: "Unreadable validity dates" };
    if (now < notBefore.getTime()) return { state: "future", text: `Not valid for another ${formatDays(notBefore - now)}` };
    if (now > notAfter.getTime()) return { state: "expired", text: `Expired ${formatDays(now - notAfter)} ago` };
    return { state: "valid", text: `Valid, expires in ${formatDays(notAfter - now)}` };
  }

  function pemBlocks(text) {
    const out = [];
    const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
    let m;
    while ((m = re.exec(text))) {
      const body = m[2].replace(/^[A-Za-z-]+:.*$/gm, "");
      try { out.push({ label: m[1], der: base64ToBytes(body) }); } catch { out.push({ label: m[1], der: null }); }
    }
    return out;
  }

  function certificateLayers(cert, index, total, now) {
    const label = total > 1 ? `Certificate ${index + 1} of ${total}` : "Certificate";
    const summary = {
      Subject: nameValue(cert.subject, "CN") || nameText(cert.subject) || "(empty)",
      Domains: cert.san.length ? cert.san.join(", ") : "(no subject alternative names)",
      Issuer: nameValue(cert.issuer, "CN") || nameText(cert.issuer),
      Status: cert.status.text,
      "Valid from": cert.notBefore ? cert.notBefore.toISOString() : "?",
      "Valid until": cert.notAfter ? cert.notAfter.toISOString() : "?",
      Key: cert.key.description,
      Signature: cert.signature,
      Type: selfSignedSite(cert) ? "Self-signed certificate"
        : cert.ca ? (cert.selfSigned ? "Root CA (self-signed)" : "Intermediate CA")
          : cert.selfSigned ? "Self-signed certificate" : "Leaf certificate",
      "SHA-256 fingerprint": cert.sha256,
    };
    const details = {
      "Full subject": nameText(cert.subject),
      "Full issuer": nameText(cert.issuer),
      Serial: cert.serial,
      Version: `v${cert.version}`,
      "SHA-1 fingerprint": cert.sha1,
      "SPKI pin (sha256)": cert.key.pin,
    };
    for (const ext of Object.values(cert.extensions)) {
      if (ext.name === "Subject alternative names") continue;
      const value = Array.isArray(ext.value) ? ext.value.join(", ") : ext.value;
      details[ext.name + (ext.critical ? " (critical)" : "")] = value === undefined ? "present" : value;
    }
    return [
      { type: label, detail: cert.status.state === "valid" ? "Valid" : cert.status.state === "expired" ? "Expired" : cert.status.text, value: summary, claims: true },
      { type: `${label} details`, detail: "Extensions", value: details, claims: true },
    ];
  }

  // CA/Browser Forum Baseline Requirements, ballot SC-081: the maximum lifetime of a
  // publicly trusted TLS certificate depends on when it was issued.
  function maxPublicLifetimeDays(notBefore) {
    const issued = notBefore.getTime();
    if (issued >= Date.UTC(2029, 2, 15)) return 47;
    if (issued >= Date.UTC(2027, 2, 15)) return 100;
    if (issued >= Date.UTC(2026, 2, 15)) return 200;
    return 398;
  }

  // `openssl req -x509` marks its self-signed output as a CA by default; one that
  // names hostnames is still a website certificate, not a trust anchor.
  const selfSignedSite = (cert) => cert.selfSigned && cert.san.some((name) => !/^(IP|email|URI):/.test(name));

  function certificateNotices(cert, index, total) {
    const who = total > 1 ? `Certificate ${index + 1}` : "This certificate";
    const notices = [];
    if (cert.status.state === "expired") notices.push(`${who} expired ${cert.status.text.replace(/^Expired /, "")}. Clients will reject it.`);
    if (cert.status.state === "future") notices.push(`${who} is not valid yet. Check the issuing system's clock.`);
    if (/sha1|md5/i.test(cert.signature)) notices.push(`${who} is signed with ${cert.signature}, which browsers no longer accept.`);
    if (cert.key.algorithm === "RSA" && cert.key.size && cert.key.size < 2048) notices.push(`${who} uses a ${cert.key.size}-bit RSA key; 2048 bits is the minimum accepted today.`);
    if (cert.selfSigned && (!cert.ca || selfSignedSite(cert))) notices.push(`${who} is self-signed: browsers will not trust it unless it is installed manually.`);
    if (!cert.ca && cert.notBefore && cert.notAfter) {
      const limit = maxPublicLifetimeDays(cert.notBefore);
      const duration = cert.notAfter - cert.notBefore;
      const days = Math.ceil(duration / 86400000);
      if (duration > limit * 86400000) {
        notices.push(`${who} is valid for ${days} days. Publicly trusted TLS certificates issued on ${cert.notBefore.toISOString().slice(0, 10)} may last at most ${limit} days (CA/Browser Forum), so this one can only come from a private CA.`);
      }
    }
    if (!cert.ca && !cert.san.length) notices.push(`${who} has no subject alternative names; modern browsers ignore the CN and will reject it for any hostname.`);
    return notices;
  }

  /** Certificates, chains, CSRs and public keys pasted as PEM (or a single DER as Base64). */
  const privateKeyResult = (label) => ({
    type: "Private key", confidence: 99, output: "",
    layers: [{ type: "Private key", detail: "Not decoded", value: { Format: label, Contents: "Not shown or analysed" }, claims: true }],
    notices: ["This is a private key. Decoder does not read it. It never left this tab, but if it was pasted anywhere else, treat it as compromised and replace it."],
  });

  function analyzePem(text, now = Date.now()) {
    const blocks = pemBlocks(text);
    // A private key with its END line missing must still stop here, never reach the Base64 decoder.
    const truncatedPrivate = !blocks.length && text.match(/-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----/);
    if (truncatedPrivate) return privateKeyResult(truncatedPrivate[1]);
    if (!blocks.length) return null;
    const layers = [];
    const notices = [];
    const certs = [];
    let type = null;
    for (const block of blocks) {
      if (/PRIVATE KEY/.test(block.label)) return privateKeyResult(block.label);
      if (!block.der) { notices.push(`The ${block.label} block is not valid Base64.`); continue; }
      try {
        if (block.label === "CERTIFICATE" || block.label === "TRUSTED CERTIFICATE") certs.push(parseCertificate(block.der, now));
        else if (block.label === "PUBLIC KEY") {
          const key = publicKeyInfo(parseDer(block.der));
          type = type || "Public key";
          layers.push({ type: "Public key", detail: key.algorithm, value: { Key: key.description, "SPKI pin (sha256)": key.pin }, claims: true });
        } else if (block.label === "CERTIFICATE REQUEST" || block.label === "NEW CERTIFICATE REQUEST") {
          const csr = parseDer(block.der);
          const info = csr.children[0];
          const subject = derName(info.children[1]);
          const key = publicKeyInfo(info.children[2]);
          const attrs = info.children.find((c) => c.tag === 0xa0);
          let san = [];
          for (const attr of (attrs && attrs.children) || []) {
            if (oid(attr.children[0]) === "1.2.840.113549.1.9.14") {
              const exts = extensions({ children: [attr.children[1].children[0]] });
              san = (exts["2.5.29.17"] && exts["2.5.29.17"].value) || [];
            }
          }
          type = type || "Certificate signing request";
          layers.push({ type: "Certificate signing request", detail: key.description, value: {
            Subject: nameText(subject) || "(empty)", "Requested domains": san.length ? san.join(", ") : "(none)",
            Key: key.description, Signature: oidName(oid(csr.children[1].children[0])),
          }, claims: true });
          if (key.algorithm === "RSA" && key.size && key.size < 2048) notices.push(`The request uses a ${key.size}-bit RSA key; CAs require at least 2048 bits.`);
        } else notices.push(`${block.label} blocks are not decoded yet.`);
      } catch (error) {
        notices.push(`The ${block.label} block could not be parsed: ${error.message}.`);
      }
    }
    certs.forEach((cert, i) => {
      layers.push(...certificateLayers(cert, i, certs.length, now));
      notices.push(...certificateNotices(cert, i, certs.length));
    });
    for (let i = 0; i + 1 < certs.length; i += 1) {
      if (nameText(certs[i].issuer) !== nameText(certs[i + 1].subject)) {
        notices.push(`Chain order: certificate ${i + 1} was not issued by certificate ${i + 2} (issuer and subject names differ). Servers must send the leaf first, then each issuer.`);
      }
    }
    if (certs.length) type = certs.length > 1 ? `Certificate chain (${certs.length})` : "X.509 certificate";
    if (!layers.length) return { type: "PEM block", confidence: 80, layers: [{ type: "PEM", detail: "Unreadable", value: text }], notices, output: text };
    const output = certs.length
      ? certs.map((c) => `${nameValue(c.subject, "CN") || nameText(c.subject)}: ${c.status.text}`).join("\n")
      : text;
    return { type, confidence: 99, layers, notices, output, certificates: certs };
  }

  function certificateFromDer(bytes, now = Date.now()) {
    if (bytes.length < 200 || bytes[0] !== 0x30 || bytes[1] !== 0x82) return null;
    try {
      const cert = parseCertificate(bytes, now);
      return {
        type: "X.509 certificate", confidence: 94,
        layers: certificateLayers(cert, 0, 1, now),
        notices: ["Decoded from Base64 DER (a certificate without PEM headers).", ...certificateNotices(cert, 0, 1)],
        output: `${nameValue(cert.subject, "CN") || nameText(cert.subject)}: ${cert.status.text}`,
        certificates: [cert],
      };
    } catch { return null; }
  }

  // ------------------------------------------------------------------ XML
  // Tolerant parser for display and SAML summaries. It never resolves
  // entities beyond the five predefined ones and ignores DOCTYPEs.

  function decodeEntities(text) {
    return text.replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9a-fA-F]+);/g, (_, e) => {
      if (e === "lt") return "<";
      if (e === "gt") return ">";
      if (e === "amp") return "&";
      if (e === "quot") return '"';
      if (e === "apos") return "'";
      const code = e[1] === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : "";
    });
  }

  function parseXml(text) {
    const rootNode = { name: "#document", children: [] };
    const stack = [rootNode];
    const re = /<!--[\s\S]*?-->|<!\[CDATA\[([\s\S]*?)\]\]>|<\?[\s\S]*?\?>|<!DOCTYPE[^>[]*(?:\[[\s\S]*?\])?\s*>|<\/\s*([^\s>]+)\s*>|<([^\s/>!?]+)((?:\s+[^\s=>/]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)/g;
    let m;
    let consumed = 0;
    while ((m = re.exec(text))) {
      if (m.index !== consumed) throw new Error("Unexpected markup");
      consumed = re.lastIndex;
      const top = stack[stack.length - 1];
      if (m[1] !== undefined) top.children.push({ text: m[1] });
      else if (m[2]) {
        if (stack.length < 2 || top.name !== m[2]) throw new Error(`Unexpected closing tag </${m[2]}>`);
        stack.pop();
      } else if (m[3]) {
        const attrs = {};
        const attrRe = /([^\s=]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
        let a;
        while ((a = attrRe.exec(m[4] || ""))) attrs[a[1]] = decodeEntities(a[2] !== undefined ? a[2] : a[3]);
        const node = { name: m[3], local: m[3].replace(/^.*:/, ""), attrs, children: [] };
        top.children.push(node);
        if (!m[5]) stack.push(node);
      } else if (m[6] !== undefined) {
        if (m[6].trim()) top.children.push({ text: decodeEntities(m[6]) });
      }
    }
    if (consumed !== text.length || stack.length !== 1) throw new Error("Unclosed element");
    const elements = rootNode.children.filter((c) => c.name);
    if (elements.length !== 1) throw new Error("XML must have one root element");
    return elements[0];
  }

  function escapeXml(text) {
    return String(text).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  }

  function prettyXml(node, depth = 0) {
    const indent = "  ".repeat(depth);
    const attrs = Object.entries(node.attrs).map(([k, v]) => ` ${k}="${escapeXml(v)}"`).join("");
    if (!node.children.length) return `${indent}<${node.name}${attrs}/>`;
    if (node.children.every((c) => c.text !== undefined)) {
      return `${indent}<${node.name}${attrs}>${escapeXml(node.children.map((c) => c.text).join("").trim())}</${node.name}>`;
    }
    const inner = node.children.map((c) => (c.text !== undefined ? `${indent}  ${escapeXml(c.text.trim())}` : prettyXml(c, depth + 1)));
    return `${indent}<${node.name}${attrs}>\n${inner.join("\n")}\n${indent}</${node.name}>`;
  }

  const textOf = (node) => (node ? node.children.map((c) => (c.text !== undefined ? c.text : textOf(c))).join("").trim() : "");
  const child = (node, local) => node && node.children.find((c) => c.local === local);
  function find(node, local, out = []) {
    for (const c of node.children || []) {
      if (c.local === local) out.push(c);
      if (c.children) find(c, local, out);
    }
    return out;
  }

  function samlTime(label, value, now, summary, notices, kind) {
    if (!value) return;
    summary[label] = value;
    const t = Date.parse(value);
    if (Number.isNaN(t)) return;
    if (kind === "notOnOrAfter" && now >= t) notices.push(`${label} (${value}) has passed: a service provider will reject this message now.`);
    if (kind === "notBefore" && now < t - 60000) notices.push(`${label} (${value}) is in the future: check clock skew between the IdP and SP.`);
  }

  function analyzeXml(text, now = Date.now(), how = null) {
    let root;
    try { root = parseXml(text.trim()); } catch { return null; }
    const layers = [];
    const notices = [];
    const saml = /^(AuthnRequest|Response|LogoutRequest|LogoutResponse|Assertion|ArtifactResolve|ArtifactResponse)$/.test(root.local)
      && /SAML|saml/.test(JSON.stringify(Object.values(root.attrs)) + root.name);
    if (how) layers.push({ type: "Transport", detail: how.steps.join(" → "), value: how.value, claims: true });
    if (saml) {
      const summary = { Message: `SAML ${root.local}` };
      const issuer = child(root, "Issuer") || find(root, "Issuer")[0];
      if (issuer) summary.Issuer = textOf(issuer);
      for (const attr of ["ID", "InResponseTo", "IssueInstant", "Destination", "AssertionConsumerServiceURL", "ProtocolBinding", "ForceAuthn", "IsPassive"]) {
        if (root.attrs[attr]) summary[attr] = root.attrs[attr];
      }
      const status = find(root, "StatusCode")[0];
      if (status) {
        summary.Status = (status.attrs.Value || "").replace(/^.*:status:/, "");
        const nested = find(status, "StatusCode")[0];
        if (nested) summary.Status += ` / ${(nested.attrs.Value || "").replace(/^.*:status:/, "")}`;
        const message = find(root, "StatusMessage")[0];
        if (message) summary["Status message"] = textOf(message);
        if (!/Success/.test(summary.Status)) notices.push(`The IdP answered with status ${summary.Status}: the login did not succeed.`);
      }
      const policy = find(root, "NameIDPolicy")[0];
      if (policy && policy.attrs.Format) summary["Requested NameID format"] = policy.attrs.Format.replace(/^.*:nameid-format:/, "");
      const ctxRef = find(root, "AuthnContextClassRef")[0];
      if (ctxRef) summary["Authentication context"] = textOf(ctxRef).replace(/^.*:ac:classes:/, "");
      layers.push({ type: `SAML ${root.local}`, detail: summary.Status || "Summary", value: summary, claims: true });

      const assertions = root.local === "Assertion" ? [root] : find(root, "Assertion");
      assertions.forEach((assertion, index) => {
        const a = {};
        const aIssuer = child(assertion, "Issuer");
        if (aIssuer) a.Issuer = textOf(aIssuer);
        const nameId = find(assertion, "NameID")[0];
        if (nameId) {
          a.NameID = textOf(nameId);
          if (nameId.attrs.Format) a["NameID format"] = nameId.attrs.Format.replace(/^.*:nameid-format:/, "");
        }
        const conditions = find(assertion, "Conditions")[0];
        if (conditions) {
          samlTime("Not before", conditions.attrs.NotBefore, now, a, notices, "notBefore");
          samlTime("Not on or after", conditions.attrs.NotOnOrAfter, now, a, notices, "notOnOrAfter");
          const audiences = find(conditions, "Audience").map(textOf);
          if (audiences.length) a.Audience = audiences.join(", ");
        }
        const confirmation = find(assertion, "SubjectConfirmationData")[0];
        if (confirmation) {
          if (confirmation.attrs.Recipient) a.Recipient = confirmation.attrs.Recipient;
          samlTime("Subject valid until", confirmation.attrs.NotOnOrAfter, now, a, notices, "notOnOrAfter");
        }
        const authn = find(assertion, "AuthnStatement")[0];
        if (authn) {
          if (authn.attrs.AuthnInstant) a["Authenticated at"] = authn.attrs.AuthnInstant;
          if (authn.attrs.SessionIndex) a["Session index"] = authn.attrs.SessionIndex;
        }
        a.Signed = child(assertion, "Signature") ? "Yes (not verified here)" : "No";
        layers.push({ type: assertions.length > 1 ? `Assertion ${index + 1}` : "Assertion", detail: a.NameID ? "Subject" : "Details", value: a, claims: true });
        const attributes = {};
        for (const attribute of find(assertion, "Attribute")) {
          const key = attribute.attrs.FriendlyName || attribute.attrs.Name || "(unnamed)";
          attributes[key] = find(attribute, "AttributeValue").map(textOf).join(", ");
        }
        if (Object.keys(attributes).length) layers.push({ type: "Attributes", detail: `${Object.keys(attributes).length} values`, value: attributes, claims: true });
      });
      if (find(root, "EncryptedAssertion").length) notices.push("The assertion is encrypted. Only the service provider's private key can open it, so its contents are not shown.");
      const signedResponse = !!child(root, "Signature");
      const signedAssertion = assertions.some((a) => child(a, "Signature"));
      if (root.local === "Response" && !signedResponse && !signedAssertion && !find(root, "EncryptedAssertion").length) {
        notices.push("Neither the response nor the assertion carries a signature. A service provider must reject an unsigned response.");
      }
      notices.push("Signatures are not verified here. Decoded does not mean trusted.");
      layers.push({ type: "XML", detail: "Formatted", value: prettyXml(root) });
      return { type: `SAML ${root.local}`, confidence: 98, layers, notices, output: prettyXml(root) };
    }
    layers.push({ type: "XML", detail: `<${root.name}>`, value: prettyXml(root) });
    return { type: "XML", confidence: 90, layers, notices, output: prettyXml(root) };
  }

  /** SAMLRequest/SAMLResponse values: URL-encoded, Base64, optionally deflated. */
  function unwrapSamlValue(value) {
    const steps = [];
    let current = value.trim();
    if (/%[0-9A-Fa-f]{2}/.test(current)) {
      try { current = decodeURIComponent(current.replace(/\+/g, "%20")); steps.push("URL decoded"); } catch { /* keep */ }
    }
    let bytes;
    try { bytes = base64ToBytes(current); } catch { return null; }
    steps.push("Base64");
    let text = null;
    try { text = utf8(bytes, true); } catch { text = null; }
    if (!text || !text.trim().startsWith("<")) {
      const inflated = decompress(bytes);
      if (!inflated) return null;
      steps.push(`${inflated.format} inflated`);
      try { text = utf8(inflated.bytes, true); } catch { return null; }
    }
    return text.trim().startsWith("<") ? { text, steps } : null;
  }

  function analyzeSamlUrl(raw, now = Date.now()) {
    let url;
    try { url = new URL(raw); } catch { return null; }
    const name = ["SAMLRequest", "SAMLResponse"].find((n) => url.searchParams.has(n));
    if (!name) return null;
    const unwrapped = unwrapSamlValue(encodeURIComponent(url.searchParams.get(name)));
    if (!unwrapped) return null;
    const result = analyzeXml(unwrapped.text, now, {
      steps: ["Query parameter", ...unwrapped.steps],
      value: { Endpoint: `${url.origin}${url.pathname}`, Parameter: name, RelayState: url.searchParams.get("RelayState") || "(none)", "Signature algorithm": url.searchParams.get("SigAlg") || "(unsigned redirect)" },
    });
    return result;
  }

  // ------------------------------------------------------------------ IDs

  const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

  function plausible(ms, now) {
    return ms > Date.UTC(1990, 0, 1) && ms < now + 366 * 86400000;
  }

  function analyzeId(raw, now = Date.now()) {
    const value = raw.trim();
    const uuidMatch = value.match(/^(?:urn:uuid:|\{)?([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\}?$/i);
    if (uuidMatch) {
      const h = uuidMatch.slice(1).join("").toLowerCase();
      if (/^0+$/.test(h)) return idResult("UUID", { Kind: "Nil UUID", Value: "All bits zero" }, []);
      if (/^f+$/.test(h)) return idResult("UUID", { Kind: "Max UUID", Value: "All bits one" }, []);
      const version = parseInt(h[12], 16);
      const variantNibble = parseInt(h[16], 16);
      const variant = variantNibble < 8 ? "NCS (reserved)" : variantNibble < 12 ? "RFC 9562" : variantNibble < 14 ? "Microsoft GUID" : "Reserved";
      const names = { 1: "time-based (MAC)", 2: "DCE security", 3: "name-based (MD5)", 4: "random", 5: "name-based (SHA-1)", 6: "time-ordered", 7: "Unix time-ordered", 8: "custom" };
      const info = { Version: `v${version} · ${names[version] || "unknown"}`, Variant: variant, Canonical: `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}` };
      const notices = [];
      if (variant === "RFC 9562") {
        if (version === 1 || version === 6) {
          const ticks = version === 1
            ? (BigInt(`0x${h.slice(13, 16)}`) << 48n) | (BigInt(`0x${h.slice(8, 12)}`) << 32n) | BigInt(`0x${h.slice(0, 8)}`)
            : (BigInt(`0x${h.slice(0, 8)}`) << 28n) | (BigInt(`0x${h.slice(8, 12)}`) << 12n) | BigInt(`0x${h.slice(13, 16)}`);
          const ms = Number(ticks / 10000n) - 12219292800000;
          info.Created = new Date(ms).toISOString();
          info["Clock sequence"] = String(parseInt(h.slice(16, 20), 16) & 0x3fff);
          const node = h.slice(20).match(/.{2}/g).join(":");
          const random = parseInt(h.slice(20, 22), 16) & 1;
          info.Node = random ? `${node} (random, not a MAC)` : `${node} (MAC address)`;
          if (!random && version === 1) notices.push("Version 1 UUIDs embed the generating machine's network card address and creation time. Do not use them where either should stay private.");
        } else if (version === 7) {
          const ms = parseInt(h.slice(0, 12), 16);
          info.Created = new Date(ms).toISOString();
          info.Random = `${h.slice(13, 16)}${h.slice(17)}`;
        } else if (version === 4) {
          info.Random = "122 random bits: no time or machine information inside";
        } else if (version === 3 || version === 5) {
          info.Note = "A hash of a namespace and a name: the same inputs always give this UUID, and the inputs cannot be recovered";
        }
      }
      return idResult("UUID", info, notices, info.Created);
    }

    if (/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/i.test(value)) {
      let ms = 0;
      for (const char of value.slice(0, 10).toUpperCase()) ms = ms * 32 + CROCKFORD.indexOf(char);
      if (plausible(ms, now)) {
        return idResult("ULID", { Created: new Date(ms).toISOString(), Timestamp: `${ms} ms`, Random: value.slice(10).toUpperCase() },
          ["ULIDs sort by creation time: the first 10 characters are the millisecond timestamp."], new Date(ms).toISOString());
      }
    }

    if (/^[0-9a-f]{24}$/i.test(value)) {
      const seconds = parseInt(value.slice(0, 8), 16);
      if (plausible(seconds * 1000, now) && seconds * 1000 > Date.UTC(2009, 0, 1)) {
        return idResult("MongoDB ObjectId", {
          Created: new Date(seconds * 1000).toISOString(),
          "Random / machine": value.slice(8, 18).toLowerCase(),
          Counter: String(parseInt(value.slice(18), 16)),
        }, [], new Date(seconds * 1000).toISOString());
      }
    }

    // 16 digits is read as a microsecond timestamp instead.
    if (/^\d{15,20}$/.test(value) && value.length !== 16 && BigInt(value) < 2n ** 63n) {
      const id = BigInt(value);
      const epochs = [["Twitter / X", 1288834974657], ["Discord", 1420070400000], ["Instagram", 1314220021721]];
      const readings = {};
      for (const [service, epoch] of epochs) {
        const ms = Number(id >> 22n) + epoch;
        if (plausible(ms, now) && ms > epoch) readings[`If ${service}`] = new Date(ms).toISOString();
      }
      if (value.length === 19) {
        const nsMs = Number(id / 1000000n);
        if (plausible(nsMs, now) && nsMs > Date.UTC(2000, 0, 1)) readings["If a nanosecond timestamp"] = new Date(nsMs).toISOString();
      }
      if (Object.keys(readings).length) {
        readings.Sequence = String(Number(id & 0xfffn));
        readings["Worker / shard"] = String(Number((id >> 12n) & 0x3ffn));
        return idResult("Snowflake ID", readings,
          ["Snowflake IDs carry their creation time, but the number alone does not say which service issued it. Each reading assumes that service's epoch."]);
      }
    }
    return null;
  }

  function idResult(kind, info, notices, created) {
    return {
      type: kind, confidence: 93, notices,
      layers: [{ type: kind, detail: created ? "Timestamp inside" : "Structure", value: info, claims: true }],
      output: created || info.Canonical || JSON.stringify(info),
    };
  }

  // ------------------------------------------------------ email headers

  function unfoldHeaders(text) {
    const lines = text.replace(/\r\n/g, "\n").split("\n");
    const headers = [];
    for (const line of lines) {
      if (!line.trim()) { if (headers.length) break; else continue; }
      if (/^[ \t]/.test(line) && headers.length) headers[headers.length - 1][1] += ` ${line.trim()}`;
      else {
        const sep = line.indexOf(":");
        if (sep < 1 || /\s/.test(line.slice(0, sep))) return null;
        headers.push([line.slice(0, sep).trim(), line.slice(sep + 1).trim()]);
      }
    }
    return headers;
  }

  function decodeWords(value) {
    return value.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=(\s+(?==\?))?/g, (_, charset, enc, data) => {
      try {
        const bytes = /b/i.test(enc)
          ? base64ToBytes(data)
          : Uint8Array.from(data.replace(/_/g, " ").replace(/=([0-9A-F]{2})/gi, (__, h) => String.fromCharCode(parseInt(h, 16))), (c) => c.charCodeAt(0));
        return new TextDecoder(charset.toLowerCase()).decode(bytes);
      } catch { return data; }
    });
  }

  const addrDomain = (value) => ((value || "").match(/@([A-Za-z0-9.-]+)/) || [])[1]?.toLowerCase() || null;
  // Registrable domain without a Public Suffix List: keep one more label under
  // two-letter country codes with a generic second level (co.uk, com.au, gov.br, ac.jp).
  const orgDomain = (domain) => {
    if (!domain) return null;
    const labels = domain.split(".");
    const keep = labels.length > 2 && labels[labels.length - 1].length === 2
      && /^(co|com|net|org|gov|edu|ac|or|ne|go|ltd|plc)$/.test(labels[labels.length - 2]) ? 3 : 2;
    return labels.slice(-keep).join(".");
  };

  function privateIp(ip) {
    return /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|f[cd][0-9a-f]{2}:|fe80:)/i.test(ip);
  }

  function isEmailHeaders(text) {
    const headers = unfoldHeaders(text);
    if (!headers || headers.length < 3) return null;
    const names = headers.map(([n]) => n.toLowerCase());
    const mailish = names.filter((n) => /^(received|return-path|delivered-to|dkim-signature|authentication-results|arc-.*|received-spf|message-id|x-mailer|mime-version|x-originating-ip)$/.test(n)).length;
    return mailish >= 2 && (names.includes("received") || names.includes("authentication-results")) ? headers : null;
  }

  function analyzeEmail(text) {
    const headers = isEmailHeaders(text);
    if (!headers) return null;
    const get = (name) => (headers.find(([n]) => n.toLowerCase() === name) || [])[1];
    const all = (name) => headers.filter(([n]) => n.toLowerCase() === name).map(([, v]) => v);
    const notices = [];
    const layers = [];

    const summary = {};
    for (const [label, name] of [["From", "from"], ["To", "to"], ["Subject", "subject"], ["Date", "date"], ["Reply-To", "reply-to"], ["Return-Path", "return-path"], ["Message-ID", "message-id"]]) {
      const value = get(name);
      if (value) summary[label] = decodeWords(value);
    }

    const auth = {};
    const results = all("authentication-results");
    if (results.length) {
      const top = results[0];
      for (const method of ["spf", "dkim", "dmarc", "arc"]) {
        const m = top.match(new RegExp(`\\b${method}=([a-z]+)([^;]*)`, "i"));
        if (m) {
          const detail = (m[2].match(/header\.(?:d|i|from)=([^\s;]+)|smtp\.mailfrom=([^\s;]+)/i) || []).slice(1).find(Boolean);
          auth[method.toUpperCase()] = m[1].toLowerCase() + (detail ? ` (${detail})` : "");
        }
      }
      auth["Checked by"] = top.split(";")[0].trim();
    } else {
      const spf = get("received-spf");
      if (spf) auth.SPF = spf.split(/\s/)[0].toLowerCase();
    }
    const dkim = all("dkim-signature");
    dkim.forEach((sig, i) => {
      const tag = (t) => (sig.match(new RegExp(`(?:^|;)\\s*${t}=([^;]+)`)) || [])[1]?.trim();
      auth[dkim.length > 1 ? `DKIM signature ${i + 1}` : "DKIM signature"] = `d=${tag("d") || "?"} s=${tag("s") || "?"} a=${tag("a") || "?"}`;
    });
    for (const method of ["SPF", "DKIM", "DMARC"]) {
      const value = auth[method];
      if (!value) continue;
      if (/^(fail|permerror|hardfail)/.test(value)) notices.push(`${method} failed. The message may be forged or was sent through a server the domain did not authorise.`);
      else if (/^softfail/.test(value)) notices.push(`${method} soft-failed: the sending server is not clearly authorised by the domain.`);
      else if (/^(none|neutral)/.test(value)) notices.push(`${method} result is ${value.split(" ")[0]}: the domain publishes no usable policy for this check.`);
    }
    if (!auth.DMARC && results.length) notices.push("No DMARC result was recorded, so nothing tied the visible From address to an authenticated domain.");

    const fromDomain = addrDomain(summary.From);
    const returnDomain = addrDomain(summary["Return-Path"]);
    const replyDomain = addrDomain(summary["Reply-To"]);
    if (fromDomain && returnDomain && orgDomain(fromDomain) !== orgDomain(returnDomain)) {
      notices.push(`The bounce address (Return-Path) is at ${returnDomain} while From shows ${fromDomain}. Normal for mailing services, but also a common sign of spoofing.`);
    }
    if (fromDomain && replyDomain && orgDomain(fromDomain) !== orgDomain(replyDomain)) {
      notices.push(`Replies go to ${replyDomain}, not to the sender's domain ${fromDomain}. Be careful if the message asks for money or credentials.`);
    }

    const hops = all("received").map((value) => {
      const [route, date] = [value.slice(0, value.lastIndexOf(";")), value.slice(value.lastIndexOf(";") + 1).trim()];
      const from = (route.match(/\bfrom\s+(\S+)/i) || [])[1];
      const by = (route.match(/\bby\s+(\S+)/i) || [])[1];
      const withProto = (route.match(/\bwith\s+(\S+)/i) || [])[1];
      const ip = (route.match(/\[(?:IPv6:)?([0-9a-fA-F:.]{3,})\]/) || [])[1];
      const time = Date.parse(date.replace(/\s*\([^)]*\)\s*$/, ""));
      return { from, by, with: withProto, ip, time: Number.isNaN(time) ? null : time };
    }).reverse();

    if (hops.length) {
      const route = {};
      hops.forEach((hop, i) => {
        const previous = i > 0 ? hops[i - 1].time : null;
        const delay = hop.time && previous ? Math.round((hop.time - previous) / 1000) : null;
        const label = `${i + 1}. ${hop.by || "?"}`;
        route[label] = [
          hop.from ? `from ${hop.from}${hop.ip ? ` [${hop.ip}]` : ""}` : "(local submission)",
          hop.with ? `via ${hop.with}` : null,
          hop.time ? new Date(hop.time).toISOString() : null,
          delay !== null ? `${delay < 0 ? "clock skew " : "+"}${Math.abs(delay)}s` : null,
        ].filter(Boolean).join(" · ");
        if (delay !== null && delay > 600) notices.push(`Hop ${i + 1} (${hop.by || "unknown server"}) held the message for ${Math.round(delay / 60)} minutes.`);
      });
      const times = hops.map((h) => h.time).filter(Boolean);
      if (times.length > 1) summary["Transit time"] = `${Math.round((Math.max(...times) - Math.min(...times)) / 1000)} s over ${hops.length} hops`;
      const origin = hops.find((h) => h.ip && !privateIp(h.ip));
      if (origin) summary["Originating IP"] = `${origin.ip}${origin.from ? ` (${origin.from})` : ""}`;
      layers.push({ type: "Summary", detail: summary.Subject ? "Message" : "Headers", value: summary, claims: true });
      if (Object.keys(auth).length) layers.push({ type: "Authentication", detail: [auth.SPF, auth.DKIM, auth.DMARC].filter(Boolean).map((v) => v.split(" ")[0]).join(" / ") || "Signatures", value: auth, claims: true });
      layers.push({ type: "Delivery route", detail: `${hops.length} hops, oldest first`, value: route, claims: true });
    } else {
      layers.push({ type: "Summary", detail: "Headers", value: summary, claims: true });
      if (Object.keys(auth).length) layers.push({ type: "Authentication", detail: "Results", value: auth, claims: true });
    }
    if (/\n\s*\n\s*\S/.test(text.trim())) notices.push("Only the header block was analysed; the message body was ignored.");
    return { type: "Email headers", confidence: 97, layers, notices, output: [summary.From, summary.Subject, auth.DMARC && `DMARC ${auth.DMARC}`].filter(Boolean).join(" · ") };
  }

  // -------------------------------------------------- response headers

  const RESPONSE_ONLY = /^(set-cookie|strict-transport-security|content-security-policy|content-security-policy-report-only|x-frame-options|server|x-powered-by|x-content-type-options|referrer-policy|permissions-policy|access-control-allow-origin|cross-origin-opener-policy|cross-origin-embedder-policy|cross-origin-resource-policy|x-xss-protection|expect-ct|public-key-pins|location|etag|last-modified|age|vary)$/i;

  function parseResponse(text) {
    const lines = text.replace(/\r\n/g, "\n").split("\n");
    // `curl -I -L` prints every response in a redirect chain: keep the last one.
    let startLine = -1;
    lines.forEach((line, i) => { if (/^HTTP\/[\d.]+\s+\d{3}/i.test(line.trim())) startLine = i; });
    const status = startLine >= 0 ? lines[startLine].trim() : null;
    const headers = [];
    for (const line of lines.slice(startLine + 1)) {
      if (!line.trim()) { if (headers.length) break; else continue; }
      if (/^[ \t]/.test(line) && headers.length) { headers[headers.length - 1][1] += ` ${line.trim()}`; continue; }
      const sep = line.indexOf(":");
      if (sep < 1 || /\s/.test(line.slice(0, sep))) return null;
      headers.push([line.slice(0, sep).trim(), line.slice(sep + 1).trim()]);
    }
    if (!headers.length) return null;
    if (!status && !headers.some(([n]) => RESPONSE_ONLY.test(n))) return null;
    return { status, headers };
  }

  function cspDirectives(value) {
    const out = {};
    for (const part of value.split(";")) {
      const [name, ...sources] = part.trim().split(/\s+/);
      if (name) out[name.toLowerCase()] = sources;
    }
    return out;
  }

  function gradeHeaders(headers) {
    const get = (name) => (headers.find(([n]) => n.toLowerCase() === name) || [])[1];
    const all = (name) => headers.filter(([n]) => n.toLowerCase() === name).map(([, v]) => v);
    const findings = [];
    const add = (level, header, text) => findings.push({ level, header, text });

    const hsts = get("strict-transport-security");
    if (!hsts) add("fail", "Strict-Transport-Security", "Missing. Browsers may still reach the site over plain HTTP.");
    else {
      const age = Number((hsts.match(/max-age=(\d+)/i) || [])[1] || 0);
      if (age < 15552000) add("warn", "Strict-Transport-Security", `max-age is ${age} s; use at least 15552000 (180 days).`);
      else add("pass", "Strict-Transport-Security", `max-age ${Math.round(age / 86400)} days${/includesubdomains/i.test(hsts) ? ", includes subdomains" : ""}${/preload/i.test(hsts) ? ", preload" : ""}.`);
    }

    const csp = get("content-security-policy");
    const cspReport = get("content-security-policy-report-only");
    const directives = csp ? cspDirectives(csp) : {};
    if (!csp) add(cspReport ? "warn" : "fail", "Content-Security-Policy", cspReport ? "Only a report-only policy is set: it records violations but blocks nothing." : "Missing. Any injected script can run.");
    else {
      const scripts = directives["script-src"] || directives["default-src"] || [];
      const problems = [];
      const nonce = scripts.some((s) => /^'(nonce|sha(256|384|512))-/.test(s));
      if (scripts.includes("'unsafe-inline'") && !nonce) problems.push("allows inline scripts ('unsafe-inline')");
      if (scripts.includes("'unsafe-eval'")) problems.push("allows eval ('unsafe-eval')");
      if (scripts.some((s) => s === "*" || s === "https:" || s === "http:" || s === "data:")) problems.push(`allows scripts from ${scripts.filter((s) => ["*", "https:", "http:", "data:"].includes(s)).join(" ")}`);
      if (!directives["script-src"] && !directives["default-src"]) problems.push("has no script-src or default-src, so scripts are unrestricted");
      if (problems.length) add("warn", "Content-Security-Policy", `Present, but it ${problems.join("; ")}.`);
      else add("pass", "Content-Security-Policy", "Restricts where scripts may load from.");
      if (!directives["object-src"] && !(directives["default-src"] || []).includes("'none'")) add("info", "Content-Security-Policy", "Consider object-src 'none' to block plugin content.");
    }

    if ((get("x-content-type-options") || "").toLowerCase() === "nosniff") add("pass", "X-Content-Type-Options", "nosniff.");
    else add("fail", "X-Content-Type-Options", "Missing nosniff: browsers may guess content types and execute uploads as scripts.");

    const xfo = (get("x-frame-options") || "").toUpperCase();
    const ancestors = directives["frame-ancestors"];
    if (ancestors && ancestors.some((s) => s === "*" || s === "https:" || s === "http:")) add("fail", "Framing", `CSP frame-ancestors ${ancestors.join(" ")} lets any site embed this page (clickjacking).`);
    else if (ancestors) add("pass", "Framing", `CSP frame-ancestors ${ancestors.join(" ")}.`);
    else if (xfo === "DENY" || xfo === "SAMEORIGIN") add("pass", "Framing", `X-Frame-Options ${xfo}.`);
    else if (xfo.startsWith("ALLOW-FROM")) add("warn", "Framing", "X-Frame-Options ALLOW-FROM is ignored by modern browsers; use CSP frame-ancestors.");
    else add("fail", "Framing", "No X-Frame-Options or frame-ancestors: other sites can embed this page (clickjacking).");

    const referrer = (get("referrer-policy") || "").toLowerCase();
    if (!referrer) add("info", "Referrer-Policy", "Not set; browsers default to strict-origin-when-cross-origin.");
    else if (/unsafe-url/.test(referrer)) add("fail", "Referrer-Policy", "unsafe-url sends full URLs, including query strings, to every other site.");
    else if (/no-referrer-when-downgrade/.test(referrer)) add("warn", "Referrer-Policy", "no-referrer-when-downgrade leaks full URLs to other HTTPS sites.");
    else add("pass", "Referrer-Policy", referrer + ".");

    if (get("permissions-policy")) add("pass", "Permissions-Policy", "Set.");
    else add("info", "Permissions-Policy", "Not set; consider disabling camera, microphone and geolocation if unused.");
    if (get("cross-origin-opener-policy")) add("pass", "Cross-Origin-Opener-Policy", get("cross-origin-opener-policy") + ".");
    else add("info", "Cross-Origin-Opener-Policy", "Not set; same-origin isolates the page from windows it opens.");

    const server = get("server");
    if (server && /\d/.test(server)) add("warn", "Server", `Reveals a version (${server}). Hide it so scanners cannot match known vulnerabilities.`);
    for (const leak of ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]) {
      if (get(leak)) add("warn", headers.find(([n]) => n.toLowerCase() === leak)[0], `Reveals the stack (${get(leak)}).`);
    }
    const xss = get("x-xss-protection");
    if (xss && !/^0/.test(xss.trim())) add("info", "X-XSS-Protection", "Deprecated; set it to 0 or remove it and rely on CSP.");
    if (get("public-key-pins")) add("warn", "Public-Key-Pins", "HPKP is obsolete and can lock visitors out; remove it.");
    if (get("expect-ct")) add("info", "Expect-CT", "Obsolete; it can be removed.");

    const acao = get("access-control-allow-origin");
    if (acao === "*" && /true/i.test(get("access-control-allow-credentials") || "")) add("fail", "CORS", "Access-Control-Allow-Origin * with credentials is invalid and signals a misconfigured CORS policy.");
    else if (acao === "*") add("info", "CORS", "Any site may read these responses (Access-Control-Allow-Origin *). Fine for public data only.");

    const cookies = all("set-cookie").map((value) => {
      const [pair, ...attrs] = value.split(";").map((s) => s.trim());
      const name = pair.split("=")[0];
      const flags = attrs.map((a) => a.split("=")[0].toLowerCase());
      const sameSite = (attrs.find((a) => /^samesite=/i.test(a)) || "").split("=")[1];
      const missing = [];
      if (!flags.includes("secure")) missing.push("Secure");
      if (!flags.includes("httponly")) missing.push("HttpOnly");
      if (!sameSite) missing.push("SameSite");
      let level = missing.includes("Secure") ? "warn" : missing.length ? "info" : "pass";
      let text = missing.length ? `Missing ${missing.join(", ")}.` : `Secure, HttpOnly, SameSite=${sameSite}.`;
      if (sameSite && sameSite.toLowerCase() === "none" && !flags.includes("secure")) { level = "fail"; text = "SameSite=None without Secure: browsers reject this cookie."; }
      if (name.startsWith("__Host-") && (!flags.includes("secure") || /domain=/i.test(value) || !/path=\/(;|$)/i.test(value))) { level = "fail"; text = "__Host- cookies need Secure, Path=/ and no Domain."; }
      add(level, `Cookie ${name}`, text);
      return { name, level };
    });

    const weights = { fail: 20, warn: 8, info: 0, pass: 0 };
    const score = Math.max(0, 100 - findings.reduce((sum, f) => sum + weights[f.level], 0));
    const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
    return { findings, score, grade, cookies };
  }

  const MARK = { pass: "✓", info: "i", warn: "!", fail: "✗" };

  function analyzeResponse(text) {
    const response = parseResponse(text);
    if (!response) return null;
    const { findings, score, grade } = gradeHeaders(response.headers);
    const counts = { pass: 0, info: 0, warn: 0, fail: 0 };
    findings.forEach((f) => { counts[f.level] += 1; });
    const table = {};
    for (const f of findings) {
      let key = `${MARK[f.level]} ${f.header}`;
      while (table[key] !== undefined) key += " ";
      table[key] = f.text;
    }
    const headerMap = {};
    for (const [name, value] of response.headers) headerMap[name] = headerMap[name] === undefined ? value : `${headerMap[name]}\n${value}`;
    const layers = [
      { type: "Security headers", detail: `Grade ${grade}`, value: { Grade: `${grade} (${score}/100)`, Status: response.status || "(status line not pasted)", Passed: String(counts.pass), Warnings: String(counts.warn), Failures: String(counts.fail), Suggestions: String(counts.info) }, claims: true },
      { type: "Findings", detail: "✓ pass · ! warning · ✗ failure · i suggestion", value: table, claims: true },
      { type: "Response headers", detail: `${response.headers.length} fields`, value: headerMap, claims: true },
    ];
    const notices = counts.fail ? [`${counts.fail} security header problem${counts.fail === 1 ? "" : "s"} found. Each finding says what to change.`] : [];
    notices.push("Graded from the pasted headers only; decoder.in never contacts the site.");
    return { type: "HTTP response headers", confidence: 96, layers, notices, output: findings.map((f) => `${MARK[f.level]} ${f.header}: ${f.text}`).join("\n"), grade };
  }

  // ------------------------------------------------------ JWT verification

  const JWT_ALGS = {
    HS256: { name: "HMAC", hash: "SHA-256" }, HS384: { name: "HMAC", hash: "SHA-384" }, HS512: { name: "HMAC", hash: "SHA-512" },
    RS256: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, RS384: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, RS512: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
    PS256: { name: "RSA-PSS", hash: "SHA-256", saltLength: 32 }, PS384: { name: "RSA-PSS", hash: "SHA-384", saltLength: 48 }, PS512: { name: "RSA-PSS", hash: "SHA-512", saltLength: 64 },
    ES256: { name: "ECDSA", hash: "SHA-256", namedCurve: "P-256" }, ES384: { name: "ECDSA", hash: "SHA-384", namedCurve: "P-384" }, ES512: { name: "ECDSA", hash: "SHA-512", namedCurve: "P-521" },
    EdDSA: { name: "Ed25519" }, Ed25519: { name: "Ed25519" },
  };

  function subtle() {
    const c = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
    if (!c || !c.subtle) throw new Error("This browser does not offer Web Crypto, so signatures cannot be checked here.");
    return c.subtle;
  }

  async function importVerifyKey(alg, spec, keyText, header) {
    const text = keyText.trim();
    const importParams = spec.name === "HMAC" ? { name: "HMAC", hash: spec.hash }
      : spec.name === "ECDSA" ? { name: "ECDSA", namedCurve: spec.namedCurve }
        : spec.name === "Ed25519" ? { name: "Ed25519" } : { name: spec.name, hash: spec.hash };
    if (/PRIVATE KEY-----/.test(text)) throw new Error("That is a private key. Paste the public key or certificate instead, and replace the private key if it was shared.");
    if (text.startsWith("{")) {
      let jwk = JSON.parse(text);
      if (Array.isArray(jwk.keys)) {
        const match = header.kid ? jwk.keys.find((k) => k.kid === header.kid) : jwk.keys.length === 1 ? jwk.keys[0] : null;
        if (!match) throw new Error(header.kid ? `No key with kid "${header.kid}" in this JWKS.` : "The JWKS holds several keys and the token has no kid.");
        jwk = match;
      }
      if (jwk.d) throw new Error("This JWK contains a private key (d). Paste the public key only.");
      const kty = { HMAC: "oct", ECDSA: "EC", Ed25519: "OKP" }[spec.name] || "RSA";
      if (jwk.kty !== kty) throw new Error(`The token uses ${alg} but this is a ${jwk.kty} key. A mismatch like this is how algorithm-confusion attacks work.`);
      const clean = { ...jwk };
      delete clean.alg; delete clean.use; delete clean.key_ops;
      return { key: await subtle().importKey("jwk", clean, importParams, false, ["verify"]), kind: `JWK${jwk.kid ? ` (kid ${jwk.kid})` : ""}` };
    }
    if (/-----BEGIN (CERTIFICATE|PUBLIC KEY)-----/.test(text)) {
      if (spec.name === "HMAC") throw new Error(`The token uses ${alg}, which needs a shared secret, but a public key was given. Accepting it would allow algorithm-confusion attacks.`);
      const block = pemBlocks(text)[0];
      const spki = block.label === "CERTIFICATE" ? parseCertificate(block.der).spkiDer : block.der;
      return { key: await subtle().importKey("spki", spki, importParams, false, ["verify"]), kind: block.label === "CERTIFICATE" ? "certificate public key" : "PEM public key" };
    }
    if (spec.name !== "HMAC") throw new Error(`${alg} needs a public key: paste a PEM public key, a certificate, a JWK or a JWKS.`);
    return { key: await subtle().importKey("raw", new TextEncoder().encode(keyText), importParams, false, ["verify"]), kind: "shared secret" };
  }

  /** Verify a JWT signature locally. Resolves to { ok, alg, kind, message }. */
  async function verifyJwt(token, keyText) {
    const parts = String(token).trim().split(".");
    if (parts.length !== 3) return { ok: false, message: "Not a JWT." };
    let header;
    try { header = JSON.parse(utf8(base64ToBytes(parts[0]))); } catch { return { ok: false, message: "The token header is not readable." }; }
    const alg = header.alg;
    if (!alg || String(alg).toLowerCase() === "none") return { ok: false, alg, message: "The token declares alg: none. There is no signature to verify, and it must never be accepted." };
    const spec = JWT_ALGS[alg];
    if (!spec) return { ok: false, alg, message: `Algorithm ${alg} is not supported here.` };
    if (!keyText || !keyText.trim()) return { ok: false, alg, message: "Paste a key to check the signature." };
    try {
      const { key, kind } = await importVerifyKey(alg, spec, keyText, header);
      const signature = base64ToBytes(parts[2]);
      const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
      const params = spec.name === "RSA-PSS" ? { name: "RSA-PSS", saltLength: spec.saltLength }
        : spec.name === "ECDSA" ? { name: "ECDSA", hash: spec.hash } : { name: spec.name };
      let ok = await subtle().verify(params, key, signature, data);
      let usedKind = kind;
      if (!ok && kind === "shared secret" && /^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(keyText.trim())) {
        // Many services hand out Base64-encoded secrets; try the decoded bytes as well.
        let decodedBytes = null;
        try { decodedBytes = base64ToBytes(keyText.trim()); } catch { /* looked like Base64 but is not: keep the mismatch */ }
        if (decodedBytes && decodedBytes.length) {
          const decodedKey = await subtle().importKey("raw", decodedBytes, { name: "HMAC", hash: spec.hash }, false, ["verify"]);
          if (await subtle().verify(params, decodedKey, signature, data)) { ok = true; usedKind = "Base64-decoded shared secret"; }
        }
      }
      return ok
        ? { ok: true, alg, kind: usedKind, message: `Signature valid: ${alg} with the ${usedKind}.` }
        : { ok: false, alg, kind, message: `Signature does NOT match this ${kind}. The token was altered or signed with a different key.` };
    } catch (error) {
      return { ok: false, alg, message: error.message || "The key could not be used." };
    }
  }

  return {
    base64ToBytes, bytesToBase64, hex, sha1, sha256, inflateRaw, decompress, readable, utf8,
    parseDer, parseCertificate, analyzePem, certificateFromDer, parseXml, prettyXml, analyzeXml,
    analyzeSamlUrl, unwrapSamlValue, analyzeId, analyzeEmail, analyzeResponse, gradeHeaders, verifyJwt,
  };
});
