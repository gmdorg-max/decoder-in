(function (root, factory) {
  const tools = typeof module === "object" && typeof require === "function" ? require("./tools.js") : root.DecoderTools;
  const api = factory(tools);
  if (typeof module === "object" && module.exports) module.exports = api;
  root.DecoderProtocols = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (T) {
  "use strict";

  const { base64ToBytes, bytesToBase64, hex, sha256, readable, utf8 } = T;
  const b64url = (bytes) => bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const MARK = { pass: "✓", info: "i", warn: "!", fail: "✗" };

  function findingsTable(findings) {
    const table = {};
    for (const f of findings) {
      let key = `${MARK[f.level]} ${f.label}`;
      while (table[key] !== undefined) key += " ";
      table[key] = f.text;
    }
    return table;
  }

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const p of parts) { out.set(p, offset); offset += p.length; }
    return out;
  }

  // ------------------------------------------------------------------- MD5
  // Only for the legacy SSH fingerprint format (`ssh-keygen -E md5`).

  function md5(bytes) {
    const s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    const K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);
    const total = Math.ceil((bytes.length + 9) / 64) * 64;
    const msg = new Uint8Array(total);
    msg.set(bytes);
    msg[bytes.length] = 0x80;
    const view = new DataView(msg.buffer);
    view.setUint32(total - 8, (bytes.length * 8) >>> 0, true);
    view.setUint32(total - 4, Math.floor((bytes.length * 8) / 2 ** 32), true);
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (let off = 0; off < total; off += 64) {
      const M = Array.from({ length: 16 }, (_, i) => view.getUint32(off + i * 4, true));
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i += 1) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i) % 16; }
        F = (F + A + K[i] + M[g]) >>> 0;
        A = D; D = C; C = B;
        B = (B + ((F << s[i]) | (F >>> (32 - s[i])))) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    const out = new Uint8Array(16);
    const outView = new DataView(out.buffer);
    [a0, b0, c0, d0].forEach((w, i) => outView.setUint32(i * 4, w, true));
    return out;
  }

  // ------------------------------------------------------------------- SSH

  function sshReader(bytes) {
    let pos = 0;
    const need = (n) => { if (pos + n > bytes.length) throw new Error("SSH key data ends early"); };
    return {
      u32() { need(4); const v = ((bytes[pos] << 24) | (bytes[pos + 1] << 16) | (bytes[pos + 2] << 8) | bytes[pos + 3]) >>> 0; pos += 4; return v; },
      u64() { need(8); let v = 0n; for (let i = 0; i < 8; i += 1) v = (v << 8n) | BigInt(bytes[pos + i]); pos += 8; return v; },
      bytes() { const n = this.u32(); need(n); const out = bytes.subarray(pos, pos + n); pos += n; return out; },
      text() { return utf8(this.bytes()); },
      done() { return pos === bytes.length; },
      get pos() { return pos; },
    };
  }

  function bits(mpint) {
    let i = 0;
    while (i < mpint.length && mpint[i] === 0) i += 1;
    return i === mpint.length ? 0 : (mpint.length - i - 1) * 8 + (32 - Math.clz32(mpint[i]));
  }

  const CURVE_BITS = { nistp256: 256, nistp384: 384, nistp521: 521 };

  /** Read the key fields for `base` from r; returns { description, size }. */
  function sshKeyFields(base, r) {
    if (base === "ssh-rsa") { const e = r.bytes(); const n = r.bytes(); const size = bits(n); return { description: `RSA ${size}-bit`, size, algorithm: "RSA", exponent: bits(e) <= 32 ? String(parseInt(hex(e), 16)) : "large" }; }
    if (base === "ssh-dss") { const p = r.bytes(); r.bytes(); r.bytes(); r.bytes(); return { description: `DSA ${bits(p)}-bit`, size: bits(p), algorithm: "DSA" }; }
    if (base === "ssh-ed25519") { r.bytes(); return { description: "Ed25519 (256-bit)", size: 256, algorithm: "Ed25519" }; }
    if (base === "ssh-ed448") { r.bytes(); return { description: "Ed448 (456-bit)", size: 456, algorithm: "Ed448" }; }
    if (base.startsWith("ecdsa-sha2-")) { const curve = r.text(); r.bytes(); return { description: `ECDSA ${curve} (${CURVE_BITS[curve] || "?"}-bit)`, size: CURVE_BITS[curve] || null, algorithm: "ECDSA" }; }
    if (base === "sk-ssh-ed25519@openssh.com") { r.bytes(); const app = r.text(); return { description: "Ed25519 on a security key (FIDO)", size: 256, algorithm: "Ed25519-SK", application: app }; }
    if (base === "sk-ecdsa-sha2-nistp256@openssh.com") { r.text(); r.bytes(); const app = r.text(); return { description: "ECDSA P-256 on a security key (FIDO)", size: 256, algorithm: "ECDSA-SK", application: app }; }
    throw new Error(`Unsupported key type ${base}`);
  }

  function sshFingerprints(blob) {
    return {
      sha256: `SHA256:${bytesToBase64(sha256(blob)).replace(/=+$/, "")}`,
      md5: `MD5:${hex(md5(blob), ":")}`,
    };
  }

  function sshTime(value) {
    if (value === 0n) return "always";
    if (value >= 0xffffffffffffffffn) return "forever";
    return new Date(Number(value) * 1000).toISOString();
  }

  /** Parse one base64 public key blob (plain key or certificate). */
  function parseSshBlob(blob, now = Date.now()) {
    const r = sshReader(blob);
    const type = r.text();
    const result = { type, fingerprints: sshFingerprints(blob) };
    if (type.endsWith("-cert-v01@openssh.com")) {
      const base = type.replace("-cert-v01@openssh.com", "").replace(/^sk-ssh-ed25519$/, "sk-ssh-ed25519@openssh.com").replace(/^sk-ecdsa-sha2-nistp256$/, "sk-ecdsa-sha2-nistp256@openssh.com");
      r.bytes(); // nonce
      const key = sshKeyFields(base, r);
      const serial = r.u64();
      const certType = r.u32();
      const keyId = r.text();
      const principalsRaw = sshReader(r.bytes());
      const principals = [];
      while (!principalsRaw.done()) principals.push(principalsRaw.text());
      const after = r.u64();
      const before = r.u64();
      const critical = sshOptions(r.bytes());
      const extensions = sshOptions(r.bytes());
      r.bytes(); // reserved
      const caBlob = r.bytes();
      const caType = sshReader(caBlob).text();
      Object.assign(result, {
        certificate: true, key, serial: String(serial), certType: certType === 1 ? "user" : certType === 2 ? "host" : `unknown (${certType})`,
        keyId, principals, validAfter: sshTime(after), validBefore: sshTime(before),
        critical, extensions, ca: { type: caType, fingerprints: sshFingerprints(caBlob) },
      });
      // The embedded key's own fingerprint is what `ssh-keygen -l` prints for a certificate.
      const keyBlobWriter = [];
      const w = (b) => { const len = new Uint8Array(4); new DataView(len.buffer).setUint32(0, b.length); keyBlobWriter.push(len, b); };
      const rr = sshReader(blob);
      rr.text(); rr.bytes();
      const startKey = rr.pos;
      sshKeyFields(base, rr);
      w(new TextEncoder().encode(base));
      keyBlobWriter.push(blob.subarray(startKey, rr.pos));
      result.fingerprints = sshFingerprints(concat(...keyBlobWriter));
      const nowS = BigInt(Math.floor(now / 1000));
      result.status = nowS < after ? "not yet valid" : before !== 0xffffffffffffffffn && nowS >= before ? "expired" : "valid";
    } else {
      result.key = sshKeyFields(type, r);
    }
    return result;
  }

  function sshOptions(bytes) {
    const r = sshReader(bytes);
    const out = [];
    while (!r.done()) {
      const name = r.text();
      const data = r.bytes();
      let value = "";
      if (data.length) { try { value = sshReader(data).text(); } catch { value = hex(data); } }
      out.push(value ? `${name}=${value}` : name);
    }
    return out;
  }

  const SSH_TYPE = /(?:^|\s)((?:sk-)?(?:ssh-(?:rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp(?:256|384|521))(?:@openssh\.com)?(?:-cert-v01@openssh\.com)?)\s+(AAAA[A-Za-z0-9+/]+={0,3})(?:\s+(.*))?$/;

  function sshKeyWarnings(key, label) {
    const out = [];
    if (key.algorithm === "RSA" && key.size < 2048) out.push({ level: "fail", label, text: `RSA ${key.size}-bit is too weak; OpenSSH refuses keys under 1024 bits and 3072 bits is the default today.` });
    else if (key.algorithm === "RSA" && key.size < 3072) out.push({ level: "info", label, text: `RSA ${key.size}-bit is acceptable; new keys should be Ed25519 or RSA 3072+.` });
    if (key.algorithm === "DSA") out.push({ level: "fail", label, text: "DSA (ssh-dss) keys have been disabled by default since OpenSSH 7.0. Replace this key." });
    return out;
  }

  function analyzeSshLines(text, now = Date.now()) {
    const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    if (!lines.length || !lines.every((l) => SSH_TYPE.test(l))) return null;
    const layers = [];
    const notices = [];
    const findings = [];
    const outputs = [];
    lines.forEach((line, index) => {
      const m = line.match(SSH_TYPE);
      const prefix = line.slice(0, line.indexOf(m[1])).trim();
      const label = lines.length > 1 ? `Key ${index + 1}` : "Key";
      let parsed;
      try { parsed = parseSshBlob(base64ToBytes(m[2]), now); } catch (error) {
        layers.push({ type: label, detail: "Unreadable", value: { Error: error.message }, claims: true });
        return;
      }
      if (parsed.type !== m[1]) notices.push(`${label}: the line says ${m[1]} but the key data is ${parsed.type}.`);
      const key = parsed.key;
      const info = {
        Type: parsed.type,
        Key: key.description,
        "SHA256 fingerprint": parsed.fingerprints.sha256,
        "MD5 fingerprint": parsed.fingerprints.md5,
        Comment: m[3] ? m[3].trim() : "(none)",
      };
      if (key.application) info["Security key application"] = key.application;
      if (key.exponent) info["RSA exponent"] = key.exponent;
      if (prefix) {
        if (prefix.startsWith("|1|")) info["Known host"] = "Hashed host name (HashKnownHosts)";
        else if (/^@(cert-authority|revoked)\b/.test(prefix)) info.Marker = prefix;
        else if (/^[^\s="]+(,[^\s="]+)*$/.test(prefix) && !/[="]/.test(prefix)) info["Known host"] = prefix.split(",").join(", ");
        else info["authorized_keys options"] = prefix;
        if (/(^|,)command=/.test(prefix)) findings.push({ level: "info", label, text: "Forced command: this key can only run that command." });
        if (/(^|,)from=/.test(prefix)) findings.push({ level: "pass", label, text: "Restricted to connections from the listed addresses." });
      }
      if (parsed.certificate) {
        Object.assign(info, {
          Certificate: `${parsed.certType} certificate, ${parsed.status}`,
          "Key ID": parsed.keyId || "(empty)",
          Principals: parsed.principals.length ? parsed.principals.join(", ") : "(none: valid for any user/host)",
          "Valid from": parsed.validAfter,
          "Valid until": parsed.validBefore,
          Serial: parsed.serial,
          "Signed by CA": `${parsed.ca.type} ${parsed.ca.fingerprints.sha256}`,
          "Critical options": parsed.critical.length ? parsed.critical.join(", ") : "(none)",
          Extensions: parsed.extensions.length ? parsed.extensions.join(", ") : "(none)",
        });
        if (!parsed.principals.length) findings.push({ level: "warn", label, text: "The certificate lists no principals, so it is valid for every user or host the CA is trusted for." });
        if (parsed.status === "expired") findings.push({ level: "fail", label, text: "The certificate has expired." });
        if (parsed.validBefore === "forever") findings.push({ level: "warn", label, text: "The certificate never expires." });
      }
      findings.push(...sshKeyWarnings(key, label));
      layers.push({ type: parsed.certificate ? `${label}: SSH certificate` : `${label}: SSH public key`, detail: key.description, value: info, claims: true });
      outputs.push(`${parsed.fingerprints.sha256} ${info.Comment} (${key.description})`);
    });
    if (findings.length) layers.push({ type: "Checks", detail: "✓ pass · ! warning · ✗ failure · i note", value: findingsTable(findings), claims: true });
    const kind = /cert-v01/.test(text) ? "SSH certificate" : lines.length > 1 ? `SSH public keys (${lines.length})` : "SSH public key";
    return { type: kind, confidence: 99, layers, notices, output: outputs.join("\n") };
  }

  /** OpenSSH private key files carry the public key in clear; show only that. */
  function analyzeOpensshPrivate(text, now = Date.now()) {
    const m = text.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/);
    if (!m) return null;
    const notice = "This is a private key. Only its public half was read; the secret part was not decoded. If it was pasted anywhere else, replace it.";
    try {
      const bytes = base64ToBytes(m[1]);
      const magic = utf8(bytes.subarray(0, 15));
      if (magic !== "openssh-key-v1\0") throw new Error("not openssh-key-v1");
      const r = sshReader(bytes.subarray(15));
      const cipher = r.text();
      const kdf = r.text();
      r.bytes();
      const count = r.u32();
      const keys = [];
      for (let i = 0; i < count; i += 1) keys.push(parseSshBlob(r.bytes(), now));
      const info = {
        Protection: cipher === "none" ? "NOT encrypted: anyone with this file can use the key" : `Encrypted with ${cipher} (key derivation: ${kdf})`,
      };
      keys.forEach((k, i) => {
        const p = keys.length > 1 ? `Key ${i + 1} ` : "";
        info[`${p}Type`] = k.key.description;
        info[`${p}SHA256 fingerprint`] = k.fingerprints.sha256;
      });
      const notices = [notice];
      if (cipher === "none") notices.push("The key has no passphrase. Consider adding one: ssh-keygen -p -f <file>.");
      return { type: "OpenSSH private key", confidence: 99, layers: [{ type: "Private key file", detail: "Public half only", value: info, claims: true }], notices, output: keys.map((k) => k.fingerprints.sha256).join("\n") };
    } catch {
      return { type: "OpenSSH private key", confidence: 95, layers: [{ type: "Private key file", detail: "Not decoded", value: { Contents: "Not shown or analysed" }, claims: true }], notices: [notice], output: "" };
    }
  }

  // -------------------------------------------------------------- protobuf

  function readVarint(b, pos) {
    let result = 0n;
    let shift = 0n;
    for (let i = 0; i < 10; i += 1) {
      if (pos >= b.length) throw new Error("Varint ends early");
      const byte = b[pos++];
      result |= BigInt(byte & 0x7f) << shift;
      if (!(byte & 0x80)) return [result, pos];
      shift += 7n;
    }
    throw new Error("Varint longer than 10 bytes");
  }

  const printable = (text) => /^[^\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]*$/.test(text) && readable(text);

  function parseProtobuf(b, depth = 0) {
    if (depth > 24) throw new Error("Nesting too deep");
    const fields = [];
    let pos = 0;
    while (pos < b.length) {
      const [key, p] = readVarint(b, pos);
      pos = p;
      const field = Number(key >> 3n);
      const wire = Number(key & 7n);
      if (field < 1 || field > 536870911) throw new Error("Invalid field number");
      if (wire === 0) {
        const [value, p2] = readVarint(b, pos);
        pos = p2;
        fields.push({ field, wire: "varint", value });
      } else if (wire === 1 || wire === 5) {
        const n = wire === 1 ? 8 : 4;
        if (pos + n > b.length) throw new Error("Fixed field ends early");
        fields.push({ field, wire: wire === 1 ? "i64" : "i32", bytes: b.slice(pos, pos + n) });
        pos += n;
      } else if (wire === 2) {
        const [len, p2] = readVarint(b, pos);
        pos = p2;
        if (len > BigInt(b.length - pos)) throw new Error("Length runs past the end");
        const sub = b.subarray(pos, pos + Number(len));
        pos += Number(len);
        fields.push({ field, wire: "len", ...classifyBytes(sub, depth) });
      } else throw new Error(`Unsupported wire type ${wire}`);
    }
    return fields;
  }

  function classifyBytes(sub, depth) {
    if (!sub.length) return { kind: "empty", bytes: sub };
    let text = null;
    try { text = utf8(sub, true); } catch { /* not UTF-8 */ }
    if (text !== null && printable(text)) return { kind: "string", text };
    try {
      const fields = parseProtobuf(sub, depth + 1);
      if (fields.length) return { kind: "message", fields };
    } catch { /* not a nested message */ }
    try {
      const packed = [];
      let pos = 0;
      while (pos < sub.length) { const [v, p] = readVarint(sub, pos); packed.push(v); pos = p; }
      if (packed.length > 1) return { kind: "bytes", bytes: sub, packed };
    } catch { /* not packed varints */ }
    return { kind: "bytes", bytes: sub };
  }

  function fixedInterpretations(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
    if (bytes.length === 8) return `double ${fmtFloat(view.getFloat64(0, true))}, int64 ${view.getBigInt64(0, true)}`;
    return `float ${fmtFloat(view.getFloat32(0, true))}, int32 ${view.getInt32(0, true)}`;
  }
  const fmtFloat = (v) => (Number.isFinite(v) ? String(Number(v.toPrecision(9))) : String(v));
  const zigzag = (v) => ((v & 1n) ? -((v + 1n) >> 1n) : v >> 1n);
  const quote = (text) => JSON.stringify(text);

  function protobufText(fields, indent = "") {
    const lines = [];
    for (const f of fields) {
      if (f.wire === "varint") {
        const notes = [];
        if (f.value >= 2n ** 63n) notes.push(`int64 ${f.value - 2n ** 64n}`);
        else if (f.value > 0n) notes.push(`sint ${zigzag(f.value)}`);
        lines.push(`${indent}${f.field}: ${f.value}${notes.length ? `  # ${notes.join(", ")}` : ""}`);
      } else if (f.wire === "i64" || f.wire === "i32") {
        lines.push(`${indent}${f.field}: 0x${hex(Array.from(f.bytes).reverse())}  # ${fixedInterpretations(f.bytes)}`);
      } else if (f.kind === "message") {
        lines.push(`${indent}${f.field} {`, ...protobufText(f.fields, `${indent}  `), `${indent}}`);
      } else if (f.kind === "string") {
        lines.push(`${indent}${f.field}: ${quote(f.text)}`);
      } else if (f.kind === "empty") {
        lines.push(`${indent}${f.field}: ""`);
      } else {
        const packed = f.packed ? `  # packed? ${f.packed.slice(0, 12).join(", ")}${f.packed.length > 12 ? ", …" : ""}` : "";
        lines.push(`${indent}${f.field}: bytes ${hex(f.bytes.subarray(0, 48))}${f.bytes.length > 48 ? "…" : ""} (${f.bytes.length})${packed}`);
      }
    }
    return lines;
  }

  function countFields(fields) {
    return fields.reduce((n, f) => n + 1 + (f.kind === "message" ? countFields(f.fields) : 0), 0);
  }

  /** strict: require the shape of a real message (used by the auto-detect). */
  function analyzeProtobuf(bytes, { strict = true } = {}) {
    let fields;
    try { fields = parseProtobuf(bytes); } catch { return null; }
    if (!fields.length) return null;
    if (strict && (fields.some((f) => f.field > 1000) || countFields(fields) < 2)) return null;
    const text = protobufText(fields).join("\n");
    const summary = {
      "Top-level fields": String(fields.length),
      "All fields": String(countFields(fields)),
      Size: `${bytes.length} bytes`,
      "Field numbers": [...new Set(fields.map((f) => f.field))].sort((a, b) => a - b).join(", "),
    };
    return {
      type: "Protocol Buffers (raw)", confidence: strict ? 80 : 95,
      layers: [
        { type: "Protobuf message", detail: "Wire format, no schema", value: summary, claims: true },
        { type: "Decoded fields", detail: "Like protoc --decode_raw", value: text },
      ],
      notices: ["Without the .proto schema, field names are unknown and each value is shown in the wire types that fit. A string could also be bytes or a nested message."],
      output: text,
    };
  }

  // ------------------------------------------------------------------ CBOR

  function decodeCbor(b, start = 0, depth = 0) {
    if (depth > 64) throw new Error("CBOR nesting too deep");
    let pos = start;
    const need = (n) => { if (pos + n > b.length) throw new Error("CBOR ends early"); };
    need(1);
    const initial = b[pos++];
    const major = initial >> 5;
    const info = initial & 31;
    const argument = () => {
      if (info < 24) return info;
      const size = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
      if (!size) throw new Error("Bad CBOR length");
      need(size);
      let v = 0n;
      for (let i = 0; i < size; i += 1) v = (v << 8n) | BigInt(b[pos++]);
      return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
    };
    if (major === 7) {
      if (info === 20) return [false, pos];
      if (info === 21) return [true, pos];
      if (info === 22) return [null, pos];
      if (info === 23) return [undefined, pos];
      if (info === 25) { need(2); const h = (b[pos] << 8) | b[pos + 1]; pos += 2; return [half(h), pos]; }
      if (info === 26) { need(4); const v = new DataView(b.buffer, b.byteOffset + pos, 4).getFloat32(0); pos += 4; return [v, pos]; }
      if (info === 27) { need(8); const v = new DataView(b.buffer, b.byteOffset + pos, 8).getFloat64(0); pos += 8; return [v, pos]; }
      if (info < 24) return [{ simple: info }, pos];
      throw new Error("Unsupported CBOR simple value");
    }
    const indefinite = info === 31 && major >= 2 && major <= 5;
    const n = indefinite ? null : argument();
    if (typeof n === "bigint" && major !== 0 && major !== 1 && major !== 6) throw new Error("CBOR item too large");
    if (major === 0) return [n, pos];
    if (major === 1) return [typeof n === "bigint" ? -1n - n : -1 - n, pos];
    if (major === 2 || major === 3) {
      let data;
      if (indefinite) {
        const chunks = [];
        while (b[pos] !== 0xff) { const [chunk, p] = decodeCbor(b, pos, depth + 1); chunks.push(typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk); pos = p; need(1); }
        pos += 1;
        data = concat(...chunks);
      } else { need(n); data = b.slice(pos, pos + n); pos += n; }
      return [major === 2 ? data : utf8(data, true), pos];
    }
    if (major === 4) {
      const out = [];
      if (indefinite) { need(1); while (b[pos] !== 0xff) { const [v, p] = decodeCbor(b, pos, depth + 1); out.push(v); pos = p; need(1); } pos += 1; }
      else for (let i = 0; i < n; i += 1) { const [v, p] = decodeCbor(b, pos, depth + 1); out.push(v); pos = p; }
      return [out, pos];
    }
    if (major === 5) {
      const out = new Map();
      const entry = () => { const [k, p] = decodeCbor(b, pos, depth + 1); pos = p; const [v, p2] = decodeCbor(b, pos, depth + 1); pos = p2; out.set(k, v); };
      if (indefinite) { need(1); while (b[pos] !== 0xff) { entry(); need(1); } pos += 1; }
      else for (let i = 0; i < n; i += 1) entry();
      return [out, pos];
    }
    if (major === 6) { const [v, p] = decodeCbor(b, pos, depth + 1); return [{ tag: n, value: v }, p]; }
    throw new Error("Bad CBOR");
  }

  function half(h) {
    const exp = (h >> 10) & 0x1f;
    const frac = h & 0x3ff;
    const sign = h & 0x8000 ? -1 : 1;
    if (exp === 0) return sign * 2 ** -14 * (frac / 1024);
    if (exp === 31) return frac ? NaN : sign * Infinity;
    return sign * 2 ** (exp - 15) * (1 + frac / 1024);
  }

  function cborDisplay(value) {
    if (value instanceof Uint8Array) return `h'${hex(value.subarray(0, 64))}${value.length > 64 ? "…" : ""}' (${value.length} bytes)`;
    if (value instanceof Map) return Object.fromEntries([...value].map(([k, v]) => [String(k), cborDisplay(v)]));
    if (Array.isArray(value)) return value.map(cborDisplay);
    if (typeof value === "bigint") return value.toString();
    if (value && typeof value === "object" && "tag" in value) return { [`tag ${value.tag}`]: cborDisplay(value.value) };
    return value;
  }

  // -------------------------------------------------------- DER / JWK → PEM

  function derLength(n) {
    if (n < 128) return Uint8Array.of(n);
    const out = [];
    while (n) { out.unshift(n & 255); n = Math.floor(n / 256); }
    return Uint8Array.of(0x80 | out.length, ...out);
  }
  const der = (tag, ...parts) => { const body = concat(...parts); return concat(Uint8Array.of(tag), derLength(body.length), body); };
  function derInt(bytes) {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i += 1;
    const trimmed = bytes.subarray(i);
    return der(0x02, trimmed[0] & 0x80 ? concat(Uint8Array.of(0), trimmed) : trimmed);
  }
  function derOid(dotted) {
    const parts = dotted.split(".").map(Number);
    const out = [parts[0] * 40 + parts[1]];
    for (const p of parts.slice(2)) {
      const chunk = [p & 0x7f];
      let v = Math.floor(p / 128);
      while (v) { chunk.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
      out.push(...chunk);
    }
    return der(0x06, Uint8Array.from(out));
  }
  const bitString = (bytes) => der(0x03, Uint8Array.of(0), bytes);
  const CURVE_OID = { "P-256": "1.2.840.10045.3.1.7", "P-384": "1.3.132.0.34", "P-521": "1.3.132.0.35" };

  function jwkToSpki(jwk) {
    const d = (v) => base64ToBytes(v);
    if (jwk.kty === "RSA") return der(0x30, der(0x30, derOid("1.2.840.113549.1.1.1"), Uint8Array.of(5, 0)), bitString(der(0x30, derInt(d(jwk.n)), derInt(d(jwk.e)))));
    if (jwk.kty === "EC") {
      if (!CURVE_OID[jwk.crv]) throw new Error(`Curve ${jwk.crv} cannot be exported`);
      return der(0x30, der(0x30, derOid("1.2.840.10045.2.1"), derOid(CURVE_OID[jwk.crv])), bitString(concat(Uint8Array.of(4), d(jwk.x), d(jwk.y))));
    }
    if (jwk.kty === "OKP" && (jwk.crv === "Ed25519" || jwk.crv === "X25519")) {
      return der(0x30, der(0x30, derOid(jwk.crv === "Ed25519" ? "1.3.101.112" : "1.3.101.110")), bitString(d(jwk.x)));
    }
    throw new Error(`Key type ${jwk.kty}${jwk.crv ? ` ${jwk.crv}` : ""} cannot be exported to PEM`);
  }

  const pem = (label, der) => `-----BEGIN ${label}-----\n${bytesToBase64(der).match(/.{1,64}/g).join("\n")}\n-----END ${label}-----`;

  // ------------------------------------------------------------ JWK / JWKS

  const THUMBPRINT_MEMBERS = { RSA: ["e", "kty", "n"], EC: ["crv", "kty", "x", "y"], OKP: ["crv", "kty", "x"], oct: ["k", "kty"] };
  const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth"];

  function jwkThumbprint(jwk) {
    const members = THUMBPRINT_MEMBERS[jwk.kty];
    if (!members || members.some((m) => typeof jwk[m] !== "string")) return null;
    const canonical = `{${members.map((m) => `${JSON.stringify(m)}:${JSON.stringify(jwk[m])}`).join(",")}}`;
    return b64url(sha256(new TextEncoder().encode(canonical)));
  }

  function jwkSummary(jwk, now) {
    const info = { Type: jwk.kty || "(missing kty)" };
    const findings = [];
    if (jwk.kid) info["Key ID (kid)"] = jwk.kid;
    if (jwk.use) info.Use = jwk.use === "sig" ? "sig (signatures)" : jwk.use === "enc" ? "enc (encryption)" : jwk.use;
    if (jwk.alg) info.Algorithm = jwk.alg;
    try {
      if (jwk.kty === "RSA") info.Size = `${bits(base64ToBytes(jwk.n))}-bit`;
      else if (jwk.kty === "EC" || jwk.kty === "OKP") info.Curve = jwk.crv;
      else if (jwk.kty === "oct") info.Size = `${base64ToBytes(jwk.k).length * 8}-bit symmetric key`;
    } catch { findings.push({ level: "fail", label: "Key data", text: "The key parameters are not valid Base64URL." }); }
    const thumb = jwkThumbprint(jwk);
    if (thumb) {
      info["RFC 7638 thumbprint"] = thumb;
      if (jwk.kid && jwk.kid === thumb) findings.push({ level: "pass", label: "kid", text: "The kid is the key's RFC 7638 thumbprint." });
    } else findings.push({ level: "fail", label: "Members", text: `A ${jwk.kty || "?"} JWK needs ${(THUMBPRINT_MEMBERS[jwk.kty] || ["kty"]).join(", ")}.` });
    const privateMembers = PRIVATE_MEMBERS.filter((m) => m in jwk);
    if (privateMembers.length || jwk.kty === "oct") {
      findings.push({ level: "fail", label: "Secret material", text: jwk.kty === "oct"
        ? "This is a symmetric (oct) key: whoever holds it can create valid tokens. It must never be published in a JWKS."
        : `This JWK contains private members (${privateMembers.join(", ")}). If it came from a public JWKS URL, the key is compromised and must be replaced.` });
    }
    if (jwk.kty === "RSA" && info.Size && parseInt(info.Size, 10) < 2048) findings.push({ level: "fail", label: "Size", text: `${info.Size} RSA is too weak; use 2048 bits or more.` });
    if (Array.isArray(jwk.x5c) && jwk.x5c.length) {
      try {
        const cert = T.parseCertificate(base64ToBytes(jwk.x5c[0]), now);
        info["Certificate (x5c)"] = `${cert.subject.map(([k, v]) => `${k}=${v}`).join(", ")} · ${cert.status.text}`;
        if (cert.status.state !== "valid") findings.push({ level: "warn", label: "x5c", text: `The attached certificate: ${cert.status.text}.` });
      } catch { findings.push({ level: "warn", label: "x5c", text: "The x5c certificate could not be read." }); }
    }
    let pemText = null;
    if (!privateMembers.length && jwk.kty !== "oct") {
      try { pemText = pem("PUBLIC KEY", jwkToSpki(jwk)); } catch (error) { info.PEM = error.message; }
    }
    return { info, findings, pem: pemText };
  }

  function analyzeJwk(value, now = Date.now()) {
    const keys = Array.isArray(value && value.keys) && value.keys.every((k) => k && typeof k === "object" && k.kty) ? value.keys
      : value && typeof value === "object" && typeof value.kty === "string" ? [value] : null;
    if (!keys || !keys.length) return null;
    const layers = [];
    const findings = [];
    const pems = [];
    const kids = new Map();
    keys.forEach((jwk, i) => {
      const label = keys.length > 1 ? `Key ${i + 1}${jwk.kid ? ` (${jwk.kid})` : ""}` : "JWK";
      const s = jwkSummary(jwk, now);
      layers.push({ type: label, detail: [jwk.kty, jwk.crv || s.info.Size, jwk.use].filter(Boolean).join(" · "), value: s.info, claims: true });
      findings.push(...s.findings.map((f) => ({ ...f, label: keys.length > 1 ? `${label}: ${f.label}` : f.label })));
      if (s.pem) pems.push(keys.length > 1 ? `# ${label}\n${s.pem}` : s.pem);
      if (jwk.kid) kids.set(jwk.kid, (kids.get(jwk.kid) || 0) + 1);
    });
    for (const [kid, count] of kids) if (count > 1) findings.push({ level: "warn", label: "kid", text: `kid "${kid}" appears ${count} times; verifiers cannot tell which key to use.` });
    if (keys.length > 1 && !kids.size) findings.push({ level: "warn", label: "kid", text: "Several keys but no kid values: tokens cannot name their key." });
    if (findings.length) layers.push({ type: "Checks", detail: "✓ pass · ! warning · ✗ failure", value: findingsTable(findings), claims: true });
    if (pems.length) layers.push({ type: "Public key as PEM", detail: "SubjectPublicKeyInfo", value: pems.join("\n\n") });
    const secret = findings.some((f) => f.label.endsWith("Secret material"));
    return {
      type: keys.length > 1 || value.keys ? `JWKS (${keys.length} key${keys.length === 1 ? "" : "s"})` : "JSON Web Key", confidence: 97, layers,
      notices: secret ? ["Private or symmetric key material was pasted. It stayed in this tab, but replace the key if it was ever exposed."] : [],
      output: pems.join("\n\n") || keys.map((k) => jwkThumbprint(k)).filter(Boolean).join("\n"),
    };
  }

  // ------------------------------------------------------------------- JWE

  const JWE_ALG = {
    "RSA1_5": "RSA PKCS#1 v1.5 key wrap", "RSA-OAEP": "RSA-OAEP (SHA-1) key wrap", "RSA-OAEP-256": "RSA-OAEP with SHA-256 key wrap",
    "RSA-OAEP-384": "RSA-OAEP with SHA-384 key wrap", "RSA-OAEP-512": "RSA-OAEP with SHA-512 key wrap",
    A128KW: "AES-128 key wrap", A192KW: "AES-192 key wrap", A256KW: "AES-256 key wrap", dir: "Direct: a shared symmetric key is the content key",
    "ECDH-ES": "ECDH-ES key agreement (direct)", "ECDH-ES+A128KW": "ECDH-ES + AES-128 key wrap", "ECDH-ES+A192KW": "ECDH-ES + AES-192 key wrap",
    "ECDH-ES+A256KW": "ECDH-ES + AES-256 key wrap", A128GCMKW: "AES-128-GCM key wrap", A192GCMKW: "AES-192-GCM key wrap", A256GCMKW: "AES-256-GCM key wrap",
    "PBES2-HS256+A128KW": "Password-based (PBES2) + AES-128 key wrap", "PBES2-HS384+A192KW": "Password-based (PBES2) + AES-192 key wrap", "PBES2-HS512+A256KW": "Password-based (PBES2) + AES-256 key wrap",
  };
  const JWE_ENC = {
    A128GCM: { name: "AES-128-GCM", iv: 12, tag: 16 }, A192GCM: { name: "AES-192-GCM", iv: 12, tag: 16 }, A256GCM: { name: "AES-256-GCM", iv: 12, tag: 16 },
    "A128CBC-HS256": { name: "AES-128-CBC + HMAC-SHA-256", iv: 16, tag: 16 }, "A192CBC-HS384": { name: "AES-192-CBC + HMAC-SHA-384", iv: 16, tag: 24 },
    "A256CBC-HS512": { name: "AES-256-CBC + HMAC-SHA-512", iv: 16, tag: 32 },
  };

  function analyzeJwe(raw) {
    const parts = raw.split(".");
    if (parts.length !== 5 || !parts.every((p, i) => /^[A-Za-z0-9_-]*$/.test(p) && (p.length || i === 1))) return null;
    let header;
    try { header = JSON.parse(utf8(base64ToBytes(parts[0]), true)); } catch { return null; }
    if (!header || typeof header !== "object" || !header.enc) return null;
    const sizes = parts.map((p) => { try { return base64ToBytes(p).length; } catch { return null; } });
    const enc = JWE_ENC[header.enc];
    const findings = [];
    const envelope = {
      "Key management (alg)": `${header.alg} · ${JWE_ALG[header.alg] || "unknown algorithm"}`,
      "Content encryption (enc)": `${header.enc} · ${enc ? enc.name : "unknown algorithm"}`,
      "Encrypted key": sizes[1] === 0 ? "0 bytes (none: dir or ECDH-ES)" : `${sizes[1]} bytes${/^RSA/.test(header.alg || "") && sizes[1] ? ` (fits a ${sizes[1] * 8}-bit RSA key)` : ""}`,
      "Initialization vector": `${sizes[2]} bytes`,
      Ciphertext: `${sizes[3]} bytes`,
      "Authentication tag": `${sizes[4]} bytes`,
    };
    if (enc && sizes[2] !== enc.iv) findings.push({ level: "fail", label: "IV", text: `${header.enc} uses a ${enc.iv}-byte IV; this one has ${sizes[2]}.` });
    else if (enc) findings.push({ level: "pass", label: "IV", text: `${enc.iv} bytes, as ${header.enc} requires.` });
    if (enc && sizes[4] !== enc.tag) findings.push({ level: "fail", label: "Tag", text: `${header.enc} produces a ${enc.tag}-byte tag; this one has ${sizes[4]}.` });
    else if (enc) findings.push({ level: "pass", label: "Tag", text: `${enc.tag} bytes, as ${header.enc} requires.` });
    if ((header.alg === "dir" || header.alg === "ECDH-ES") && sizes[1] !== 0) findings.push({ level: "fail", label: "Encrypted key", text: `${header.alg} must have an empty encrypted-key part.` });
    if (header.alg === "RSA1_5") findings.push({ level: "warn", label: "alg", text: "RSA1_5 is vulnerable to padding-oracle attacks; use RSA-OAEP-256 or ECDH-ES." });
    if (header.alg === "RSA-OAEP") findings.push({ level: "info", label: "alg", text: "RSA-OAEP uses SHA-1 internally; RSA-OAEP-256 is preferred for new systems." });
    if (/^ECDH-ES/.test(header.alg || "") && !header.epk) findings.push({ level: "fail", label: "epk", text: "ECDH-ES requires the sender's ephemeral public key (epk) in the header." });
    const layers = [
      { type: "JWE protected header", detail: header.kid ? `kid ${header.kid}` : "Header", value: Object.fromEntries(Object.entries(header).map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : v])), claims: true },
      { type: "Encryption envelope", detail: "5 parts", value: envelope, claims: true },
    ];
    if (header.epk) layers.push({ type: "Ephemeral public key (epk)", detail: header.epk.crv || header.epk.kty, value: Object.fromEntries(Object.entries(header.epk).map(([k, v]) => [k, String(v)])), claims: true });
    layers.push({ type: "Checks", detail: "✓ pass · ! warning · ✗ failure", value: findingsTable(findings), claims: true });
    const notices = [`This is an encrypted token (JWE), not a broken JWT. The payload is encrypted with ${header.enc}${JWE_ALG[header.alg] ? ` under ${header.alg}` : ""}${header.kid ? ` for key ${header.kid}` : ""}. Only the recipient's private key can decrypt it, and decoder.in never asks for private keys.`];
    if (String(header.cty || "").toUpperCase() === "JWT") notices.push("cty: JWT means a signed JWT is nested inside. After decryption it still needs its own signature check.");
    if (header.zip === "DEF") notices.push("zip: DEF means the plaintext was DEFLATE-compressed before encryption.");
    return { type: "JWE (encrypted token)", confidence: 98, layers, notices, output: JSON.stringify(header, null, 2) };
  }

  // -------------------------------------------------------------- WebAuthn

  const AAGUIDS = {
    "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
    "fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud Keychain",
    "dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain (managed)",
    "adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
    "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
    "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
    "6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
    "bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
    "d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
    "531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",
    "cb69481e-8ff7-4039-93ec-0a2729a154a8": "YubiKey 5 Series",
    "ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5 Series",
    "00000000-0000-0000-0000-000000000000": "None (no attestation / privacy-preserving)",
  };
  const COSE_ALG = { "-7": "ES256", "-35": "ES384", "-36": "ES512", "-8": "EdDSA", "-257": "RS256", "-258": "RS384", "-259": "RS512", "-37": "PS256", "-38": "PS384", "-39": "PS512" };
  const COSE_CRV = { 1: "P-256", 2: "P-384", 3: "P-521", 6: "Ed25519", 7: "Ed448" };

  function coseToJwk(map) {
    const kty = map.get(1);
    if (kty === 2) return { kty: "EC", crv: COSE_CRV[map.get(-1)], x: b64url(map.get(-2)), y: b64url(map.get(-3)) };
    if (kty === 1) return { kty: "OKP", crv: COSE_CRV[map.get(-1)], x: b64url(map.get(-2)) };
    if (kty === 3) return { kty: "RSA", n: b64url(map.get(-1)), e: b64url(map.get(-2)) };
    return null;
  }

  function parseAuthData(bytes) {
    if (bytes.length < 37) throw new Error("authenticatorData is shorter than 37 bytes");
    const flags = bytes[32];
    const out = {
      rpIdHash: bytes.subarray(0, 32),
      flags,
      up: !!(flags & 0x01), uv: !!(flags & 0x04), be: !!(flags & 0x08), bs: !!(flags & 0x10), at: !!(flags & 0x40), ed: !!(flags & 0x80),
      signCount: new DataView(bytes.buffer, bytes.byteOffset + 33, 4).getUint32(0),
    };
    let pos = 37;
    if (out.at) {
      if (bytes.length < pos + 18) throw new Error("Attested credential data ends early");
      const g = hex(bytes.subarray(pos, pos + 16));
      out.aaguid = `${g.slice(0, 8)}-${g.slice(8, 12)}-${g.slice(12, 16)}-${g.slice(16, 20)}-${g.slice(20)}`;
      pos += 16;
      const idLen = (bytes[pos] << 8) | bytes[pos + 1];
      pos += 2;
      if (bytes.length < pos + idLen) throw new Error("Credential ID ends early");
      out.credentialId = bytes.subarray(pos, pos + idLen);
      pos += idLen;
      const [cose, p] = decodeCbor(bytes, pos);
      out.cose = cose;
      pos = p;
    }
    if (out.ed) { const [ext, p] = decodeCbor(bytes, pos); out.extensions = ext; pos = p; }
    if (pos !== bytes.length) throw new Error("Unexpected bytes after authenticatorData");
    return out;
  }

  function flagText(a) {
    return [a.up ? "UP user present" : "no UP", a.uv ? "UV user verified" : "no UV", a.be ? "BE backup eligible" : null, a.bs ? "BS backed up" : null, a.at ? "AT credential data" : null, a.ed ? "ED extensions" : null].filter(Boolean).join(" · ");
  }

  function authDataLayers(a, origin, findings) {
    const info = {
      "RP ID hash": hex(a.rpIdHash),
      Flags: `0x${a.flags.toString(16).padStart(2, "0")} · ${flagText(a)}`,
      "Signature counter": String(a.signCount),
    };
    if (origin) {
      let host = null;
      try { host = new URL(origin).hostname; } catch { /* keep null */ }
      if (host) {
        const labels = host.split(".");
        const match = labels.map((_, i) => labels.slice(i).join(".")).filter((d) => d.includes(".") || d === "localhost")
          .find((d) => hex(sha256(new TextEncoder().encode(d))) === hex(a.rpIdHash));
        if (match) { info["RP ID"] = `${match} (matches the hash)`; findings.push({ level: "pass", label: "RP ID", text: `The RP ID hash is SHA-256("${match}"), which fits the origin ${origin}.` }); }
        else findings.push({ level: "fail", label: "RP ID", text: `The RP ID hash matches neither ${host} nor any parent domain, so the relying party will reject it.` });
      }
    }
    const layers = [{ type: "Authenticator data", detail: `${a.signCount === 0 ? "counter 0" : `counter ${a.signCount}`}`, value: info, claims: true }];
    if (!a.up) findings.push({ level: "fail", label: "UP", text: "User presence was not asserted." });
    if (!a.uv) findings.push({ level: "warn", label: "UV", text: "User verification (PIN or biometrics) was not performed. Acceptable only if the relying party asked for userVerification: discouraged." });
    else findings.push({ level: "pass", label: "UV", text: "The user was verified by PIN or biometrics." });
    if (!a.be && a.bs) findings.push({ level: "fail", label: "BE/BS", text: "BS is set without BE: this combination is invalid." });
    if (a.be) findings.push({ level: "info", label: "Backup", text: a.bs ? "A synced passkey: it is backed up and can move between devices." : "Backup-eligible, not yet backed up." });
    if (a.signCount === 0) findings.push({ level: "info", label: "Counter", text: "A counter of 0 is normal for synced passkeys, which do not count signatures." });
    if (a.at) {
      const cred = {
        AAGUID: `${a.aaguid}${AAGUIDS[a.aaguid] ? ` (${AAGUIDS[a.aaguid]})` : ""}`,
        "Credential ID": b64url(a.credentialId),
        "Credential ID length": `${a.credentialId.length} bytes`,
      };
      if (a.cose instanceof Map) {
        const alg = a.cose.get(3);
        cred["Public key"] = `${{ 1: "OKP", 2: "EC2", 3: "RSA" }[a.cose.get(1)] || a.cose.get(1)}${COSE_CRV[a.cose.get(-1)] && a.cose.get(1) !== 3 ? ` ${COSE_CRV[a.cose.get(-1)]}` : ""} · ${COSE_ALG[String(alg)] || `alg ${alg}`}`;
        try {
          const jwk = coseToJwk(a.cose);
          if (jwk) {
            if (jwk.kty === "RSA") cred["Public key"] += ` · ${bits(base64ToBytes(jwk.n))}-bit`;
            cred["Public key (JWK)"] = JSON.stringify(jwk);
            cred["Public key (PEM)"] = pem("PUBLIC KEY", jwkToSpki(jwk));
          }
        } catch { /* leave the raw description */ }
      }
      layers.push({ type: "Attested credential", detail: AAGUIDS[a.aaguid] || "Authenticator", value: cred, claims: true });
    }
    if (a.extensions) layers.push({ type: "Authenticator extensions", detail: "CBOR", value: JSON.stringify(cborDisplay(a.extensions), null, 2) });
    return layers;
  }

  function clientDataLayer(client, findings) {
    const info = { Type: client.type, Origin: client.origin };
    try { info.Challenge = `${client.challenge} (${base64ToBytes(client.challenge).length} bytes)`; } catch { info.Challenge = String(client.challenge); }
    if (client.crossOrigin !== undefined) info["Cross-origin"] = String(client.crossOrigin);
    if (client.topOrigin) info["Top origin"] = client.topOrigin;
    if (client.tokenBinding) info["Token binding"] = JSON.stringify(client.tokenBinding);
    if (!/^webauthn\.(create|get)$/.test(client.type)) findings.push({ level: "fail", label: "type", text: `type must be webauthn.create or webauthn.get, not ${client.type}.` });
    if (/^http:/.test(client.origin || "") && !/^http:\/\/localhost(:\d+)?$/.test(client.origin)) findings.push({ level: "fail", label: "Origin", text: "WebAuthn only works on HTTPS origins (or localhost)." });
    if (client.crossOrigin === true) findings.push({ level: "warn", label: "Cross-origin", text: "The ceremony ran inside a cross-origin iframe; the relying party must allow that explicitly." });
    try { if (base64ToBytes(client.challenge).length < 16) findings.push({ level: "warn", label: "Challenge", text: "The challenge is shorter than 16 bytes; use at least 16 random bytes." }); } catch { /* shown as-is */ }
    return { type: "Client data (clientDataJSON)", detail: client.type === "webauthn.create" ? "Registration" : client.type === "webauthn.get" ? "Sign-in" : client.type, value: info, claims: true };
  }

  function attestationLayers(att, origin, findings, now) {
    const layers = [];
    const fmt = att.get("fmt");
    const stmt = att.get("attStmt");
    const info = { Format: fmt === "none" ? "none (no attestation)" : fmt };
    if (stmt instanceof Map) {
      if (stmt.has("alg")) info["Statement algorithm"] = COSE_ALG[String(stmt.get("alg"))] || String(stmt.get("alg"));
      const x5c = stmt.get("x5c");
      if (Array.isArray(x5c) && x5c.length) {
        info["Certificates (x5c)"] = String(x5c.length);
        try {
          const cert = T.parseCertificate(x5c[0], now);
          info["Attestation certificate"] = cert.subject.map(([k, v]) => `${k}=${v}`).join(", ");
          info["Issued by"] = cert.issuer.map(([k, v]) => `${k}=${v}`).join(", ");
        } catch { info["Attestation certificate"] = "(unreadable)"; }
      }
    }
    layers.push({ type: "Attestation", detail: fmt, value: info, claims: true });
    if (fmt !== "none") findings.push({ level: "info", label: "Attestation", text: "The attestation signature is not verified here; checking it needs the FIDO metadata for this authenticator." });
    const authData = att.get("authData");
    if (authData instanceof Uint8Array) layers.push(...authDataLayers(parseAuthData(authData), origin, findings));
    return layers;
  }

  function analyzeWebAuthn(value, bytes, now = Date.now(), authDataHint = false) {
    const findings = [];
    const layers = [];
    let kind = null;
    try {
      if (value && typeof value === "object" && !Array.isArray(value)) {
        const response = value.response && typeof value.response === "object" ? value.response : null;
        if (response && (response.clientDataJSON || response.attestationObject || response.authenticatorData)) {
          let client = null;
          if (response.clientDataJSON) {
            client = JSON.parse(utf8(base64ToBytes(response.clientDataJSON), true));
            layers.push(clientDataLayer(client, findings));
          }
          const origin = client && client.origin;
          if (response.attestationObject) {
            const [att] = decodeCbor(base64ToBytes(response.attestationObject));
            layers.push(...attestationLayers(att, origin, findings, now));
            kind = "WebAuthn registration";
          } else if (response.authenticatorData) {
            layers.push(...authDataLayers(parseAuthData(base64ToBytes(response.authenticatorData)), origin, findings));
            if (response.signature) layers.push({ type: "Assertion", detail: "Signature", value: { Signature: `${base64ToBytes(response.signature).length} bytes (not verified here)`, "User handle": response.userHandle ? utf8(base64ToBytes(response.userHandle)) : "(none)" }, claims: true });
            kind = "WebAuthn sign-in (assertion)";
          } else kind = "WebAuthn response";
          if (value.id) layers.unshift({ type: "Credential", detail: value.type || "public-key", value: { ID: value.id, "Authenticator attachment": value.authenticatorAttachment || "(not reported)" }, claims: true });
        } else if (typeof value.type === "string" && /^webauthn\./.test(value.type) && value.challenge) {
          layers.push(clientDataLayer(value, findings));
          kind = "WebAuthn client data";
        }
      } else if (bytes) {
        let att = null;
        try { const [v, end] = decodeCbor(bytes); if (end === bytes.length) att = v; } catch { /* not CBOR */ }
        if (att instanceof Map && att.has("fmt") && att.has("authData")) {
          layers.push(...attestationLayers(att, null, findings, now));
          kind = "WebAuthn attestation object";
        } else if (authDataHint) {
          layers.push(...authDataLayers(parseAuthData(bytes), null, findings));
          kind = "WebAuthn authenticator data";
        }
      }
    } catch (error) {
      if (!kind && !layers.length) return null;
      findings.push({ level: "fail", label: "Parse", text: error.message });
    }
    if (!kind) return null;
    if (findings.length) layers.push({ type: "Checks", detail: "✓ pass · ! warning · ✗ failure · i note", value: findingsTable(findings), claims: true });
    return { type: kind, confidence: 97, layers, notices: ["Signatures are not verified here. Decoded does not mean trusted."], output: layers.map((l) => `${l.type}: ${typeof l.value === "string" ? l.value : JSON.stringify(l.value)}`).join("\n") };
  }

  // --------------------------------------------------------- OAuth / OIDC

  const OAUTH_ERRORS = {
    invalid_request: "The request is missing a parameter or has a malformed one.",
    unauthorized_client: "This client is not allowed to use this flow.",
    access_denied: "The user or the authorization server refused the request.",
    unsupported_response_type: "The server does not support this response_type for this client.",
    invalid_scope: "A requested scope is unknown or not allowed for this client.",
    server_error: "The authorization server hit an internal error.",
    temporarily_unavailable: "The authorization server is overloaded or down for maintenance.",
    login_required: "prompt=none was requested but the user is not signed in.",
    consent_required: "prompt=none was requested but the user has not consented yet.",
    interaction_required: "prompt=none was requested but the server needs the user to interact.",
    invalid_grant: "The code, refresh token or PKCE verifier is invalid, expired, already used, or was issued to another client or redirect URI.",
    invalid_client: "Client authentication failed: wrong client_id, secret or assertion.",
    unsupported_grant_type: "The server does not accept this grant_type.",
  };

  const PKCE_VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;
  const pkceChallenge = (verifier) => b64url(sha256(new TextEncoder().encode(verifier)));

  function paramsFrom(raw) {
    let url = null;
    try { url = new URL(raw); } catch { /* not a URL */ }
    if (url) {
      const params = new URLSearchParams(url.search);
      const fragment = url.hash.length > 1 && url.hash.includes("=") ? new URLSearchParams(url.hash.slice(1)) : null;
      if (fragment) for (const [k, v] of fragment) params.append(k, v);
      return { url, params, fragment: !!fragment };
    }
    if (/^[\w.\-~%]+=[^&\s]*(?:&[\w.\-~%]+=[^&\s]*)+$/.test(raw)) return { url: null, params: new URLSearchParams(raw), fragment: false };
    return null;
  }

  function analyzeOAuth(raw) {
    const parsed = paramsFrom(raw.trim());
    if (!parsed) return null;
    const { url, params } = parsed;
    const get = (k) => params.get(k);
    const findings = [];
    const add = (level, label, text) => findings.push({ level, label, text });
    let kind = null;
    const info = {};
    let check = null;

    if (params.has("response_type") && params.has("client_id")) {
      kind = "OAuth authorization request";
      const responseType = get("response_type").split(" ").sort().join(" ");
      const flow = responseType === "code" ? "Authorization code" : /code/.test(responseType) ? "Hybrid (OIDC)" : "Implicit";
      const scopes = (get("scope") || "").split(/\s+/).filter(Boolean);
      const oidc = scopes.includes("openid");
      if (url) info.Endpoint = `${url.origin}${url.pathname}`;
      Object.assign(info, { Flow: `${flow} (response_type=${get("response_type")})`, client_id: get("client_id") });
      for (const k of ["redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "response_mode", "prompt", "max_age", "login_hint", "audience", "resource", "acr_values", "request_uri"]) if (params.has(k)) info[k] = get(k);
      if (oidc) info.Protocol = "OpenID Connect (scope openid)";
      if (flow === "Implicit") add("fail", "Flow", "The implicit flow returns tokens in the URL. OAuth 2.0 Security BCP and OAuth 2.1 remove it: use the authorization code flow with PKCE.");
      if (!get("state")) add(get("code_challenge") ? "warn" : "fail", "state", "No state parameter: nothing ties the callback to this browser session (CSRF).");
      else if (get("state").length < 16) add("warn", "state", "state is short; use at least 16 random characters.");
      else add("pass", "state", "Present.");
      if (/code/.test(responseType)) {
        if (!get("code_challenge")) add("warn", "PKCE", "No code_challenge. PKCE is required for public clients (SPAs, mobile apps) and recommended for all.");
        else if ((get("code_challenge_method") || "plain") === "plain") add("fail", "PKCE", "code_challenge_method is plain (or missing, which means plain): the challenge equals the verifier. Use S256.");
        else if (get("code_challenge_method") === "S256") {
          if (!/^[A-Za-z0-9_-]{43}$/.test(get("code_challenge"))) add("fail", "PKCE", "An S256 code_challenge is always 43 Base64URL characters.");
          else add("pass", "PKCE", "S256 challenge present. Paste the code_verifier below to check it.");
          check = { kind: "pkce", challenge: get("code_challenge") };
        }
      }
      const redirect = get("redirect_uri");
      if (!redirect) add("info", "redirect_uri", "Not sent: the server uses the registered default. Required when several are registered.");
      else {
        let target = null;
        try { target = new URL(redirect); } catch { add("fail", "redirect_uri", "Not a valid absolute URL."); }
        if (target) {
          if (target.protocol === "http:" && !/^(localhost|127\.0\.0\.1|\[::1\])$/.test(target.hostname)) add("fail", "redirect_uri", "Plain http: codes and tokens travel unencrypted.");
          else if (target.hash) add("fail", "redirect_uri", "A redirect URI must not contain a fragment.");
          else add("pass", "redirect_uri", target.protocol === "http:" ? "Loopback http is allowed for native apps." : "HTTPS.");
        }
      }
      if (oidc && flow !== "Authorization code" && !get("nonce")) add("fail", "nonce", "OIDC implicit and hybrid flows require a nonce to stop ID token replay.");
      else if (oidc && !get("nonce")) add("info", "nonce", "No nonce; recommended with OIDC even for the code flow.");
      if (get("response_mode") === "query" && /token/.test(responseType)) add("fail", "response_mode", "Tokens must never be returned in the query string.");
      if (params.has("client_secret")) add("fail", "client_secret", "A client secret in a browser URL is exposed to the user, browser history and logs. Rotate it.");
    } else if (params.has("grant_type")) {
      kind = "OAuth token request";
      for (const k of ["grant_type", "client_id", "code", "redirect_uri", "code_verifier", "refresh_token", "scope", "audience", "resource", "client_assertion_type"]) if (params.has(k)) info[k] = k === "refresh_token" ? `${get(k).slice(0, 8)}… (hidden)` : get(k);
      if (params.has("client_secret")) { info.client_secret = "(present, not shown)"; add("warn", "client_secret", "Sent in the body. Fine for confidential clients over HTTPS; never ship it in a SPA or mobile app."); }
      if (get("grant_type") === "authorization_code" && !get("code_verifier")) add("warn", "PKCE", "No code_verifier: this exchange is not protected by PKCE.");
      if (get("grant_type") === "password") add("fail", "grant_type", "The password grant is deprecated (OAuth 2.0 Security BCP) and removed in OAuth 2.1.");
      const verifier = get("code_verifier");
      if (verifier) {
        if (!PKCE_VERIFIER.test(verifier)) add("fail", "code_verifier", "A code_verifier must be 43–128 characters of A–Z a–z 0–9 - . _ ~");
        else add("pass", "code_verifier", "Valid format.");
        info["Matching code_challenge (S256)"] = pkceChallenge(verifier);
      }
    } else if (params.has("code") || params.has("error") || params.has("access_token") || params.has("id_token")) {
      if (!(params.has("state") || params.has("error_description") || params.has("access_token") || params.has("id_token") || params.has("session_state") || params.has("iss"))) return null;
      kind = params.has("error") ? "OAuth error callback" : "OAuth callback";
      if (url) info["Redirect URI"] = `${url.origin}${url.pathname}`;
      for (const k of ["code", "state", "iss", "session_state", "error", "error_description", "error_uri", "token_type", "expires_in", "scope"]) if (params.has(k)) info[k] = get(k);
      if (params.has("access_token")) info.access_token = `${get("access_token").slice(0, 12)}… (${get("access_token").length} characters)`;
      if (get("error")) add("fail", "error", OAUTH_ERRORS[get("error")] || "The server returned an error.");
      if (params.has("access_token") || params.has("id_token")) add(parsed.fragment ? "warn" : "fail", "Tokens in URL", "Tokens in the URL (implicit flow) end up in history and logs. Move to the code flow with PKCE.");
      if (params.has("code") && !params.has("state")) add("warn", "state", "No state came back: the client cannot check the callback belongs to its request.");
      if (params.has("iss")) add("pass", "iss", "The server names itself (RFC 9207), which protects against mix-up attacks.");
    } else return null;

    const layers = [{ type: kind, detail: info.Flow ? info.Flow.split(" (")[0] : info.grant_type || info.error || "Parameters", value: info, claims: true }];
    const known = new Set(Object.keys(info));
    const other = {};
    for (const [k, v] of params) if (!known.has(k) && k !== "client_secret") other[k] = v;
    if (Object.keys(other).length) layers.push({ type: "Other parameters", detail: `${Object.keys(other).length}`, value: other, claims: true });
    if (findings.length) layers.push({ type: "Checks", detail: "✓ pass · ! warning · ✗ failure · i note", value: findingsTable(findings), claims: true });
    const idToken = get("id_token");
    return { type: kind, confidence: 96, layers, notices: [], output: JSON.stringify(info, null, 2), check, idToken };
  }

  function analyzeTokenResponse(value) {
    if (!value || typeof value !== "object" || typeof value.access_token !== "string" || !value.token_type) return null;
    const info = { token_type: value.token_type };
    info.access_token = `${value.access_token.slice(0, 12)}… (${value.access_token.length} characters${value.access_token.split(".").length === 3 ? ", a JWT" : ", opaque"})`;
    if (value.expires_in !== undefined) info.expires_in = `${value.expires_in} s (${Math.round(Number(value.expires_in) / 60)} min)`;
    for (const k of ["scope", "refresh_token_expires_in", "issued_token_type"]) if (value[k] !== undefined) info[k] = String(value[k]);
    if (value.refresh_token) info.refresh_token = "(present, not shown)";
    if (value.id_token) info.id_token = "JWT (decoded below)";
    const findings = [];
    if (String(value.token_type).toLowerCase() !== "bearer" && String(value.token_type).toLowerCase() !== "dpop") findings.push({ level: "info", label: "token_type", text: `Unusual token type ${value.token_type}.` });
    if (Number(value.expires_in) > 86400) findings.push({ level: "warn", label: "expires_in", text: "The access token lives longer than a day; short lifetimes plus refresh tokens limit the damage of a leak." });
    const layers = [{ type: "Token response", detail: value.token_type, value: info, claims: true }];
    if (findings.length) layers.push({ type: "Checks", detail: "! warning · i note", value: findingsTable(findings), claims: true });
    const jwtAccess = value.access_token.split(".").length === 3 ? value.access_token : null;
    return { type: "OAuth token response", confidence: 97, layers, notices: [], output: JSON.stringify(info, null, 2), idToken: value.id_token || null, accessJwt: jwtAccess };
  }

  // -------------------------------------------------------------------- DNS

  const DNS_TYPES = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 64: "SVCB", 65: "HTTPS", 99: "SPF", 255: "ANY", 257: "CAA" };
  const RCODES = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"];
  const DNSSEC_ALGS = { 5: "RSASHA1", 7: "RSASHA1-NSEC3-SHA1", 8: "RSASHA256", 10: "RSASHA512", 13: "ECDSAP256SHA256", 14: "ECDSAP384SHA384", 15: "ED25519", 16: "ED448" };

  function dnsName(b, start) {
    const labels = [];
    let pos = start;
    let end = null;
    let jumps = 0;
    for (;;) {
      if (pos >= b.length) throw new Error("Name runs past the end");
      const len = b[pos];
      if ((len & 0xc0) === 0xc0) {
        if (pos + 1 >= b.length) throw new Error("Bad compression pointer");
        if (end === null) end = pos + 2;
        const target = ((len & 0x3f) << 8) | b[pos + 1];
        if (target >= pos || ++jumps > 64) throw new Error("Compression loop");
        pos = target;
        continue;
      }
      if (len & 0xc0) throw new Error("Bad label type");
      if (len === 0) { pos += 1; break; }
      if (pos + 1 + len > b.length) throw new Error("Label runs past the end");
      labels.push(Array.from(b.subarray(pos + 1, pos + 1 + len), (c) => (c > 32 && c < 127 && c !== 46 ? String.fromCharCode(c) : `\\${String(c).padStart(3, "0")}`)).join(""));
      pos += 1 + len;
      if (labels.join(".").length > 255) throw new Error("Name too long");
    }
    return [labels.length ? `${labels.join(".")}.` : ".", end === null ? pos : end];
  }

  const u16 = (b, p) => (b[p] << 8) | b[p + 1];
  const u32 = (b, p) => ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
  const dnsTime = (t) => new Date(t * 1000).toISOString().replace(/\.000Z$/, "Z");

  function rdataText(b, type, pos, len) {
    const end = pos + len;
    const r = b.subarray(pos, end);
    switch (type) {
      case 1: if (len !== 4) throw new Error("Bad A record"); return Array.from(r).join(".");
      case 28: if (len !== 16) throw new Error("Bad AAAA record"); return hex(r).match(/.{4}/g).join(":").replace(/(^|:)0{1,3}/g, "$1").replace(/(^|:)(0:)+/, "::").replace(/::+/, "::");
      case 2: case 5: case 12: return dnsName(b, pos)[0];
      case 15: return `${u16(b, pos)} ${dnsName(b, pos + 2)[0]}`;
      case 16: case 99: {
        const strings = [];
        let p = pos;
        while (p < end) { const n = b[p]; if (p + 1 + n > end) throw new Error("Bad TXT string"); strings.push(utf8(b.subarray(p + 1, p + 1 + n))); p += 1 + n; }
        return strings.map((s) => JSON.stringify(s)).join(" ");
      }
      case 33: return `${u16(b, pos)} ${u16(b, pos + 2)} ${u16(b, pos + 4)} ${dnsName(b, pos + 6)[0]}`;
      case 6: {
        const [mname, p1] = dnsName(b, pos);
        const [rname, p2] = dnsName(b, p1);
        return `${mname} ${rname} serial ${u32(b, p2)} refresh ${u32(b, p2 + 4)} retry ${u32(b, p2 + 8)} expire ${u32(b, p2 + 12)} minimum ${u32(b, p2 + 16)}`;
      }
      case 257: { const tagLen = r[1]; return `${r[0]} ${utf8(r.subarray(2, 2 + tagLen))} ${JSON.stringify(utf8(r.subarray(2 + tagLen)))}`; }
      case 43: return `key tag ${u16(r, 0)} · ${DNSSEC_ALGS[r[2]] || `alg ${r[2]}`} · digest ${({ 1: "SHA-1", 2: "SHA-256", 4: "SHA-384" })[r[3]] || r[3]} ${hex(r.subarray(4))}`;
      case 48: return `flags ${u16(r, 0)}${u16(r, 0) & 1 ? " (KSK)" : " (ZSK)"} · protocol ${r[2]} · ${DNSSEC_ALGS[r[3]] || `alg ${r[3]}`} · key ${bytesToBase64(r.subarray(4)).slice(0, 44)}…`;
      case 46: {
        const [signer, p] = dnsName(b, pos + 18);
        return `covers ${DNS_TYPES[u16(r, 0)] || u16(r, 0)} · ${DNSSEC_ALGS[r[2]] || `alg ${r[2]}`} · labels ${r[3]} · ttl ${u32(r, 4)} · valid ${dnsTime(u32(r, 12))} → ${dnsTime(u32(r, 8))} · key tag ${u16(r, 16)} · signer ${signer} · ${end - p} byte signature`;
      }
      case 64: case 65: {
        const [target] = dnsName(b, pos + 2);
        return `priority ${u16(b, pos)} target ${target}`;
      }
      default: return `\\# ${len} ${hex(r)}`;
    }
  }

  function parseDns(b) {
    if (b.length < 12) throw new Error("Shorter than a DNS header");
    const flags = u16(b, 2);
    const header = {
      id: u16(b, 0), qr: !!(flags & 0x8000), opcode: (flags >> 11) & 15, aa: !!(flags & 0x400), tc: !!(flags & 0x200),
      rd: !!(flags & 0x100), ra: !!(flags & 0x80), ad: !!(flags & 0x20), cd: !!(flags & 0x10), rcode: flags & 15,
      counts: [u16(b, 4), u16(b, 6), u16(b, 8), u16(b, 10)],
    };
    if (header.opcode > 6 || (flags & 0x40)) throw new Error("Invalid DNS flags");
    if (header.counts.reduce((a, c) => a + c, 0) > 1000) throw new Error("Implausible record counts");
    let pos = 12;
    const questions = [];
    for (let i = 0; i < header.counts[0]; i += 1) {
      const [name, p] = dnsName(b, pos);
      if (p + 4 > b.length) throw new Error("Question ends early");
      questions.push({ name, type: u16(b, p), cls: u16(b, p + 2) });
      pos = p + 4;
    }
    const sections = [[], [], []];
    for (let s = 0; s < 3; s += 1) {
      for (let i = 0; i < header.counts[s + 1]; i += 1) {
        const [name, p] = dnsName(b, pos);
        if (p + 10 > b.length) throw new Error("Record ends early");
        const type = u16(b, p);
        const cls = u16(b, p + 2);
        const ttl = u32(b, p + 4);
        const len = u16(b, p + 8);
        if (p + 10 + len > b.length) throw new Error("Record data ends early");
        const rec = { name, type, cls, ttl, len };
        if (type === 41) rec.opt = { udp: cls, extRcode: ttl >>> 24, version: (ttl >>> 16) & 255, dnssecOk: !!(ttl & 0x8000), options: len };
        else rec.data = rdataText(b, type, p + 10, len);
        sections[s].push(rec);
        pos = p + 10 + len;
      }
    }
    if (pos !== b.length) throw new Error("Trailing bytes after the DNS message");
    return { header, questions, sections };
  }

  function analyzeDns(bytes, { strict = true } = {}) {
    let msg;
    try { msg = parseDns(bytes); } catch { return null; }
    const { header, questions, sections } = msg;
    if (strict && (header.counts[0] !== 1 || questions[0].cls !== 1)) return null;
    const typeName = (t) => DNS_TYPES[t] || `TYPE${t}`;
    const q = questions[0];
    const flags = [["qr", "QR"], ["aa", "AA"], ["tc", "TC"], ["rd", "RD"], ["ra", "RA"], ["ad", "AD"], ["cd", "CD"]].filter(([k]) => header[k]).map(([, n]) => n).join(" ");
    const info = {
      Kind: header.qr ? "Response" : "Query",
      Question: q ? `${q.name} ${typeName(q.type)}` : "(none)",
      ID: String(header.id),
      Flags: flags || "(none)",
      Status: RCODES[header.rcode] || `RCODE ${header.rcode}`,
      Records: `${header.counts[1]} answer · ${header.counts[2]} authority · ${header.counts[3]} additional`,
    };
    const layers = [{ type: header.qr ? "DNS response" : "DNS query", detail: info.Status, value: info, claims: true }];
    const notices = [];
    const names = ["Answer", "Authority", "Additional"];
    sections.forEach((records, s) => {
      if (!records.length) return;
      const lines = records.map((r) => (r.opt
        ? `EDNS: UDP ${r.opt.udp} bytes${r.opt.dnssecOk ? ", DNSSEC OK" : ""}${r.opt.options ? `, ${r.opt.options} bytes of options` : ""}`
        : `${r.name} ${r.ttl} ${r.cls === 1 ? "IN" : `CLASS${r.cls}`} ${typeName(r.type)} ${r.data}`));
      layers.push({ type: `${names[s]} section`, detail: `${records.length} record${records.length === 1 ? "" : "s"}`, value: lines.join("\n") });
      for (const r of records) {
        if (r.type === 16 && r.data) {
          const txt = JSON.parse(`[${r.data.replace(/" "/g, '","')}]`).join("");
          const policy = analyzeMailRecord(txt);
          if (policy) layers.push(...policy.layers.map((l) => ({ ...l, type: `${l.type} (${r.name})` })));
        }
      }
    });
    if (header.tc) notices.push("TC is set: the answer was truncated and the client should retry over TCP.");
    if (header.qr && header.rcode === 3) notices.push("NXDOMAIN: the name does not exist.");
    if (header.qr && header.rcode === 2) notices.push("SERVFAIL: the resolver failed, often a DNSSEC validation failure or an unreachable authoritative server.");
    if (header.ad) notices.push("AD is set: the resolver says it validated the answer with DNSSEC.");
    return { type: header.qr ? "DNS response (wire format)" : "DNS query (wire format)", confidence: strict ? 90 : 97, layers, notices, output: layers.filter((l) => typeof l.value === "string").map((l) => l.value).join("\n") || info.Question };
  }

  // --------------------------------------------------- SPF / DMARC / DKIM

  function analyzeMailRecord(text) {
    const record = text.trim().replace(/^"|"$/g, "").replace(/"\s*"/g, "");
    const findings = [];
    const add = (level, label, t) => findings.push({ level, label, text: t });
    if (/^v=spf1(\s|$)/i.test(record)) {
      const terms = record.split(/\s+/).slice(1);
      const info = {};
      let lookups = 0;
      let all = null;
      const QUAL = { "+": "pass", "-": "fail", "~": "softfail", "?": "neutral" };
      for (const term of terms) {
        const m = term.match(/^([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists|redirect|exp)([:=/].*)?$/i);
        if (!m) { add("fail", term, "Unknown mechanism: receivers return permerror for the whole record."); continue; }
        const [, q, mech] = m;
        const lower = mech.toLowerCase();
        if (["include", "a", "mx", "ptr", "exists", "redirect"].includes(lower)) lookups += 1;
        if (lower === "all") all = q || "+";
        if (lower === "ptr") add("warn", "ptr", "ptr is slow and deprecated (RFC 7208); remove it.");
        const key = `${lower}${info[lower] !== undefined ? ` ${Object.keys(info).filter((k) => k.startsWith(lower)).length + 1}` : ""}`;
        info[key] = `${(m[3] || "").replace(/^[:=]/, "") || "(this domain)"}${lower === "redirect" || lower === "exp" ? "" : ` → ${QUAL[q || "+"]}`}`;
      }
      if (all === "+") add("fail", "all", "+all lets every server on the internet send as this domain.");
      else if (all === "?") add("warn", "all", "?all is neutral: receivers treat unlisted senders as unknown.");
      else if (all === "~") add("info", "all", "~all soft-fails unlisted senders; -all is stricter once all senders are listed.");
      else if (all === "-") add("pass", "all", "-all rejects unlisted senders.");
      else if (!terms.some((t) => /^redirect=/i.test(t))) add("warn", "all", "No all mechanism and no redirect: unlisted senders get a neutral result.");
      if (lookups > 10) add("fail", "Lookups", `${lookups} DNS lookups in this record alone; SPF allows 10 in total, so evaluation fails (permerror).`);
      else add(lookups > 7 ? "warn" : "pass", "Lookups", `${lookups} lookups in this record; includes add their own, and the total may not exceed 10.`);
      if (record.length > 255) add("info", "Length", "Longer than 255 characters: it must be published as several strings in one TXT record.");
      return { type: "SPF record", layers: [{ type: "SPF record", detail: `${terms.length} terms`, value: info, claims: true }, { type: "SPF checks", detail: "✓ pass · ! warning · ✗ failure · i note", value: findingsTable(findings), claims: true }] };
    }
    if (/^v=DMARC1\s*;/i.test(record)) {
      const tags = Object.fromEntries(record.split(";").map((p) => p.trim()).filter(Boolean).map((p) => [p.split("=")[0].trim().toLowerCase(), p.slice(p.indexOf("=") + 1).trim()]));
      const POLICY = { none: "none (monitor only: nothing is blocked)", quarantine: "quarantine (failing mail goes to spam)", reject: "reject (failing mail is refused)" };
      const info = { Policy: POLICY[tags.p] || `${tags.p} (invalid)` };
      if (tags.sp) info["Subdomain policy"] = POLICY[tags.sp] || tags.sp;
      info["Applies to"] = `${tags.pct || 100}% of failing mail`;
      info["DKIM alignment"] = tags.adkim === "s" ? "strict" : "relaxed";
      info["SPF alignment"] = tags.aspf === "s" ? "strict" : "relaxed";
      if (tags.rua) info["Aggregate reports to"] = tags.rua;
      if (tags.ruf) info["Failure reports to"] = tags.ruf;
      if (!tags.p || !POLICY[tags.p]) add("fail", "p", "The p tag is missing or invalid, so receivers ignore the record.");
      else if (tags.p === "none") add("warn", "p", "p=none only monitors. Move to quarantine, then reject, once the reports show legitimate mail passes.");
      else add("pass", "p", `p=${tags.p} protects the domain against spoofing.`);
      if (tags.pct && Number(tags.pct) < 100) add("info", "pct", `Only ${tags.pct}% of failing mail gets the policy.`);
      if (!tags.rua) add("info", "rua", "No aggregate report address: you will not see who sends as this domain.");
      return { type: "DMARC record", layers: [{ type: "DMARC record", detail: tags.p || "no policy", value: info, claims: true }, { type: "DMARC checks", detail: "✓ pass · ! warning · ✗ failure · i note", value: findingsTable(findings), claims: true }] };
    }
    if (/^v=DKIM1\s*;/i.test(record) || /(^|;)\s*k=(rsa|ed25519)\s*;.*\bp=/i.test(record)) {
      const tags = Object.fromEntries(record.split(";").map((p) => p.trim()).filter(Boolean).map((p) => [p.split("=")[0].trim().toLowerCase(), p.slice(p.indexOf("=") + 1).replace(/\s+/g, "")]));
      const info = { "Key type": tags.k || "rsa" };
      if (!tags.p) add("warn", "p", "Empty p=: this key has been revoked.");
      else if ((tags.k || "rsa") === "rsa") {
        try {
          const key = T.analyzePem(`-----BEGIN PUBLIC KEY-----\n${tags.p}\n-----END PUBLIC KEY-----`);
          const desc = key.layers[0].value.Key;
          info.Key = desc;
          const size = parseInt((desc.match(/(\d+)-bit/) || [])[1], 10);
          if (size < 1024) add("fail", "Key size", `${size}-bit keys are rejected by major receivers.`);
          else if (size < 2048) add("warn", "Key size", `${size}-bit works but 2048-bit is the recommended minimum.`);
          else add("pass", "Key size", `${size}-bit.`);
        } catch { add("fail", "p", "The public key is not valid Base64 SubjectPublicKeyInfo."); }
      } else info.Key = `${base64ToBytes(tags.p).length * 8}-bit Ed25519`;
      if (tags.t) info.Flags = tags.t.split(":").map((f) => (f === "y" ? "y (testing: receivers may ignore failures)" : f === "s" ? "s (no subdomains)" : f)).join(", ");
      if (tags.h) info["Hash algorithms"] = tags.h;
      if (/y/.test(tags.t || "")) add("info", "t", "Testing mode is on.");
      return { type: "DKIM record", layers: [{ type: "DKIM key record", detail: info.Key || "revoked", value: info, claims: true }, { type: "DKIM checks", detail: "✓ pass · ! warning · ✗ failure · i note", value: findingsTable(findings), claims: true }] };
    }
    return null;
  }

  function analyzeMailPolicy(text) {
    const r = analyzeMailRecord(text);
    if (!r) return null;
    return { type: r.type, confidence: 98, layers: r.layers, notices: ["Only this record is analysed; decoder.in does not look anything up in DNS."], output: text.trim() };
  }

  // ---------------------------------------------------------------- inputs

  function hexToBytes(text, { loose = false } = {}) {
    const trimmed = text.trim().replace(/^0x/i, "");
    const separated = /^[0-9a-fA-F]{2}(?:[\s:,-]+[0-9a-fA-F]{2})+$/.test(trimmed);
    if (!separated && !(loose && /^(?:[0-9a-fA-F]{2})+$/.test(trimmed))) return null;
    const clean = trimmed.replace(/[\s:,-]+/g, "");
    return Uint8Array.from(clean.match(/.{2}/g), (h) => parseInt(h, 16));
  }

  function dohUrl(raw) {
    let url;
    try { url = new URL(raw); } catch { return null; }
    const dns = url.searchParams.get("dns");
    if (!dns) return null;
    try { return analyzeDns(base64ToBytes(dns), { strict: false }); } catch { return null; }
  }

  return {
    md5, parseSshBlob, analyzeSshLines, analyzeOpensshPrivate, parseProtobuf, analyzeProtobuf, decodeCbor, parseAuthData,
    analyzeWebAuthn, jwkThumbprint, jwkToSpki, analyzeJwk, analyzeJwe, analyzeOAuth, analyzeTokenResponse, pkceChallenge,
    parseDns, analyzeDns, analyzeMailRecord, analyzeMailPolicy, hexToBytes, dohUrl, cborDisplay,
  };
});
