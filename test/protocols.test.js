const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const P = require("../public/protocols.js");
const { analyze } = require("../public/decoder.js");
const E = require("../build/encoders.js");

const ssh = (name) => fs.readFileSync(path.join(__dirname, "fixtures", "ssh", name), "utf8").trim();
const results = [];
async function test(name, fn) {
  try { await fn(); results.push(["ok", name]); } catch (error) { results.push(["FAIL", name, error]); }
}
const layer = (r, prefix) => r.layers.find((l) => l.type.startsWith(prefix));

(async () => {
  // ------------------------------------------------------------------- SSH
  const expected = Object.fromEntries(ssh("fingerprints.txt").split("\n").map((line) => {
    const [name, rest] = [line.slice(0, line.indexOf(" ")), line.slice(line.indexOf(" ") + 1)];
    return [name, { sha256: rest.match(/SHA256:\S+/)[0], md5: rest.match(/MD5:\S+/)[0] }];
  }));

  await test("md5 matches node crypto", () => {
    for (const size of [0, 1, 55, 56, 64, 100, 1000]) {
      const data = crypto.randomBytes(size);
      assert.equal(Buffer.from(P.md5(data)).toString("hex"), crypto.createHash("md5").update(data).digest("hex"));
    }
  });

  await test("SSH public keys: types, sizes and fingerprints match ssh-keygen", () => {
    for (const [file, key, desc] of [["ed25519.pub", "ed25519", "Ed25519 (256-bit)"], ["rsa3072.pub", "rsa3072", "RSA 3072-bit"], ["ecdsa384.pub", "ecdsa384", "ECDSA nistp384 (384-bit)"], ["rsa1024.pub", "rsa1024", "RSA 1024-bit"]]) {
      const r = analyze(ssh(file));
      assert.equal(r.type, "SSH public key", file);
      const info = r.layers[0].value;
      assert.equal(info.Key, desc, file);
      assert.equal(info["SHA256 fingerprint"], expected[key].sha256, file);
      assert.equal(info["MD5 fingerprint"], expected[key].md5, file);
    }
    assert.equal(analyze(ssh("ed25519.pub")).layers[0].value.Comment, "ada@laptop");
    assert.match(layer(analyze(ssh("rsa1024.pub")), "Checks").value["✗ Key"], /too weak/);
  });

  await test("known_hosts and authorized_keys lines", () => {
    const kh = analyze(ssh("known_hosts")).layers[0].value;
    assert.equal(kh["Known host"], "github.com, 140.82.121.4");
    assert.equal(kh["SHA256 fingerprint"], expected.ecdsa384.sha256);
    const ak = analyze(ssh("authorized_keys"));
    assert.match(ak.layers[0].value["authorized_keys options"], /command="\/usr\/bin\/backup"/);
    assert.match(layer(ak, "Checks").value["i Key"], /Forced command/);
    const both = analyze(`${ssh("ed25519.pub")}\n# comment\n${ssh("rsa3072.pub")}`);
    assert.equal(both.type, "SSH public keys (2)");
  });

  await test("SSH certificate: principals, validity, CA", () => {
    const r = analyze(ssh("ed25519-cert.pub"), Date.parse("2026-12-01T00:00:00Z"));
    assert.equal(r.type, "SSH certificate");
    const info = r.layers[0].value;
    assert.equal(info["SHA256 fingerprint"], expected["ed25519-cert"].sha256);
    assert.equal(info["Key ID"], "ada-2026");
    assert.equal(info.Principals, "ada, deploy");
    assert.match(info.Certificate, /^user certificate, valid/);
    assert.match(info.Extensions, /permit-pty/);
    assert.equal(new Date(info["Valid until"]) - new Date(info["Valid from"]), 365 * 86400000);
    assert.match(analyze(ssh("ed25519-cert.pub"), Date.parse("2028-01-01T00:00:00Z")).layers[0].value.Certificate, /expired/);
  });

  await test("OpenSSH private keys: public half only, encryption reported", () => {
    const plain = analyze(ssh("ed25519.private"));
    assert.equal(plain.type, "OpenSSH private key");
    assert.equal(plain.layers[0].value["SHA256 fingerprint"], expected.ed25519.sha256);
    assert.match(plain.layers[0].value.Protection, /NOT encrypted/);
    const enc = analyze(ssh("enc.private"));
    assert.match(enc.layers[0].value.Protection, /Encrypted with aes256-ctr/);
    const privateBody = ssh("ed25519.private").split("\n").slice(1, -1).join("");
    assert.ok(!JSON.stringify(plain).includes(privateBody.slice(-40)), "private key data must not be echoed");
  });

  // -------------------------------------------------------------- protobuf
  const sample = E.protobuf([
    [1, "varint", 150], [2, "string", "Ada Lovelace"], [3, "message", [[1, "varint", 1], [2, "string", "admin"]]],
    [4, "double", 1.5], [5, "float", 0.25], [6, "varint", -1], [7, "bytes", Buffer.from([0xff, 0x00, 0x10, 0x80])], [8, "varint", 3],
  ]);

  await test("protobuf wire format decodes like protoc --decode_raw", () => {
    const r = analyze(sample.toString("base64"));
    assert.equal(r.type, "Protocol Buffers (raw)");
    const text = layer(r, "Decoded fields").value;
    for (const line of ["1: 150  # sint 75", '2: "Ada Lovelace"', "3 {", '  2: "admin"', "4: 0x3ff8000000000000  # double 1.5", "5: 0x3e800000  # float 0.25", "6: 18446744073709551615  # int64 -1", "7: bytes ff001080 (4)"]) {
      assert.ok(text.includes(line), `missing: ${line}\n${text}`);
    }
  });

  await test("protobuf from hex, and the page hint accepts short messages", () => {
    assert.equal(analyze("08 96 01 12 03 61 62 63").type, "Protocol Buffers (raw)");
    assert.equal(analyze("089601", Date.now(), { tool: "protobuf" }).type, "Protocol Buffers (raw)");
    assert.notEqual(analyze("089601").type, "Protocol Buffers (raw)");
    assert.equal(analyze("hello world").type, "Plain text");
  });

  await test("protobuf parser rejects garbage", () => {
    let accepted = 0;
    for (let i = 0; i < 300; i += 1) if (P.analyzeProtobuf(crypto.randomBytes(40))) accepted += 1;
    assert.ok(accepted < 6, `${accepted} random buffers accepted`);
  });

  // ------------------------------------------------------------------ CBOR
  await test("CBOR round trip against the encoder", () => {
    const value = new Map([["a", 1], ["neg", -500], [3, [true, false, null, "x"]], ["b", Buffer.from([1, 2, 3])], [-2, new Map([["k", 70000]])]]);
    const [decoded, end] = P.decodeCbor(E.cbor(value));
    assert.equal(end, E.cbor(value).length);
    assert.equal(decoded.get("neg"), -500);
    assert.deepEqual(decoded.get(3), [true, false, null, "x"]);
    assert.deepEqual(Array.from(decoded.get("b")), [1, 2, 3]);
    assert.equal(decoded.get(-2).get("k"), 70000);
  });

  // -------------------------------------------------------------- WebAuthn
  await test("WebAuthn registration JSON: client data, flags, AAGUID, COSE key", () => {
    const reg = E.webauthnRegistration();
    const r = analyze(JSON.stringify(reg.json));
    assert.equal(r.type, "WebAuthn registration");
    assert.equal(layer(r, "Client data").value.Origin, "https://example.com");
    const auth = layer(r, "Authenticator data").value;
    assert.equal(auth["RP ID"], "example.com (matches the hash)");
    assert.match(auth.Flags, /UP user present · UV user verified · BE backup eligible · BS backed up · AT credential data/);
    const cred = layer(r, "Attested credential").value;
    assert.match(cred.AAGUID, /Google Password Manager/);
    assert.match(cred["Public key"], /EC2 P-256 · ES256/);
    const pem = cred["Public key (PEM)"];
    assert.equal(crypto.createPublicKey(pem).export({ format: "jwk" }).x, reg.jwk.x);
    assert.match(layer(r, "Checks").value["i Backup"], /synced passkey/);
  });

  await test("WebAuthn: RP ID mismatch, missing UV, attestation object and authData alone", () => {
    const reg = E.webauthnRegistration({ rpId: "evil.test", flags: 0x41 });
    const r = analyze(JSON.stringify(reg.json));
    assert.match(layer(r, "Checks").value["✗ RP ID"], /matches neither/);
    assert.match(layer(r, "Checks").value["! UV"], /not performed/);
    assert.equal(analyze(Buffer.from(reg.attestationObject).toString("base64url")).type, "WebAuthn attestation object");
    assert.equal(analyze(Buffer.from(reg.authData).toString("base64"), Date.now(), { tool: "webauthn" }).type, "WebAuthn authenticator data");
    const client = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: "AAAA", origin: "http://example.com" })).toString("base64url");
    const cd = analyze(client);
    assert.equal(cd.type, "WebAuthn client data");
    assert.match(layer(cd, "Checks").value["✗ Origin"], /HTTPS/);
  });

  // ------------------------------------------------------------ OAuth/PKCE
  await test("PKCE challenge matches RFC 7636 appendix B", () => {
    assert.equal(P.pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  await test("authorization request: good code+PKCE flow and a bad implicit one", () => {
    const good = analyze("https://auth.example.com/authorize?response_type=code&client_id=app1&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=openid%20email&state=9f8e7d6c5b4a39281706&nonce=n-0S6_WzA2Mj&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256");
    assert.equal(good.type, "OAuth authorization request");
    assert.equal(good.check.kind, "pkce");
    const checks = layer(good, "Checks").value;
    assert.ok(Object.keys(checks).every((k) => k.startsWith("✓")), JSON.stringify(checks));
    const bad = analyze("https://auth.example.com/authorize?response_type=id_token%20token&client_id=app1&redirect_uri=http://app.example.com/cb&scope=openid&client_secret=hunter2");
    const b = layer(bad, "Checks").value;
    for (const key of ["✗ Flow", "✗ state", "✗ redirect_uri", "✗ nonce", "✗ client_secret"]) assert.ok(b[key], `${key} in ${JSON.stringify(b)}`);
    assert.match(analyze("https://a.test/authorize?response_type=code&client_id=x&state=aaaaaaaaaaaaaaaaaaaa&code_challenge=abc&code_challenge_method=plain").layers.find((l) => l.type === "Checks").value["✗ PKCE"], /plain/);
  });

  await test("callbacks, errors, token requests and token responses", () => {
    const err = analyze("https://app.example.com/cb?error=invalid_scope&error_description=bad%20scope&state=xyz");
    assert.equal(err.type, "OAuth error callback");
    assert.match(layer(err, "Checks").value["✗ error"], /scope is unknown/);
    const implicit = analyze("https://app.example.com/cb#access_token=abc123&token_type=Bearer&expires_in=3600&state=xyz");
    assert.match(layer(implicit, "Checks").value["! Tokens in URL"], /history/);
    const tokenReq = analyze("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&client_id=app1");
    assert.equal(tokenReq.type, "OAuth token request");
    assert.equal(tokenReq.layers[0].value["Matching code_challenge (S256)"], "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    const b64 = (v) => Buffer.from(JSON.stringify(v)).toString("base64url");
    const idToken = `${b64({ alg: "RS256", kid: "k1" })}.${b64({ iss: "https://auth.example.com", sub: "42", aud: "app1", exp: 2082758400 })}.sig`;
    const resp = analyze(JSON.stringify({ access_token: "opaque-abc", token_type: "Bearer", expires_in: 3600, id_token: idToken, refresh_token: "r" }));
    assert.equal(resp.type, "OAuth token response");
    assert.equal(layer(resp, "ID token claims").value.sub, "42");
    assert.equal(resp.jwt, idToken);
    assert.ok(!JSON.stringify(resp.layers).includes('"r"'), "refresh token must not be shown");
    assert.equal(analyze("https://example.com/search?q=hello&page=2").type, "URL");
  });

  // -------------------------------------------------------------- JWE / JWK
  const b64 = (v) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url");
  const rand = (n) => crypto.randomBytes(n).toString("base64url");

  await test("JWE envelope: sizes, checks and nested JWT", () => {
    const jwe = [b64({ alg: "RSA-OAEP-256", enc: "A256GCM", kid: "enc-1", cty: "JWT" }), rand(256), rand(12), rand(300), rand(16)].join(".");
    const r = analyze(jwe);
    assert.equal(r.type, "JWE (encrypted token)");
    const env = layer(r, "Encryption envelope").value;
    assert.match(env["Encrypted key"], /256 bytes \(fits a 2048-bit RSA key\)/);
    assert.equal(env.Ciphertext, "300 bytes");
    assert.match(layer(r, "Checks").value["✓ IV"], /12 bytes/);
    assert.ok(r.notices.some((n) => /nested inside/.test(n)));
    const badIv = [b64({ alg: "dir", enc: "A128CBC-HS256" }), "", rand(12), rand(64), rand(16)].join(".");
    assert.match(layer(analyze(badIv), "Checks").value["✗ IV"], /16-byte IV/);
    const ecdh = [b64({ alg: "ECDH-ES+A256KW", enc: "A256GCM", epk: { kty: "EC", crv: "P-256", x: "a", y: "b" } }), rand(40), rand(12), rand(20), rand(16)].join(".");
    assert.equal(layer(analyze(ecdh), "Ephemeral public key").value.crv, "P-256");
  });

  await test("JWK thumbprint matches RFC 7638, PEM export matches node", () => {
    // RFC 7638 section 3.1 example key and thumbprint.
    const rfc = { kty: "RSA", e: "AQAB", alg: "RS256", kid: "2011-04-29",
      n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw" };
    assert.equal(P.jwkThumbprint(rfc), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    for (const [type, opts] of [["rsa", { modulusLength: 2048 }], ["ec", { namedCurve: "P-384" }], ["ed25519", {}]]) {
      const { publicKey } = crypto.generateKeyPairSync(type, opts);
      const jwk = publicKey.export({ format: "jwk" });
      const r = analyze(JSON.stringify({ keys: [{ ...jwk, kid: "a", use: "sig" }] }));
      assert.equal(layer(r, "Public key as PEM").value.trim(), publicKey.export({ type: "spki", format: "pem" }).trim(), type);
    }
  });

  await test("JWKS with private material, duplicate kids and x5c", () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const leaked = analyze(JSON.stringify({ keys: [{ ...privateKey.export({ format: "jwk" }), kid: "x" }, { ...publicKey.export({ format: "jwk" }), kid: "x" }] }));
    const checks = layer(leaked, "Checks").value;
    assert.match(checks["✗ Key 1 (x): Secret material"], /compromised/);
    assert.match(checks["! kid"], /appears 2 times/);
    assert.ok(!JSON.stringify(leaked.layers).includes(privateKey.export({ format: "jwk" }).d));
    const pemCert = fs.readFileSync(path.join(__dirname, "fixtures", "ec-leaf.pem"), "utf8");
    const der = pemCert.replace(/-----[^-]+-----|\s/g, "");
    const leafJwk = crypto.createPublicKey(pemCert).export({ format: "jwk" });
    const withCert = analyze(JSON.stringify({ ...leafJwk, kid: "leaf", x5c: [der] }), Date.parse("2026-10-01T00:00:00Z"));
    assert.match(withCert.layers[0].value["Certificate (x5c)"], /CN=api\.example\.test/);
  });

  // ------------------------------------------------------------------- DNS
  await test("DNS: RFC 8484 example query, from Base64URL and from a DoH URL", () => {
    const q = analyze("AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB");
    assert.equal(q.type, "DNS query (wire format)");
    assert.equal(q.layers.find((l) => l.type === "DNS query").value.Question, "www.example.com. A");
    const doh = analyze("https://dns.example.net/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB");
    assert.equal(doh.layers[0].type, "DoH request");
  });

  await test("DNS response with compression, MX, TXT policies, AAAA and CAA", () => {
    const msg = E.dnsMessage({ id: 4242, response: true, ra: true, ad: true, question: ["example.com", "TXT"], answers: [
      ["example.com", "TXT", 300, "v=spf1 include:_spf.google.com ip4:192.0.2.0/24 ~all"],
      ["example.com", "MX", 3600, [10, "mail.example.com"]],
      ["example.com", "AAAA", 60, "2001:db8:0:0:0:0:0:1"],
      ["example.com", "CAA", 3600, [0, "issue", "letsencrypt.org"]],
      ["_dmarc.example.com", "TXT", 300, "v=DMARC1; p=none; rua=mailto:d@example.com"],
    ] });
    const r = analyze(msg.toString("base64"));
    assert.equal(r.type, "DNS response (wire format)");
    const answers = layer(r, "Answer section").value;
    assert.match(answers, /example\.com\. 3600 IN MX 10 mail\.example\.com\./);
    assert.match(answers, /AAAA 2001:db8::1/);
    assert.match(answers, /CAA 0 issue "letsencrypt\.org"/);
    assert.ok(r.layers.some((l) => l.type === "SPF record (example.com.)"));
    assert.match(r.layers.find((l) => l.type === "DMARC checks (_dmarc.example.com.)").value["! p"], /only monitors/);
    assert.ok(r.notices.some((n) => /DNSSEC/.test(n)));
    const nx = E.dnsMessage({ response: true, rcode: 3, question: ["nope.example", "A"] });
    assert.ok(analyze(nx.toString("hex").match(/.{2}/g).join(" ")).notices.some((n) => /NXDOMAIN/.test(n)));
  });

  await test("SPF, DMARC and DKIM records pasted as text", () => {
    const spf = analyze("v=spf1 a mx ptr include:a.test include:b.test include:c.test include:d.test include:e.test include:f.test include:g.test include:h.test +all");
    assert.equal(spf.type, "SPF record");
    const c = layer(spf, "SPF checks").value;
    assert.match(c["✗ all"], /every server/);
    assert.match(c["✗ Lookups"], /11 DNS lookups/);
    assert.match(c["! ptr"], /deprecated/);
    const dmarc = analyze("v=DMARC1; p=reject; pct=50; rua=mailto:r@example.com; adkim=s");
    assert.equal(layer(dmarc, "DMARC record").value["DKIM alignment"], "strict");
    const { publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
    const p = publicKey.export({ type: "spki", format: "der" }).toString("base64");
    const dkim = analyze(`v=DKIM1; k=rsa; t=y; p=${p}`);
    assert.equal(layer(dkim, "DKIM key record").value.Key, "RSA 1024-bit");
    assert.match(layer(dkim, "DKIM checks").value["! Key size"], /2048/);
  });

  await test("DNS parser rejects random bytes", () => {
    let accepted = 0;
    for (let i = 0; i < 300; i += 1) if (P.analyzeDns(crypto.randomBytes(48))) accepted += 1;
    assert.equal(accepted, 0);
  });

  // ---------------------------------------------------------- regressions
  await test("batch 1 formats still win on their inputs", () => {
    assert.equal(analyze("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln").type, "JSON Web Token");
    assert.equal(analyze('{"ok":true}').type, "JSON");
    assert.equal(analyze("SGVsbG8sIGRlY29kZXIu").type, "Base64");
    assert.equal(analyze("1704067200").type, "Unix timestamp");
    assert.equal(analyze("507f1f77bcf86cd799439011").type, "MongoDB ObjectId");
  });

  let failed = 0;
  for (const [status, name, error] of results) {
    console.log(`${status === "ok" ? "  ok  " : "  FAIL"} ${name}`);
    if (error) { failed += 1; console.log(`       ${String(error.stack || error).split("\n").slice(0, 5).join("\n       ")}`); }
  }
  console.log(`\n${results.length - failed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
