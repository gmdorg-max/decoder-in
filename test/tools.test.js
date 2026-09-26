const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");
const Tools = require("../public/tools.js");
const { analyze } = require("../public/decoder.js");

const fixture = (name) => fs.readFileSync(path.join(__dirname, "fixtures", name), "utf8");
const results = [];
async function test(name, fn) {
  try { await fn(); results.push(["ok", name]); } catch (error) { results.push(["FAIL", name, error]); }
}

(async () => {
  // ---------------------------------------------------------------- hashes
  await test("sha1 and sha256 match node crypto on random inputs", () => {
    for (const size of [0, 1, 55, 56, 63, 64, 65, 119, 1000, 4097]) {
      const data = crypto.randomBytes(size);
      assert.equal(Tools.hex(Tools.sha256(data)), crypto.createHash("sha256").update(data).digest("hex"), `sha256 ${size}`);
      assert.equal(Tools.hex(Tools.sha1(data)), crypto.createHash("sha1").update(data).digest("hex"), `sha1 ${size}`);
    }
  });

  // --------------------------------------------------------------- inflate
  await test("inflate matches zlib for raw, zlib and gzip at several levels", () => {
    const samples = [
      Buffer.from(""), Buffer.from("a"), Buffer.from("hello hello hello hello"),
      crypto.randomBytes(5000), Buffer.from("<xml>" + "abc123".repeat(4000) + "</xml>"),
      Buffer.from(JSON.stringify({ items: Array.from({ length: 300 }, (_, i) => ({ i, name: `item-${i % 17}` })) })),
    ];
    for (const sample of samples) {
      for (const level of [0, 1, 6, 9]) {
        const raw = zlib.deflateRawSync(sample, { level });
        assert.deepEqual(Buffer.from(Tools.inflateRaw(raw).bytes), sample, `raw level ${level} len ${sample.length}`);
        if (sample.length) {
          assert.deepEqual(Buffer.from(Tools.decompress(zlib.gzipSync(sample, { level })).bytes), sample, `gzip ${level}`);
          assert.deepEqual(Buffer.from(Tools.decompress(zlib.deflateSync(sample, { level })).bytes), sample, `zlib ${level}`);
        }
      }
    }
  });

  await test("inflate rejects garbage and truncated streams without hanging", () => {
    const good = zlib.deflateRawSync(Buffer.from("x".repeat(10000)));
    assert.throws(() => Tools.inflateRaw(good.subarray(0, good.length - 3)));
    for (let i = 0; i < 200; i += 1) {
      try { Tools.inflateRaw(crypto.randomBytes(64)); } catch { /* expected for most */ }
    }
  });

  await test("inflate caps output (compression bomb)", () => {
    const bomb = zlib.deflateRawSync(Buffer.alloc(20 * 1024 * 1024));
    assert.throws(() => Tools.inflateRaw(bomb), /exceeds 8 MB/);
  });

  await test("padded gzip cannot bypass the inflate cap", () => {
    // 9 MB of zeros gzips to a few KB; padding the input to 3 MB used to size the
    // output buffer at 12 MB up front, so the 8 MB cap never fired.
    const member = zlib.gzipSync(Buffer.alloc(9 * 1024 * 1024));
    const padded = Buffer.concat([member, Buffer.alloc(3 * 1024 * 1024, 0x41)]);
    assert.equal(Tools.decompress(padded), null);
    assert.throws(() => Tools.inflateRaw(padded, 10), /exceeds 8 MB/);
    const small = zlib.gzipSync(Buffer.from("hello"));
    assert.equal(Buffer.from(Tools.decompress(Buffer.concat([small, Buffer.alloc(1024, 0x41)])).bytes).toString(), "hello");
  });

  await test("gzip Base64 pastes are decompressed by the auto-detect", () => {
    const text = JSON.stringify({ ok: true, user: "ada", roles: ["admin", "ops"] });
    const result = analyze(zlib.gzipSync(text).toString("base64"));
    assert.equal(result.type, "Compressed data");
    assert.ok(result.layers.some((l) => l.type === "gzip decompressed"));
    assert.ok(result.layers.some((l) => l.type === "JSON" && l.value.user === "ada"));
  });

  // ---------------------------------------------------------- certificates
  const now = Date.parse("2026-10-01T00:00:00Z");
  const openssl = (name) => Object.fromEntries(fixture(name).trim().split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));

  await test("RSA self-signed certificate matches openssl", () => {
    const expected = openssl("rsa-selfsigned.openssl.txt");
    const result = analyze(fixture("rsa-selfsigned.pem"), now);
    assert.equal(result.type, "X.509 certificate");
    const summary = result.layers[0].value;
    assert.equal(summary.Subject, "example.test");
    assert.equal(summary.Domains, "example.test, www.example.test, IP:192.0.2.10");
    assert.equal(summary.Key, "RSA 2048-bit");
    assert.equal(summary.Signature, "sha256WithRSAEncryption");
    assert.equal(summary["SHA-256 fingerprint"], expected["sha256 Fingerprint"]);
    assert.equal(result.layers[1].value.Serial.replace(/:/g, "").toUpperCase().replace(/^0+/, ""), expected.serial.replace(/^0+/, ""));
    assert.equal(new Date(summary["Valid until"]).getTime(), Date.parse(expected.notAfter));
    assert.ok(result.notices.some((n) => /self-signed/.test(n)));
  });

  await test("chain: EC leaf plus root, extensions, order check", () => {
    const expected = openssl("ec-leaf.openssl.txt");
    const result = analyze(fixture("chain.pem"), now);
    assert.equal(result.type, "Certificate chain (2)");
    const leaf = result.layers[0].value;
    assert.equal(leaf.Key, "EC P-256");
    assert.equal(leaf.Signature, "ecdsa-with-SHA256");
    assert.equal(leaf.Issuer, "Decoder Test Root");
    assert.equal(leaf.Type, "Leaf certificate");
    assert.equal(leaf["SHA-256 fingerprint"], expected["sha256 Fingerprint"]);
    const details = result.layers[1].value;
    assert.equal(details["Extended key usage"], "TLS server");
    assert.match(details["Authority information access"], /OCSP: http:\/\/ocsp\.example\.test/);
    const root = result.layers[2].value;
    assert.equal(root.Type, "Root CA (self-signed)");
    assert.match(result.layers[3].value["Key usage (critical)"], /keyCertSign/);
    assert.ok(!result.notices.some((n) => /Chain order/.test(n)));
    const reversed = analyze(fixture("ca.pem") + "\n" + fixture("ec-leaf.pem"), now);
    assert.ok(reversed.notices.some((n) => /Chain order/.test(n)));
  });

  await test("expired and not-yet-valid certificates are flagged", () => {
    const later = analyze(fixture("ec-leaf.pem"), Date.parse("2027-06-01T00:00:00Z"));
    assert.match(later.layers[0].value.Status, /^Expired/);
    assert.ok(later.notices.some((n) => /expired/.test(n)));
    const earlier = analyze(fixture("ec-leaf.pem"), Date.parse("2020-01-01T00:00:00Z"));
    assert.match(earlier.layers[0].value.Status, /^Not valid for another/);
  });

  await test("CSR, public key, private key and bare DER", () => {
    const csr = analyze(fixture("ec.csr.pem"), now);
    assert.equal(csr.type, "Certificate signing request");
    assert.equal(csr.layers[0].value["Requested domains"], "api.example.test");
    const pub = analyze(fixture("ec-public.pem"), now);
    assert.equal(pub.type, "Public key");
    assert.equal(pub.layers[0].value.Key, "EC P-256");
    const priv = analyze(fixture("ec-private.pem"), now);
    assert.equal(priv.type, "Private key");
    assert.ok(!JSON.stringify(priv).includes(fixture("ec-private.pem").split("\n")[1]), "private key bytes must not be echoed");
    const der = analyze(fixture("rsa-selfsigned.der.b64"), now);
    assert.equal(der.type, "X.509 certificate");
    assert.equal(der.layers[0].value.Subject, "example.test");
  });

  await test("SPKI pin matches openssl-style pin-sha256", () => {
    const pem = fixture("ec-public.pem");
    const der = crypto.createPublicKey(pem).export({ type: "spki", format: "der" });
    const pin = crypto.createHash("sha256").update(der).digest("base64");
    assert.equal(analyze(pem, now).layers[0].value["SPKI pin (sha256)"], pin);
  });

  // ------------------------------------------------------------------ SAML
  const authnRequest = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1b2" Version="2.0" IssueInstant="2026-09-26T08:00:00Z" Destination="https://idp.example.test/sso" AssertionConsumerServiceURL="https://sp.example.test/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>https://sp.example.test</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>`;
  const response = `<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" InResponseTo="_a1b2" Version="2.0" IssueInstant="2026-09-26T08:00:05Z" Destination="https://sp.example.test/acs"><saml:Issuer>https://idp.example.test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_as1" Version="2.0" IssueInstant="2026-09-26T08:00:05Z"><saml:Issuer>https://idp.example.test</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">ada@example.test</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2026-09-26T08:05:05Z" Recipient="https://sp.example.test/acs" InResponseTo="_a1b2"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2026-09-26T07:59:35Z" NotOnOrAfter="2026-09-26T08:05:05Z"><saml:AudienceRestriction><saml:Audience>https://sp.example.test</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2026-09-26T08:00:04Z" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" FriendlyName="mail"><saml:AttributeValue>ada@example.test</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue>admins</saml:AttributeValue><saml:AttributeValue>ops &amp; on-call</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`;
  const samlNow = Date.parse("2026-09-26T08:01:00Z");

  await test("SAML redirect-binding URL (deflate + Base64 + URL encoding)", () => {
    const value = zlib.deflateRawSync(Buffer.from(authnRequest)).toString("base64");
    const url = `https://idp.example.test/sso?SAMLRequest=${encodeURIComponent(value)}&RelayState=%2Fdashboard`;
    const result = analyze(url, samlNow);
    assert.equal(result.type, "SAML AuthnRequest");
    assert.equal(result.layers[0].type, "Transport");
    assert.match(result.layers[0].detail, /deflate inflated/);
    assert.equal(result.layers[0].value.RelayState, "/dashboard");
    const summary = result.layers[1].value;
    assert.equal(summary.Issuer, "https://sp.example.test");
    assert.equal(summary.AssertionConsumerServiceURL, "https://sp.example.test/acs");
    assert.equal(summary["Requested NameID format"], "emailAddress");
  });

  await test("bare SAMLRequest value is inflated by the auto-detect", () => {
    const value = encodeURIComponent(zlib.deflateRawSync(Buffer.from(authnRequest)).toString("base64"));
    assert.equal(analyze(value, samlNow).type, "SAML AuthnRequest");
  });

  await test("SAML POST response: status, subject, conditions, attributes", () => {
    const result = analyze(Buffer.from(response).toString("base64"), samlNow);
    assert.equal(result.type, "SAML Response");
    const summary = result.layers.find((l) => l.type === "SAML Response").value;
    assert.equal(summary.Status, "Success");
    assert.equal(summary.InResponseTo, "_a1b2");
    const assertion = result.layers.find((l) => l.type === "Assertion").value;
    assert.equal(assertion.NameID, "ada@example.test");
    assert.equal(assertion.Audience, "https://sp.example.test");
    assert.equal(assertion.Signed, "No");
    const attributes = result.layers.find((l) => l.type === "Attributes").value;
    assert.equal(attributes.mail, "ada@example.test");
    assert.equal(attributes.groups, "admins, ops & on-call");
    assert.ok(result.notices.some((n) => /Neither the response nor the assertion/.test(n)));
    const late = analyze(response, Date.parse("2026-09-26T09:00:00Z"));
    assert.ok(late.notices.some((n) => /has passed/.test(n)));
  });

  await test("failed SAML status and plain XML", () => {
    const failed = response.replace("status:Success", "status:Responder");
    assert.ok(analyze(failed, samlNow).notices.some((n) => /did not succeed/.test(n)));
    const xml = analyze("<note><to>Ada</to><body>Hi &amp; bye</body></note>");
    assert.equal(xml.type, "XML");
    assert.match(xml.output, /<body>Hi &amp; bye<\/body>/);
    assert.equal(analyze("<not closed>").type, "Plain text");
  });

  // ------------------------------------------------------------------- IDs
  await test("UUID v1, v6, v7 timestamps match RFC 9562 examples", () => {
    const v1 = analyze("C232AB00-9414-11EC-B3C8-9F6BDECED846");
    assert.equal(v1.type, "UUID");
    assert.equal(v1.layers[0].value.Created, "2022-02-22T19:22:22.000Z");
    assert.match(v1.layers[0].value.Node, /9f:6b:de:ce:d8:46/);
    assert.equal(analyze("1EC9414C-232A-6B00-B3C8-9F6BDECED846").layers[0].value.Created, "2022-02-22T19:22:22.000Z");
    assert.equal(analyze("017F22E2-79B0-7CC3-98C4-DC0C0C07398F").layers[0].value.Created, "2022-02-22T19:22:22.000Z");
    assert.match(analyze("919108f7-52d1-4320-9bac-f847db4148a8").layers[0].value.Version, /v4 · random/);
    assert.equal(analyze("00000000-0000-0000-0000-000000000000").layers[0].value.Kind, "Nil UUID");
  });

  await test("ULID, ObjectId and Snowflake", () => {
    const ulid = analyze("01ARZ3NDEKTSV4RRFFQ69G5FAV");
    assert.equal(ulid.type, "ULID");
    assert.equal(ulid.layers[0].value.Created, "2016-07-30T23:54:10.259Z");
    const oid = analyze("507f1f77bcf86cd799439011");
    assert.equal(oid.type, "MongoDB ObjectId");
    assert.equal(oid.layers[0].value.Created, "2012-10-17T21:13:27.000Z");
    const discord = analyze("175928847299117063");
    assert.equal(discord.type, "Snowflake ID");
    assert.equal(discord.layers[0].value["If Discord"], "2016-04-30T11:18:25.796Z");
    assert.equal(analyze("1704067200").type, "Unix timestamp");
  });

  // ------------------------------------------------------------------ email
  const email = [
    "Delivered-To: dorel@example.test",
    "Received: by 2002:a05:6a10:1234 with SMTP id abc;",
    "        Fri, 25 Sep 2026 07:00:09 -0700 (PDT)",
    "Received: from mail.sender.test (mail.sender.test [198.51.100.7])",
    "        by mx.google.com with ESMTPS id xyz",
    "        for <dorel@example.test>; Fri, 25 Sep 2026 07:00:05 -0700 (PDT)",
    "Received: from [10.0.0.5] (helo=laptop) by mail.sender.test with esmtpsa; Fri, 25 Sep 2026 14:00:01 +0000",
    "Authentication-Results: mx.google.com;",
    "       dkim=pass header.i=@sender.test header.s=s1;",
    "       spf=softfail (google.com: domain of transitioning bounce@bulk.test does not designate 198.51.100.7) smtp.mailfrom=bounce@bulk.test;",
    "       dmarc=fail (p=REJECT) header.from=sender.test",
    "DKIM-Signature: v=1; a=rsa-sha256; d=sender.test; s=s1; h=from:to:subject; bh=abc; b=def",
    "Return-Path: <bounce@bulk.test>",
    "From: =?UTF-8?B?QWRhIEzDtnZlbGFjZQ==?= <ada@sender.test>",
    "Reply-To: payments@elsewhere.test",
    "To: dorel@example.test",
    "Subject: =?UTF-8?Q?Invoice_f=C3=BCr_September?=",
    "Date: Fri, 25 Sep 2026 14:00:00 +0000",
    "Message-ID: <1@sender.test>",
    "",
    "Body text here.",
  ].join("\n");

  await test("email headers: summary, auth results, route and warnings", () => {
    const result = analyze(email);
    assert.equal(result.type, "Email headers");
    const summary = result.layers[0].value;
    assert.equal(summary.From, "Ada Lövelace <ada@sender.test>");
    assert.equal(summary.Subject, "Invoice für September");
    assert.equal(summary["Originating IP"], "198.51.100.7 (mail.sender.test)");
    assert.equal(summary["Transit time"], "8 s over 3 hops");
    const auth = result.layers.find((l) => l.type === "Authentication").value;
    assert.match(auth.DKIM, /^pass/);
    assert.match(auth.SPF, /^softfail/);
    assert.match(auth.DMARC, /^fail/);
    assert.equal(auth["DKIM signature"], "d=sender.test s=s1 a=rsa-sha256");
    const route = result.layers.find((l) => l.type === "Delivery route");
    assert.equal(route.detail, "3 hops, oldest first");
    assert.match(Object.values(route.value)[1], /from mail\.sender\.test \[198\.51\.100\.7\].*\+4s/);
    for (const pattern of [/DMARC failed/, /soft-failed/, /Return-Path/, /Replies go to elsewhere\.test/, /body was ignored/]) {
      assert.ok(result.notices.some((n) => pattern.test(n)), pattern.toString());
    }
  });

  // -------------------------------------------------------- response headers
  await test("weak response headers get a low grade with specific findings", () => {
    const weak = [
      "HTTP/1.1 301 Moved Permanently", "Location: https://example.test/", "",
      "HTTP/2 200", "server: nginx/1.18.0", "x-powered-by: PHP/8.1.2",
      "content-security-policy: default-src * 'unsafe-inline' 'unsafe-eval'",
      "set-cookie: session=abc; Path=/", "set-cookie: pref=1; Secure; HttpOnly; SameSite=Lax",
      "referrer-policy: unsafe-url", "x-xss-protection: 1; mode=block",
    ].join("\n");
    const result = analyze(weak);
    assert.equal(result.type, "HTTP response headers");
    assert.equal(result.layers[0].value.Status, "HTTP/2 200");
    assert.equal(result.grade, "F");
    const findings = result.layers[1].value;
    assert.match(findings["✗ Strict-Transport-Security"], /Missing/);
    assert.match(findings["! Content-Security-Policy"], /unsafe-inline.*unsafe-eval/);
    assert.match(findings["! Server"], /nginx\/1\.18\.0/);
    assert.match(findings["! Cookie session"], /Missing Secure, HttpOnly, SameSite/);
    assert.match(findings["✓ Cookie pref"], /Secure, HttpOnly, SameSite=Lax/);
    assert.match(findings["✗ Referrer-Policy"], /unsafe-url/);
  });

  await test("decoder.in's own strict headers grade A", () => {
    const strict = [
      "HTTP/2 200",
      "strict-transport-security: max-age=31536000; includeSubDomains",
      "content-security-policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'",
      "x-content-type-options: nosniff", "referrer-policy: no-referrer", "x-frame-options: DENY",
      "permissions-policy: camera=(), microphone=()", "cross-origin-opener-policy: same-origin", "server: cloudflare",
    ].join("\n");
    const result = analyze(strict);
    assert.equal(result.grade, "A");
    assert.equal(result.layers[0].value.Failures, "0");
  });

  await test("request headers still parse as request headers", () => {
    assert.equal(analyze("Content-Type: application/json\nCookie: a=1; b=2").type, "HTTP headers");
  });

  // ------------------------------------------------------- JWT verification
  const b64url = (b) => Buffer.from(b).toString("base64url");
  const sign = (header, payload, signer) => {
    const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
    return `${input}.${b64url(signer(Buffer.from(input)))}`;
  };

  await test("HS256 with text secret, Base64 secret, wrong secret, tampered payload", async () => {
    const token = sign({ alg: "HS256", typ: "JWT" }, { sub: "1" }, (d) => crypto.createHmac("sha256", "s3cret").update(d).digest());
    assert.equal((await Tools.verifyJwt(token, "s3cret")).ok, true);
    assert.equal((await Tools.verifyJwt(token, "wrong")).ok, false);
    const keyBytes = crypto.randomBytes(32);
    const token2 = sign({ alg: "HS256" }, { sub: "2" }, (d) => crypto.createHmac("sha256", keyBytes).update(d).digest());
    const r2 = await Tools.verifyJwt(token2, keyBytes.toString("base64"));
    assert.equal(r2.ok, true);
    assert.match(r2.message, /Base64-decoded/);
    const [h, , s] = token.split(".");
    assert.equal((await Tools.verifyJwt(`${h}.${b64url('{"sub":"admin"}')}.${s}`, "s3cret")).ok, false);
  });

  await test("RS256 / PS256 / ES256 / EdDSA with PEM, certificate, JWK and JWKS", async () => {
    const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const rsaPem = rsa.publicKey.export({ type: "spki", format: "pem" });
    const rs = sign({ alg: "RS256", kid: "k2" }, { sub: "rs" }, (d) => crypto.sign("sha256", d, rsa.privateKey));
    assert.equal((await Tools.verifyJwt(rs, rsaPem)).ok, true);
    const jwk = rsa.publicKey.export({ format: "jwk" });
    const jwks = JSON.stringify({ keys: [{ ...crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "jwk" }), kid: "k1" }, { ...jwk, kid: "k2" }] });
    const viaJwks = await Tools.verifyJwt(rs, jwks);
    assert.equal(viaJwks.ok, true);
    assert.match(viaJwks.kind, /kid k2/);
    const ps = sign({ alg: "PS256" }, { sub: "ps" }, (d) => crypto.sign("sha256", d, { key: rsa.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }));
    assert.equal((await Tools.verifyJwt(ps, rsaPem)).ok, true);
    const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const es = sign({ alg: "ES256" }, { sub: "es" }, (d) => crypto.sign("sha256", d, { key: ec.privateKey, dsaEncoding: "ieee-p1363" }));
    assert.equal((await Tools.verifyJwt(es, JSON.stringify(ec.publicKey.export({ format: "jwk" })))).ok, true);
    const ed = crypto.generateKeyPairSync("ed25519");
    const eddsa = sign({ alg: "EdDSA" }, { sub: "ed" }, (d) => crypto.sign(null, d, ed.privateKey));
    assert.equal((await Tools.verifyJwt(eddsa, ed.publicKey.export({ type: "spki", format: "pem" }))).ok, true);
    // The EC leaf fixture's certificate verifies a token signed by its key.
    const leafKey = crypto.createPrivateKey(fixture("ec-private.pem"));
    const certToken = sign({ alg: "ES256" }, { sub: "cert" }, (d) => crypto.sign("sha256", d, { key: leafKey, dsaEncoding: "ieee-p1363" }));
    const viaCert = await Tools.verifyJwt(certToken, fixture("ec-leaf.pem"));
    assert.equal(viaCert.ok, true);
    assert.match(viaCert.kind, /certificate/);
  });

  await test("algorithm confusion, alg none and private keys are refused", async () => {
    const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const pem = rsa.publicKey.export({ type: "spki", format: "pem" });
    const confused = sign({ alg: "HS256" }, { sub: "x" }, (d) => crypto.createHmac("sha256", pem).update(d).digest());
    const r = await Tools.verifyJwt(confused, pem);
    assert.equal(r.ok, false);
    assert.match(r.message, /algorithm-confusion/);
    const none = `${b64url('{"alg":"none"}')}.${b64url('{"sub":"x"}')}.`;
    assert.match((await Tools.verifyJwt(none, "anything")).message, /alg: none/);
    const rs = sign({ alg: "RS256" }, { sub: "x" }, (d) => crypto.sign("sha256", d, rsa.privateKey));
    assert.match((await Tools.verifyJwt(rs, rsa.privateKey.export({ type: "pkcs8", format: "pem" }))).message, /private key/);
    const privJwk = JSON.stringify(rsa.privateKey.export({ format: "jwk" }));
    assert.match((await Tools.verifyJwt(rs, privJwk)).message, /private key/);
  });

  await test("analyze exposes the raw token for the verify panel", () => {
    const token = sign({ alg: "HS256" }, { sub: "1" }, (d) => crypto.createHmac("sha256", "k").update(d).digest());
    assert.equal(analyze(token).jwt, token);
  });

  // ------------------------------------------------- review fixes (PR #1)
  await test("certificate lifetime limit follows the issue date (SC-081)", () => {
    const long = analyze(fixture("leaf-300-days.pem"), Date.parse("2026-10-01T00:00:00Z"));
    assert.ok(long.notices.some((n) => /valid for 300 days.*at most 200 days/.test(n)), JSON.stringify(long.notices));
    assert.match(long.notices.find((n) => /at most/.test(n)), /valid for 300 days/);
    const short = analyze(fixture("ec-leaf.pem"), Date.parse("2026-10-01T00:00:00Z"));
    assert.ok(!short.notices.some((n) => /at most/.test(n)));
  });

  await test("Reply-To spoofing is caught under two-level country suffixes", () => {
    const headers = "Received: from a.bank.co.uk by mx.test; Fri, 25 Sep 2026 14:00:00 +0000\nAuthentication-Results: mx.test; dmarc=pass header.from=bank.co.uk\nFrom: Bank <help@bank.co.uk>\nReply-To: pay@attacker.co.uk\nSubject: hi";
    assert.ok(analyze(headers).notices.some((n) => /Replies go to attacker\.co\.uk/.test(n)));
    const same = headers.replace("attacker.co.uk", "mail.bank.co.uk");
    assert.ok(!analyze(same).notices.some((n) => /Replies go to/.test(n)));
  });

  await test("frame-ancestors * fails the framing check", () => {
    const result = analyze("HTTP/2 200\ncontent-security-policy: default-src 'self'; frame-ancestors *");
    assert.match(result.layers[1].value["✗ Framing"], /any site/);
  });

  await test("a wrong 17-character secret reports a mismatch, not a Base64 error", async () => {
    const token = sign({ alg: "HS256" }, { sub: "1" }, (d) => crypto.createHmac("sha256", "right").update(d).digest());
    const result = await Tools.verifyJwt(token, "abcdefghijklmnopq");
    assert.equal(result.ok, false);
    assert.match(result.message, /does NOT match/);
  });

  await test("requiring the page generator writes nothing", () => {
    const before = fs.statSync(path.join(__dirname, "..", "public", "index.html")).mtimeMs;
    const pages = require("../build/pages.js");
    assert.ok(Array.isArray(pages.PAGES) && pages.PAGES.length === pages.TOOLS.length + 1);
    assert.equal(fs.statSync(path.join(__dirname, "..", "public", "index.html")).mtimeMs, before);
  });

  // ------------------------------------------------------------------ report
  let failed = 0;
  for (const [status, name, error] of results) {
    console.log(`${status === "ok" ? "  ok  " : "  FAIL"} ${name}`);
    if (error) { failed += 1; console.log(`       ${String(error.stack || error).split("\n").slice(0, 4).join("\n       ")}`); }
  }
  console.log(`\n${results.length - failed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
