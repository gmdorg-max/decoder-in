#!/usr/bin/env node
// Generates every decoder page from one template, plus examples.js and sitemap.xml.
//   node build/pages.js          write the files into public/
//   node build/pages.js --check  exit 1 if public/ is not up to date (used by the tests)
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");

const ROOT = path.join(__dirname, "..");
const PUBLIC = path.join(ROOT, "public");
const VERSION = "0.4.0";
const ASSET = "20260926-3";
const LASTMOD = "2026-09-26";
const SITE = "https://decoder.in";

const E = require("./encoders.js");
const fixture = (name) => fs.readFileSync(path.join(ROOT, "test", "fixtures", name), "utf8").trim();
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

// ------------------------------------------------------------------ examples

function hs256(payload, secret) {
  const b64 = (v) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const input = `${b64({ alg: "HS256", typ: "JWT" })}.${b64(payload)}`;
  return `${input}.${crypto.createHmac("sha256", secret).update(input).digest("base64url")}`;
}

const DEMO_SECRET = "decoder-in-demo-secret";
const samlRequest = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8d1c" Version="2.0" IssueInstant="2026-09-26T08:00:00Z" Destination="https://idp.example.com/sso" AssertionConsumerServiceURL="https://app.example.com/saml/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>https://app.example.com</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>`;
const samlResponse = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r42" InResponseTo="_8d1c" Version="2.0" IssueInstant="2026-09-26T08:00:05Z" Destination="https://app.example.com/saml/acs"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_a42" Version="2.0" IssueInstant="2026-09-26T08:00:05Z"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">ada@example.com</saml:NameID></saml:Subject><saml:Conditions NotBefore="2026-09-26T07:59:35Z" NotOnOrAfter="2026-09-26T08:05:05Z"><saml:AudienceRestriction><saml:Audience>https://app.example.com</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="groups"><saml:AttributeValue>engineering</saml:AttributeValue><saml:AttributeValue>on-call</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`;

const EXAMPLES = {
  jwt: [hs256({ sub: "1234567890", name: "Ada Lovelace", role: "admin", iat: 1790323200, exp: 2082758400 }, DEMO_SECRET)],
  certificate: [fixture("chain.pem"), fixture("rsa-selfsigned.pem")],
  saml: [
    `https://idp.example.com/sso?SAMLRequest=${encodeURIComponent(zlib.deflateRawSync(Buffer.from(samlRequest)).toString("base64"))}&RelayState=%2Fdashboard`,
    Buffer.from(samlResponse).toString("base64"),
  ],
  headers: [[
    "HTTP/2 200",
    "server: nginx/1.18.0",
    "x-powered-by: PHP/8.1.2",
    "content-type: text/html; charset=UTF-8",
    "content-security-policy: default-src * 'unsafe-inline' 'unsafe-eval'",
    "set-cookie: PHPSESSID=5f2c9a; path=/",
    "set-cookie: lang=en; Secure; HttpOnly; SameSite=Lax",
    "x-frame-options: SAMEORIGIN",
    "x-xss-protection: 1; mode=block",
  ].join("\n")],
  ids: ["01929c3a-7f3e-7b1a-9c4d-5e6f7a8b9c0d", "01J8ZQ4X7K3M2N5P6R7S8T9V0W", "c232ab00-9414-11ec-b3c8-9f6bdeced846", "1216421371813109760"],
  email: [[
    "Delivered-To: you@example.com",
    "Received: by 2002:a05:7300:5b0a with SMTP id k10csp1942;",
    "        Fri, 25 Sep 2026 07:02:13 -0700 (PDT)",
    "Received: from mail.invoices-portal.example (mail.invoices-portal.example [203.0.113.45])",
    "        by mx.google.com with ESMTPS id d9443c01a7336;",
    "        Fri, 25 Sep 2026 07:02:11 -0700 (PDT)",
    "Authentication-Results: mx.google.com;",
    "       dkim=pass header.i=@invoices-portal.example header.s=mail;",
    "       spf=pass (google.com: domain of billing@invoices-portal.example designates 203.0.113.45 as permitted sender) smtp.mailfrom=billing@invoices-portal.example;",
    "       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=yourbank.example",
    "Return-Path: <billing@invoices-portal.example>",
    "From: Your Bank <security@yourbank.example>",
    "Reply-To: verify-account@invoices-portal.example",
    "To: you@example.com",
    "Subject: =?UTF-8?Q?Action_required=3A_confirm_your_account?=",
    "Date: Fri, 25 Sep 2026 14:02:09 +0000",
    "Message-ID: <20260925140209.1@invoices-portal.example>",
  ].join("\n")],
};
// gzip writes the producing OS into byte 9 of its header (3 = Unix, 11 = Windows),
// which would make the generated examples differ between machines. Pin it.
const gzipStable = (data) => { const out = zlib.gzipSync(data); out[9] = 3; return out; };

// Deterministic bytes for example payloads that are random in real life.
const pseudo = (seed, n) => {
  const out = [];
  for (let i = 0; out.length < n; i += 1) out.push(...crypto.createHash("sha256").update(`${seed}:${i}`).digest());
  return Buffer.from(out.slice(0, n));
};
const b64u = (v) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url");
const exampleKey = require("node:crypto").createPublicKey(fixture("ec-public.pem")).export({ format: "jwk" });
const registration = E.webauthnRegistration({ rpId: "example.com", origin: "https://example.com", jwk: exampleKey });

Object.assign(EXAMPLES, {
  ssh: [fixture("ssh/authorized_keys"), fixture("ssh/ed25519-cert.pub"), fixture("ssh/known_hosts")],
  protobuf: [
    E.protobuf([[1, "varint", 150], [2, "string", "Ada Lovelace"], [3, "message", [[1, "varint", 1], [2, "string", "admin"], [2, "string", "on-call"]]], [4, "double", 99.5], [5, "varint", 1790380800]]).toString("base64"),
    "08 96 01 12 07 74 65 73 74 69 6e 67 1a 03 08 e8 07",
  ],
  webauthn: [JSON.stringify(registration.json, null, 2), Buffer.from(registration.attestationObject).toString("base64url")],
  oauth: [
    "https://auth.example.com/oauth2/authorize?response_type=code&client_id=web-app&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=openid%20profile%20email&state=af0ifjsldkj3n4k5l6m7&nonce=n-0S6_WzA2Mj&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
    "https://auth.example.com/authorize?response_type=token&client_id=legacy-spa&redirect_uri=http%3A%2F%2Fapp.example.com%2Fcb&scope=openid",
    JSON.stringify({ access_token: "2YotnFZFEjr1zCsicMWpAA", token_type: "Bearer", expires_in: 3600, refresh_token: "tGzv3JOkF0XG5Qx2TlKWIA", scope: "openid profile email",
      id_token: hs256({ iss: "https://auth.example.com", sub: "248289761001", aud: "web-app", nonce: "n-0S6_WzA2Mj", iat: 1790380800, exp: 2082758400, email: "ada@example.com" }, DEMO_SECRET) }, null, 2),
  ],
  jose: [
    [b64u({ alg: "RSA-OAEP-256", enc: "A256GCM", kid: "enc-2026-09", cty: "JWT" }), pseudo("ek", 256).toString("base64url"), pseudo("iv", 12).toString("base64url"), pseudo("ct", 412).toString("base64url"), pseudo("tag", 16).toString("base64url")].join("."),
    JSON.stringify({ keys: [{ ...exampleKey, kid: "sig-2026-09", use: "sig", alg: "ES256" }] }, null, 2),
  ],
  dns: [
    "https://dns.google/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
    E.dnsMessage({ id: 51966, response: true, ra: true, ad: true, question: ["example.com", "TXT"], answers: [
      ["example.com", "TXT", 3600, "v=spf1 include:_spf.google.com include:mailgun.org ~all"],
      ["example.com", "MX", 3600, [10, "mx1.example.com"]],
      ["example.com", "CAA", 3600, [0, "issue", "letsencrypt.org"]],
    ] }).toString("base64url"),
    "v=DMARC1; p=none; rua=mailto:dmarc@example.com; pct=100",
  ],
  base64: ["eyJ1c2VyIjoiYWRhIiwicm9sZXMiOlsiYWRtaW4iLCJvcHMiXSwidGhlbWUiOiJkYXJrIn0=", "SGVsbG8gZnJvbSBkZWNvZGVyLmluIPCfkYs=", gzipStable(JSON.stringify({ event: "login", user: "ada", ok: true })).toString("base64")],
  url: ["https%3A%2F%2Fexample.com%2Fsearch%3Fq%3Dcaf%C3%A9%2520cr%C3%A8me%26lang%3Dfr", "https://shop.example.com/cart?item=42&item=43&coupon=SAVE%2010&ref=newsletter#checkout"],
  json: ['{"user":"ada","roles":["admin","ops",],"active":true,}', '{"id":42,"name":"Ada","tags":["math","code"],"address":{"city":"Geneva","zip":"1201"}}'],
  timestamp: ["1790380800", "1790380800123456789", "2026-09-26T08:00:00+02:00"],
  http: [
    `curl 'https://api.example.com/v1/orders?status=open&limit=20' -H 'Accept: application/json' -H 'Authorization: Bearer ${hs256({ sub: "42", scope: "orders:read", exp: 2082758400 }, DEMO_SECRET)}' -H 'Cookie: session=abc; theme=dark'`,
    "POST /v1/orders HTTP/1.1\nHost: api.example.com\nContent-Type: application/json\n\n{\"item\":42,\"qty\":2}",
  ],
});

EXAMPLES.home = [EXAMPLES.jwt[0], EXAMPLES.certificate[0], EXAMPLES.headers[0], EXAMPLES.oauth[0], EXAMPLES.ssh[0], EXAMPLES.saml[0], EXAMPLES.email[0],
  EXAMPLES.dns[1], EXAMPLES.webauthn[0], EXAMPLES.jose[0], EXAMPLES.protobuf[0], EXAMPLES.ids[0], EXAMPLES.base64[2], EXAMPLES.timestamp[2],
  `curl 'https://api.example.com/users?active=true&role=admin' -H 'Accept: application/json' -H 'Cookie: session=demo; theme=dark' -d '{"name":"Ada"}'`,
  '{"ok":true,"items":[1,2,],}'];

// --------------------------------------------------------------------- pages

const GROUPS = [
  ["Tokens & identity", [
    { slug: "jwt-decoder", tool: "jwt", nav: "JWT decoder & verifier", short: "JWT" },
    { slug: "jwe-jwk-decoder", tool: "jose", nav: "JWE & JWK inspector", short: "JWE & JWK" },
    { slug: "oauth-decoder", tool: "oauth", nav: "OAuth, OIDC & PKCE checker", short: "OAuth & PKCE" },
    { slug: "saml-decoder", tool: "saml", nav: "SAML decoder", short: "SAML" },
    { slug: "webauthn-decoder", tool: "webauthn", nav: "WebAuthn & passkey inspector", short: "Passkeys" },
  ]],
  ["Certificates & keys", [
    { slug: "certificate-decoder", tool: "certificate", nav: "Certificate decoder", short: "Certificates" },
    { slug: "ssh-key-decoder", tool: "ssh", nav: "SSH key inspector", short: "SSH keys" },
  ]],
  ["Web, mail & network", [
    { slug: "http-security-headers", tool: "headers", nav: "Security headers check", short: "Security headers" },
    { slug: "curl-parser", tool: "http", nav: "cURL & HTTP request parser", short: "cURL & HTTP" },
    { slug: "email-header-analyzer", tool: "email", nav: "Email header analyzer", short: "Email headers" },
    { slug: "dns-decoder", tool: "dns", nav: "DNS, DoH, SPF & DMARC decoder", short: "DNS & SPF" },
  ]],
  ["Data & encodings", [
    { slug: "base64-decoder", tool: "base64", nav: "Base64 decoder", short: "Base64" },
    { slug: "url-decoder", tool: "url", nav: "URL decoder", short: "URL" },
    { slug: "json-formatter", tool: "json", nav: "JSON formatter & validator", short: "JSON" },
    { slug: "timestamp-converter", tool: "timestamp", nav: "Unix timestamp converter", short: "Timestamps" },
    { slug: "uuid-decoder", tool: "ids", nav: "UUID & ID decoder", short: "UUID & IDs" },
    { slug: "protobuf-decoder", tool: "protobuf", nav: "Protobuf decoder", short: "Protobuf" },
  ]],
];
const TOOLS = GROUPS.flatMap(([, tools]) => tools);

const PAGES = [
  {
    slug: "", tool: "home",
    title: "decoder.in — Make encoded data readable",
    description: "17 private developer tools in one box: JWT, OAuth/PKCE, SAML, passkeys, certificates, SSH keys, security and email headers, DNS/SPF, Base64, JSON, timestamps, UUIDs and protobuf. Decoded in your browser.",
    ogTitle: "decoder.in — Make encoded data readable",
    h1: ["Make encoded data", "readable."],
    intro: "Paste a token, key, certificate, URL, header, record, ID, JSON or encoded string. Decoder identifies it and unwraps every layer in your browser. Or pick a tool above.",
    placeholder: "Paste a token, certificate, request, headers, JSON, or encoded value…",
    chips: ["Tokens & identity", "Certificates & keys", "Web, mail & network", "Data & encodings"],
  },
  {
    slug: "jwt-decoder", tool: "jwt",
    title: "JWT decoder and signature verifier — decoder.in",
    description: "Decode a JSON Web Token and verify its HS256, RS256, PS256, ES256 or EdDSA signature with a secret, PEM key, certificate or JWKS. Runs entirely in your browser.",
    h1: ["Decode and verify", "JWTs."],
    intro: "Paste a JSON Web Token to read its header and claims, see when it expires, and check the signature against a secret or public key. Nothing leaves this tab.",
    placeholder: "Paste a JWT (eyJ…) or an Authorization: Bearer header…",
    chips: ["Claims & expiry", "HS · RS · PS · ES · EdDSA", "PEM, JWK & JWKS", "alg-confusion guard"],
    hint: `The example is signed with the secret <code>${DEMO_SECRET}</code>: paste it into the key box to see a valid signature.`,
    sections: [
      ["Reading the result", [
        "<strong>JWT header</strong> shows the algorithm (<code>alg</code>) and, when present, the key id (<code>kid</code>) that tells you which key signed it.",
        "<strong>JWT intelligence</strong> turns <code>iat</code>, <code>nbf</code> and <code>exp</code> into dates and says whether the token is active, expired or not yet valid.",
        "<strong>Verify signature</strong> appears under the result. Paste the shared secret for HS256/384/512, or the issuer's public key for RS, PS, ES and EdDSA tokens: a PEM public key, an X.509 certificate, a single JWK or a whole JWKS (the key is picked by <code>kid</code>).",
      ]],
      ["Why decoding is not verifying", [
        "Anyone can create a token with any claims. Only a matching signature proves the issuer made it and nobody changed it since. Decoder refuses tokens with <code>alg: none</code>, refuses to use a public key as an HMAC secret (the classic algorithm-confusion attack), and never accepts a private key.",
      ]],
    ],
    faq: [
      ["Is it safe to paste a production token here?", "Decoding and verification run in your browser with the Web Crypto API. The page makes no network requests (its Content-Security-Policy forbids them), so the token and key never leave the tab. Treat tokens like passwords anyway and prefer expired or test tokens."],
      ["My HS256 secret is Base64. Does that work?", "Yes. If the text secret does not match, Decoder also tries the Base64-decoded bytes and tells you which one matched."],
      ["Where do I get the public key?", "Most identity providers publish a JWKS at a URL like /.well-known/jwks.json. Open it, copy the JSON, and paste it into the key box."],
    ],
  },
  {
    slug: "certificate-decoder", tool: "certificate",
    title: "SSL certificate decoder — PEM, chains and CSRs — decoder.in",
    description: "Decode a PEM or Base64 X.509 certificate, chain or CSR: domains, issuer, expiry, key size, fingerprints and chain order. Private and local in your browser.",
    h1: ["Decode SSL", "certificates."],
    intro: "Paste a certificate, a full chain, a certificate signing request or a public key. See which domains it covers, who issued it, when it expires, and what a browser will object to.",
    placeholder: "Paste -----BEGIN CERTIFICATE----- … or a whole chain…",
    chips: ["Domains & expiry", "Chains & order", "CSRs & public keys", "Fingerprints & pins"],
    sections: [
      ["What Decoder checks", [
        "<strong>Domains</strong> come from the Subject Alternative Names. Browsers ignore the Common Name, so a certificate without SANs fails everywhere.",
        "<strong>Status</strong> compares the validity dates with your clock: valid with days remaining, expired, or not yet valid.",
        "<strong>Chain order</strong>: when you paste several certificates, each must be issued by the next one. Servers that send them in the wrong order break some clients.",
        "<strong>Warnings</strong> cover SHA-1 or MD5 signatures, RSA keys under 2048 bits, self-signed site certificates, and lifetimes over the 398 days browsers allow for public certificates.",
      ]],
      ["Getting a certificate to paste", [
        "From a server: <code>openssl s_client -connect example.com:443 -showcerts &lt;/dev/null</code> prints the chain. From a file: open the <code>.pem</code> or <code>.crt</code> in a text editor. Windows <code>.cer</code> files exported as Base64 paste directly.",
      ]],
    ],
    faq: [
      ["Can I paste my private key?", "Please don't. Decoder recognises private keys and refuses to read them, but a private key pasted anywhere should be treated as exposed and replaced."],
      ["What is the SPKI pin?", "The SHA-256 of the public key, Base64-encoded. It identifies the key regardless of which certificate carries it, which is useful for certificate pinning and for matching a certificate to a key."],
      ["Does it check revocation?", "No. Revocation needs a network request to the CA's OCSP or CRL servers, and this page makes none. The OCSP and CRL addresses are listed so you can check them yourself."],
    ],
  },
  {
    slug: "http-security-headers", tool: "headers",
    title: "HTTP security headers checker — grade CSP, HSTS and cookies — decoder.in",
    description: "Paste HTTP response headers and get a grade with specific fixes for CSP, HSTS, framing, referrer policy, cookies, CORS and version leaks. Nothing is sent anywhere.",
    h1: ["Check security", "headers."],
    intro: "Paste the response headers of any page and get a grade, with a plain explanation of each problem and what to change. Decoder never contacts the site.",
    placeholder: "Paste the output of curl -I https://example.com…",
    chips: ["CSP & HSTS", "Framing & referrer", "Cookie flags", "Version leaks"],
    hint: "Get the headers with <code>curl -sI https://example.com</code>, or from your browser: DevTools → Network → select the page → Response Headers → copy.",
    sections: [
      ["How the grade works", [
        "Each missing or weak protection costs points: a failure 20, a warning 8. Suggestions cost nothing. 90 and above is an A; below 40 is an F.",
        "<strong>Failures</strong>: no HSTS, no Content-Security-Policy, no <code>nosniff</code>, no framing protection, a referrer policy that leaks full URLs, cookies browsers will reject.",
        "<strong>Warnings</strong>: a CSP that still allows inline scripts or <code>eval</code>, short HSTS lifetimes, cookies without <code>Secure</code>, and <code>Server</code> or <code>X-Powered-By</code> headers that reveal software versions.",
      ]],
      ["Redirect chains", [
        "When you paste the output of <code>curl -IL</code>, which contains every hop of a redirect, Decoder grades the final response: the one that serves the page.",
      ]],
    ],
    faq: [
      ["Why not just enter a URL?", "Fetching a URL would mean our server contacting the site on your behalf, which decoder.in never does. Pasting headers also works for staging servers, intranets and local development."],
      ["Is X-XSS-Protection still needed?", "No. Browsers removed the XSS auditor it controlled. Set it to 0 or drop it and rely on a Content-Security-Policy."],
      ["Which CSP should I start with?", "For a site that serves its own scripts and styles: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'. Then add the origins your pages really need."],
    ],
  },
  {
    slug: "saml-decoder", tool: "saml",
    title: "SAML decoder — SAMLRequest and SAMLResponse — decoder.in",
    description: "Decode SAMLRequest and SAMLResponse values from redirect URLs or POST forms: inflates, formats the XML and summarises issuer, NameID, conditions and attributes locally.",
    h1: ["Decode SAML", "messages."],
    intro: "Paste a SAML redirect URL, a SAMLRequest or SAMLResponse value, or the raw XML. Decoder undoes the URL encoding, Base64 and compression, then explains the message.",
    placeholder: "Paste a URL with SAMLRequest=…, a Base64 SAMLResponse, or XML…",
    chips: ["Redirect & POST binding", "Inflate & format", "NameID & attributes", "Expiry & status"],
    hint: "In the browser: DevTools → Network → the request to your IdP or to the /acs endpoint → copy the SAMLRequest query parameter or the SAMLResponse form field.",
    sections: [
      ["What you get", [
        "<strong>Transport</strong> shows each step that was undone: URL decoding, Base64, and deflate for the HTTP-Redirect binding.",
        "<strong>Summary</strong> lists the issuer, destination, assertion consumer URL and, for responses, the status. A non-Success status is the usual reason a login fails.",
        "<strong>Assertion</strong> shows the NameID, audience, validity window and whether it is signed. <strong>Attributes</strong> lists every attribute value the IdP sent.",
      ]],
      ["Common failures it explains", [
        "An expired <code>NotOnOrAfter</code> (usually clock skew or a slow redirect), an audience that does not match the service provider's entity ID, an error status from the IdP, and responses with no signature at all.",
      ]],
    ],
    faq: [
      ["Does it verify the XML signature?", "No. It shows whether a signature is present on the response and on the assertion. Checking it needs the IdP certificate and a canonicalisation engine; your service provider does that."],
      ["Can it read encrypted assertions?", "No. An EncryptedAssertion can only be opened with the service provider's private key, which should never be pasted into a website."],
    ],
  },
  {
    slug: "email-header-analyzer", tool: "email",
    title: "Email header analyzer — SPF, DKIM, DMARC and delivery route — decoder.in",
    description: "Paste raw email headers to see SPF, DKIM and DMARC results, the delivery route with delays per hop, the originating IP and signs of spoofing. Private, in your browser.",
    h1: ["Analyze email", "headers."],
    intro: "Paste the headers of a message to see whether it really came from who it claims, which servers it passed through, and where it was delayed.",
    placeholder: "Paste the full headers (Received:, Authentication-Results:, From: …)…",
    chips: ["SPF · DKIM · DMARC", "Delivery route", "Originating IP", "Spoofing signs"],
    hint: "Gmail: ⋮ → Show original. Outlook: File → Properties → Internet headers. Apple Mail: View → Message → All Headers. Copy everything above the message body.",
    sections: [
      ["Reading the result", [
        "<strong>Authentication</strong> shows what the receiving server decided. DMARC is the one that matters: it ties the visible From address to a domain that passed SPF or DKIM.",
        "<strong>Delivery route</strong> lists the servers oldest first with the time each one added. Long gaps point at the server that held the message.",
        "<strong>Warnings</strong> flag failed checks, a bounce address or Reply-To on an unrelated domain, and delays over ten minutes.",
      ]],
      ["Spotting phishing", [
        "A failed DMARC on a message that claims to come from your bank, together with a Reply-To somewhere else, is the classic pattern. The example on this page shows exactly that.",
      ]],
    ],
    faq: [
      ["Is my email content sent anywhere?", "No. Only the header block is read, in your browser, and the body is ignored."],
      ["Why does a legitimate newsletter show a different Return-Path?", "Mailing services send bounces to their own domain. That is normal when DKIM and DMARC still pass."],
    ],
  },
  {
    slug: "uuid-decoder", tool: "ids",
    title: "UUID decoder — versions, timestamps, ULID, ObjectId and Snowflake — decoder.in",
    description: "Decode UUIDs (v1–v8), ULIDs, MongoDB ObjectIds and Snowflake IDs: version, variant and the creation time hidden inside. Runs locally in your browser.",
    h1: ["Decode UUIDs", "and IDs."],
    intro: "Paste a UUID, ULID, MongoDB ObjectId or Snowflake ID. Decoder tells you what kind it is and, where it has one, when it was created.",
    placeholder: "Paste a UUID, ULID, ObjectId or numeric Snowflake ID…",
    chips: ["UUID v1–v8", "ULID", "MongoDB ObjectId", "Snowflake IDs"],
    sections: [
      ["Which IDs carry a timestamp", [
        "<strong>UUID v1 and v6</strong> hold a 100-nanosecond timestamp and, in v1, often the MAC address of the machine that made them. <strong>UUID v7</strong> and <strong>ULID</strong> start with a millisecond Unix timestamp, so they sort by creation time.",
        "<strong>MongoDB ObjectIds</strong> begin with the creation second. <strong>Snowflake IDs</strong> (X/Twitter, Discord, Instagram) hold milliseconds since the service's own epoch, so Decoder shows a reading for each plausible service.",
        "<strong>UUID v4</strong> is random and <strong>v3/v5</strong> are hashes of a name: they contain no time at all.",
      ]],
    ],
    faq: [
      ["Can a v1 UUID identify a computer?", "Often, yes. Unless the generator randomised the node field, the last 12 hex digits are the network card's MAC address. Decoder tells you which case applies."],
      ["Which version should I use for database keys?", "UUID v7: it is unique like v4 but ordered by time, which keeps database indexes compact."],
    ],
  },

  {
    slug: "ssh-key-decoder", tool: "ssh",
    title: "SSH key inspector — fingerprints, key size and certificates — decoder.in",
    description: "Paste an SSH public key, authorized_keys or known_hosts line, or an SSH certificate: type, bits, SHA256 and MD5 fingerprints, principals and validity. Runs in your browser.",
    h1: ["Inspect SSH", "keys."],
    intro: "Paste a public key, a line from authorized_keys or known_hosts, or an OpenSSH certificate. Decoder shows the key type and strength and the fingerprints ssh-keygen would print.",
    placeholder: "Paste ssh-ed25519 AAAA… or an authorized_keys / known_hosts line…",
    chips: ["Ed25519 · RSA · ECDSA", "SHA256 & MD5 fingerprints", "authorized_keys options", "SSH certificates"],
    hint: "The fingerprints match <code>ssh-keygen -lf key.pub</code> and <code>ssh-keygen -E md5 -lf key.pub</code>, so you can compare them with what a server shows on first connect.",
    sections: [
      ["What it reads", [
        "<strong>Public keys</strong>: ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256/384/521, security-key (sk-) keys and DSA. RSA keys under 2048 bits and DSA keys are flagged.",
        "<strong>authorized_keys</strong> lines with options such as <code>command=</code>, <code>from=</code> and <code>no-pty</code>, and <strong>known_hosts</strong> lines, including hashed host names.",
        "<strong>OpenSSH certificates</strong>: user or host, key ID, principals, validity window, critical options, extensions and the signing CA's fingerprint.",
      ]],
      ["Private keys", [
        "If an <code>OPENSSH PRIVATE KEY</code> is pasted, Decoder reads only the public half stored in clear inside it and tells you whether the file has a passphrase. The secret part is never decoded. A private key pasted anywhere else should be replaced.",
      ]],
    ],
    faq: [
      ["Why do SHA256 and MD5 fingerprints differ?", "They are two formats for the same key. OpenSSH shows SHA256 since version 6.8; older servers, panels and cloud consoles still show the MD5 colon format."],
      ["Which key type should I use?", "Ed25519 for new keys. Use RSA with at least 3072 bits only where Ed25519 is not supported."],
    ],
  },
  {
    slug: "protobuf-decoder", tool: "protobuf",
    title: "Protobuf decoder without a schema — raw wire format — decoder.in",
    description: "Decode Protocol Buffers messages without the .proto file: field numbers, varints, zigzag, fixed64/32, strings and nested messages from Base64 or hex, in your browser.",
    h1: ["Decode Protobuf", "without a schema."],
    intro: "Paste a Protocol Buffers message as Base64 or hex, such as a gRPC body, a Firebase payload or a captured request. Decoder reads the wire format like protoc --decode_raw.",
    placeholder: "Paste Base64 or hex bytes (08 96 01 …)…",
    chips: ["Base64 or hex", "Nested messages", "varint · zigzag · fixed", "No .proto needed"],
    sections: [
      ["How to read the output", [
        "Each line is <code>field: value</code>, with nested messages in braces, the same layout as <code>protoc --decode_raw</code>. Without the schema the names are unknown, so the numbers are what the .proto file calls field tags.",
        "Varints show their unsigned value and, as a comment, the zigzag (sint) reading. Fixed 64- and 32-bit fields show the double/float and integer readings. Length-delimited fields become a string when they are readable text, a nested message when they parse as one, and bytes otherwise; bytes that parse as a list of varints are marked as possibly packed.",
      ]],
      ["gRPC bodies", [
        "A gRPC message on the wire starts with 5 extra bytes: a compression flag and a 4-byte length. Remove them before pasting, or paste the message field from your gRPC tool.",
      ]],
    ],
    faq: [
      ["Is a string always a string?", "No. The wire format has one type for strings, bytes and nested messages. Decoder picks the reading that fits best; the schema decides the truth."],
      ["Why is -1 shown as 18446744073709551615?", "Negative int32 and int64 values are encoded as 10-byte varints. Decoder shows the int64 reading next to it."],
    ],
  },
  {
    slug: "webauthn-decoder", tool: "webauthn",
    title: "WebAuthn and passkey decoder — attestation, authenticatorData, clientDataJSON — decoder.in",
    description: "Decode WebAuthn registration and sign-in payloads: clientDataJSON, attestationObject and authenticatorData with flags, AAGUID, RP ID hash and the COSE public key. Local and private.",
    h1: ["Inspect passkey", "payloads."],
    intro: "Paste the JSON of a navigator.credentials.create() or get() response, an attestationObject, authenticatorData or clientDataJSON. Decoder unpacks the CBOR and explains every flag.",
    placeholder: "Paste a PublicKeyCredential JSON, attestationObject or clientDataJSON…",
    chips: ["clientDataJSON", "Flags UP · UV · BE · BS", "AAGUID & COSE key", "RP ID check"],
    hint: "In the browser, <code>JSON.stringify(credential)</code> on the result of <code>navigator.credentials.create()</code> gives exactly the JSON this page reads.",
    sections: [
      ["What it checks", [
        "<strong>Client data</strong>: the ceremony type, the origin (HTTPS or localhost only), cross-origin use and the challenge length.",
        "<strong>Authenticator data</strong>: the RP ID hash compared with the origin's host and its parent domains, the UP, UV, BE, BS, AT and ED flags, and the signature counter. A counter of 0 is normal for synced passkeys.",
        "<strong>Attested credential</strong>: the AAGUID, with known passkey providers named, the credential ID, and the public key as COSE, JWK and PEM.",
      ]],
    ],
    faq: [
      ["Does it verify the attestation?", "No. Verifying needs the FIDO Metadata Service entry for the authenticator. Decoder shows the format and certificate so you can see what a verifier would check."],
      ["Where do I find the AAGUID of a passkey provider?", "It is inside authenticatorData whenever a credential is created. Decoder names common providers such as Google Password Manager, iCloud Keychain, Windows Hello, 1Password and Bitwarden."],
    ],
  },
  {
    slug: "oauth-decoder", tool: "oauth",
    title: "OAuth 2.0 and OIDC URL decoder with PKCE checker — decoder.in",
    description: "Paste an OAuth authorize URL, callback, token request or token response: flows, scopes, state, nonce and PKCE are explained and checked, and the ID token is decoded. In your browser.",
    h1: ["Debug OAuth", "and PKCE."],
    intro: "Paste an authorization URL, a redirect callback, a token request body or a token response. Decoder names the flow, checks it against current OAuth security advice and decodes any ID token.",
    placeholder: "Paste https://…/authorize?response_type=code&… or a callback URL…",
    chips: ["Flow & parameters", "PKCE verifier check", "Security checks", "ID token decoding"],
    hint: "For the example, paste <code>dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk</code> into the PKCE box: it is the verifier from RFC 7636 that matches the example's code_challenge.",
    sections: [
      ["Checks", [
        "<strong>Flow</strong>: the implicit flow (tokens in the URL) is flagged; the code flow with PKCE is the current recommendation for every client.",
        "<strong>PKCE</strong>: S256 is required, plain is flagged, and you can paste the <code>code_verifier</code> to confirm it produces the <code>code_challenge</code>.",
        "<strong>state and nonce</strong>: missing or short values are flagged. OIDC implicit and hybrid flows require a nonce.",
        "<strong>redirect_uri</strong>: plain http outside loopback, and fragments, are flagged. A client_secret in a browser URL is treated as leaked.",
      ]],
      ["Callbacks and errors", [
        "Error callbacks are explained in plain words: access_denied, invalid_scope, login_required and the rest. The <code>iss</code> parameter from RFC 9207, which protects against mix-up attacks, is recognised.",
      ]],
    ],
    faq: [
      ["Is PKCE only for mobile apps?", "No. It started there, but the OAuth 2.0 Security Best Current Practice recommends it for every client, including confidential server-side ones."],
      ["Are my tokens safe here?", "The page makes no network requests and refresh tokens are never displayed. Prefer test or expired tokens anyway."],
    ],
  },
  {
    slug: "jwe-jwk-decoder", tool: "jose",
    title: "JWE decoder and JWK / JWKS inspector — thumbprints and PEM export — decoder.in",
    description: "Recognise encrypted JWE tokens and read their header and envelope, and inspect JWK or JWKS key sets: key size, RFC 7638 thumbprint, leaked private keys and PEM export.",
    h1: ["Read JWE and", "JWK sets."],
    intro: "Paste a five-part encrypted token (JWE) to read its header and envelope, or a JWK or JWKS to check its keys and export them as PEM. No private keys are needed or accepted.",
    placeholder: "Paste a JWE (five dot-separated parts), a JWK or a JWKS…",
    chips: ["JWE header & envelope", "IV and tag checks", "RFC 7638 thumbprints", "JWK to PEM"],
    sections: [
      ["JWE: why your JWT won't decode", [
        "A signed JWT has three parts; an encrypted JWE has five: header, encrypted key, IV, ciphertext and tag. Only the header is readable. Decoder shows the key-management and content-encryption algorithms, the key ID, whether a signed JWT is nested inside (<code>cty: JWT</code>), and whether the IV and tag lengths fit the algorithm.",
        "Decryption needs the recipient's private key, which should never be pasted into a website, so Decoder does not offer it.",
      ]],
      ["JWK and JWKS", [
        "For each key: type, size or curve, use, algorithm, and its RFC 7638 thumbprint. Keys are exported as PEM for tools that need it. Decoder flags JWKS documents that expose private members or symmetric keys, duplicate or missing <code>kid</code> values, and expired x5c certificates.",
      ]],
    ],
    faq: [
      ["What is a JWK thumbprint?", "A SHA-256 hash of the key's required members in a fixed order (RFC 7638). Many providers use it as the kid, which Decoder confirms when it matches."],
      ["Can a JWKS leak a private key?", "Yes, when a server publishes its full key by mistake. Decoder marks any JWK with d, p, q or other private members as compromised."],
    ],
  },
  {
    slug: "dns-decoder", tool: "dns",
    title: "DNS message and DoH decoder, SPF, DKIM and DMARC checker — decoder.in",
    description: "Decode DNS wire-format queries and responses from DoH URLs, Base64 or hex, and check SPF, DKIM and DMARC records: lookups, policies, key sizes. Nothing is looked up.",
    h1: ["Decode DNS and", "mail records."],
    intro: "Paste a DNS-over-HTTPS URL, a DNS message as Base64 or hex, or an SPF, DKIM or DMARC record. Decoder unpacks the message and checks the mail policies.",
    placeholder: "Paste a ?dns= URL, a DNS message, or v=spf1 / v=DMARC1 / v=DKIM1…",
    chips: ["DoH & wire format", "A · MX · TXT · CAA · DNSSEC", "SPF lookup count", "DMARC & DKIM checks"],
    sections: [
      ["DNS messages", [
        "Header flags (QR, AA, TC, RD, RA, AD, CD), the response code, questions and every record in zone-file form, including compressed names, CAA, SRV, SOA, DS, DNSKEY and RRSIG, and EDNS options.",
      ]],
      ["Mail records", [
        "<strong>SPF</strong>: every mechanism, the qualifier on all, deprecated ptr, and the DNS lookup count against the limit of 10. <strong>DMARC</strong>: policy, subdomain policy, percentage, alignment and report addresses. <strong>DKIM</strong>: key type and size, testing flag and revocation.",
        "Pair it with the <a href=\"/email-header-analyzer/\">email header analyzer</a> to see how receivers actually judged a message.",
        "Need the live records first? <a href=\"https://ip6.in/\">ip6.in</a>, the hosting readiness check by swiss.software, looks up a domain's SPF, DMARC, MX and IPv6 setup in one click; paste the records here for the full breakdown.",
      ]],
    ],
    faq: [
      ["Does it query DNS?", "No. decoder.in makes no network requests. Look the record up with dig or your DNS provider, or test your live domain in one click on ip6.in, then paste the record here."],
      ["Why does my SPF fail with 11 lookups?", "SPF allows at most 10 DNS lookups in total, including those inside every include. Flatten or remove includes you no longer use."],
    ],
  },
  {
    slug: "base64-decoder", tool: "base64",
    title: "Base64 decoder — text, Base64URL, gzip and nested layers — decoder.in",
    description: "Decode Base64 and Base64URL to text, including Unicode, gzip or deflate-compressed data, JSON inside and nested encodings. Binary certificates and protobuf are recognised too.",
    h1: ["Decode", "Base64."],
    intro: "Paste Base64 or Base64URL. Decoder turns it into text, unpacks gzip or deflate, formats JSON inside, and keeps going through nested layers until the data is readable.",
    placeholder: "Paste a Base64 or Base64URL string…",
    chips: ["Base64 & Base64URL", "Unicode text", "gzip · zlib · deflate", "Nested layers"],
    sections: [
      ["More than text", [
        "When the decoded bytes are not text, Decoder checks what they are: a compressed stream, a DER certificate, a CBOR passkey object, a DNS message or a protobuf message, and hands them to the right decoder.",
        "Nested encodings are unwrapped up to six layers deep, for example URL encoding around Base64 around JSON, and each step is listed.",
      ]],
    ],
    faq: [
      ["What is Base64URL?", "The URL-safe variant: - and _ instead of + and /, usually without = padding. JWTs and many APIs use it. Decoder accepts both."],
      ["Is my data uploaded?", "No. Decoding happens in your browser and the page makes no network requests."],
    ],
  },
  {
    slug: "url-decoder", tool: "url",
    title: "URL decoder — percent-encoding, query parameters and double encoding — decoder.in",
    description: "Decode percent-encoded strings and URLs, split query parameters (including repeated ones), and unwrap double-encoded values, in your browser.",
    h1: ["Decode", "URLs."],
    intro: "Paste a URL or a percent-encoded string. Decoder decodes it, splits the query parameters, and unwraps values that were encoded twice.",
    placeholder: "Paste a URL or %-encoded text…",
    chips: ["Percent-encoding", "Query parameters", "Repeated keys", "Double encoding"],
    sections: [
      ["What it shows", [
        "For a full URL: scheme, host, path, fragment and every query parameter, with repeated keys collected into lists. For encoded text: each decoding step, so double-encoded values such as <code>%2520</code> are visible.",
        "Special URLs are recognised and passed on: OAuth authorize and callback URLs, SAML redirects and DNS-over-HTTPS queries.",
      ]],
    ],
    faq: [
      ["Why does + turn into a space?", "In form-encoded query strings + means space. Decoder follows that rule; a literal plus sign is encoded as %2B."],
    ],
  },
  {
    slug: "json-formatter", tool: "json",
    title: "JSON formatter and validator with error location and repair — decoder.in",
    description: "Format and validate JSON; broken JSON gets the line, column and likely cause, plus a repair preview for trailing commas. JWKs, token responses and passkeys inside JSON are recognised.",
    h1: ["Format and fix", "JSON."],
    intro: "Paste JSON to format it, or broken JSON to find out why it fails: the line and column, the likely cause, and a repaired version when the fix is unambiguous.",
    placeholder: "Paste JSON…",
    chips: ["Pretty print", "Line & column errors", "Trailing-comma repair", "Special JSON recognised"],
    sections: [
      ["Errors it explains", [
        "Trailing commas, single-quoted or unquoted property names, and missing closing braces or brackets, each with the position and the text around it.",
        "Some JSON has more meaning: a JWK or JWKS, an OAuth token response, or a WebAuthn credential. Decoder recognises those and explains them instead of just formatting.",
      ]],
    ],
    faq: [
      ["Does it fix every error?", "Only trailing commas are repaired automatically, because that fix is always safe. Other errors are located and explained so you can fix them."],
    ],
  },
  {
    slug: "timestamp-converter", tool: "timestamp",
    title: "Unix timestamp converter — seconds, ms, µs, ns and dates — decoder.in",
    description: "Convert Unix timestamps in seconds, milliseconds, microseconds or nanoseconds to dates, and ISO 8601 or email dates back to Unix time, with UTC, local time and relative time.",
    h1: ["Convert", "timestamps."],
    intro: "Paste a Unix timestamp in seconds, milliseconds, microseconds or nanoseconds, or paste a date to get its Unix time. Decoder shows UTC, your local time, and how long ago or ahead it is.",
    placeholder: "Paste 1790380800, 1790380800123, or 2026-09-26T08:00:00Z…",
    chips: ["s · ms · µs · ns", "Date to Unix time", "UTC and local", "Relative time"],
    sections: [
      ["Recognised forms", [
        "10 digits are seconds, 13 milliseconds, 16 microseconds and 19 nanoseconds, which is common in Go, OpenTelemetry and database logs. On other pages a 19-digit number may also be read as a Snowflake ID; this page always reads it as time.",
        "Dates in ISO 8601 (<code>2026-09-26T08:00:00Z</code>, with or without an offset) and email-style dates (<code>Fri, 25 Sep 2026 14:00:00 +0000</code>) are converted to Unix seconds and milliseconds. Dates without a time zone are read in your browser's time zone, and Decoder says so.",
      ]],
    ],
    faq: [
      ["What is the Unix epoch?", "1 January 1970 00:00:00 UTC. A Unix timestamp counts the seconds (or smaller units) since then, ignoring leap seconds."],
      ["Why does my timestamp land in 1970?", "It is probably in a larger unit than assumed, or has been truncated. Check the digit count: 10 digits are seconds, 13 milliseconds, 16 microseconds and 19 nanoseconds."],
    ],
  },
  {
    slug: "curl-parser", tool: "http",
    title: "cURL command and HTTP request parser — decoder.in",
    description: "Paste a cURL command or raw HTTP request to see the method, URL, query parameters, headers, cookies and JSON body, with Bearer JWTs decoded. Nothing is sent.",
    h1: ["Read cURL and", "HTTP requests."],
    intro: "Paste a cURL command or a raw HTTP request. Decoder splits it into method, URL, query parameters, headers, cookies and body, and decodes any Bearer JWT it carries.",
    placeholder: "Paste curl '…' -H '…' or GET /path HTTP/1.1…",
    chips: ["Method & URL", "Headers & cookies", "JSON bodies", "Bearer JWTs"],
    hint: "Browsers can copy any request as cURL: DevTools → Network → right-click a request → Copy → Copy as cURL. The command is only read here, never executed.",
    sections: [
      ["What it understands", [
        "cURL options -X, -H, -d / --data / --data-raw / --data-binary, --url and -I, quoted with single or double quotes and split across lines with \\ or ^. Raw HTTP/1.x requests with headers and a body. Pasted response headers go to the <a href=\"/http-security-headers/\">security headers check</a>.",
      ]],
    ],
    faq: [
      ["Does Decoder run the command?", "Never. The command is parsed as text and no request is made."],
    ],
  },
];

// ------------------------------------------------------------------ template

const link = (t, current, label) => `<a href="/${t.slug}/"${t.slug === current ? ' aria-current="page"' : ""}>${esc(label)}</a>`;

/** The grouped tool directory ("the tool library") on every page. */
function toolDirectory(current) {
  return GROUPS.map(([name, tools], i) => {
    const id = `group-${i + 1}`;
    const links = tools.map((t) => `<a href="/${t.slug}/"${t.slug === current ? ' aria-current="page"' : ""}>${esc(t.nav)} <span aria-hidden="true">→</span></a>`).join("");
    return `<section class="tool-group" aria-labelledby="${id}"><div class="group-title"><span>0${i + 1} /</span><h3 id="${id}">${esc(name)}</h3></div><div class="group-links">${links}</div></section>`;
  }).join("\n          ");
}

/** Header shared by generated and static pages. local = the inspector lives on this page. */
function siteHeader(active, local = true) {
  const items = [
    ["Inspector", local ? "#workspace" : "/#workspace", "inspector"],
    ["All tools", local ? "#tools" : "/#tools", "tools"],
    ["Docs", "/docs/", "docs"],
    ["Privacy", "/privacy/", "privacy"],
  ];
  const nav = items.map(([label, href, key]) => `<a${key === active ? ' class="active" aria-current="page"' : ""} href="${href}">${label}</a>`).join("");
  return `<header class="site-header shell">
      <a class="wordmark" href="/" aria-label="decoder.in home"><span class="wordmark-mark" aria-hidden="true">d/</span><span>decoder.in</span></a>
      <nav class="primary-nav" aria-label="Primary navigation">${nav}</nav>
      <span class="privacy-pill"><span class="status-dot"></span>Local only</span>
    </header>`;
}

function siteFooter() {
  return `<footer class="shell">
      <div><a class="wordmark" href="/"><span class="wordmark-mark" aria-hidden="true">d/</span><span>decoder.in</span></a><p>Technical data, made readable.<br />Built by <a href="https://swiss.software/">swiss.software</a>.</p></div>
      <nav aria-label="Footer navigation"><a href="/docs/">Documentation</a><a href="/privacy/">Privacy</a><a href="https://github.com/gmdorg-max/decoder-in">Source ↗</a><a href="mailto:hello@swiss.software?subject=decoder.in%20feedback">Send feedback</a></nav>
      <small>BETA ${VERSION} · RUNS IN YOUR BROWSER</small>
    </footer>`;
}

function sectionsHtml(page) {
  if (!page.sections && !page.faq) return "";
  const sections = (page.sections || []).map(([h, paragraphs]) =>
    `<section class="content-section"><h2>${esc(h)}</h2>${paragraphs.map((p) => `<p>${p}</p>`).join("")}</section>`).join("\n        ");
  const faq = page.faq ? `<section class="content-section"><h2>Questions</h2>${page.faq.map(([q, a]) => `<h3>${esc(q)}</h3><p>${esc(a)}</p>`).join("")}</section>` : "";
  return `
      <section class="guide shell"><article class="content-page tool-guide">
        ${sections}
        ${faq}
      </article></section>`;
}

function jsonLd(page, url) {
  const graph = [{
    "@type": "WebApplication", name: page.slug ? page.title.replace(/ — decoder\.in$/, "") : "decoder.in", url,
    applicationCategory: "DeveloperApplication", operatingSystem: "Any (runs in the browser)",
    offers: { "@type": "Offer", price: "0", priceCurrency: "CHF" },
    creator: { "@type": "Organization", name: "swiss.software", url: "https://swiss.software/" },
  }];
  if (page.faq) {
    graph.push({ "@type": "FAQPage", mainEntity: page.faq.map(([q, a]) => ({ "@type": "Question", name: q, acceptedAnswer: { "@type": "Answer", text: a } })) });
  }
  // A data block, not a script: the CSP (script-src 'self') does not apply to it.
  return JSON.stringify({ "@context": "https://schema.org", "@graph": graph }).replace(/</g, "\\u003c");
}

function render(page) {
  const url = `${SITE}/${page.slug ? `${page.slug}/` : ""}`;
  const tool = TOOLS.find((t) => t.slug === page.slug);
  const eyebrow = tool ? esc(tool.nav) : "Private technical payload inspector";
  const principles = page.slug ? "" : `
    <section class="principles" aria-labelledby="principles-title"><div class="shell principle-layout"><div><p class="section-kicker">How it works / 03</p><h2 id="principles-title">Clarity, without the upload.</h2></div><div class="principle-list"><article><span>01</span><div><h3>Automatic</h3><p>Decoder recognizes common formats and nested layers. Start with the data, not a dropdown.</p></div></article><article><span>02</span><div><h3>Private</h3><p>Inspection runs in your browser. No uploads, accounts or server-side processing.</p></div></article><article><span>03</span><div><h3>Explicit</h3><p>Each transformation is shown, so you can check how the result was reached.</p></div></article></div></div></section>`;
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="description" content="${esc(page.description)}" />
    <meta name="theme-color" content="#f6f3ed" />
    <meta name="application-name" content="decoder.in" />
    <meta name="robots" content="index, follow" />
    <link rel="canonical" href="${url}" />
    <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
    <link rel="manifest" href="/site.webmanifest" />
    <meta property="og:type" content="website" />
    <meta property="og:site_name" content="decoder.in" />
    <meta property="og:title" content="${esc(page.ogTitle || page.title)}" />
    <meta property="og:description" content="${esc(page.description)}" />
    <meta property="og:url" content="${url}" />
    <meta property="og:image" content="${SITE}/og-card.png" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta name="twitter:card" content="summary_large_image" />
    <title>${esc(page.title)}</title>
    <link rel="stylesheet" href="/styles.css?v=${ASSET}" />
    <script type="application/ld+json">${jsonLd(page, url)}</script>
  </head>
  <body data-tool="${page.tool}">
    <a class="skip-link" href="#workspace">Skip to inspector</a>
    ${siteHeader("inspector")}

    <main>
      <section class="hero shell" aria-labelledby="page-title">
        <div class="hero-copy">
          <p class="eyebrow"><span class="eyebrow-line"></span> ${eyebrow} <span class="eyebrow-index">/ 01</span></p>
          <h1 id="page-title">${esc(page.h1[0])}<br /><em>${esc(page.h1[1])}</em></h1>
          <p class="intro">${esc(page.intro)}</p>
          <div class="hero-tags" aria-label="Supported inspections">${page.chips.map((c) => `<span>${esc(c)}</span>`).join("")}</div>
          <div class="hero-actions"><a class="button-primary" href="#payload">Start decoding <span aria-hidden="true">↗</span></a><a class="button-secondary" href="#tools">Browse all tools <span aria-hidden="true">↓</span></a></div>
        </div>
        <div class="hero-graphic" aria-hidden="true"><span class="graphic-label">INPUT → INSIGHT</span><span class="graphic-glyph">d<span>/</span></span><span class="graphic-foot"><span>01 / DETECT</span><span>02 / UNWRAP</span><span>03 / VERIFY</span></span></div>
      </section>

      <section class="work-section" id="workspace" aria-labelledby="work-title">
        <div class="shell">
          <div class="section-head"><div><p class="section-kicker">The workbench / 01</p><h2 id="work-title">Inspect your input</h2></div><p>Recognizes common formats automatically. No selection needed.</p></div>
          <div class="workspace" aria-label="Decoder workspace">
            <div class="input-panel">
              <div class="panel-heading"><label for="payload"><span class="panel-number">01</span> Input</label><div class="input-actions"><button id="exampleButton" type="button">Try example <span aria-hidden="true">↗</span></button><button id="clearButton" type="button">Clear</button></div></div>
              <textarea id="payload" spellcheck="false" autocomplete="off" placeholder="${esc(page.placeholder)}"></textarea>
              <div class="panel-foot"><span>⌘ / Ctrl + V</span><span>Data stays in this tab <span class="tiny-dot"></span></span></div>
            </div>
            <div class="result-panel" id="resultPanel" aria-live="polite">
              <div class="panel-heading"><span><span class="panel-number">02</span> Analysis</span><span class="panel-meta">Local output</span></div>
              <div class="empty-state" id="emptyState"><div class="empty-symbol" aria-hidden="true"><span>[</span> _ <span>]</span></div><h3>Waiting for input.</h3><p>Paste something in the left panel, or load an example to see the decoder at work.</p></div>
              <div class="results" id="results" hidden>
                <div class="result-topline"><div><p class="result-label">Detected as</p><h3 id="detectedType">Unknown</h3></div><button class="copy-button" id="copyButton" type="button">Copy output</button></div>
                <div class="confidence-row"><span id="confidenceText">High confidence</span><div class="confidence-track"><span id="confidenceBar"></span></div></div>
                <div id="notices"></div>
                <section class="verify-panel" id="checkPanel" hidden aria-label="PKCE check"><label for="checkKey">PKCE: check the code_verifier</label><textarea id="checkKey" spellcheck="false" autocomplete="off" placeholder="code_verifier (43–128 characters)"></textarea><p class="verify-result" id="checkResult">Paste the code_verifier to confirm it matches the code_challenge.</p></section>
                <section class="verify-panel" id="verifyPanel" hidden aria-label="Verify signature"><label for="verifyKey">Verify signature</label><textarea id="verifyKey" spellcheck="false" autocomplete="off" placeholder="Secret (HS256…), PEM public key, certificate, JWK or JWKS"></textarea><p class="verify-result" id="verifyResult">Paste a key to check the signature. It stays in this tab.</p></section>
                <div class="layers" id="layers"></div>
              </div>
            </div>
          </div>
          <p class="workspace-note"><span class="note-icon">↳</span> Decoding is not verification. When a format supports verification, check the result against a trusted key.</p>${page.hint ? `
          <p class="workspace-note"><span class="note-icon">↳</span> ${page.hint}</p>` : ""}
        </div>
      </section>

      <section class="tools-section shell" id="tools" aria-labelledby="tools-title">
        <div class="section-head tools-head"><div><p class="section-kicker">The tool library / 02</p><h2 id="tools-title">Go straight to the right tool.</h2></div><p>Focused inspectors for specific formats. Every one runs in your browser.</p></div>
        <div class="tool-directory">
          ${toolDirectory(page.slug)}
        </div>
      </section>
${principles}
${sectionsHtml(page)}
    </main>

    ${siteFooter()}

    <script src="/tools.js?v=${ASSET}"></script>
    <script src="/protocols.js?v=${ASSET}"></script>
    <script src="/decoder.js?v=${ASSET}"></script>
    <script src="/examples.js?v=${ASSET}"></script>
    <script src="/app.js?v=${ASSET}"></script>
  </body>
</html>
`;
}

function sitemap() {
  const entries = [
    ["", "weekly", "1.0"], ...TOOLS.map((t) => [`${t.slug}/`, "monthly", "0.9"]), ["docs/", "monthly", "0.6"], ["privacy/", "yearly", "0.4"],
  ];
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${entries.map(([p, freq, prio]) => `  <url>
    <loc>${SITE}/${p}</loc>
    <lastmod>${LASTMOD}</lastmod>
    <changefreq>${freq}</changefreq>
    <priority>${prio}</priority>
  </url>`).join("\n")}
</urlset>
`;
}

function outputs() {
  const files = {};
  for (const page of PAGES) files[page.slug ? `${page.slug}/index.html` : "index.html"] = render(page);
  files["examples.js"] = `// Generated by build/pages.js from the test fixtures. Do not edit by hand.\nglobalThis.DecoderExamples = ${JSON.stringify(EXAMPLES, null, 2)};\n`;
  files["sitemap.xml"] = sitemap();
  // The flat .html copies exist for old links; keep them identical to the directory pages.
  for (const name of ["docs", "privacy"]) files[`${name}.html`] = fs.readFileSync(path.join(PUBLIC, name, "index.html"), "utf8");
  return files;
}

function main() {
  const check = process.argv.includes("--check");
  let stale = 0;
  for (const [name, contents] of Object.entries(outputs())) {
    const target = path.join(PUBLIC, name);
    const current = fs.existsSync(target) ? fs.readFileSync(target, "utf8") : null;
    if (current === contents) continue;
    if (check) { console.log(`stale: public/${name}`); stale += 1; continue; }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, contents);
    console.log(`wrote public/${name}`);
  }
  if (check) {
    if (stale) { console.log("run: node build/pages.js"); process.exit(1); }
    console.log("pages up to date");
  }
}

if (require.main === module) main();
module.exports = { PAGES, TOOLS, EXAMPLES, DEMO_SECRET, siteHeader, siteFooter };
