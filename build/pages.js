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
const VERSION = "0.3.0";
const ASSET = "20260926-1";
const LASTMOD = "2026-09-26";
const SITE = "https://decoder.in";

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
EXAMPLES.home = [EXAMPLES.jwt[0], EXAMPLES.certificate[0], EXAMPLES.headers[0], EXAMPLES.saml[0], EXAMPLES.email[0], EXAMPLES.ids[0],
  `curl 'https://api.example.com/users?active=true&role=admin' -H 'Accept: application/json' -H 'Cookie: session=demo; theme=dark' -d '{"name":"Ada"}'`,
  '{"ok":true,"items":[1,2,],}'];

// --------------------------------------------------------------------- pages

const TOOLS = [
  { slug: "jwt-decoder", tool: "jwt", nav: "JWT decoder & verifier" },
  { slug: "certificate-decoder", tool: "certificate", nav: "Certificate decoder" },
  { slug: "http-security-headers", tool: "headers", nav: "Security headers check" },
  { slug: "saml-decoder", tool: "saml", nav: "SAML decoder" },
  { slug: "email-header-analyzer", tool: "email", nav: "Email header analyzer" },
  { slug: "uuid-decoder", tool: "ids", nav: "UUID & ID decoder" },
];

const PAGES = [
  {
    slug: "", tool: "home",
    title: "decoder.in — Make encoded data readable",
    description: "Privately inspect JWTs, certificates, SAML, email headers, security headers, UUIDs, cURL, JSON and Base64. Everything is decoded locally in your browser.",
    ogTitle: "decoder.in — Make encoded data readable",
    h1: ["Make encoded data", "readable."],
    intro: "Paste a token, certificate, SAML message, email header, HTTP response, ID, JSON or encoded string. Decoder identifies it and unwraps every layer in your browser.",
    placeholder: "Paste a token, certificate, request, headers, JSON, or encoded value…",
    chips: ["JWT & signatures", "Certificates", "SAML & headers", "IDs & encodings"],
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
];

// ------------------------------------------------------------------ template

function toolsNav(current) {
  return TOOLS.map((t) => `<a href="/${t.slug}/"${t.slug === current ? ' aria-current="page"' : ""}>${esc(t.nav)}</a>`).join("");
}

function sectionsHtml(page) {
  if (!page.sections && !page.faq) return "";
  const sections = (page.sections || []).map(([h, paragraphs]) =>
    `<section class="content-section"><h2>${esc(h)}</h2>${paragraphs.map((p) => `<p>${p}</p>`).join("")}</section>`).join("\n        ");
  const faq = page.faq ? `<section class="content-section"><h2>Questions</h2>${page.faq.map(([q, a]) => `<h3>${esc(q)}</h3><p>${esc(a)}</p>`).join("")}</section>` : "";
  return `
      <article class="content-page tool-guide">
        ${sections}
        ${faq}
      </article>`;
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
  const principles = page.slug ? "" : `
      <section class="principles" aria-label="Product principles">
        <article><span>01</span><h3>Automatic</h3><p>No dropdowns. Decoder recognizes common technical formats and nested layers.</p></article>
        <article><span>02</span><h3>Private</h3><p>No uploads, accounts, analytics payloads, or server-side processing.</p></article>
        <article><span>03</span><h3>Explicit</h3><p>Every transformation is shown so you can verify exactly what happened.</p></article>
      </section>`;
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="description" content="${esc(page.description)}" />
    <meta name="theme-color" content="#f4f1e8" />
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
    <header class="site-header">
      <a class="wordmark" href="/" aria-label="decoder.in home">
        <span class="wordmark-mark" aria-hidden="true">d/</span>
        <span>decoder.in</span>
      </a>
      <div class="header-actions">
        <nav aria-label="Primary navigation">
          <a href="/#tools">Tools</a>
          <a href="/docs/">Docs</a>
          <a href="/privacy/">Privacy</a>
        </nav>
        <div class="privacy-pill"><span></span> Local only</div>
      </div>
    </header>

    <main>
      <section class="hero">
        <p class="eyebrow">A private technical payload inspector by <a href="https://swiss.software/">swiss.software</a></p>
        <h1>${esc(page.h1[0])}<br /><em>${esc(page.h1[1])}</em></h1>
        <p class="intro">${esc(page.intro)}</p>
      </section>

      <div class="capability-strip" aria-label="Supported inspections">
        ${page.chips.map((c) => `<span>${esc(c)}</span>`).join("\n        ")}
      </div>

      <section class="workspace" aria-label="Decoder workspace">
        <div class="input-panel">
          <div class="panel-heading">
            <label for="payload">Input</label>
            <div class="input-actions">
              <button class="text-button" id="exampleButton" type="button">Try example</button>
              <button class="text-button" id="clearButton" type="button">Clear</button>
            </div>
          </div>
          <textarea
            id="payload"
            spellcheck="false"
            autocomplete="off"
            placeholder="${esc(page.placeholder)}"
          ></textarea>
          <div class="drop-hint">⌘ / Ctrl + V &nbsp;·&nbsp; Data never leaves this tab</div>
        </div>

        <div class="result-panel" id="resultPanel" aria-live="polite">
          <div class="empty-state" id="emptyState">
            <div class="radar" aria-hidden="true"><span></span></div>
            <h2>Waiting for a signal</h2>
            <p>Decoder will inspect the structure, not guess at its meaning.</p>
          </div>

          <div class="results" id="results" hidden>
            <div class="result-topline">
              <div>
                <p class="result-label">Detected as</p>
                <h2 id="detectedType">Unknown</h2>
              </div>
              <button class="copy-button" id="copyButton" type="button">Copy output</button>
            </div>

            <div class="confidence-row">
              <span id="confidenceText">High confidence</span>
              <div class="confidence-track"><span id="confidenceBar"></span></div>
            </div>

            <div id="notices"></div>
            <section class="verify-panel" id="verifyPanel" hidden aria-label="Verify signature">
              <label for="verifyKey">Verify signature</label>
              <textarea id="verifyKey" spellcheck="false" autocomplete="off" placeholder="Secret (HS256…), PEM public key, certificate, JWK or JWKS"></textarea>
              <p class="verify-result" id="verifyResult">Paste a key to check the signature. It stays in this tab.</p>
            </section>
            <div class="layers" id="layers"></div>
          </div>
        </div>
      </section>
${page.hint ? `
      <p class="tool-hint">${page.hint}</p>
` : ""}${principles}
      <nav class="tool-links" id="tools" aria-label="Decoder tools">
        <h2>Tools</h2>
        <div>${toolsNav(page.slug)}</div>
      </nav>
${sectionsHtml(page)}
    </main>

    <footer>
      <span>decoder.in · beta ${VERSION} · built by <a href="https://swiss.software/">swiss.software</a></span>
      <nav aria-label="Footer navigation">
        <a href="/docs/">Documentation</a>
        <a href="/privacy/">Privacy</a>
        <a href="https://github.com/gmdorg-max/decoder-in">Source</a>
        <a href="mailto:hello@swiss.software?subject=decoder.in%20feedback">Send feedback</a>
      </nav>
    </footer>

    <script src="/tools.js?v=${ASSET}"></script>
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
module.exports = { PAGES, TOOLS, EXAMPLES, DEMO_SECRET };
