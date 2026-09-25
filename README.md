# decoder.in

A private, browser-only inspector for technical payloads: paste something, and it
recognises what it is and unwraps every layer. Live at **https://decoder.in**.

Built by [swiss.software](https://swiss.software/). Free to use.

## What it reads

| Tool | Page |
|---|---|
| JWTs: claims, expiry, and signature verification (HS, RS, PS, ES, EdDSA) with a secret, PEM key, certificate, JWK or JWKS | [/jwt-decoder/](https://decoder.in/jwt-decoder/) |
| X.509 certificates, chains, CSRs and public keys: domains, expiry, key, fingerprints, chain order | [/certificate-decoder/](https://decoder.in/certificate-decoder/) |
| HTTP response headers: graded CSP, HSTS, framing, cookies, CORS, version leaks | [/http-security-headers/](https://decoder.in/http-security-headers/) |
| SAML redirect URLs, SAMLRequest / SAMLResponse values and XML | [/saml-decoder/](https://decoder.in/saml-decoder/) |
| Email headers: SPF, DKIM, DMARC, delivery route, spoofing signs | [/email-header-analyzer/](https://decoder.in/email-header-analyzer/) |
| UUID v1–v8, ULID, MongoDB ObjectId, Snowflake IDs | [/uuid-decoder/](https://decoder.in/uuid-decoder/) |
| cURL commands, raw HTTP requests, JSON (with repair hints), Base64, URL encoding, gzip/zlib/deflate, Unix timestamps | [/](https://decoder.in/) |

## Privacy by construction

Everything runs in the browser. There are no dependencies, no build step for the
runtime code, no analytics and no backend. Production serves the site with
`connect-src 'none'`, so the page cannot send your input anywhere even if it
wanted to. Signature checks use the browser's Web Crypto API.

## Layout

```
public/          everything that is served (deploy this directory)
  tools.js       certificates (ASN.1/DER), inflate, SHA-1/256, XML/SAML, IDs, email, headers, JWT verify
  decoder.js     the auto-detect: decides what a paste is and builds the result layers
  app.js         the page UI
  examples.js    generated: the "Try example" payloads
build/pages.js   generates the tool pages, examples.js and sitemap.xml from one template
build/serve.js   local preview with the production security headers
test/            node tests; fixtures were generated with openssl
```

## Develop

Requires Node.js 20 or newer; no packages to install.

```sh
npm test              # page check + decoder tests + tool tests
node build/pages.js   # regenerate pages after editing build/pages.js or the fixtures
node build/serve.js   # preview on http://127.0.0.1:8765 with the production CSP
```

## Security

Found a problem? Write to security@decoder.in (see `/.well-known/security.txt`).

## Licence

MIT, see [LICENSE](LICENSE).
