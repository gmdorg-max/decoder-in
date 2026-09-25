# decoder.in beta 0.2

A zero-dependency, browser-only technical payload inspector.

## Run locally

Serve this directory with any static HTTP server, or open `index.html` directly.

```powershell
npx serve .
```

## Test

```powershell
node test.js
```

## Supported formats

- JWT (decode only; signatures are explicitly not verified)
- JWT time/status intelligence for `iat`, `nbf`, and `exp`
- JSON
- Malformed JSON diagnostics and conservative trailing-comma repair previews
- cURL commands, raw HTTP requests, header blocks, cookies, and JSON bodies
- URLs and query parameters
- Base64 and Base64URL
- URL encoding
- Unix timestamps in seconds or milliseconds
- Nested URL/Base64 layers up to six transformations

All analysis happens locally in the browser.
