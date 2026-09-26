const assert = require("node:assert/strict");
const { analyze, analyzeHttp, analyzeJwtClaims, decodeJwt, diagnoseJson, timestampInfo } = require("../public/decoder.js");

const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJuYW1lIjoiQWRhIn0.signature";
assert.equal(analyze(jwt).type, "JSON Web Token");
assert.equal(decodeJwt(jwt).payload.name, "Ada");
assert.equal(analyze(jwt).layers[2].type, "JWT intelligence");

const expiredClaims = analyzeJwtClaims({
  header: { alg: "HS256" },
  payload: { sub: "123", iat: 1600000000, exp: 1704067200 },
  signature: "signature",
}, Date.parse("2024-01-02T00:00:00.000Z"));
assert.match(expiredClaims.summary.Status, /^Expired/);
assert.ok(expiredClaims.notices.some((notice) => /expired/i.test(notice)));

const noneAlgorithm = analyzeJwtClaims({ header: { alg: "none" }, payload: {}, signature: "(empty)" });
assert.ok(noneAlgorithm.notices.some((notice) => /alg: none/i.test(notice)));

const json = analyze('{"ok":true,"count":2}');
assert.equal(json.type, "JSON");
assert.match(json.output, /"count": 2/);

const base64 = analyze("SGVsbG8sIGRlY29kZXIu");
assert.equal(base64.type, "Base64");
assert.equal(base64.output, "Hello, decoder.");

const unicodeBase64 = analyze("8J+RiyBIZWxsbyE=");
assert.equal(unicodeBase64.type, "Base64");
assert.equal(unicodeBase64.output, "👋 Hello!");

const url = analyze("hello%20decoder%21");
assert.equal(url.type, "URL encoding");
assert.equal(url.output, "hello decoder!");

assert.equal(timestampInfo("1704067200").iso, "2024-01-01T00:00:00.000Z");
assert.equal(analyze("1704067200").type, "Unix timestamp");
assert.equal(analyze("1704067200000").type, "Unix timestamp");
assert.equal(analyze("ordinary sentence").type, "Plain text");
assert.equal(analyze("abc.def.ghi").type, "Malformed JWT");
assert.equal(analyze('{"ok":true,}').type, "Malformed JSON");
assert.equal(analyze('[1, 2,').type, "Malformed JSON");
assert.equal(diagnoseJson('{"ok":true,}').reason, "Trailing comma before a closing bracket");
assert.equal(diagnoseJson('{"ok":true,}').repair, '{"ok":true}');

const curl = analyze(`curl 'https://api.example.com/users?active=true&role=admin' -H 'Accept: application/json' -H 'Cookie: session=abc; theme=dark' -d '{"name":"Ada"}'`);
assert.equal(curl.type, "cURL request");
assert.equal(curl.layers[0].value.Method, "POST");
assert.ok(curl.layers.some((layer) => layer.type === "Query parameters" && layer.value.role === "admin"));
assert.ok(curl.layers.some((layer) => layer.type === "Cookies" && layer.value.theme === "dark"));
assert.ok(curl.layers.some((layer) => layer.type === "Request body" && layer.value.name === "Ada"));

const rawHttp = analyze("GET /users?page=2 HTTP/1.1\nHost: api.example.com\nAccept: application/json");
assert.equal(rawHttp.type, "HTTP request");
assert.ok(rawHttp.layers.some((layer) => layer.type === "Query parameters" && layer.value.page === "2"));

const plainUrl = analyze("https://decoder.in/path?q=hello%20world&tag=a&tag=b#result");
assert.equal(plainUrl.type, "URL");
assert.ok(plainUrl.layers.some((layer) => layer.type === "Query parameters"));
assert.deepEqual(plainUrl.layers.find((layer) => layer.type === "Query parameters").value.tag, ["a", "b"]);

const headers = analyzeHttp("Content-Type: application/json\nCookie: a=1; b=2");
assert.equal(headers.type, "HTTP headers");
assert.ok(headers.layers.some((layer) => layer.type === "Cookies" && layer.value.b === "2"));

const bearerHeaders = analyze(`Authorization: Bearer ${jwt}`);
assert.equal(bearerHeaders.type, "HTTP headers");
assert.ok(bearerHeaders.layers.some((layer) => layer.type === "Bearer JWT payload" && layer.value.name === "Ada"));

console.log("All decoder tests passed.");

// Deep nesting: JSON.parse accepts it, JSON.stringify and the renderer do not.
// analyze() must return a result instead of throwing (the page kept the previous
// input's result on screen when it threw).
{
  const deep = "[".repeat(100000) + "]".repeat(100000);
  const result = analyze(deep, Date.now(), { tool: "json" });
  assert.equal(result.type, "Deeply nested JSON");
  assert.ok(result.notices.some((n) => /512 levels/.test(n)));
  assert.equal(result.output, deep);
  const wrapped = analyze(Buffer.from(deep).toString("base64"));
  assert.ok(["Base64", "Deeply nested JSON", "Plain text"].includes(wrapped.type), wrapped.type);
  const fine = analyze("[".repeat(100) + "]".repeat(100));
  assert.equal(fine.type, "JSON");
}
