(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.Decoder = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const Tools = typeof module === "object" && typeof require === "function" ? require("./tools.js") : globalThis.DecoderTools;
  const MAX_LAYERS = 6;

  function prettify(value) {
    return typeof value === "string" ? value : JSON.stringify(value, null, 2);
  }

  function decodeBase64(value) {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(padded)) throw new Error("Not Base64");
    const binary = typeof atob === "function" ? atob(padded) : Buffer.from(padded, "base64").toString("binary");
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }

  function isMostlyReadable(value) {
    if (!value.length) return false;
    const characters = [...value];
    const unreadableControl = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u;
    const readable = characters.filter((char) => char !== "\uFFFD" && !unreadableControl.test(char)).length;
    return readable / characters.length > 0.92;
  }

  function parseJson(value) {
    try { return JSON.parse(value); } catch { return null; }
  }

  function timestampInfo(value) {
    if (!/^\d{10}(\d{3})?$/.test(value)) return null;
    const milliseconds = value.length === 10 ? Number(value) * 1000 : Number(value);
    const date = new Date(milliseconds);
    if (Number.isNaN(date.getTime()) || date.getUTCFullYear() < 2000 || date.getUTCFullYear() > 2200) return null;
    return { original: value, iso: date.toISOString(), local: date.toLocaleString() };
  }

  function decodeJwt(value) {
    const parts = value.split(".");
    if (parts.length !== 3 || !parts[0] || !parts[1]) return null;
    try {
      const header = parseJson(decodeBase64(parts[0]));
      const payload = parseJson(decodeBase64(parts[1]));
      if (!header || !payload || typeof header !== "object" || typeof payload !== "object") return null;
      return { header, payload, signature: parts[2] || "(empty)" };
    } catch { return null; }
  }

  function looksLikeJwt(value) {
    const parts = value.split(".");
    return parts.length === 3 && parts.every((part) => part.length > 0 && /^[A-Za-z0-9_-]+$/.test(part));
  }

  function formatDuration(milliseconds) {
    const seconds = Math.max(0, Math.round(Math.abs(milliseconds) / 1000));
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.round(seconds / 60);
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.round(minutes / 60);
    if (hours < 48) return `${hours}h`;
    return `${Math.round(hours / 24)}d`;
  }

  function jwtTime(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) return null;
    const date = new Date(value * 1000);
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
  }

  function analyzeJwtClaims(jwt, now = Date.now()) {
    const summary = {};
    const notices = [];
    const { header, payload, signature } = jwt;

    if (payload.iss !== undefined) summary.Issuer = payload.iss;
    if (payload.aud !== undefined) summary.Audience = payload.aud;
    if (payload.sub !== undefined) summary.Subject = payload.sub;
    if (payload.iat !== undefined) summary["Issued at"] = jwtTime(payload.iat) || "Invalid timestamp";
    if (payload.nbf !== undefined) summary["Not before"] = jwtTime(payload.nbf) || "Invalid timestamp";
    if (payload.exp !== undefined) summary.Expires = jwtTime(payload.exp) || "Invalid timestamp";

    if (typeof payload.exp === "number") {
      const delta = payload.exp * 1000 - now;
      summary.Status = delta <= 0 ? `Expired ${formatDuration(delta)} ago` : `Expires in ${formatDuration(delta)}`;
      if (delta <= 0) notices.push("This token is expired. Do not treat its claims as an active authorization.");
    } else if (typeof payload.nbf === "number" && payload.nbf * 1000 > now) {
      summary.Status = `Not active for ${formatDuration(payload.nbf * 1000 - now)}`;
      notices.push("This token is not active yet according to its nbf claim.");
    } else {
      summary.Status = "No expiration claim";
    }

    if (typeof payload.iat === "number" && payload.iat * 1000 > now + 300000) {
      notices.push("The issued-at time is in the future. Check the token source or system clock.");
    }
    if (String(header.alg || "").toLowerCase() === "none") {
      notices.push("Security warning: this token declares alg: none and has no cryptographic signature protection.");
    } else if (!signature || signature === "(empty)") {
      notices.push("Security warning: the token has an empty signature.");
    }
    notices.push("Decoded does not mean verified. The signature has not been checked against a trusted key.");
    return { summary, notices };
  }

  function diagnoseJson(value) {
    let message = "Invalid JSON syntax";
    let position = value.length;
    try { JSON.parse(value); } catch (error) {
      const positionMatch = String(error.message).match(/position\s+(\d+)/i);
      if (positionMatch) position = Number(positionMatch[1]);
      if (/unexpected end/i.test(error.message)) position = value.length;
      message = String(error.message).replace(/^JSON\.parse:\s*/i, "");
    }

    let reason = message;
    if (/,\s*[}\]]/.test(value)) reason = "Trailing comma before a closing bracket";
    else if (/'[^']*'\s*:/.test(value)) reason = "JSON property names must use double quotes";
    else if (/[{,]\s*[A-Za-z_$][\w$]*\s*:/.test(value)) reason = "JSON property names must be wrapped in double quotes";
    else if (value.startsWith("{") && !value.trimEnd().endsWith("}")) reason = "Object appears to be missing a closing brace";
    else if (value.startsWith("[") && !value.trimEnd().endsWith("]")) reason = "Array appears to be missing a closing bracket";

    const before = value.slice(0, position);
    const line = before.split("\n").length;
    const lastNewline = before.lastIndexOf("\n");
    const column = position - lastNewline;
    const near = value.slice(Math.max(0, position - 18), Math.min(value.length, position + 18)).replace(/\s+/g, " ");
    const repairedText = value.replace(/,\s*([}\]])/g, "$1");
    const repair = repairedText !== value && parseJson(repairedText) !== null ? repairedText : null;
    return { reason, line, column, near: near || "End of input", repair };
  }

  function shellTokens(value) {
    const normalized = value.replace(/(?:\\|\^)\r?\n/g, " ");
    const matches = normalized.match(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\S+/g) || [];
    return matches.map((token) => {
      const quoted = (token.startsWith('"') && token.endsWith('"')) || (token.startsWith("'") && token.endsWith("'"));
      return quoted ? token.slice(1, -1).replace(/\\"/g, '"') : token;
    });
  }

  function parseHeaders(lines) {
    const headers = {};
    for (const line of lines) {
      const separator = line.indexOf(":");
      if (separator < 1) continue;
      headers[line.slice(0, separator).trim()] = line.slice(separator + 1).trim();
    }
    return headers;
  }

  function headerValue(headers, name) {
    const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
    return key ? headers[key] : null;
  }

  function urlLayers(rawUrl, layers) {
    try {
      const url = new URL(rawUrl, "https://relative.invalid");
      const details = {
        Scheme: url.protocol.replace(":", ""),
        Host: url.host === "relative.invalid" ? "Relative URL" : url.host,
        Path: url.pathname,
      };
      if (url.hash) details.Fragment = url.hash.slice(1);
      layers.push({ type: "URL", detail: url.host === "relative.invalid" ? "Relative" : url.protocol.replace(":", "").toUpperCase(), value: details, claims: true });
      const query = {};
      for (const [key, value] of url.searchParams) {
        if (query[key] === undefined) query[key] = value;
        else query[key] = Array.isArray(query[key]) ? [...query[key], value] : [query[key], value];
      }
      if (Object.keys(query).length) layers.push({ type: "Query parameters", detail: `${url.searchParams.size} values`, value: query, claims: true });
      return url;
    } catch { return null; }
  }

  function addHeaderLayers(headers, layers, notices) {
    if (!Object.keys(headers).length) return;
    layers.push({ type: "HTTP headers", detail: `${Object.keys(headers).length} fields`, value: headers, claims: true });
    const cookie = headerValue(headers, "cookie");
    if (cookie) {
      const cookies = {};
      for (const part of cookie.split(";")) {
        const separator = part.indexOf("=");
        if (separator > 0) cookies[part.slice(0, separator).trim()] = part.slice(separator + 1).trim();
      }
      if (Object.keys(cookies).length) layers.push({ type: "Cookies", detail: `${Object.keys(cookies).length} values`, value: cookies, claims: true });
    }
    const authorization = headerValue(headers, "authorization");
    const bearer = authorization && authorization.match(/^Bearer\s+(.+)$/i);
    if (bearer) {
      const jwt = decodeJwt(bearer[1]);
      if (jwt) {
        const intelligence = analyzeJwtClaims(jwt);
        layers.push({ type: "Bearer JWT header", detail: jwt.header.alg || "JSON", value: jwt.header, claims: true });
        layers.push({ type: "Bearer JWT payload", detail: "Claims", value: jwt.payload, claims: true });
        layers.push({ type: "JWT intelligence", detail: intelligence.summary.Status, value: intelligence.summary, claims: true });
        notices.push(...intelligence.notices);
      } else notices.push("A Bearer credential was found, but it is not a valid JSON Web Token.");
    }
  }

  function requestAnalysis(type, method, rawUrl, headers, body) {
    const layers = [];
    const notices = [];
    const request = { Method: method || (body ? "POST" : "GET"), URL: rawUrl || "Not provided" };
    layers.push({ type: "Request", detail: request.Method, value: request, claims: true });
    if (rawUrl) urlLayers(rawUrl, layers);
    addHeaderLayers(headers, layers, notices);
    if (body) {
      const json = parseJson(body);
      layers.push({ type: "Request body", detail: json !== null ? "JSON" : `${body.length} characters`, value: json !== null ? json : body, claims: json !== null && typeof json === "object" && !Array.isArray(json) });
    }
    return { type, confidence: 97, layers, notices, output: prettify(request) };
  }

  function analyzeHttp(value) {
    if (/^curl(?:\.exe)?\s/i.test(value)) {
      const tokens = shellTokens(value);
      let method = "GET";
      let rawUrl = "";
      let body = "";
      const headerLines = [];
      for (let index = 1; index < tokens.length; index += 1) {
        const token = tokens[index];
        if (["-X", "--request"].includes(token) && tokens[index + 1]) method = tokens[++index].toUpperCase();
        else if (["-H", "--header"].includes(token) && tokens[index + 1]) headerLines.push(tokens[++index]);
        else if (["-d", "--data", "--data-raw", "--data-binary"].includes(token) && tokens[index + 1]) { body = tokens[++index]; if (method === "GET") method = "POST"; }
        else if (token === "--url" && tokens[index + 1]) rawUrl = tokens[++index];
        else if (token === "-I" || token === "--head") method = "HEAD";
        else if (/^https?:\/\//i.test(token)) rawUrl = token;
      }
      return requestAnalysis("cURL request", method, rawUrl, parseHeaders(headerLines), body);
    }

    const lines = value.split(/\r?\n/);
    const requestLine = lines[0].match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/i);
    if (requestLine) {
      const blank = lines.findIndex((line, index) => index > 0 && line.trim() === "");
      const headerEnd = blank === -1 ? lines.length : blank;
      return requestAnalysis("HTTP request", requestLine[1].toUpperCase(), requestLine[2], parseHeaders(lines.slice(1, headerEnd)), blank === -1 ? "" : lines.slice(blank + 1).join("\n"));
    }

    if (/^https?:\/\/\S+$/i.test(value)) {
      const layers = [];
      const url = urlLayers(value, layers);
      if (url) return { type: "URL", confidence: 99, layers, notices: [], output: url.href };
    }

    const nonEmptyLines = lines.filter((line) => line.trim());
    if (nonEmptyLines.length && nonEmptyLines.every((line) => /^[A-Za-z0-9-]+\s*:/.test(line))) {
      const layers = [];
      const notices = [];
      addHeaderLayers(parseHeaders(nonEmptyLines), layers, notices);
      return { type: "HTTP headers", confidence: 94, layers, notices, output: value };
    }
    return null;
  }

  function analyze(input, now = Date.now()) {
    const raw = String(input ?? "").trim();
    if (!raw) return { type: "Empty", confidence: 0, layers: [], notices: [], output: "" };

    const notices = [];
    const layers = [];
    if (/-----BEGIN [A-Z0-9 ]+-----/.test(raw)) {
      const pem = Tools.analyzePem(raw, now);
      if (pem) return pem;
    }

    const jwt = decodeJwt(raw);
    if (jwt) {
      const intelligence = analyzeJwtClaims(jwt);
      layers.push({ type: "JWT header", detail: jwt.header.alg || "JSON", value: jwt.header, claims: true });
      layers.push({ type: "JWT payload", detail: "Claims", value: jwt.payload, claims: true });
      layers.push({ type: "JWT intelligence", detail: intelligence.summary.Status, value: intelligence.summary, claims: true });
      layers.push({ type: "Signature", detail: "Not verified", value: jwt.signature });
      notices.push(...intelligence.notices);
      return { type: "JSON Web Token", confidence: 98, layers, notices, output: prettify(jwt.payload), jwt: raw };
    }

    if (looksLikeJwt(raw)) {
      layers.push({ type: "JWT-shaped input", detail: "Invalid", value: raw });
      notices.push("Three token sections were found, but the header or payload is not valid Base64URL-encoded JSON.");
      return { type: "Malformed JWT", confidence: 95, layers, notices, output: raw };
    }

    if (/^https?:\/\/\S+[?&]SAML(Request|Response)=/i.test(raw)) {
      const saml = Tools.analyzeSamlUrl(raw, now);
      if (saml) return saml;
    }

    const email = Tools.analyzeEmail(raw);
    if (email) return email;

    const response = Tools.analyzeResponse(raw);
    if (response) return response;

    const http = analyzeHttp(raw);
    if (http) return http;

    if (raw.startsWith("<")) {
      const xml = Tools.analyzeXml(raw, now);
      if (xml) return xml;
    }

    const id = Tools.analyzeId(raw, now);
    if (id) return id;

    const timestamp = timestampInfo(raw);
    if (timestamp) {
      layers.push({ type: "Unix timestamp", detail: raw.length === 10 ? "Seconds" : "Milliseconds", value: timestamp, claims: true });
      return { type: "Unix timestamp", confidence: 96, layers, notices, output: timestamp.iso };
    }

    const json = parseJson(raw);
    if (json !== null) {
      layers.push({ type: "JSON", detail: Array.isArray(json) ? "Array" : typeof json, value: json, claims: typeof json === "object" && !Array.isArray(json) });
      return { type: "JSON", confidence: 99, layers, notices, output: prettify(json) };
    }

    if (/^[\[{]/.test(raw)) {
      const diagnosis = diagnoseJson(raw);
      layers.push({ type: "JSON diagnosis", detail: `Line ${diagnosis.line}, column ${diagnosis.column}`, value: { Issue: diagnosis.reason, Line: diagnosis.line, Column: diagnosis.column, Near: diagnosis.near }, claims: true });
      layers.push({ type: "Original input", detail: "Unchanged", value: raw });
      if (diagnosis.repair) layers.push({ type: "Possible repair", detail: "Review before use", value: parseJson(diagnosis.repair), claims: true });
      notices.push("The input resembles JSON but could not be parsed. Review the diagnosis and any suggested repair before using it.");
      return { type: "Malformed JSON", confidence: 95, layers, notices, output: raw };
    }

    let current = raw;
    let firstType = "Plain text";
    for (let index = 0; index < MAX_LAYERS; index += 1) {
      let decoded = null;
      let type = null;

      if (/%[0-9A-Fa-f]{2}/.test(current)) {
        try {
          const candidate = decodeURIComponent(current.replace(/\+/g, "%20"));
          if (candidate !== current) { decoded = candidate; type = "URL encoding"; }
        } catch { /* leave malformed URLs untouched */ }
      }

      if (decoded === null && current.length >= 8 && /^[A-Za-z0-9+/_=-]+$/.test(current.replace(/\s/g, ""))) {
        try {
          const candidate = decodeBase64(current);
          if (candidate !== current && isMostlyReadable(candidate)) { decoded = candidate; type = "Base64"; }
        } catch {
          // Binary Base64: a DER certificate, or gzip / zlib / deflate compressed text.
          let bytes = null;
          try { bytes = Tools.base64ToBytes(current); } catch { /* not Base64 at all */ }
          if (bytes) {
            const cert = Tools.certificateFromDer(bytes, now);
            if (cert) return { ...cert, layers: [...layers, ...cert.layers], notices: [...notices, ...cert.notices] };
            const inflated = Tools.decompress(bytes);
            let text = null;
            if (inflated) {
              try { text = Tools.utf8(inflated.bytes, true); } catch { /* binary payload */ }
            }
            if (text && Tools.readable(text)) {
              layers.push({ type: "Base64", detail: `Layer ${layers.length + 1}`, value: `${bytes.length} bytes of ${inflated.format} data` });
              if (layers.length === 1) firstType = "Compressed data";
              decoded = text;
              type = `${inflated.format} decompressed`;
            }
          }
        }
      }

      if (decoded === null) break;
      if (layers.length === 0) firstType = type;
      layers.push({ type, detail: `Layer ${layers.length + 1}`, value: decoded });
      current = decoded.trim();

      const nestedJson = parseJson(current);
      if (nestedJson !== null) {
        layers.push({ type: "JSON", detail: "Decoded payload", value: nestedJson, claims: typeof nestedJson === "object" && !Array.isArray(nestedJson) });
        current = prettify(nestedJson);
        break;
      }

      if (current.startsWith("<")) {
        const xml = Tools.analyzeXml(current, now);
        if (xml) return { ...xml, layers: [...layers, ...xml.layers], notices: [...notices, ...xml.notices] };
      }

      const nestedTimestamp = timestampInfo(current);
      if (nestedTimestamp) {
        layers.push({ type: "Unix timestamp", detail: "Decoded value", value: nestedTimestamp, claims: true });
        current = nestedTimestamp.iso;
        break;
      }
    }

    if (layers.length) return { type: firstType, confidence: 91, layers, notices, output: current };

    layers.push({ type: "Plain text", detail: `${raw.length} characters`, value: raw });
    notices.push("No supported encoding was detected. The input is shown unchanged.");
    return { type: "Plain text", confidence: 65, layers, notices, output: raw };
  }

  return { analyze, analyzeHttp, analyzeJwtClaims, decodeBase64, decodeJwt, diagnoseJson, timestampInfo };
});
