const payload = document.querySelector("#payload");
const emptyState = document.querySelector("#emptyState");
const results = document.querySelector("#results");
const detectedType = document.querySelector("#detectedType");
const confidenceText = document.querySelector("#confidenceText");
const confidenceBar = document.querySelector("#confidenceBar");
const layers = document.querySelector("#layers");
const notices = document.querySelector("#notices");
const copyButton = document.querySelector("#copyButton");
const verifyPanel = document.querySelector("#verifyPanel");
const verifyKey = document.querySelector("#verifyKey");
const verifyResult = document.querySelector("#verifyResult");
const tool = document.body.dataset.tool || "home";
const examples = (globalThis.DecoderExamples && globalThis.DecoderExamples[tool]) || [];
let latestOutput = "";
let latestToken = null;
let latestCheck = null;
let exampleIndex = 0;
let verifyRun = 0;

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
}

function displayValue(layer) {
  if (layer.claims && layer.value && typeof layer.value === "object" && !Array.isArray(layer.value)) {
    return `<dl class="claims">${Object.entries(layer.value).map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(typeof value === "object" ? JSON.stringify(value) : value)}</dd>`).join("")}</dl>`;
  }
  const value = typeof layer.value === "string" ? layer.value : JSON.stringify(layer.value, null, 2);
  return `<pre>${escapeHtml(value)}</pre>`;
}

function setVerify(state, message) {
  verifyResult.textContent = message;
  verifyResult.dataset.state = state;
}

async function verify() {
  const run = ++verifyRun;
  if (!latestToken) return;
  if (!verifyKey.value.trim()) { setVerify("idle", "Paste a key to check the signature. It stays in this tab."); return; }
  setVerify("busy", "Checking…");
  let result;
  try {
    result = await DecoderTools.verifyJwt(latestToken, verifyKey.value);
  } catch (error) {
    result = { ok: false, message: (error && error.message) || "The key could not be used." };
  }
  if (run !== verifyRun) return;
  setVerify(result.ok ? "ok" : "bad", result.message);
}

function render() {
  const value = payload.value.trim();
  if (!value) {
    emptyState.hidden = false;
    results.hidden = true;
    latestOutput = "";
    latestToken = null;
    verifyRun += 1; // a verification still in flight must not report into the cleared panel
    return;
  }

  const analysis = Decoder.analyze(value, Date.now(), { tool });
  latestOutput = analysis.output;
  emptyState.hidden = true;
  results.hidden = false;
  detectedType.textContent = analysis.type;
  confidenceText.textContent = `${analysis.confidence}% confidence`;
  confidenceBar.style.width = `${analysis.confidence}%`;
  notices.innerHTML = analysis.notices.map((notice) => `<div class="notice">${escapeHtml(notice)}</div>`).join("");
  layers.innerHTML = analysis.layers.map((layer) => `
    <article class="layer">
      <div class="layer-heading"><span>${escapeHtml(layer.type)}</span><span>${escapeHtml(layer.detail)}</span></div>
      ${displayValue(layer)}
    </article>`).join("");

  const token = analysis.jwt || null;
  verifyPanel.hidden = !token;
  if (token !== latestToken) {
    latestToken = token;
    if (token) verify();
  }

  const check = analysis.check || null;
  if (JSON.stringify(check) !== JSON.stringify(latestCheck)) {
    latestCheck = check;
    checkPanel.hidden = !check;
    if (check) { checkKey.value = ""; setCheck("idle", "Paste the code_verifier to confirm it matches the code_challenge."); }
  }
}

const checkPanel = document.querySelector("#checkPanel");
const checkKey = document.querySelector("#checkKey");
const checkResult = document.querySelector("#checkResult");

function setCheck(state, message) {
  checkResult.textContent = message;
  checkResult.dataset.state = state;
}

function runCheck() {
  if (!latestCheck || latestCheck.kind !== "pkce") return;
  const verifier = checkKey.value.trim();
  if (!verifier) { setCheck("idle", "Paste the code_verifier to confirm it matches the code_challenge."); return; }
  if (!/^[A-Za-z0-9-._~]{43,128}$/.test(verifier)) { setCheck("bad", "A code_verifier is 43 to 128 characters of A-Z a-z 0-9 - . _ ~"); return; }
  const challenge = DecoderProtocols.pkceChallenge(verifier);
  setCheck(challenge === latestCheck.challenge ? "ok" : "bad", challenge === latestCheck.challenge
    ? "The verifier matches: BASE64URL(SHA256(code_verifier)) equals the code_challenge."
    : `No match. This verifier gives ${challenge}, the request carries ${latestCheck.challenge}.`);
}
checkKey.addEventListener("input", runCheck);

payload.addEventListener("input", render);
verifyKey.addEventListener("input", verify);
document.querySelector("#clearButton").addEventListener("click", () => { payload.value = ""; render(); payload.focus(); });
const exampleButton = document.querySelector("#exampleButton");
if (!examples.length) exampleButton.hidden = true;
exampleButton.addEventListener("click", (event) => {
  payload.value = examples[exampleIndex];
  exampleIndex = (exampleIndex + 1) % examples.length;
  if (examples.length > 1) event.currentTarget.textContent = "Next example";
  render();
});
copyButton.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(latestOutput);
    copyButton.textContent = "Copied";
  } catch {
    // Clipboard access can be refused (permissions, embedded frames); the input stays untouched.
    copyButton.textContent = "Copy blocked by the browser";
  }
  window.setTimeout(() => { copyButton.textContent = "Copy output"; }, 1600);
});
