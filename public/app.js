const payload = document.querySelector("#payload");
const emptyState = document.querySelector("#emptyState");
const results = document.querySelector("#results");
const detectedType = document.querySelector("#detectedType");
const confidenceText = document.querySelector("#confidenceText");
const confidenceBar = document.querySelector("#confidenceBar");
const layers = document.querySelector("#layers");
const notices = document.querySelector("#notices");
const copyButton = document.querySelector("#copyButton");
let latestOutput = "";
let exampleIndex = 0;

const examples = [
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkYSBMb3ZlbGFjZSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNzA0MDY3MjAwfQ.signature-not-verified",
  `curl 'https://api.example.com/users?active=true&role=admin' -H 'Accept: application/json' -H 'Cookie: session=demo; theme=dark' -d '{"name":"Ada"}'`,
  '{"ok":true,"items":[1,2,],}',
];

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

function render() {
  const value = payload.value.trim();
  if (!value) {
    emptyState.hidden = false;
    results.hidden = true;
    latestOutput = "";
    return;
  }

  const analysis = Decoder.analyze(value);
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
}

payload.addEventListener("input", render);
document.querySelector("#clearButton").addEventListener("click", () => { payload.value = ""; render(); payload.focus(); });
document.querySelector("#exampleButton").addEventListener("click", (event) => {
  payload.value = examples[exampleIndex];
  exampleIndex = (exampleIndex + 1) % examples.length;
  event.currentTarget.textContent = "Next example";
  render();
});
copyButton.addEventListener("click", async () => {
  await navigator.clipboard.writeText(latestOutput);
  copyButton.textContent = "Copied";
  window.setTimeout(() => { copyButton.textContent = "Copy output"; }, 1200);
});
