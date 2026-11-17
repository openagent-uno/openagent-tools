// Resolve a model-supplied `navigate` URL into the URL the browser may load.
//
// The browser runs as the host account, so a local-file URL would hand the
// model any file that account can read (agent configuration, mounted secrets).
// Web pages cannot open those schemes themselves; CDP navigation can, so this
// is the gate for every browser-initiated navigation the tools perform.

const LOCAL_SCHEMES = /^\s*(file|filesystem|view-source|blob|data|javascript):/i;
const BROWSER_SCHEMES = /^(about|chrome|edge|brave):/i;

export function navigationTarget(url) {
  const raw = String(url ?? "");
  if (LOCAL_SCHEMES.test(raw)) {
    return { error: `Navigation to "${raw.split(":")[0].trim().toLowerCase()}:" URLs is not allowed; use an http(s) URL.` };
  }
  let target = raw;
  if (!/^https?:\/\//i.test(target) && !BROWSER_SCHEMES.test(target)) {
    target = "https://" + target.replace(/^[a-z]{1,6}:\/+/i, "");
  }
  try { new URL(target); } catch { return { error: `Invalid URL: "${raw}".` }; }
  return { url: target };
}
