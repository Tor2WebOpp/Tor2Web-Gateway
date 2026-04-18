// API client. Reads/refreshes the CSRF token from /api/me and stores it
// for subsequent mutating requests. All requests use credentials:'include'
// so the session cookie flows. 401 responses force a full reload so the
// handler can mint a new session.

let csrfToken = "";
let primed = false;
const CSRF_HEADER = "X-CSRF-Token";

// Base path is derived from window.location: the admin is served
// under a random prefix, so relative paths (no leading slash) are used
// throughout. adminBase() returns the prefix that the app was loaded
// under, ending with "/".
export function adminBase() {
  const p = window.location.pathname;
  const i = p.lastIndexOf("/");
  return i >= 0 ? p.slice(0, i + 1) : "/";
}

function apiPath(path) {
  // Callers pass "/api/foo" — convert to "<base>api/foo".
  if (path.startsWith("/")) path = path.slice(1);
  return adminBase() + path;
}

// prime fetches /api/me to populate the CSRF token cache. Called once
// on first request; subsequent calls no-op.
async function prime() {
  if (primed) return;
  const res = await fetch(apiPath("/api/me"), {
    method: "GET",
    credentials: "include",
    headers: { Accept: "application/json" },
  });
  captureCSRF(res);
  primed = true;
}

function captureCSRF(res) {
  const t = res.headers.get(CSRF_HEADER);
  if (t) csrfToken = t;
}

async function doFetch(method, path, body, isRetry = false) {
  const headers = { Accept: "application/json" };
  const opts = { method, credentials: "include", headers };
  if (body !== undefined && body !== null) {
    headers["Content-Type"] = "application/json";
    opts.body = typeof body === "string" ? body : JSON.stringify(body);
  }
  const isMutating = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
  if (isMutating && csrfToken) {
    headers[CSRF_HEADER] = csrfToken;
  }
  let res;
  try {
    res = await fetch(apiPath(path), opts);
  } catch (netErr) {
    if (isRetry) throw netErr;
    // One retry on network error.
    return doFetch(method, path, body, true);
  }
  captureCSRF(res);
  if (res.status === 401) {
    window.location.reload();
    // Never resolves; the reload terminates the page.
    return new Promise(() => {});
  }
  if (!res.ok) {
    let bodyText = "";
    try { bodyText = await res.text(); } catch (_) { /* ignore */ }
    const err = new Error("api error " + res.status);
    err.status = res.status;
    err.body = bodyText;
    throw err;
  }
  return res;
}

// apiGet returns parsed JSON, or raw text for text/plain responses.
export async function apiGet(path) {
  await prime();
  const res = await doFetch("GET", path);
  const ct = res.headers.get("Content-Type") || "";
  if (ct.startsWith("application/json")) {
    if (res.status === 204) return null;
    return res.json();
  }
  return res.text();
}

// apiJSON performs a mutating request and returns parsed JSON body or
// null for 204 No Content.
export async function apiJSON(method, path, body) {
  await prime();
  const res = await doFetch(method, path, body);
  if (res.status === 204) return null;
  const ct = res.headers.get("Content-Type") || "";
  if (ct.startsWith("application/json")) return res.json();
  return res.text();
}

// csrf exposes the current token for tests / debugging.
export function csrf() { return csrfToken; }
