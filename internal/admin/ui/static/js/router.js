// Hash-based router. Each page module registers a mount(contentEl)
// function; optional unmount() cleans up listeners. On hashchange the
// router finds the matching module, unmounts the outgoing page, and
// mounts the incoming one into #content.

const routes = new Map();
let currentName = "";
let currentUnmount = null;

export function register(name, mount, unmount) {
  routes.set(name, { mount, unmount: unmount || null });
}

export function route(path) {
  if (typeof path === "string") {
    if (!path.startsWith("#")) path = "#" + path;
    if (window.location.hash !== path) {
      window.location.hash = path;
      return;
    }
  }
  dispatch();
}

function parseName() {
  const raw = window.location.hash || "#/dashboard";
  // "#/dashboard" or "#/foo/bar" → "dashboard" / "foo-bar"
  const trimmed = raw.replace(/^#\/?/, "");
  const first = trimmed.split("/")[0] || "dashboard";
  return first;
}

async function dispatch() {
  const name = parseName();
  const contentEl = document.getElementById("content");
  if (!contentEl) return;
  const target = routes.get(name) || routes.get("dashboard");
  if (!target) {
    contentEl.textContent = "";
    return;
  }
  if (currentUnmount) {
    try { currentUnmount(); } catch (_) { /* ignore */ }
  }
  currentUnmount = null;
  // Clear content and reset scroll.
  contentEl.textContent = "";
  contentEl.scrollTop = 0;
  // Update active nav link.
  document.querySelectorAll(".nav-link").forEach((el) => {
    const r = el.getAttribute("data-route");
    if (r === name) el.classList.add("active");
    else el.classList.remove("active");
  });
  currentName = name;
  try {
    const maybe = target.mount(contentEl);
    // If mount returned an async unmount, remember it.
    const resolved = await Promise.resolve(maybe);
    if (typeof resolved === "function") currentUnmount = resolved;
    else if (target.unmount) currentUnmount = target.unmount;
  } catch (e) {
    contentEl.innerHTML = "";
    const err = document.createElement("div");
    err.className = "empty";
    err.textContent = "page error: " + (e && e.message ? e.message : String(e));
    contentEl.appendChild(err);
  }
}

export function start() {
  window.addEventListener("hashchange", dispatch);
  if (!window.location.hash) {
    window.location.hash = "#/dashboard";
  } else {
    dispatch();
  }
}

export function current() { return currentName; }
