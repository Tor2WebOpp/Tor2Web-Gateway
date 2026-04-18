// Admin app entry point. Wires i18n, theme, router, and shell handlers,
// then reveals the main UI once the first page has been mounted.

import { apiGet, apiJSON } from "./api.js";
import { init as i18nInit, applyDom, t } from "./i18n.js";
import * as router from "./router.js";
import { toast } from "./components.js";

import dashboard from "./pages/dashboard.js";
import tenants from "./pages/tenants.js";
import mirrors from "./pages/mirrors.js";
import blocklist from "./pages/blocklist.js";
import features from "./pages/features.js";
import nodes from "./pages/nodes.js";
import metrics from "./pages/metrics.js";
import audit from "./pages/audit.js";
import autoDomains from "./pages/auto-domains.js";

const THEME_KEY = "gw_adm_theme";
const LANG_KEY = "gw_adm_lang";

function applyTheme(theme) {
  if (theme !== "light" && theme !== "dark") theme = "dark";
  document.documentElement.setAttribute("data-theme", theme);
  try { localStorage.setItem(THEME_KEY, theme); } catch (_) { /* ignore */ }
}

function readStoredTheme() {
  try { return localStorage.getItem(THEME_KEY) || "dark"; } catch (_) { return "dark"; }
}

// Language resolution precedence:
//   1. ?lang= query parameter (persists into localStorage so later loads
//      keep the operator's explicit choice across soft reloads)
//   2. previously stored value in localStorage
//   3. navigator.language (best client-side proxy for Accept-Language;
//      the server can't forward it without a full template layer)
//   4. "en" as the final fallback
function normalizeLang(raw) {
  if (!raw || typeof raw !== "string") return "";
  const short = raw.toLowerCase().split(/[-_]/)[0];
  if (short === "ru" || short === "zh" || short === "en") return short;
  return "";
}

function readStoredLang() {
  let fromQuery = "";
  try {
    const params = new URLSearchParams(window.location.search);
    fromQuery = normalizeLang(params.get("lang"));
    if (fromQuery) {
      try { localStorage.setItem(LANG_KEY, fromQuery); } catch (_) { /* ignore */ }
      return fromQuery;
    }
  } catch (_) { /* ignore */ }
  try {
    const stored = normalizeLang(localStorage.getItem(LANG_KEY));
    if (stored) return stored;
  } catch (_) { /* ignore */ }
  try {
    const nav = normalizeLang(navigator.language || (navigator.languages && navigator.languages[0]));
    if (nav) return nav;
  } catch (_) { /* ignore */ }
  return "en";
}

function revealShell(me) {
  const boot = document.getElementById("boot");
  const sidebar = document.getElementById("sidebar");
  const main = document.getElementById("main");
  if (sidebar) sidebar.hidden = false;
  if (main) main.hidden = false;
  if (boot) boot.remove();
  const nodeEl = document.getElementById("node-id");
  if (nodeEl && me) {
    const parts = [];
    if (me.node_type) parts.push(me.node_type);
    if (me.node_id) parts.push(me.node_id);
    nodeEl.textContent = parts.join(" / ");
  }
  // Hide hub-only nav entries on non-hub nodes.
  if (me && me.node_type && me.node_type !== "hub") {
    const hubOnly = ["tenants", "mirrors", "nodes"];
    for (const name of hubOnly) {
      const el = document.querySelector('[data-route="' + name + '"]');
      if (el) el.hidden = true;
    }
  }
}

function wireShellHandlers() {
  const sidebarToggle = document.getElementById("sidebar-toggle");
  if (sidebarToggle) {
    sidebarToggle.addEventListener("click", () => {
      document.body.classList.toggle("sidebar-open");
    });
  }
  const themeToggle = document.getElementById("theme-toggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", () => {
      const cur = document.documentElement.getAttribute("data-theme") || "dark";
      applyTheme(cur === "dark" ? "light" : "dark");
    });
  }
  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      try {
        await apiJSON("POST", "/api/logout");
        window.location.reload();
      } catch (e) {
        toast(t("toast.error"), "error");
      }
    });
  }
  // Close the sidebar on nav click (mobile).
  document.querySelectorAll(".nav-link").forEach((el) => {
    el.addEventListener("click", () => {
      if (window.innerWidth < 900) {
        document.body.classList.remove("sidebar-open");
      }
    });
  });
}

async function boot() {
  applyTheme(readStoredTheme());
  try {
    await i18nInit(readStoredLang());
  } catch (_) { /* ignore */ }

  // Register pages.
  router.register("dashboard", dashboard.mount, dashboard.unmount);
  router.register("tenants", tenants.mount, tenants.unmount);
  router.register("mirrors", mirrors.mount, mirrors.unmount);
  router.register("blocklist", blocklist.mount, blocklist.unmount);
  router.register("features", features.mount, features.unmount);
  router.register("nodes", nodes.mount, nodes.unmount);
  router.register("metrics", metrics.mount, metrics.unmount);
  router.register("audit", audit.mount, audit.unmount);
  router.register("auto-domains", autoDomains.mount, autoDomains.unmount);

  let me = null;
  try {
    me = await apiGet("/api/me");
  } catch (e) {
    // Still reveal the shell; pages will show their own errors.
    console.warn("me fetch failed", e);
  }
  revealShell(me);
  wireShellHandlers();
  applyDom();
  router.start();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}
