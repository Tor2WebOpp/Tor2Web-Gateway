// Dashboard page: 6 summary cards pulling from several /api endpoints.

import { apiGet } from "../api.js";
import { el } from "../components.js";
import { t } from "../i18n.js";

function card(title, valueNode, sub) {
  return el("section", { class: "card" }, [
    el("h2", { class: "card-title", text: title }),
    valueNode,
    sub ? el("p", { class: "card-sub", text: sub }) : null,
  ]);
}

function parseMetricsText(text) {
  // Very loose parser: pick a "gateway_requests_total" style figure if
  // present; otherwise sum all numeric values on non-comment lines.
  if (!text || typeof text !== "string") return { total: 0 };
  let total = 0;
  let lines = 0;
  for (const raw of text.split("\n")) {
    if (!raw || raw.startsWith("#")) continue;
    lines++;
    const parts = raw.trim().split(/\s+/);
    const n = parts.length >= 2 ? parseFloat(parts[parts.length - 1]) : NaN;
    if (Number.isFinite(n)) total += n;
  }
  return { total, lines };
}

async function mount(root) {
  const title = el("h1", { class: "page-title", text: t("page.dashboard.title") });
  const grid = el("div", { class: "grid grid-cards" });
  root.appendChild(title);
  root.appendChild(grid);

  let me = null;
  try { me = await apiGet("/api/me"); } catch (_) { /* ignore */ }
  const isHub = me && me.node_type === "hub";

  // Node info card.
  const nodeCard = card(
    t("page.dashboard.title"),
    el("p", { class: "card-value", text: (me && me.node_id) || "-" }),
    me ? (me.node_type || "") : "",
  );
  grid.appendChild(nodeCard);

  // Features.
  try {
    const fs = await apiGet("/api/features");
    const arr = Array.isArray(fs) ? fs : [];
    const enabled = arr.filter((f) => f && f.enabled).length;
    grid.appendChild(card(
      t("nav.features"),
      el("p", { class: "card-value", text: enabled + " / " + arr.length }),
      t("label.enabled"),
    ));
  } catch (_) {
    grid.appendChild(card(t("nav.features"), el("p", { class: "card-value", text: "-" })));
  }

  // Audit recent.
  try {
    const events = await apiGet("/api/audit?limit=10");
    const arr = Array.isArray(events) ? events : [];
    const list = el("ul", { class: "list-clean" });
    if (arr.length === 0) {
      list.appendChild(el("li", { class: "empty", text: "-" }));
    } else {
      for (const e of arr.slice(0, 5)) {
        list.appendChild(el("li", { text: (e.action || "?") + "  " + (e.target || "") }));
      }
    }
    grid.appendChild(card(t("nav.audit"), list));
  } catch (_) {
    grid.appendChild(card(t("nav.audit"), el("p", { class: "card-value", text: "-" })));
  }

  // Metrics summary.
  try {
    const text = await apiGet("/api/metrics");
    const m = parseMetricsText(String(text || ""));
    grid.appendChild(card(
      t("nav.metrics"),
      el("p", { class: "card-value", text: String(m.lines || 0) }),
      t("label.status"),
    ));
  } catch (_) {
    grid.appendChild(card(t("nav.metrics"), el("p", { class: "card-value", text: "-" })));
  }

  // Hub-only cards.
  if (isHub) {
    try {
      const tenants = await apiGet("/api/tenants");
      const arr = Array.isArray(tenants) ? tenants : [];
      grid.appendChild(card(
        t("nav.tenants"),
        el("p", { class: "card-value", text: String(arr.length) }),
      ));
    } catch (_) {
      grid.appendChild(card(t("nav.tenants"), el("p", { class: "card-value", text: "-" })));
    }
    try {
      const mirrors = await apiGet("/api/mirrors");
      const arr = Array.isArray(mirrors) ? mirrors : [];
      const live = arr.filter((m) => m && (m.verdict === "live" || m.Verdict === "live")).length;
      const blocked = arr.filter((m) => m && (m.verdict === "blocked" || m.Verdict === "blocked")).length;
      grid.appendChild(card(
        t("nav.mirrors"),
        el("p", { class: "card-value", text: live + " / " + arr.length }),
        blocked ? (blocked + " " + t("verdict.blocked")) : "",
      ));
    } catch (_) {
      grid.appendChild(card(t("nav.mirrors"), el("p", { class: "card-value", text: "-" })));
    }
  } else {
    grid.appendChild(card(t("label.status"), el("p", { class: "card-value", text: t("verdict.live") })));
    grid.appendChild(card(t("label.type"), el("p", { class: "card-value", text: me ? (me.node_type || "-") : "-" })));
  }
}

export default { mount, unmount: null };
