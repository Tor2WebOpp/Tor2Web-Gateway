// Mirrors page (hub-only). Table with verdict badges + force-block/unblock
// controls. The mutating endpoints are best-effort: the spec reserves
// POST /api/mirrors/... for a future P4 milestone, so the UI wires the
// calls defensively and surfaces errors rather than pretending success.

import { apiGet, apiJSON } from "../api.js";
import { el, modal, toast } from "../components.js";
import { t } from "../i18n.js";

function verdictBadge(v) {
  const norm = (v || "").toLowerCase();
  const klass =
    norm === "live" ? "badge-ok" :
    norm === "degraded" ? "badge-warn" :
    norm === "blocked" ? "badge-error" :
    "badge";
  return el("span", { class: "badge " + klass, text: t("verdict." + (norm || "unknown")) });
}

function formatTime(v) {
  if (!v) return "-";
  try {
    const d = new Date(v);
    if (isNaN(d.getTime())) return String(v);
    return d.toISOString().replace("T", " ").slice(0, 19) + "Z";
  } catch (_) { return String(v); }
}

async function openForceBlock(host, reload) {
  const v = await modal({
    title: t("action.forceBlock") + " " + host,
    body: (dialog) => {
      const wrap = el("div");
      wrap.appendChild(el("p", { class: "label", text: t("confirm.deleteBody") }));
      const input = el("input", { class: "input", type: "text", placeholder: "reason" });
      wrap.appendChild(input);
      dialog.__input = input;
      return wrap;
    },
    actions: [
      { label: t("action.cancel"), kind: "ghost", value: null },
      { label: t("action.forceBlock"), kind: "danger", value: "confirm" },
    ],
  });
  if (v !== "confirm") return;
  try {
    await apiJSON("POST", "/api/mirrors/" + encodeURIComponent(host) + "/block");
    toast(t("toast.saved"), "ok");
    reload();
  } catch (e) {
    toast(t("toast.error") + " " + (e.status || ""), "error");
  }
}

async function unblock(host, reload) {
  try {
    await apiJSON("POST", "/api/mirrors/" + encodeURIComponent(host) + "/unblock");
    toast(t("toast.saved"), "ok");
    reload();
  } catch (e) {
    toast(t("toast.error") + " " + (e.status || ""), "error");
  }
}

async function mount(root) {
  root.appendChild(el("div", { class: "section-head" }, [
    el("h1", { class: "page-title", text: t("page.mirrors.title") }),
    el("button", { class: "btn btn-ghost", text: t("action.refresh"), onclick: () => render() }),
  ]));
  const wrap = el("div", { class: "table-wrap" });
  root.appendChild(wrap);

  async function render() {
    wrap.textContent = "";
    let list;
    try { list = await apiGet("/api/mirrors"); } catch (e) {
      wrap.appendChild(el("div", { class: "empty", text: "error " + (e.status || "") }));
      return;
    }
    const arr = Array.isArray(list) ? list : [];
    const tbl = el("table", { class: "table" });
    tbl.appendChild(el("thead", {}, [el("tr", {}, [
      el("th", { text: t("label.host") }),
      el("th", { text: t("label.verdict") }),
      el("th", { text: t("label.lastCheck") }),
      el("th", { class: "actions", text: "" }),
    ])]));
    const body = el("tbody");
    if (arr.length === 0) {
      body.appendChild(el("tr", {}, [el("td", { colspan: "4", class: "empty", text: "-" })]));
    } else {
      for (const m of arr) {
        const host = m.host || m.Host || "";
        const verdict = m.verdict || m.Verdict || "";
        const last = m.last_check || m.LastCheck || m.checked_at || "";
        const blocked = (verdict || "").toLowerCase() === "blocked";
        body.appendChild(el("tr", {}, [
          el("td", { text: host }),
          el("td", {}, [verdictBadge(verdict)]),
          el("td", { text: formatTime(last) }),
          el("td", { class: "actions" }, [
            blocked
              ? el("button", { class: "btn btn-sm", text: t("action.unblock"), onclick: () => unblock(host, render) })
              : el("button", { class: "btn btn-sm btn-danger", text: t("action.forceBlock"), onclick: () => openForceBlock(host, render) }),
          ]),
        ]));
      }
    }
    tbl.appendChild(body);
    wrap.appendChild(tbl);
  }
  await render();
}

export default { mount, unmount: null };
