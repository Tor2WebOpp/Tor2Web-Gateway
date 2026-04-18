// Tenants page (hub-only). Table with an edit drawer + delete confirm.

import { apiGet, apiJSON } from "../api.js";
import { el, drawer, confirm, toast } from "../components.js";
import { t } from "../i18n.js";

function tenantRow(tn, onEdit, onDelete) {
  const host = tn.host || tn.Host || "";
  const enabled = tn.enabled === true || tn.Enabled === true;
  const backends = Array.isArray(tn.backends) ? tn.backends : (Array.isArray(tn.Backends) ? tn.Backends : []);
  return el("tr", {}, [
    el("td", { text: host }),
    el("td", {}, [el("span", {
      class: "badge " + (enabled ? "badge-ok" : "badge-warn"),
      text: enabled ? t("label.enabled") : "-",
    })]),
    el("td", { text: String(backends.length) }),
    el("td", { class: "actions" }, [
      el("button", { class: "btn btn-sm btn-ghost", text: t("action.edit"), onclick: () => onEdit(tn) }),
      el("button", { class: "btn btn-sm btn-danger", text: t("action.delete"), onclick: () => onDelete(tn) }),
    ]),
  ]);
}

async function openEdit(tn, reload) {
  const host = tn.host || tn.Host || "";
  const initial = JSON.stringify(tn, null, 2);
  await drawer({
    title: t("action.edit") + " " + host,
    body: (panel, close) => {
      const wrap = el("div");
      const ta = el("textarea", { class: "textarea" });
      ta.value = initial;
      wrap.appendChild(el("p", { class: "label", text: t("label.host") + ": " + host }));
      wrap.appendChild(ta);
      const actions = el("div", { class: "modal-actions" }, [
        el("button", { class: "btn btn-ghost", text: t("action.cancel"), onclick: () => close(null) }),
        el("button", {
          class: "btn btn-primary",
          text: t("action.save"),
          onclick: async () => {
            let body;
            try { body = JSON.parse(ta.value); } catch (e) { toast("invalid json: " + e.message, "error"); return; }
            try {
              await apiJSON("PUT", "/api/tenants/" + encodeURIComponent(host), body);
              toast(t("toast.saved"), "ok");
              close(true);
              reload();
            } catch (e) {
              toast(t("toast.error") + " " + (e.status || ""), "error");
            }
          },
        }),
      ]);
      wrap.appendChild(actions);
      return wrap;
    },
  });
}

async function deleteTenant(tn, reload) {
  const host = tn.host || tn.Host || "";
  const ok = await confirm(t("confirm.deleteBody") + " " + host);
  if (!ok) return;
  try {
    await apiJSON("DELETE", "/api/tenants/" + encodeURIComponent(host));
    toast(t("toast.deleted"), "ok");
    reload();
  } catch (e) {
    toast(t("toast.error"), "error");
  }
}

async function mount(root) {
  root.appendChild(el("div", { class: "section-head" }, [
    el("h1", { class: "page-title", text: t("page.tenants.title") }),
    el("button", { class: "btn btn-ghost", text: t("action.refresh"), onclick: () => render() }),
  ]));
  const wrap = el("div", { class: "table-wrap" });
  root.appendChild(wrap);

  async function render() {
    wrap.textContent = "";
    let list;
    try { list = await apiGet("/api/tenants"); } catch (e) {
      wrap.appendChild(el("div", { class: "empty", text: "error " + (e.status || "") }));
      return;
    }
    const arr = Array.isArray(list) ? list : [];
    const tbl = el("table", { class: "table" });
    tbl.appendChild(el("thead", {}, [el("tr", {}, [
      el("th", { text: t("label.host") }),
      el("th", { text: t("label.status") }),
      el("th", { text: t("label.backends") }),
      el("th", { class: "actions", text: "" }),
    ])]));
    const body = el("tbody");
    if (arr.length === 0) {
      body.appendChild(el("tr", {}, [el("td", { colspan: "4", class: "empty", text: "-" })]));
    } else {
      for (const tn of arr) {
        body.appendChild(tenantRow(tn, (x) => openEdit(x, render), (x) => deleteTenant(x, render)));
      }
    }
    tbl.appendChild(body);
    wrap.appendChild(tbl);
  }
  await render();
}

export default { mount, unmount: null };
