// Blocklist page. Tenant selector + list. The spec pencils in a
// /api/blocklist endpoint; until that's wired, the page degrades
// gracefully and shows an empty state with the tenant dropdown.

import { apiGet, apiJSON } from "../api.js";
import { el, confirm, toast } from "../components.js";
import { t } from "../i18n.js";

async function loadTenants() {
  try {
    const list = await apiGet("/api/tenants");
    return Array.isArray(list) ? list : [];
  } catch (_) { return []; }
}

async function loadEntries(host) {
  try {
    const list = await apiGet("/api/blocklist?host=" + encodeURIComponent(host));
    return Array.isArray(list) ? list : [];
  } catch (_) { return []; }
}

async function mount(root) {
  root.appendChild(el("h1", { class: "page-title", text: t("page.blocklist.title") }));

  const controls = el("div", { class: "card", style: "margin-bottom:16px" });
  const select = el("select", { class: "select" });
  select.appendChild(el("option", { value: "", text: "-- " + t("label.host") + " --" }));
  controls.appendChild(el("label", { class: "label", text: t("label.host") }));
  controls.appendChild(select);
  const addForm = el("div", { class: "row", style: "margin-top:16px;gap:8px" });
  const patternInput = el("input", { class: "input", type: "text", placeholder: "pattern" });
  const actionSel = el("select", { class: "select" }, [
    el("option", { value: "block", text: "block" }),
    el("option", { value: "allow", text: "allow" }),
    el("option", { value: "warn", text: "warn" }),
  ]);
  const addBtn = el("button", { class: "btn btn-primary", text: t("action.add") });
  addForm.appendChild(patternInput);
  addForm.appendChild(actionSel);
  addForm.appendChild(addBtn);
  controls.appendChild(addForm);
  root.appendChild(controls);

  const listWrap = el("div", { class: "table-wrap" });
  root.appendChild(listWrap);

  const tenants = await loadTenants();
  for (const tn of tenants) {
    const host = tn.host || tn.Host || "";
    if (!host) continue;
    select.appendChild(el("option", { value: host, text: host }));
  }

  async function render() {
    listWrap.textContent = "";
    const host = select.value;
    if (!host) {
      listWrap.appendChild(el("div", { class: "empty", text: "-- " + t("label.host") + " --" }));
      return;
    }
    const entries = await loadEntries(host);
    if (entries.length === 0) {
      listWrap.appendChild(el("div", { class: "empty", text: "-" }));
      return;
    }
    const tbl = el("table", { class: "table" });
    tbl.appendChild(el("thead", {}, [el("tr", {}, [
      el("th", { text: "pattern" }),
      el("th", { text: "action" }),
      el("th", { class: "actions", text: "" }),
    ])]));
    const tbody = el("tbody");
    for (const e of entries) {
      const id = e.id || e.ID;
      tbody.appendChild(el("tr", {}, [
        el("td", { text: e.pattern || e.Pattern || "" }),
        el("td", { text: e.action || e.Action || "" }),
        el("td", { class: "actions" }, [
          el("button", {
            class: "btn btn-sm btn-danger", text: t("action.delete"),
            onclick: async () => {
              if (!(await confirm(t("confirm.deleteBody")))) return;
              try {
                await apiJSON("DELETE", "/api/blocklist/" + encodeURIComponent(id));
                toast(t("toast.deleted"), "ok");
                render();
              } catch (err) { toast(t("toast.error"), "error"); }
            },
          }),
        ]),
      ]));
    }
    tbl.appendChild(tbody);
    listWrap.appendChild(tbl);
  }

  select.addEventListener("change", render);
  addBtn.addEventListener("click", async () => {
    const host = select.value;
    if (!host) { toast(t("toast.error"), "warn"); return; }
    const pattern = patternInput.value.trim();
    if (!pattern) return;
    try {
      await apiJSON("POST", "/api/blocklist", {
        host, pattern, action: actionSel.value,
      });
      toast(t("toast.saved"), "ok");
      patternInput.value = "";
      render();
    } catch (err) { toast(t("toast.error"), "error"); }
  });

  await render();
}

export default { mount, unmount: null };
