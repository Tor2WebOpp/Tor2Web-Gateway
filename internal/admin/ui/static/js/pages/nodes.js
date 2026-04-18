// Nodes page (hub-only). Table of cluster nodes with a revoke action.

import { apiGet, apiJSON } from "../api.js";
import { el, confirm, toast } from "../components.js";
import { t } from "../i18n.js";

async function mount(root) {
  root.appendChild(el("div", { class: "section-head" }, [
    el("h1", { class: "page-title", text: t("page.nodes.title") }),
    el("button", { class: "btn btn-ghost", text: t("action.refresh"), onclick: () => render() }),
  ]));
  const wrap = el("div", { class: "table-wrap" });
  root.appendChild(wrap);

  async function render() {
    wrap.textContent = "";
    let list;
    try { list = await apiGet("/api/nodes"); } catch (e) {
      wrap.appendChild(el("div", { class: "empty", text: "error " + (e.status || "") }));
      return;
    }
    const arr = Array.isArray(list) ? list : [];
    const tbl = el("table", { class: "table" });
    tbl.appendChild(el("thead", {}, [el("tr", {}, [
      el("th", { text: t("label.node") }),
      el("th", { text: t("label.type") }),
      el("th", { text: t("label.status") }),
      el("th", { class: "actions", text: "" }),
    ])]));
    const body = el("tbody");
    if (arr.length === 0) {
      body.appendChild(el("tr", {}, [el("td", { colspan: "4", class: "empty", text: "-" })]));
    } else {
      for (const n of arr) {
        const id = n.id || n.ID || n.node_id || "";
        const type = n.type || n.Type || n.node_type || "";
        const status = n.status || n.Status || "";
        body.appendChild(el("tr", {}, [
          el("td", { text: id }),
          el("td", { text: type }),
          el("td", { text: status }),
          el("td", { class: "actions" }, [
            el("button", {
              class: "btn btn-sm btn-danger", text: t("action.revoke"),
              onclick: async () => {
                if (!(await confirm(t("confirm.deleteBody") + " " + id))) return;
                try {
                  await apiJSON("POST", "/api/nodes/" + encodeURIComponent(id) + "/revoke");
                  toast(t("toast.saved"), "ok");
                  render();
                } catch (err) { toast(t("toast.error"), "error"); }
              },
            }),
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
