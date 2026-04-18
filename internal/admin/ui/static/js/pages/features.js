// Features page. Toggle switches posting to /api/features/{name}/toggle.

import { apiGet, apiJSON } from "../api.js";
import { el, toast } from "../components.js";
import { t } from "../i18n.js";

async function mount(root) {
  root.appendChild(el("div", { class: "section-head" }, [
    el("h1", { class: "page-title", text: t("page.features.title") }),
    el("button", { class: "btn btn-ghost", text: t("action.refresh"), onclick: () => render() }),
  ]));
  const wrap = el("div", { class: "card" });
  root.appendChild(wrap);

  async function render() {
    wrap.textContent = "";
    let list;
    try { list = await apiGet("/api/features"); } catch (e) {
      wrap.appendChild(el("div", { class: "empty", text: "error " + (e.status || "") }));
      return;
    }
    const arr = Array.isArray(list) ? list : [];
    if (arr.length === 0) {
      wrap.appendChild(el("div", { class: "empty", text: "-" }));
      return;
    }
    const list_ = el("ul", { class: "list-clean" });
    for (const f of arr) {
      const name = f.name || f.Name || "";
      const enabled = f.enabled === true || f.Enabled === true;
      const row = el("li", { class: "row" });
      row.appendChild(el("span", { text: name, style: "flex:1" }));
      const label = el("label", { class: "switch" });
      const input = el("input", { type: "checkbox" });
      if (enabled) input.setAttribute("checked", "");
      const slider = el("span", { class: "switch-slider" });
      label.appendChild(input);
      label.appendChild(slider);
      input.addEventListener("change", async () => {
        try {
          await apiJSON("POST", "/api/features/" + encodeURIComponent(name) + "/toggle", { enabled: input.checked });
          toast(t("toast.saved"), "ok");
        } catch (e) {
          input.checked = enabled;
          toast(t("toast.error"), "error");
        }
      });
      row.appendChild(label);
      list_.appendChild(row);
    }
    wrap.appendChild(list_);
  }

  await render();
}

export default { mount, unmount: null };
