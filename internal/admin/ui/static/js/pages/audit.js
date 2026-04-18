// Audit page. Paginated (by `since` cursor) event list with a JSON
// detail drawer on row click.

import { apiGet } from "../api.js";
import { el, drawer } from "../components.js";
import { t } from "../i18n.js";

const PAGE = 50;

function formatTime(v) {
  if (!v) return "-";
  try { return new Date(v).toISOString().replace("T", " ").slice(0, 19) + "Z"; }
  catch (_) { return String(v); }
}

async function mount(root) {
  root.appendChild(el("div", { class: "section-head" }, [
    el("h1", { class: "page-title", text: t("page.audit.title") }),
    el("button", { class: "btn btn-ghost", text: t("action.refresh"), onclick: () => load("") }),
  ]));
  const wrap = el("div", { class: "table-wrap" });
  root.appendChild(wrap);
  const pager = el("div", { class: "row", style: "margin-top:12px" });
  root.appendChild(pager);

  let since = "";

  async function load(nextSince) {
    since = nextSince || "";
    wrap.textContent = "";
    pager.textContent = "";
    const q = "?limit=" + PAGE + (since ? "&since=" + encodeURIComponent(since) : "");
    let list;
    try { list = await apiGet("/api/audit" + q); } catch (e) {
      wrap.appendChild(el("div", { class: "empty", text: "error " + (e.status || "") }));
      return;
    }
    const arr = Array.isArray(list) ? list : [];
    const tbl = el("table", { class: "table" });
    tbl.appendChild(el("thead", {}, [el("tr", {}, [
      el("th", { text: "time" }),
      el("th", { text: "action" }),
      el("th", { text: "target" }),
      el("th", { text: "actor" }),
    ])]));
    const body = el("tbody");
    if (arr.length === 0) {
      body.appendChild(el("tr", {}, [el("td", { colspan: "4", class: "empty", text: "-" })]));
    }
    for (const e of arr) {
      const tr = el("tr", { style: "cursor:pointer" }, [
        el("td", { text: formatTime(e.time || e.Time) }),
        el("td", { text: e.action || e.Action || "" }),
        el("td", { text: e.target || e.Target || "" }),
        el("td", { text: (e.actor || e.Actor || "").slice(0, 12) }),
      ]);
      tr.addEventListener("click", () => {
        drawer({
          title: e.action || "event",
          body: el("pre", { class: "pre", text: JSON.stringify(e, null, 2) }),
        });
      });
      body.appendChild(tr);
    }
    tbl.appendChild(body);
    wrap.appendChild(tbl);

    if (arr.length === PAGE) {
      const last = arr[arr.length - 1];
      const cursor = last.time || last.Time;
      pager.appendChild(el("button", {
        class: "btn btn-ghost", text: "next", onclick: () => load(cursor),
      }));
    }
    if (since) {
      pager.appendChild(el("button", {
        class: "btn btn-ghost", text: "reset", onclick: () => load(""),
      }));
    }
  }

  await load("");
}

export default { mount, unmount: null };
