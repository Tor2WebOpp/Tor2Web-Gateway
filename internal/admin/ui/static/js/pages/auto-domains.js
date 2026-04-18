// Auto-Domains page. Placeholder until registrar integration lands.

import { el } from "../components.js";
import { t } from "../i18n.js";

async function mount(root) {
  root.appendChild(el("h1", { class: "page-title", text: t("page.autoDomains.title") }));
  const card = el("section", { class: "card" });
  card.appendChild(el("p", { text: t("page.autoDomains.body") }));
  const btn = el("button", { class: "btn", text: t("action.add"), disabled: "disabled" });
  card.appendChild(btn);
  root.appendChild(card);
}

export default { mount, unmount: null };
