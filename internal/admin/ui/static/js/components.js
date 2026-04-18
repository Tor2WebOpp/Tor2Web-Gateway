// Shared UI primitives: toast, modal, confirm, drawer.

import { t } from "./i18n.js";

let toastRoot = null;
let modalRoot = null;

function roots() {
  if (!toastRoot) toastRoot = document.getElementById("toast-root");
  if (!modalRoot) modalRoot = document.getElementById("modal-root");
}

// toast shows a transient bottom-right notification.
// kind: "ok" | "warn" | "error" (default "ok").
export function toast(msg, kind) {
  roots();
  if (!toastRoot) return;
  const el = document.createElement("div");
  el.className = "toast toast-" + (kind || "ok");
  el.setAttribute("role", kind === "error" ? "alert" : "status");
  el.textContent = msg;
  toastRoot.appendChild(el);
  setTimeout(() => {
    el.style.transition = "opacity 240ms ease";
    el.style.opacity = "0";
    setTimeout(() => el.remove(), 260);
  }, 3500);
}

// modal({title, body, actions, onClose}) returns a Promise that
// resolves when the modal is closed; resolves with the action's value
// if an action invokes close(value).
// - body can be a string, a DOM node, or a function(dialog)→node.
// - actions: [{label, kind?, value?}] rendered right-aligned.
// Close on Esc. Backdrop click closes unless modal.persistent=true.
export function modal(opts) {
  roots();
  if (!modalRoot) return Promise.resolve(null);
  return new Promise((resolve) => {
    const backdrop = document.createElement("div");
    backdrop.className = "modal-backdrop";
    const dialog = document.createElement("div");
    dialog.className = "modal-dialog";
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");

    if (opts && opts.title) {
      const h = document.createElement("h2");
      h.className = "modal-title";
      h.textContent = opts.title;
      dialog.appendChild(h);
    }
    const bodyEl = document.createElement("div");
    bodyEl.className = "modal-body";
    if (opts && opts.body !== undefined) {
      if (typeof opts.body === "function") {
        const r = opts.body(dialog);
        if (r) bodyEl.appendChild(r);
      } else if (opts.body instanceof Node) {
        bodyEl.appendChild(opts.body);
      } else {
        bodyEl.textContent = String(opts.body);
      }
    }
    dialog.appendChild(bodyEl);

    const actionsEl = document.createElement("div");
    actionsEl.className = "modal-actions";
    const actionList = (opts && opts.actions) || [
      { label: t("action.cancel"), kind: "ghost", value: null },
      { label: t("action.save"), kind: "primary", value: true },
    ];
    for (const a of actionList) {
      const btn = document.createElement("button");
      btn.className = "btn " + (a.kind === "primary" ? "btn-primary" : a.kind === "danger" ? "btn-danger" : "btn-ghost");
      btn.textContent = a.label;
      btn.addEventListener("click", () => close(a.value));
      actionsEl.appendChild(btn);
    }
    dialog.appendChild(actionsEl);

    modalRoot.appendChild(backdrop);
    modalRoot.appendChild(dialog);
    modalRoot.style.pointerEvents = "auto";

    const previouslyFocused = document.activeElement;
    const first = dialog.querySelector("input, textarea, button");
    if (first && typeof first.focus === "function") first.focus();

    function close(v) {
      document.removeEventListener("keydown", onKey);
      backdrop.remove();
      dialog.remove();
      modalRoot.style.pointerEvents = "none";
      if (previouslyFocused && typeof previouslyFocused.focus === "function") {
        previouslyFocused.focus();
      }
      if (opts && typeof opts.onClose === "function") opts.onClose(v);
      resolve(v);
    }
    function onKey(e) {
      if (e.key === "Escape") { e.preventDefault(); close(null); }
    }
    document.addEventListener("keydown", onKey);
    if (!(opts && opts.persistent)) {
      backdrop.addEventListener("click", () => close(null));
    }
  });
}

// confirm is a thin wrapper that returns Promise<bool>.
export async function confirm(msg, title) {
  const v = await modal({
    title: title || t("confirm.delete"),
    body: msg || t("confirm.deleteBody"),
    actions: [
      { label: t("action.cancel"), kind: "ghost", value: false },
      { label: t("action.delete"), kind: "danger", value: true },
    ],
  });
  return !!v;
}

// drawer({title, body}) opens a right-side drawer. Returns a Promise
// resolved with whatever value the caller passes to the close() helper
// provided as the second body argument.
export function drawer(opts) {
  roots();
  if (!modalRoot) return Promise.resolve(null);
  return new Promise((resolve) => {
    const backdrop = document.createElement("div");
    backdrop.className = "modal-backdrop";
    const panel = document.createElement("aside");
    panel.className = "drawer";
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-modal", "true");

    if (opts && opts.title) {
      const h = document.createElement("h2");
      h.className = "drawer-title";
      h.textContent = opts.title;
      panel.appendChild(h);
    }
    const bodyEl = document.createElement("div");
    panel.appendChild(bodyEl);

    function close(v) {
      document.removeEventListener("keydown", onKey);
      backdrop.remove();
      panel.remove();
      modalRoot.style.pointerEvents = "none";
      resolve(v);
    }
    function onKey(e) { if (e.key === "Escape") { e.preventDefault(); close(null); } }

    if (opts && opts.body !== undefined) {
      if (typeof opts.body === "function") {
        const r = opts.body(panel, close);
        if (r) bodyEl.appendChild(r);
      } else if (opts.body instanceof Node) {
        bodyEl.appendChild(opts.body);
      } else {
        bodyEl.textContent = String(opts.body);
      }
    }

    modalRoot.appendChild(backdrop);
    modalRoot.appendChild(panel);
    modalRoot.style.pointerEvents = "auto";
    document.addEventListener("keydown", onKey);
    backdrop.addEventListener("click", () => close(null));

    const first = panel.querySelector("input, textarea, button");
    if (first && typeof first.focus === "function") first.focus();
  });
}

// el is a tiny DOM helper. Usage: el("div", {class:"foo"}, [child, child])
export function el(tag, attrs, children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const k of Object.keys(attrs)) {
      if (k === "class") node.className = attrs[k];
      else if (k === "text") node.textContent = attrs[k];
      else if (k === "html") node.innerHTML = attrs[k];
      else if (k.startsWith("on") && typeof attrs[k] === "function") {
        node.addEventListener(k.slice(2).toLowerCase(), attrs[k]);
      } else if (attrs[k] !== undefined && attrs[k] !== null) {
        node.setAttribute(k, attrs[k]);
      }
    }
  }
  if (children) {
    for (const c of [].concat(children)) {
      if (c == null) continue;
      node.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    }
  }
  return node;
}
