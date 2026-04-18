// Minimal i18n. Loads a per-language JSON file from the admin static
// tree and exposes t(key) for programmatic use plus a DOM pass that
// replaces innerText and aria-labels on tagged elements.

import { adminBase } from "./api.js";

let current = "en";
let dict = {};
let fallback = {};

async function loadFile(lang) {
  const url = adminBase() + "static/i18n/" + lang + ".json";
  const res = await fetch(url, { credentials: "include" });
  if (!res.ok) throw new Error("i18n fetch failed: " + res.status);
  return res.json();
}

export async function init(lang) {
  if (!lang) lang = "en";
  try {
    fallback = await loadFile("en");
  } catch (_) {
    fallback = {};
  }
  if (lang === "en") {
    dict = fallback;
  } else {
    try {
      dict = await loadFile(lang);
    } catch (_) {
      dict = {};
    }
  }
  current = lang;
  applyDom();
}

export async function setLang(lang) {
  await init(lang);
}

export function t(key) {
  if (dict && Object.prototype.hasOwnProperty.call(dict, key)) return dict[key];
  if (fallback && Object.prototype.hasOwnProperty.call(fallback, key)) return fallback[key];
  return key;
}

export function applyDom(root) {
  const scope = root || document;
  scope.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (!key) return;
    el.textContent = t(key);
  });
  scope.querySelectorAll("[data-i18n-aria]").forEach((el) => {
    const key = el.getAttribute("data-i18n-aria");
    if (!key) return;
    el.setAttribute("aria-label", t(key));
  });
  scope.querySelectorAll("[data-i18n-title]").forEach((el) => {
    const key = el.getAttribute("data-i18n-title");
    if (!key) return;
    el.setAttribute("title", t(key));
  });
}

export function lang() { return current; }
