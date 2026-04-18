// Metrics page. Shows the raw Prometheus text plus an inline SVG
// sparkline of recent request-rate buckets.

import { apiGet } from "../api.js";
import { el } from "../components.js";
import { t } from "../i18n.js";

function sparkline(points) {
  if (!Array.isArray(points) || points.length === 0) {
    return el("div", { class: "empty", text: "-" });
  }
  const w = 600, h = 80, pad = 4;
  let max = 0;
  for (const p of points) if (p > max) max = p;
  if (max <= 0) max = 1;
  const step = points.length > 1 ? (w - pad * 2) / (points.length - 1) : 0;
  const yOf = (v) => h - pad - (v / max) * (h - pad * 2);
  let d = "";
  points.forEach((v, i) => {
    const x = pad + i * step;
    const y = yOf(v);
    d += (i === 0 ? "M" : "L") + x.toFixed(1) + "," + y.toFixed(1) + " ";
  });
  const last = pad + (points.length - 1) * step;
  const area = d + "L" + last.toFixed(1) + "," + (h - pad) + " L" + pad + "," + (h - pad) + " Z";
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "chart");
  svg.setAttribute("viewBox", "0 0 " + w + " " + h);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("role", "img");
  const a = document.createElementNS("http://www.w3.org/2000/svg", "path");
  a.setAttribute("class", "chart-area");
  a.setAttribute("d", area);
  const p = document.createElementNS("http://www.w3.org/2000/svg", "path");
  p.setAttribute("class", "chart-path");
  p.setAttribute("d", d.trim());
  svg.appendChild(a);
  svg.appendChild(p);
  return svg;
}

async function mount(root) {
  root.appendChild(el("h1", { class: "page-title", text: t("page.metrics.title") }));
  const chartCard = el("div", { class: "card", style: "margin-bottom:16px" });
  chartCard.appendChild(el("h2", { class: "card-title", text: "request rate" }));
  root.appendChild(chartCard);
  const preWrap = el("div", { class: "card" });
  root.appendChild(preWrap);

  try {
    const hist = await apiGet("/api/metrics/history?limit=60");
    const arr = Array.isArray(hist) ? hist : [];
    const rps = arr.map((b) => Number(b.rps || b.RPS || 0));
    chartCard.appendChild(sparkline(rps));
  } catch (_) {
    chartCard.appendChild(el("div", { class: "empty", text: "-" }));
  }
  try {
    const text = await apiGet("/api/metrics");
    preWrap.appendChild(el("pre", { class: "pre", text: String(text || "") }));
  } catch (e) {
    preWrap.appendChild(el("div", { class: "empty", text: "error " + (e.status || "") }));
  }
}

export default { mount, unmount: null };
