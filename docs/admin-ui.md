# Admin web UI (P4)

This document describes the operator-facing web interface delivered in
P4. It complements [`admin.md`](admin.md), which covers the underlying
session, CSRF, lockout, and audit subsystems shared with the JSON API.
If you are looking for gate semantics, wire formats, or `curl` examples,
start there; this document is about the browser surface on top.

## Overview

The admin UI is a single-page application embedded in the `gateway-hub`,
`gateway-proxy`, and `gateway-door` binaries as a static asset tree. At
runtime the tree is served from `go:embed` through the same admin gate
that fronts the JSON API, so the UI shares exactly one authentication
boundary with the API it calls. There is no separate web server, no
external CDN dependency, and no build step: all CSS and JavaScript are
hand-written, ship under 200 KB uncompressed, and run with no
third-party frameworks.

The UI is an SPA in the literal sense — one HTML document, hash-router
navigation, fetch-based API calls. Each "page" described below is a
pure DOM render driven by a small controller module; the browser never
leaves `index.html` during normal use.

## Access

The UI is reachable only under the hidden admin prefix:

```
https://your-domain.example/EXAMPLE-SLUG/EXAMPLE-TOKEN-A/EXAMPLE-TOKEN-B/
```

On first load the gate mints a `gw_adm` session cookie scoped to that
three-segment prefix and 302s the browser to the trailing-slash URL.
Every subsequent request carries the cookie instead of the slug and
tokens, so the address bar displays the clean prefix once the initial
load completes.

For mutating calls the UI reads the `X-CSRF-Token` value from the
response headers of any safe-method request (typically `GET /api/me`
fired at page load) and echoes it on every subsequent POST, PUT, PATCH,
and DELETE. A `403` on a mutating call is nearly always a stale token;
the client code retries once after re-reading `/api/me` before
surfacing an error to the operator.

See [`admin.md`](admin.md) for the full session lifecycle, idle and
absolute TTLs, CSRF rejection semantics, per-IP lockout tiers, and
audit event shape.

## Theme

Two themes ship side by side, both rendered with a neumorphism
vocabulary — soft raised surfaces, dual-direction inset shadows, no
hard borders. The default is **dark** (neumorphism black) and the
alternative is **light** (neumorphism white). The root `<html>` element
carries a `data-theme="dark"` or `data-theme="light"` attribute; all
component styling is expressed as CSS custom properties keyed on that
attribute, so a theme swap is a single DOM write with no reflow beyond
the repaint.

The toggle lives in the top-right of the persistent header next to the
language picker. Clicking it writes the new value to the `data-theme`
attribute and persists the choice under the `gw.admin.theme` key in
`localStorage`. The next page load reads that key before any styles
paint to avoid a flash of the wrong theme.

There is no automatic `prefers-color-scheme` follow — the choice is
explicit. Operators who want the system colour scheme can set it once
and forget; the UI will not override it on system-level theme changes.

*Screenshots placeholder — P5 documentation pass will add light and
dark captures of the Dashboard, Tenants list, and Audit browser here.*

## Language

Three interface languages are built in: English (`en`), Russian (`ru`),
and Simplified Chinese (`zh`). Catalogs are JSON files shipped in the
binary under `internal/i18n/catalogs/` and loaded into the JS runtime
on first render. The catalog format is flat `{"key": "text"}`; every
translatable string in the HTML carries a `data-i18n="namespace.key"`
attribute that the renderer resolves before the element becomes
visible.

Language selection order:

1. The `?lang=` query parameter on the current URL, if present and a
   known catalog (e.g. `?lang=ru`). The value is also written to
   `localStorage` so the override sticks across navigations.
2. The persisted `gw.admin.lang` key in `localStorage`.
3. The browser's `navigator.language` prefix, if it matches a shipped
   catalog.
4. `en` as the final fallback.

The picker in the header lets operators change language without
reloading. Keys missing from the selected catalog fall back to English;
keys missing from English render as the raw key in square brackets
(e.g. `[nav.tenants]`) so missing strings are visible in review
without breaking layout.

### Contributing a new translation

New catalogs live next to the existing ones under
`internal/i18n/catalogs/<code>.json`. Copy `en.json`, translate every
value, and leave the keys unchanged. Add the language code to the
selector in `internal/admin/ui/static/js/i18n.js`. No code change is
needed beyond that; the catalog loader discovers any `*.json` file at
startup. Translations are not required to be complete — partial
catalogs are valid and fall back key-by-key.

## Pages reference

Every page is keyed on the URL hash (`#/dashboard`, `#/tenants`, etc.)
so the browser back/forward buttons move between pages without
triggering a full reload. Hub-only pages are hidden from the navigation
on proxy and door nodes — the `/api/me` response supplies the
`node_type` that drives the nav render.

### Dashboard

Landing page. Shows current RPS, error rate, active backends, and the
last ten audit events. Used for at-a-glance health on a freshly-opened
session.

- Routes: `GET /api/metrics/history`, `GET /api/audit?limit=10`
- Available on: hub, proxy, door
- Actions: link-out to Metrics and Audit pages

### Tenants

CRUD for tenant records. The list view shows host, backend count, and
feature override summary; clicking a row opens a detail panel with the
full YAML-equivalent JSON editor and per-feature override toggles.

- Routes: `GET/PUT/DELETE /api/tenants`, `GET/PUT /api/tenants/{host}`
- Available on: hub only
- Actions: create, edit, delete, download as YAML

### Mirrors

Read-only view of the mirror-health registry. Each row shows the
mirror host, latest verdict (`live`/`degraded`/`blocked`/`unknown`),
last check timestamp, and per-region verdict breakdown. A filter row
narrows by verdict or by tenant.

- Routes: `GET /api/mirrors`
- Available on: hub only
- Actions: filter, sort, link-out to the owning tenant

### Blocklist

Interactive editor for the global and per-tenant regex blocklists.
Patterns are validated client-side against the same regex engine the
proxy uses; an invalid pattern blocks the save.

- Routes: `GET/PUT /api/globals`, `GET/PUT /api/tenants/{host}`
- Available on: hub only
- Actions: add, edit, remove pattern; preview match against a test
  input

### Features

Toggle grid for the nine P1 features plus the two hub-startup ones.
Each row shows the current global state, a switch, and a description
sourced from the i18n catalog. On hub nodes the feature registry is
global; on proxy and door nodes the same grid shows the local node's
view.

- Routes: `GET /api/features`, `POST /api/features/{name}/toggle`
- Available on: hub, proxy, door
- Actions: toggle enabled state

### Nodes

Registry of known nodes. Shows node ID, type (hub/proxy/door), last
seen, transport kind, and health.

- Routes: `GET /api/tenants`, `GET /api/mirrors` (derived view)
- Available on: hub only
- Actions: link-out to the node's own admin URL if the operator has
  its slug/tokens cached locally

### Metrics

Live metrics view. Prometheus text snapshot in a scrollable pre-
formatted block, plus a sparkline strip driven by the in-memory
history buckets.

- Routes: `GET /api/metrics`, `GET /api/metrics/history?limit=N`
- Available on: hub, proxy, door
- Actions: copy snapshot, adjust history limit

### Audit

Paginated browser of the append-only audit log. Filters by `since`
timestamp, actor session ID, action prefix, and target substring.

- Routes: `GET /api/audit?since=...&limit=...`
- Available on: hub, proxy, door
- Actions: filter, jump-to-timestamp, export visible page as JSON

### Auto-Domains

Planned integration point for automated domain provisioning. The P4
page is a stub: it shows the configured provisioner (or "not
configured") and a placeholder for the P5 flow. No mutating routes
yet.

- Routes: `GET /api/globals` (read-only reference)
- Available on: hub only
- Actions: none (stub)

## Keyboard shortcuts

The P4 UI does not ship keyboard shortcuts beyond what the browser
itself provides. Tab navigation follows the DOM order, `Enter` submits
focused forms, and `Esc` closes open modal panels. A dedicated
shortcut layer (`g d` for Dashboard, `g t` for Tenants, etc.) is
reserved for a later iteration; the controller modules already accept
a shortcut registration hook so the addition is purely additive.

## Extending the UI

Adding a new page to the SPA is a four-step change, all under
`internal/admin/ui/`:

1. **HTML fragment.** Add a template in
   `internal/admin/ui/static/html/<page>.html` that defines the
   page's root element with a `data-page="<name>"` attribute and
   `data-i18n` hints on every user-visible string. The loader
   fetches the fragment on first navigation to that page.
2. **JS controller.** Create
   `internal/admin/ui/static/js/pages/<page>.js` that exports
   `init(root)` and `destroy()`. `init` is called after the fragment
   is attached; it wires event listeners, fires initial fetches, and
   returns. `destroy` is called before the page is swapped out so
   pending fetches can be aborted.
3. **Navigation entry.** Add an entry to the nav array in
   `internal/admin/ui/static/js/nav.js` with the URL hash, label key,
   icon, and `nodeTypes` array (e.g. `["hub"]` for hub-only pages).
   The renderer hides entries whose `nodeTypes` does not include the
   current node type.
4. **i18n keys.** Add every `data-i18n` key used in the fragment to
   each of `en.json`, `ru.json`, `zh.json` under
   `internal/i18n/catalogs/`. Missing keys render as bracketed
   placeholders, so partial catalogs are visible in review before
   translators fill them in.

No build step is required: the Go `go:embed` in `ui_embed.go` picks up
every file under `internal/admin/ui/` at compile time. Run
`go test ./internal/admin/...` after the change to exercise the UI
mount's `ServeHTTP` path against the new file.

## Browser support

The UI targets evergreen browsers and relies on fetch, ES2022 modules,
CSS custom properties, and `Intl.DateTimeFormat`. Minimum supported
versions:

- Chrome 110+
- Firefox 115+
- Safari 16+
- Edge 110+

Internet Explorer is explicitly unsupported; the UI will render a
single text line asking the operator to use a modern browser, and no
further JavaScript runs.

## Known limitations

- The Auto-Domains page is a stub. It displays the configured
  provisioner or "not configured"; no mutating route is wired.
- Metrics history is held in memory on each node. A node restart
  drops all buckets; long-term history must be scraped from an
  external Prometheus-compatible store.
- The audit query endpoint caps `limit` at 5000 per request. The UI
  paginates by `since` timestamp for ranges larger than that. There
  is no full-text index — filtering is a linear scan of the BoltDB
  index.
- Dark-mode detection is manual only. `prefers-color-scheme` is
  ignored once the operator has made an explicit choice, and the
  default on a fresh profile is always dark regardless of the
  system setting.
- There is no multi-operator coordination. Two operators editing the
  same tenant from different sessions will race; the second PUT
  wins. The audit log preserves the sequence but the UI does not
  show a warning banner.
- Mirror weight and manual-block controls are reserved but not wired
  in the P4 release. Mirror CRUD appears read-only in the UI until
  the routes land.

## Troubleshooting

### Blank page after login

The most common cause is a browser that silently dropped the session
cookie — usually because the admin URL is being served over plain HTTP
and the cookie's `Secure` attribute caused it to be ignored. Check
that the URL starts with `https://`. A secondary cause is a stale
cached asset after an upgrade; hard-reload (`Ctrl+Shift+R` or the
browser's "empty cache and reload" action) clears it.

### CSRF failures on every action

The UI reads the CSRF token from the response headers of a
safe-method request and caches it for the life of the page. If the
session idle TTL expires while the page is open, the next mutating
request sees a `403`. Refresh the page; the SPA will re-read
`/api/me` and pick up the fresh token.

If refreshes keep failing, the session's absolute TTL (default 8
hours) has elapsed. A full navigation to the admin URL mints a new
session.

### 401 or 404 loops

A loop where every request returns 404 usually means the slug or
tokens were rotated. The gate strips the prefix match in constant
time regardless of outcome, so a rotated slug looks byte-identical
to an unrouted path. Check `config.yaml` on the server against the
URL in the browser; if they differ, the installer was re-run. See
[`admin.md`](admin.md#lost-slug-or-tokens) for the rotation
procedure.

A loop where the browser keeps bouncing between a 302 and the login
URL points at the session cookie being rejected by the browser.
Check that the admin URL is HTTPS and that the browser is not in a
private-mode window with third-party cookies disabled for the
origin.
