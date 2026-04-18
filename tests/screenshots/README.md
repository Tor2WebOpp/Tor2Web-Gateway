# Admin UI Screenshot Runner

Reproducible screenshots of every admin page across themes and
languages. Output lands in `docs/screenshots/`.

## Quick start

From the repository root (`gateway/`):

```sh
make screenshots
```

or, equivalently:

```sh
go run ./tests/screenshots -out=docs/screenshots
```

The runner boots an in-process admin server with mock data on a random
localhost port, drives a headless Chrome session through chromedp, and
writes one PNG per (page x theme x language) combination.

## Output convention

Files are named:

```
<page>-<theme>-<lang>.png
```

Default sweep covers nine pages, two themes, and three languages — 54
PNGs total:

| dimension | values                                                                  |
|-----------|-------------------------------------------------------------------------|
| pages     | dashboard, tenants, mirrors, blocklist, features, nodes, metrics, audit, auto-domains |
| themes    | dark, light                                                             |
| langs     | en, ru, zh                                                              |

Override any axis on the command line:

```sh
go run ./tests/screenshots -themes=dark -langs=en -pages=dashboard,audit
```

## Browser requirements

Tested with **stable Google Chrome** on Windows, macOS, and Linux. The
runner probes the standard install paths (e.g. `C:\Program
Files\Google\Chrome\Application\chrome.exe` on Windows) and falls back
to `chrome` / `chromium` on `PATH`. Chromium also works.

If no browser is found the runner exits with code `2` and writes a
`.placeholder` file to the output directory explaining how to
regenerate the screenshots elsewhere. The build itself never fails for
this reason.

## Mock data

All hostnames in the rendered UI are RFC 2606 reserved names:
`example-a.example`, `mirror-1.example`, etc. No real domains, no
project codename. The mocks are deterministic so two consecutive runs
on the same machine produce visually identical PNGs (modulo Chrome's
own fractional-pixel rendering).

## Exit codes

| code | meaning                                              |
|------|------------------------------------------------------|
| 0    | every requested PNG written                          |
| 1    | hard failure (mock setup, bind, navigation error)    |
| 2    | no Chrome found; placeholder written                 |

## Notes

- The runner uses `httptest.NewServer` over plain HTTP. The admin
  session cookie that ships in production is `Secure=true`, so a
  per-request middleware injects the pre-minted session cookie on the
  server side instead of relying on the browser to round-trip it.
- The viewport is fixed at 1440 x 900. PNG capture uses chromedp's
  full-page screenshot path so long pages (audit, metrics) capture
  beyond the viewport.
- Theme is set via `localStorage.gw_adm_theme`; language via
  `localStorage.gw_adm_lang`. The runner primes both before each page
  navigation so the SPA boot path picks them up cleanly.
