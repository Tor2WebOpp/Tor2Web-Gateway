# Door cover assets

The door node serves a benign "cover" on `/` (and on any path that does
not match a configured slug). This directory contains the default cover
bundled with the installer.

## What is shipped

| File | Role |
|---|---|
| `blank.html` | Minimal "site under construction" page. No scripts, no tracking, no favicons. |

`blank.html` is intentionally small (<500 bytes) and plain so that a
door that has not yet been customised looks like the default landing
page of a freshly-provisioned VPS rather than a distinctive fingerprint.

## Choosing a cover at install time

The installer asks for a cover kind during step-04b:

- `static_file` — any binary asset, typically an image (`cat.jpg`,
  corporate logo, a favicon-like PNG). Served with whatever
  `Content-Type` the installer sniffs, or a sensible default.
- `static_html` — an HTML landing page. Served as
  `text/html; charset=utf-8`.
- `passthrough_404` — no cover. `/` returns a generic 404 that mimics
  the default of an un-configured nginx / Apache. Best for doors that
  want to look genuinely unclaimed.

Non-interactive flags:

```
sudo ./install.sh \
    --type=door \
    --domain=door-1.example \
    --hub=hub.internal:9080 \
    --cover-kind=static_file \
    --cover-path=/root/cat.jpg \
    --yes
```

## Replacing the cover after installation

Two ways, both of which take effect without restarting the service
(the door watches `/etc/gateway/cover/` for changes):

### 1. Drop-in replacement on disk

```bash
# Copy your new asset in.
sudo install -m 0644 -o root -g gateway \
    /path/to/new-cover.jpg /etc/gateway/cover/cat.jpg

# Update config.yaml if the filename changed.
sudo $EDITOR /etc/gateway/config.yaml       # edit cover.path
sudo systemctl reload gateway-door.service  # SIGHUP; no downtime
```

Use `install(1)` rather than `cp` so the permissions are deterministic.

### 2. Live via the hub admin API

The hub's per-door admin endpoints accept a cover upload that is pushed
to the door over the existing config stream. Nothing to restart.

```bash
# Replace the cover on door-1.example with a new JPG.
curl -sS --cert admin.crt --key admin.key \
     --data-binary @new-cover.jpg \
     -H 'Content-Type: image/jpeg' \
     https://hub.internal:9080/v1/doors/door-1.example/cover
```

The hub signs the change, fans it out over the SSE config stream, and
the door atomically swaps the file under `/etc/gateway/cover/` — no
downtime, no restart. See `docs/superpowers/specs/2026-04-18-P2-door-checkhost-design.md`
section "Door config (runtime, per-door)" for the schema and the admin
API surface.

## OPSEC notes

- Avoid serving an asset with distinctive EXIF, steganographic, or
  embedded-analytics content. Operators sometimes ship a logo PNG with
  GPS metadata still in it — strip it first with `exiftool -all=`.
- The default `blank.html` contains no external resources (no CDN fonts,
  no remote images) so the door does not make outbound requests on its
  own behalf when a visitor hits `/`.
- `passthrough_404` is usually the most boring choice for an
  unattributable door; prefer it if you have no strong reason to serve
  something branded.
