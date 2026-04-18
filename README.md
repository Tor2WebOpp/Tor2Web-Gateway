# TOR Gateway

A multi-tenant reverse proxy that routes public HTTP/HTTPS traffic through a pool of Tor instances. Runs either as a single-box local install or as a fleet of disposable edge proxies fronting a central hub.

**Status.** P1 (multi-tenant proxy + hub + transports), P2 (door redirector + mirror health), P3 (admin gate + audit log), P4 (admin web UI), and P5 (operator documentation set + i18n catalogs) are delivered. Screenshots of the admin UI live under [`docs/screenshots/`](docs/screenshots/) once captured.

**[English](#english)** | **[Русский](#русский)** | **[中文](#中文)**

---

## English

### What is this?

TOR Gateway terminates public TLS, maps incoming requests to tenants by `Host` header, applies per-tenant middleware (rate limits, regex blocklists, GeoIP, content sanitizer, header rewriting), and forwards upstream through Tor to `.onion` backends. A health-based scheduler keeps the Tor pool stable: dead instances are replaced in place on their existing SOCKS ports; live instances are ranked by a score that mixes active connections, observed latency, and error rate.

### Documentation index

- [`docs/architecture.md`](docs/architecture.md) — binaries, modes, request path, registries.
- [`docs/deployment.md`](docs/deployment.md) — install walkthrough from one host to a multi-node fleet.
- [`docs/tenants.md`](docs/tenants.md) — tenant YAML schema, lifecycle, examples.
- [`docs/features.md`](docs/features.md) — middleware features, parameters, per-tenant overrides.
- [`docs/hub-api.md`](docs/hub-api.md) — admin API request/response shapes and `curl` examples.
- [`docs/admin.md`](docs/admin.md) — admin gate session, CSRF, lockout.
- [`docs/admin-ui.md`](docs/admin-ui.md) — embedded web UI page reference and theme/language.
- [`docs/door.md`](docs/door.md) — door redirector cover kinds and slug routing.
- [`docs/mirrors.md`](docs/mirrors.md) — mirror-health registry and verdict rules.
- [`docs/checkhost.md`](docs/checkhost.md) — check-host.net polling, regions, rate limits.
- [`docs/opsec.md`](docs/opsec.md) — threat model and hardening recommendations.
- [`docs/tracing.md`](docs/tracing.md) — OpenTelemetry exporter configuration and trace shape.
- [`docs/audit.md`](docs/audit.md) — append-only audit log schema and query API.
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — symptom-to-cause mappings for common failure modes.
- [`docs/upgrade.md`](docs/upgrade.md) — version upgrade flow, rollback, pre-P1 migration.

The system runs in two deployment modes. Local mode is a single machine: `gateway-proxy` and `gateway-torpool` on the same box, one or more tenants, all config in one file. Remote mode splits the roles: edge `gateway-proxy` nodes hold only public TLS and the middleware chain; a central `gateway-hub` owns the Tor pool, the tenant registry, and the mTLS CA. Edges are disposable. Burn one, spawn another pointing at the same hub.

### Modes — local vs remote

Local mode preserves the pre-P1 behavior for operators who only need one public domain on one machine. The proxy talks to the torpool over a Unix socket. There is no hub, no mTLS, and no wireguard. `node_type: local` in `config.yaml` selects this layout.

Remote mode is the multi-tenant default. The hub runs `gateway-torpool` internally and exposes two things to edges: a SOCKS5 entry point to its Tor pool, and a JSON admin/config API. Edges never reach clearnet to the backends themselves; they always egress through the hub. This keeps the set of machines that can see the `.onion` traffic small and physically separate from the machines that face the public internet.

Pick local when you run a single domain on one server and do not need to separate public surface from tor egress. Pick remote when you want to spin up and rotate edges cheaply, when you need per-tenant isolation across multiple domains, or when you need the public TLS hosts to be throwaway.

### Multi-tenancy

A tenant is defined by a public `Host` and a set of `.onion` backends. Each tenant file (`<host>.yaml`) lives in the hub runtime directory and can override global feature defaults: its own rate limit, its own regex blocklist, its own GeoIP policy, its own header rewriting rules. Onion v3 (56-char base32) addresses are validated at load time. v2 addresses are rejected with a clear error.

The Tor pool is shared across tenants. Isolation is enforced in the proxy layer: rate-limit buckets, negative-cache entries, feature toggles, and metric labels are all keyed on `tenant.host`. Stealth client authorization is per-onion, not per-tenant: auth private keys are loaded into every Tor instance's `ClientOnionAuthDir` and Tor picks the correct one based on destination.

A miss on the `Host` map returns HTTP 421 Misdirected Request, which is distinct from a blocked-path 404 and makes diagnosis straightforward from logs.

### Feature toggles

Every capability is individually switchable at two layers: `globals.yaml` sets defaults, and `tenants/<host>.yaml` overrides them. Disabled features do not just short-circuit; they are bypassed before they enter the middleware chain, so the disabled path has no allocation cost.

The nine P1 features are: `blocklist_regex`, `geoip`, `rate_limit`, `ttl_blocklist`, `content_sanitizer`, `negative_cache`, `proxy_headers`, `abuse_api`, `static_cache`. Each has its own section in [`docs/features.md`](docs/features.md) with parameters, defaults, and per-tenant override examples. `stealth_hs` (stealth client auth) and `onion_validator` (v3-only enforcement) are handled at hub startup rather than per-request, and are documented in the same file.

Hot-reload is driven by `fsnotify` on the hub's runtime directory. A reload first validates every feature across every tenant; any failure aborts the swap and keeps the previous config live. In-flight requests finish on the old config; subsequent requests pick up the new one.

### Transports

Three transports connect edges to the hub:

- `wireguard` — default. UDP overlay. Hub admin API and SOCKS listener bind to `10.0.0.1` only; edges dial via the wg tunnel. No custom wire protocol; the edge's existing SOCKS5 client reaches the pool directly.
- `https_tunnel` — WebSocket over HTTPS with mTLS. Used when UDP is blocked or the edge runs on a PaaS that does not pass UDP. Slower than wireguard because SOCKS frames ride inside WebSocket frames in userspace.
- `socks5_tls` — raw SOCKS5 inside TLS on `:9443`, admin HTTPS on `:9444`. Last resort: exposes fingerprint-able public TLS ports on the hub, and the installer warns about it.

Transport is chosen by the installer and written to the bootstrap config. It is infrastructure, not runtime state: changing it requires restart. See [`docs/architecture.md`](docs/architecture.md) for the interface and call sequence.

### Hub API overview

The hub exposes a small JSON API, bound to the private transport address and guarded by mTLS with edge client certificates signed by the hub CA. A short summary:

- `GET/PUT/DELETE /v1/tenants[/<host>]` — tenant CRUD.
- `GET/PUT /v1/globals` — global feature defaults.
- `POST /v1/nodes/register` — initial registration, returns a signed client cert.
- `GET /v1/config/stream?node_id=X` — long-poll config stream (snapshot plus deltas).
- `GET /v1/backends`, `GET /v1/health`, `POST /v1/scale` — torpool passthrough.
- `* /<slug>/<token1>/<token2>/**` — admin gate, full session-managed handler (delivered in P3, web UI in P4).

Full request/response shapes, auth model, and `curl` examples are in [`docs/hub-api.md`](docs/hub-api.md).

### Admin gate (hidden path)

The proxy router reserves a three-segment prefix `/<slug>/<token1>/<token2>/` for the admin surface. The match is evaluated with constant-time comparison on all three segments regardless of outcome, so timing behavior never leaks gate state. When `admin.enabled: false` or the tokens are empty the gate is disabled entirely and the router never checks for a match. Path-matching paths are never logged, so the slug and tokens never leave the binary once the installer finishes.

P3 delivers the hidden admin gate with session management, per-IP lockout, CSRF protection, and an append-only audit log. The admin URL is the credential — slug + two tokens configured at install time. After a valid match the handler issues a `gw_adm` session cookie scoped to the admin path with a 15-minute idle window, refreshes it on every request up to an 8-hour absolute cap, requires `X-CSRF-Token` on mutating methods, and writes every mutation to `<audit_data_dir>/audit/<date>.jsonl` plus a BoltDB index. Per-IP-hash lockout tiers (soft: 3 failures in 60s → 30s backoff; hard: 10 in 10min → 1h ban) keep probe traffic from accumulating. See [`docs/admin.md`](docs/admin.md) and [`docs/audit.md`](docs/audit.md).

P4 delivers the admin web UI. A single-page application embedded in the binary, served only through the hidden admin gate, with a neumorphism dark theme (default) and light theme alternative, and interface languages English / Russian / Simplified Chinese. No frameworks, no build step — vanilla JS under 200 KB. See [`docs/admin-ui.md`](docs/admin-ui.md) for the page reference, theme and language behaviour, and extension guide.

### Installation (phased)

Installation runs as a sequence of small scripts under `deploy/install/`. Each step writes nothing to disk until the final step; Ctrl-C aborts safely before that. The steps, in order, are: ask node type; ask public domain (proxy and local); ask hub address (proxy only); ask transport kind; generate a CSR and submit to the hub for signing; generate the admin slug and two tokens; write config, systemd units, and start services.

Interactive run:

```bash
sudo bash deploy/install.sh
```

Non-interactive run for CI or configuration management:

```bash
sudo bash deploy/install.sh \
  --type=proxy \
  --domain=mirror-7.your-domain.example \
  --hub=10.0.0.1 \
  --transport=wireguard \
  --auto-wg \
  --admin-autogen \
  --yes
```

The hub has its own entry script which pre-sets the type and additionally generates the mTLS CA. Full sequences, flag matrices, and systemd layouts are in [`docs/deployment.md`](docs/deployment.md).

### OPSEC principles

Metric labels hash tenant identifiers with a per-install salt by default; operators who need raw hostnames read them from the hub admin API. Client IPs in logs have the last octet zeroed (IPv4) or the last 64 bits dropped (IPv6). The admin slug and tokens are printed to stdout exactly once during installation and never written to a log file. Edges make no outbound calls other than to the hub and to the tenant backends through Tor: no telemetry, no update check, no analytics. Each edge gets its own TLS certificate, so the public hosts do not correlate through a shared cert fingerprint.

The full OPSEC model, with explicit lists of what is and is not protected, and recommended hardening steps (fail2ban, kernel sysctls, chrooted Tor data dirs), is in [`docs/opsec.md`](docs/opsec.md).

### Architecture

```
                              ┌──────────────┐
 Client ──HTTPS──▶  edge-1    │  gateway-hub │
                   edge-2  ──▶│  • torpool   │──SOCKS5──▶ Tor × N ──▶ .onion
                   edge-N     │  • tenants   │
                              │  • admin API │
                              │  • mTLS CA   │
                              └──────────────┘
                               (private network:
                                wg / https / socks-tls)
```

The edge runs the full middleware chain: Prometheus counters, Cloudflare IP check when enabled, security headers, regex blocklist, GeoIP, per-IP and per-tenant rate limit, static cache, content sanitizer, and finally the reverse proxy handler that dials the hub's SOCKS port. The hub runs the pool manager: spawns Tor processes with min/max bounds, probes them every 30 seconds, replaces dead ones in place on their existing SOCKS port, and scales up and down based on busy fraction. For a deeper walk-through see [`docs/architecture.md`](docs/architecture.md).

### Project structure

```
gateway/
  cmd/
    gateway-proxy/       # edge; public listener, middleware, TorTransport client
    gateway-torpool/     # pool manager (embedded in gateway-hub in remote mode)
    gateway-hub/         # central controller (tenant registry, admin API, mTLS CA)
  internal/
    config/              # bootstrap schema, tenant YAML, fsnotify reload
    proxy/               # host routing, middleware chain
    torpool/             # Tor lifecycle, health, scaler, unix socket API
    hub/                 # tenant registry, CA, admin API, config stream
    transport/           # wireguard, https_tunnel, socks5_tls abstractions
    feature/             # middleware modules, one dir per feature
    shared/              # BackendInfo, PoolHealth, TenantInfo types
    admin/               # hidden-gate carve-out (P3 fills handler)
    i18n/                # translation catalogs (en, ru, zh; full in P4)
  deploy/
    install.sh           # top-level installer
    install/             # step scripts
    *.service            # systemd units
  docs/                  # architecture, deployment, tenants, features,
                         # hub-api, opsec, tracing
  config.example.yaml    # bootstrap schema example
  tests/                 # unit + docker-compose integration
```

### Quick start (local mode)

Prerequisites: Go 1.25+, Tor on `$PATH`.

```bash
make build
cp config.example.yaml config.yaml
# Edit config.yaml: set mode: local, node_type: local, domain, tenants.
./bin/gateway-torpool -config config.yaml
./bin/gateway-proxy -config config.yaml
```

Production (Linux, root):

```bash
make build
sudo bash deploy/install.sh
sudo systemctl start gateway-torpool gateway-proxy
```

For remote mode, install the hub first, then each edge. See [`docs/deployment.md`](docs/deployment.md).

### Configuration

See [`config.example.yaml`](config.example.yaml) for the bootstrap schema with inline comments. Tenant and feature configuration lives in the hub runtime directory and is documented in [`docs/tenants.md`](docs/tenants.md) and [`docs/features.md`](docs/features.md).

### Monitoring

When `metrics.enabled: true`, Prometheus counters are exposed at the configured `metrics.listen`. Bind this to a private address; the metrics endpoint must not be public. Tenant labels are hashed by default; raw hostnames are only visible through the hub admin API. OpenTelemetry tracing can be enabled under `metrics.tracing`; exporter configuration is in [`docs/tracing.md`](docs/tracing.md).

Core series:

- `gateway_requests_total{tenant,method,status}`
- `gateway_request_duration_seconds{tenant,method}`
- `gateway_cache_total{tenant,result}`
- `gateway_active_connections`
- `gateway_tor_pool_instances{state}`
- `gateway_tor_circuit_breaker_state{port}`

### Doors and mirror-health (P2)

P2 adds a fourth binary, `gateway-door`, and a mirror-health registry on the hub. A door is a disposable redirector: it serves a cover page on `/` and emits HTTP 302 on short opaque slug paths to one of the currently-healthy tenant mirrors. Doors have no `.onion` reach, no tenant backend list, and no admin surface of their own; they read slugs and a mirror snapshot from the hub through the existing config stream. See [`docs/door.md`](docs/door.md) for the cover kinds, slug routing, and selection strategies.

The hub polls check-host.net from operator-chosen regions to learn whether a mirror is reachable outside the hub's own vantage point. Results feed into a verdict (`live`, `degraded`, `blocked`, `unknown`) per mirror; doors consult the verdict when picking a redirect target. See [`docs/mirrors.md`](docs/mirrors.md) for the registry shape and admin operations, and [`docs/checkhost.md`](docs/checkhost.md) for the API mapping, rate limits, and region tuning.

### Roadmap

Delivered in P1: multi-tenant host routing, local and remote modes, three transports, tenant registry, config hot-reload, feature toggles, v3 `.onion` validator, negative cache, regex blocklist, GeoIP, per-tenant rate limit, block-response modes, proxy-header rules, content sanitizer, stealth HS, OPSEC-safe metrics, TTL blocklist, abuse API, static pre-cache, phased installer, mTLS edge-to-hub.

Delivered in P2: `gateway-door` redirector with cover pages and slug routing, mirror-health registry, check-host.net integration with operator-chosen regions, manual block overrides, per-door runtime config over the existing stream.

Delivered in P3: hidden admin gate handler with session cookie + sliding-refresh TTL, per-IP-hash lockout with soft + hard tiers, CSRF protection on mutating methods, append-only JSONL audit log with BoltDB index, per-node-type API router (hub-only routes return 403 on edges).

Delivered in P4: admin web UI as an embedded single-page application served only through the admin gate, neumorphism dark and light themes with manual toggle and localStorage persistence, interface in English / Russian / Simplified Chinese with URL and localStorage override, page set covering Dashboard / Tenants / Mirrors / Blocklist / Features / Nodes / Metrics / Audit plus an Auto-Domains stub, no frameworks and no build step.

Delivered in P5: comprehensive operator documentation set (deployment, troubleshooting, upgrade), trilingual README, and the i18n catalogs that ship with the admin UI. The full document index is at the top of this section.

Planned: federation between hubs (deferred).

### License

MIT

---

## Русский

### Что это?

TOR Gateway терминирует публичный TLS, маршрутизирует запросы по тенантам через заголовок `Host`, применяет per-tenant middleware (rate limits, regex-блоклисты, GeoIP, content sanitizer, переписывание заголовков) и отправляет upstream через Tor на `.onion` бэкенды. Health-основанный планировщик держит Tor-пул стабильным: мёртвые инстансы заменяются in-place на тех же SOCKS-портах; живые ранжируются по score из активных соединений, наблюдаемой latency и процента ошибок.

### Указатель документации

- [`docs/architecture.md`](docs/architecture.md) — бинарники, режимы, путь запроса, реестры.
- [`docs/deployment.md`](docs/deployment.md) — установка от одного хоста до мульти-нодной фермы.
- [`docs/tenants.md`](docs/tenants.md) — схема YAML тенантов, жизненный цикл, примеры.
- [`docs/features.md`](docs/features.md) — middleware-фичи, параметры, per-tenant override.
- [`docs/hub-api.md`](docs/hub-api.md) — форма запроса/ответа admin API и примеры `curl`.
- [`docs/admin.md`](docs/admin.md) — сессии admin gate, CSRF, lockout.
- [`docs/admin-ui.md`](docs/admin-ui.md) — справочник страниц встроенного UI, темы и языки.
- [`docs/door.md`](docs/door.md) — виды cover-страниц двери и маршрутизация по slug.
- [`docs/mirrors.md`](docs/mirrors.md) — реестр здоровья зеркал и правила вердиктов.
- [`docs/checkhost.md`](docs/checkhost.md) — опрос check-host.net, регионы, rate limits.
- [`docs/opsec.md`](docs/opsec.md) — модель угроз и рекомендации по hardening.
- [`docs/tracing.md`](docs/tracing.md) — настройка OpenTelemetry-экспортёра и форма трейсов.
- [`docs/audit.md`](docs/audit.md) — схема append-only audit log и API запросов.
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — симптом-к-причине по типовым сбоям.
- [`docs/upgrade.md`](docs/upgrade.md) — upgrade-процедура, rollback, миграция с pre-P1.

Система работает в двух режимах. Локальный — одна машина: `gateway-proxy` и `gateway-torpool` на одном хосте, один или несколько тенантов, вся конфигурация в одном файле. Удалённый — роли разделены: edge-ноды `gateway-proxy` держат только публичный TLS и middleware-цепочку; центральный `gateway-hub` владеет Tor-пулом, реестром тенантов и mTLS CA. Edge-ноды одноразовые: сжёг одну, поставил другую на тот же хаб.

### Режимы — local и remote

Локальный режим сохраняет поведение до P1: один домен, одна машина, `gateway-proxy` и `gateway-torpool` на одном хосте общаются через Unix-сокет. Ни хаба, ни mTLS, ни WireGuard. Выбирается значением `node_type: local` в `config.yaml`.

Удалённый режим — новый и мультитенантный. Хаб держит внутри себя `gateway-torpool`, выдаёт клиентам SOCKS5 и admin/config JSON API. Edge-узлы никогда сами не ходят в клирнет к бэкендам; весь исходящий трафик уходит через хаб. Это сокращает число машин, через которые проходит трафик на `.onion`, и физически отделяет их от машин, видных из интернета.

Локальный режим подходит, если у вас один домен на одной машине. Удалённый — если нужна быстрая ротация публичных хостов, изоляция между доменами или желание иметь дешёвые одноразовые frontend-узлы.

### Мультитенантность

Тенант задаётся публичным `Host` и набором `.onion` бэкендов. Файл тенанта (`<host>.yaml`) лежит в runtime-каталоге хаба и может переопределять любые глобальные настройки: свой rate limit, свой regex-блоклист, свою GeoIP-политику, свои правила заголовков. Валидация v3-адресов (56 символов base32) происходит при загрузке; v2 отклоняется с понятной ошибкой.

Пул Tor общий между тенантами. Изоляция обеспечивается в прокси-слое: корзины rate-limit, записи negative-cache, переключатели фич и метки метрик ключуются по `tenant.host`. Stealth client auth — на уровне onion, а не тенанта: приватные ключи лежат в `ClientOnionAuthDir` каждого Tor-инстанса, Tor сам выбирает нужный по адресу назначения.

Промах по `Host`-мапе возвращает HTTP 421 Misdirected Request, что отличается от 404 blocked-path и упрощает диагностику по логам.

### Переключатели фич

Каждая возможность включается отдельно на двух уровнях: `globals.yaml` задаёт дефолты, `tenants/<host>.yaml` переопределяет. Выключенные фичи не просто возвращаются пустышками — они вообще не попадают в middleware-цепочку, поэтому выключенный путь не делает аллокаций.

Девять фич P1: `blocklist_regex`, `geoip`, `rate_limit`, `ttl_blocklist`, `content_sanitizer`, `negative_cache`, `proxy_headers`, `abuse_api`, `static_cache`. Каждая описана в [`docs/features.md`](docs/features.md) с параметрами, дефолтами и примерами per-tenant override. `stealth_hs` и `onion_validator` работают на старте хаба, а не на каждом запросе, и документированы там же.

Hot-reload — через `fsnotify` на runtime-каталоге. Перед применением reload валидирует всё по всем тенантам; любая ошибка прерывает swap, и действующий конфиг остаётся без изменений. Запросы в полёте дорабатывают на старом конфиге, новые — подхватывают свежий.

### Транспорты

Между edge и hub — один из трёх транспортов:

- `wireguard` — по умолчанию. UDP-оверлей. Admin API и SOCKS на хабе слушают только `10.0.0.1`; edge дозванивается по туннелю. Нет кастомного протокола: родной SOCKS5-клиент edge достаёт пул напрямую.
- `https_tunnel` — WebSocket внутри HTTPS с mTLS. Нужен, когда UDP заблокирован или edge живёт на PaaS без UDP. Медленнее WireGuard за счёт обрамления в userspace.
- `socks5_tls` — голый SOCKS5 внутри TLS на `:9443`, admin HTTPS на `:9444`. Крайний вариант: хаб выставляет наружу дактилоскопируемые TLS-порты, установщик об этом предупреждает.

Транспорт выбирается установщиком и пишется в bootstrap. Это инфраструктура, а не runtime-состояние: смена требует рестарта. Интерфейс и последовательность вызовов — в [`docs/architecture.md`](docs/architecture.md).

### Hub API — обзор

Хаб предоставляет небольшой JSON API на приватном адресе транспорта, защищённый mTLS с клиентскими сертификатами edge, подписанными CA хаба. Краткий перечень:

- `GET/PUT/DELETE /v1/tenants[/<host>]` — CRUD тенантов.
- `GET/PUT /v1/globals` — глобальные дефолты фич.
- `POST /v1/nodes/register` — первичная регистрация, возвращает подписанный клиентский сертификат.
- `GET /v1/config/stream?node_id=X` — long-poll поток конфига (snapshot + deltas).
- `GET /v1/backends`, `GET /v1/health`, `POST /v1/scale` — passthrough к torpool.
- `* /<slug>/<token1>/<token2>/**` — admin gate, полноценный session-managed handler (P3, web UI в P4).

Полные схемы запросов/ответов, auth-модель и примеры `curl` — в [`docs/hub-api.md`](docs/hub-api.md).

### Admin gate (скрытый путь)

Маршрутизатор резервирует префикс `/<slug>/<token1>/<token2>/` под admin-интерфейс. Сравнение идёт в constant-time по всем трём сегментам вне зависимости от исхода, так что тайминг не выдаёт состояние. При `admin.enabled: false` или пустых токенах gate отключён и маршрутизатор вообще не проверяет совпадение. Пути, попадающие в admin, не логируются, поэтому slug и токены после работы установщика из бинарника наружу не попадают.

P3 поставляет скрытый admin-gate с управлением сессиями, per-IP lockout, CSRF-защитой и append-only audit log. URL — это и есть credential: slug плюс два токена, заданные на этапе установки. После корректного совпадения handler выдаёт cookie сессии `gw_adm` со scope в admin-path, idle-окно 15 минут, sliding-refresh с абсолютной планкой 8 часов, требует `X-CSRF-Token` на мутирующих методах и пишет каждую мутацию в `<audit_data_dir>/audit/<date>.jsonl` плюс BoltDB-индекс. Per-IP-hash lockout (soft: 3 неудачи за 60с → 30с backoff; hard: 10 за 10м → 1ч ban) гасит probe-трафик. См. [`docs/admin.md`](docs/admin.md) и [`docs/audit.md`](docs/audit.md).

P4 поставляет admin-интерфейс в браузере. Одностраничное приложение встроено в бинарь, отдаётся только через скрытый admin-gate, с тёмной темой в стиле нейморфизм (по умолчанию) и альтернативной светлой, а также интерфейсными языками — английский / русский / упрощённый китайский. Без фреймворков, без шага сборки — ванильный JS меньше 200 КБ. Справочник страниц, поведение темы и языка, руководство по расширению — в [`docs/admin-ui.md`](docs/admin-ui.md).

### Установка (поэтапно)

Установщик — цепочка небольших скриптов в `deploy/install/`. До последнего шага на диск ничего не пишется; Ctrl-C безопасно прерывает процесс. Шаги по порядку: тип узла, публичный домен (для proxy и local), адрес хаба (только proxy), тип транспорта, генерация CSR и подпись на хабе, генерация slug и двух токенов, запись конфига и systemd, запуск.

Интерактивный запуск:

```bash
sudo bash deploy/install.sh
```

Неинтерактивный (CI/Ansible):

```bash
sudo bash deploy/install.sh \
  --type=proxy \
  --domain=mirror-7.your-domain.example \
  --hub=10.0.0.1 \
  --transport=wireguard \
  --auto-wg \
  --admin-autogen \
  --yes
```

У хаба свой стартовый скрипт, где тип уже задан и дополнительно генерируется mTLS CA. Полные последовательности, матрицы флагов и расклад systemd — в [`docs/deployment.md`](docs/deployment.md).

### OPSEC — принципы

Метки метрик по умолчанию хэшируют идентификатор тенанта с per-install солью; реальные имена хостов читаются через admin API хаба. У IP-адресов в логах обнуляется последний октет (IPv4) или /64 (IPv6). Slug и токены печатаются в stdout один раз при установке и нигде не пишутся в лог-файлы. Edge не делает исходящих соединений никуда, кроме хаба и бэкендов тенантов через Tor: никакой телеметрии, проверок обновлений и аналитики. Каждый edge получает собственный TLS-сертификат, чтобы публичные хосты не связывались через общий fingerprint.

Полная модель OPSEC — что защищено, а что нет, и рекомендуемое hardening (fail2ban, sysctl, chroot Tor data_dir) — в [`docs/opsec.md`](docs/opsec.md).

### Архитектура

```
                              ┌──────────────┐
 Client ──HTTPS──▶  edge-1    │  gateway-hub │
                   edge-2  ──▶│  • torpool   │──SOCKS5──▶ Tor × N ──▶ .onion
                   edge-N     │  • tenants   │
                              │  • admin API │
                              │  • mTLS CA   │
                              └──────────────┘
                               (приватная сеть:
                                wg / https / socks-tls)
```

Edge держит всю middleware-цепочку: Prometheus-счётчики, проверку Cloudflare IP (когда включена), security-заголовки, regex-блоклист, GeoIP, per-IP и per-tenant rate limit, static cache, content sanitizer, и в самом конце reverse-proxy handler, который дозванивается до SOCKS-порта хаба. Хаб держит pool manager: спавнит Tor-процессы в границах min/max, опрашивает каждые 60 секунд, заменяет мёртвые на тех же SOCKS-портах и скейлится вверх-вниз по busy-доле. Подробнее — в [`docs/architecture.md`](docs/architecture.md).

### Структура проекта

```
gateway/
  cmd/
    gateway-proxy/       # edge: публичный listener, middleware, TorTransport клиент
    gateway-torpool/     # pool manager (встроен в gateway-hub в remote-режиме)
    gateway-hub/         # центральный контроллер (реестр тенантов, admin API, mTLS CA)
    gateway-door/        # disposable-редиректор (P2)
  internal/
    config/              # bootstrap-схема, YAML тенантов, fsnotify reload
    proxy/               # host routing, middleware-цепочка
    torpool/             # жизненный цикл Tor, health, scaler, unix socket API
    hub/                 # реестр тенантов + зеркал, CA, admin API, config stream
    transport/           # wireguard, https_tunnel, socks5_tls абстракции
    feature/             # middleware-модули, по каталогу на фичу
    shared/              # типы BackendInfo, PoolHealth, TenantInfo
    admin/               # hidden gate + session/lockout/CSRF/audit (P3) + embed UI (P4)
    door/                # cover handler и slug-редиректор (P2)
    checkhost/           # клиент check-host.net (P2)
    metrics/             # OPSEC-хеширующий labeler
    tracing/             # OpenTelemetry абстракция
    i18n/                # каталоги переводов (en, ru, zh)
  deploy/
    install.sh           # верхнеуровневый установщик
    install/             # пошаговые скрипты
    systemd/             # systemd-юниты
  docs/                  # полный набор операторской документации
  config.example.yaml    # пример bootstrap-схемы
  tests/                 # unit + docker-compose integration + скриншоты + OPSEC lint
```

### Быстрый старт (local mode)

Требуется Go 1.25+ и Tor в `$PATH`.

```bash
make build
cp config.example.yaml config.yaml
# Отредактируйте config.yaml: mode: local, node_type: local, домен, тенанты.
./bin/gateway-torpool -config config.yaml
./bin/gateway-proxy -config config.yaml
```

Production (Linux, root):

```bash
make build
sudo bash deploy/install.sh
sudo systemctl start gateway-torpool gateway-proxy
```

Для remote-режима сначала ставится хаб, затем каждый edge. См. [`docs/deployment.md`](docs/deployment.md).

### Конфигурация

Bootstrap-схема с inline-комментариями — в [`config.example.yaml`](config.example.yaml). Тенанты и переключатели фич живут в runtime-каталоге хаба и задокументированы в [`docs/tenants.md`](docs/tenants.md) и [`docs/features.md`](docs/features.md).

### Мониторинг

При `metrics.enabled: true` Prometheus-счётчики доступны на `metrics.listen`. Привязывайте адрес к приватному интерфейсу; метрики наружу выпускать нельзя. Метки тенантов по умолчанию хэшируются, реальные имена видны только через admin API. OpenTelemetry-трассировка включается в `metrics.tracing`; конфигурация экспортёра — в [`docs/tracing.md`](docs/tracing.md).

Основные серии:

- `gateway_requests_total{tenant,method,status}`
- `gateway_request_duration_seconds{tenant,method}`
- `gateway_cache_total{tenant,result}`
- `gateway_active_connections`
- `gateway_tor_pool_instances{state}`
- `gateway_tor_circuit_breaker_state{port}`

### Двери и здоровье зеркал (P2)

P2 добавляет четвёртый бинарь — `gateway-door` — и реестр здоровья зеркал на хабе. Дверь — это одноразовый редиректор: отдаёт прикрытие (cover page) на `/` и выдаёт HTTP 302 на коротких непрозрачных slug-путях к одному из доступных зеркал тенанта. У двери нет выхода к `.onion`, нет списка бэкендов и нет собственного админ-интерфейса; она читает slug-и и снимок зеркал с хаба через уже существующий config-stream. Виды cover-страниц, маршрутизация по slug-ам и стратегии выбора описаны в [`docs/door.md`](docs/door.md).

Хаб опрашивает check-host.net из выбранных оператором регионов, чтобы знать, доступно ли зеркало снаружи собственной точки хаба. Результаты сворачиваются в вердикт (`live`, `degraded`, `blocked`, `unknown`) на каждое зеркало; двери сверяются с вердиктом при выборе цели. Структура реестра и админ-операции — в [`docs/mirrors.md`](docs/mirrors.md), маппинг API, rate limits и настройка регионов — в [`docs/checkhost.md`](docs/checkhost.md).

### План

Сдано в P1: мультитенантный host-routing, local/remote режимы, три транспорта, реестр тенантов, hot-reload конфига, переключатели фич, валидатор v3, negative cache, regex-блоклист, GeoIP, per-tenant rate limit, режимы блок-ответа, правила заголовков, content sanitizer, stealth HS, OPSEC-безопасные метрики, TTL-блоклист, abuse API, static pre-cache, поэтапный установщик, mTLS edge-to-hub.

Сдано в P2: `gateway-door` с cover-страницами и маршрутизацией по slug, реестр здоровья зеркал, интеграция с check-host.net по выбранным регионам, ручные override-блоки, runtime-конфиг двери поверх существующего stream.

Сдано в P3: скрытый admin gate handler с cookie-сессией и sliding-refresh TTL, per-IP-hash lockout с двумя уровнями, CSRF на мутирующих методах, append-only JSONL audit log с BoltDB-индексом, per-node-type API router (hub-only маршруты возвращают 403 на edge-узлах).

Сдано в P4: веб-интерфейс администратора как встроенное одностраничное приложение, отдающееся только через admin gate; нейморфизм-темы dark и light с ручным переключателем и сохранением в localStorage; интерфейс на английском / русском / упрощённом китайском с override через URL и localStorage; страницы Dashboard / Tenants / Mirrors / Blocklist / Features / Nodes / Metrics / Audit плюс стаб Auto-Domains; без фреймворков и без шага сборки.

Сдано в P5: полный набор операторской документации (deployment, troubleshooting, upgrade), трёхъязычный README и i18n-каталоги, поставляемые вместе с админ-интерфейсом. Полный индекс документов — в начале английского раздела.

Планируется: федерация между хабами (отложено).

### Лицензия

MIT

---

## 中文

### 这是什么？

TOR Gateway 终结公网 TLS，按 `Host` 头将请求映射到租户，逐租户应用中间件（rate limit、正则黑名单、GeoIP、内容净化、Header 重写），并通过 Tor 出站到 `.onion` 后端。基于健康度的调度器保持 Tor 池稳定：失效实例在原 SOCKS 端口上原地替换；存活实例按融合活跃连接数、观察到的 latency 与错误率的 score 排序。

### 文档索引

- [`docs/architecture.md`](docs/architecture.md) — 二进制、模式、请求路径、注册表。
- [`docs/deployment.md`](docs/deployment.md) — 从单机到多节点的完整安装流程。
- [`docs/tenants.md`](docs/tenants.md) — 租户 YAML schema、生命周期、示例。
- [`docs/features.md`](docs/features.md) — 中间件 feature、参数、per-tenant 覆盖。
- [`docs/hub-api.md`](docs/hub-api.md) — admin API 请求/响应形态与 `curl` 示例。
- [`docs/admin.md`](docs/admin.md) — admin gate 会话、CSRF、lockout。
- [`docs/admin-ui.md`](docs/admin-ui.md) — 内嵌 Web UI 页面参考与主题/语言行为。
- [`docs/door.md`](docs/door.md) — 门的 cover 类型与 slug 路由。
- [`docs/mirrors.md`](docs/mirrors.md) — 镜像健康注册表与裁决规则。
- [`docs/checkhost.md`](docs/checkhost.md) — check-host.net 轮询、区域、限速。
- [`docs/opsec.md`](docs/opsec.md) — 威胁模型与加固建议。
- [`docs/tracing.md`](docs/tracing.md) — OpenTelemetry 导出器配置与 trace 结构。
- [`docs/audit.md`](docs/audit.md) — append-only 审计日志 schema 与查询 API。
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — 常见故障的症状到根因映射。
- [`docs/upgrade.md`](docs/upgrade.md) — 版本升级流程、回滚、pre-P1 迁移。

系统有两种部署模式。local：单机 —— `gateway-proxy` 与 `gateway-torpool` 同机部署，单个或多个租户，所有配置在同一文件。remote：角色分离 —— 边缘 `gateway-proxy` 节点只负责公网 TLS 与中间件链；中心 `gateway-hub` 拥有 Tor 池、租户注册表和 mTLS CA。边缘节点一次性 —— 烧掉一个，再起一个接到同一 Hub。

### 模式 — local 与 remote

本地模式保留 P1 之前的行为：一个域名、一台机器，`gateway-proxy` 与 `gateway-torpool` 通过 Unix 套接字通信。没有 Hub、没有 mTLS、也没有 WireGuard。在 `config.yaml` 中通过 `node_type: local` 选择。

远程模式为新的多租户默认模式。Hub 内部运行 `gateway-torpool`，对外暴露 SOCKS5 入口和 admin/config JSON API。边缘节点从不直接触达后端的明网入口；所有出站流量都经 Hub 转发。这缩小了能看到 `.onion` 流量的机器集合，把公网暴露面与 Tor 出口物理分离。

单域单机选 local；需要频繁轮换公共主机、跨域隔离或使用廉价一次性前端时选 remote。

### 多租户

租户由公共 `Host` 和一组 `.onion` 后端定义。每个租户文件（`<host>.yaml`）放在 Hub 的 runtime 目录下，可覆盖全局设定：独立的 rate limit、独立的正则黑名单、独立的 GeoIP 策略、独立的 header 规则。加载时校验 v3 地址（56 字符 base32）；v2 明确拒绝并报错。

Tor 池在租户之间共享，隔离在代理层强制执行：rate-limit 桶、negative-cache 条目、feature 开关和指标标签都以 `tenant.host` 为 key。隐藏服务的客户端认证按 onion 维度挂载，而非按租户：私钥加载到每个 Tor 实例的 `ClientOnionAuthDir`，Tor 按目的地址自动选择。

未命中 `Host` 映射返回 HTTP 421 Misdirected Request，与阻止路径的 404 区分，便于从日志排查。

### Feature 开关

每个能力都可单独开关，分两层：`globals.yaml` 设默认值，`tenants/<host>.yaml` 覆盖。关闭的 feature 不会进入中间件链路，关闭路径没有内存分配开销。

P1 的九个 feature：`blocklist_regex`、`geoip`、`rate_limit`、`ttl_blocklist`、`content_sanitizer`、`negative_cache`、`proxy_headers`、`abuse_api`、`static_cache`。每项在 [`docs/features.md`](docs/features.md) 中有参数、默认值与 per-tenant 覆盖示例。`stealth_hs` 与 `onion_validator` 在 Hub 启动阶段生效，而非每请求，也在同一文件中记录。

热加载通过 runtime 目录上的 `fsnotify` 驱动。加载前先跨所有租户、所有 feature 做校验；任一失败则中止切换，沿用旧配置。进行中的请求用旧配置跑完，后续请求使用新配置。

### 传输层

边缘节点到 Hub 的连接使用下列三种传输之一：

- `wireguard` — 默认。UDP 覆盖网络。Hub 的 admin API 与 SOCKS 仅监听 `10.0.0.1`；边缘通过隧道访问。没有自定义协议，边缘现有的 SOCKS5 客户端直接连到池。
- `https_tunnel` — HTTPS 内部跑 WebSocket，带 mTLS。当 UDP 被封或边缘运行在不支持 UDP 的 PaaS 上时使用。由于用户态帧化，比 wireguard 慢。
- `socks5_tls` — 裸 SOCKS5 套在 TLS 内，监听 `:9443`，admin HTTPS 走 `:9444`。最后的选择：Hub 对外暴露可指纹识别的 TLS 端口，安装器会提示风险。

传输在安装时选择并写入 bootstrap。属于基础设施，非运行时状态，切换需重启。接口与调用序列见 [`docs/architecture.md`](docs/architecture.md)。

### Hub API 概览

Hub 在私有传输地址上提供一个小的 JSON API，由 Hub CA 签发的边缘客户端证书 mTLS 保护。要点：

- `GET/PUT/DELETE /v1/tenants[/<host>]` — 租户 CRUD。
- `GET/PUT /v1/globals` — 全局 feature 默认值。
- `POST /v1/nodes/register` — 初次注册，返回签发的客户端证书。
- `GET /v1/config/stream?node_id=X` — long-poll 配置流（快照 + 增量）。
- `GET /v1/backends`、`GET /v1/health`、`POST /v1/scale` — 透传到 torpool。
- `* /<slug>/<token1>/<token2>/**` — admin gate，完整 session-managed handler（P3，Web UI 在 P4）。

完整请求响应 schema、auth 模型与 `curl` 示例见 [`docs/hub-api.md`](docs/hub-api.md)。

### Admin gate（隐藏路径）

路由器预留 `/<slug>/<token1>/<token2>/` 前缀作为 admin 面。三个段都走常数时间比较，无论结果如何，因此时序不会泄露 gate 状态。若 `admin.enabled: false` 或 token 为空，gate 完全关闭，路由器不再检查匹配。admin 匹配路径不会写日志，slug 与 token 在安装完成后不会再出现在任何外部输出中。

P3 交付带会话管理、per-IP lockout、CSRF 保护与 append-only 审计日志的隐藏 admin gate。URL 即凭据：slug 加两个 token 在安装阶段配置。匹配通过后，handler 发放作用域限定在 admin path 的 `gw_adm` 会话 cookie，闲置窗口 15 分钟，sliding 刷新，绝对上限 8 小时；变更方法必须带 `X-CSRF-Token`；每次变更都写入 `<audit_data_dir>/audit/<date>.jsonl` 与 BoltDB 索引。Per-IP-hash lockout（soft：60 秒内 3 次失败 → 30 秒退避；hard：10 分钟内 10 次 → 1 小时封禁）抑制探测流量。详见 [`docs/admin.md`](docs/admin.md) 与 [`docs/audit.md`](docs/audit.md)。

P4 交付浏览器管理界面。单页应用嵌入二进制文件，仅通过隐藏的 admin gate 对外提供，带默认的拟物化深色主题（neumorphism black）和可选的浅色主题（neumorphism white），界面语言覆盖英语 / 俄语 / 简体中文。无框架、无构建步骤 —— 手写 JS 小于 200 KB。页面清单、主题与语言行为、扩展指南见 [`docs/admin-ui.md`](docs/admin-ui.md)。

### 安装（分阶段）

安装脚本是 `deploy/install/` 下一组小脚本的编排。在最后一步前不写入任何文件；Ctrl-C 可安全中止。顺序：节点类型、公共域名（proxy 与 local 需要）、Hub 地址（仅 proxy）、传输类型、生成 CSR 并送 Hub 签发、生成 slug 与两个 token、写入配置与 systemd、启动服务。

交互式：

```bash
sudo bash deploy/install.sh
```

非交互式（CI/Ansible）：

```bash
sudo bash deploy/install.sh \
  --type=proxy \
  --domain=mirror-7.your-domain.example \
  --hub=10.0.0.1 \
  --transport=wireguard \
  --auto-wg \
  --admin-autogen \
  --yes
```

Hub 有独立的入口脚本，节点类型已设为 hub，并额外生成 mTLS CA。完整流程、flag 矩阵与 systemd 布局见 [`docs/deployment.md`](docs/deployment.md)。

### OPSEC 原则

指标标签默认用 per-install salt 哈希租户标识；需要原始 host 名的运维人员通过 Hub admin API 读取。日志中客户端 IP 的最后一个八位（IPv4）或末 64 位（IPv6）被清零。admin slug 与 token 在安装时只向 stdout 打印一次，不写任何日志文件。边缘节点除去连接 Hub 与通过 Tor 访问租户后端外不做任何出站请求：无遥测、无更新检查、无分析。每个边缘使用独立 TLS 证书，公共主机之间不会因共享证书指纹被关联。

完整 OPSEC 模型 — 哪些被保护、哪些没有以及建议的强化措施（fail2ban、内核 sysctl、chroot 的 Tor data_dir） — 见 [`docs/opsec.md`](docs/opsec.md)。

### 架构

```
                              ┌──────────────┐
 Client ──HTTPS──▶  edge-1    │  gateway-hub │
                   edge-2  ──▶│  • torpool   │──SOCKS5──▶ Tor × N ──▶ .onion
                   edge-N     │  • tenants   │
                              │  • admin API │
                              │  • mTLS CA   │
                              └──────────────┘
                               （私有网络：
                                wg / https / socks-tls）
```

边缘运行完整中间件链：Prometheus 计数器、启用时的 Cloudflare IP 校验、安全 Header、正则黑名单、GeoIP、per-IP 与 per-tenant 速率限制、static cache、内容净化，最后是拨号到 Hub SOCKS 端口的反向代理 handler。Hub 运行 pool manager：在 min/max 边界内拉起 Tor 进程，每 60 秒探测一次，在原 SOCKS 端口上就地替换失效实例，并按繁忙比例上下扩缩。完整走查见 [`docs/architecture.md`](docs/architecture.md)。

### 项目结构

```
gateway/
  cmd/
    gateway-proxy/       # 边缘：公网监听、中间件、TorTransport 客户端
    gateway-torpool/     # 池管理器（remote 模式下嵌入 gateway-hub）
    gateway-hub/         # 中心控制器（租户注册表、admin API、mTLS CA）
    gateway-door/        # 一次性重定向器（P2）
  internal/
    config/              # bootstrap schema、租户 YAML、fsnotify reload
    proxy/               # host 路由、中间件链
    torpool/             # Tor 生命周期、health、scaler、unix socket API
    hub/                 # 租户与镜像注册表、CA、admin API、config stream
    transport/           # wireguard / https_tunnel / socks5_tls 抽象
    feature/             # 中间件模块，每个 feature 一个目录
    shared/              # BackendInfo、PoolHealth、TenantInfo 类型
    admin/               # 隐藏 gate + session/lockout/CSRF/audit (P3) + 内嵌 UI (P4)
    door/                # cover handler 与 slug 重定向器（P2）
    checkhost/           # check-host.net 客户端（P2）
    metrics/             # OPSEC 哈希的 labeler
    tracing/             # OpenTelemetry 抽象
    i18n/                # 翻译目录（en、ru、zh）
  deploy/
    install.sh           # 顶层安装器
    install/             # 分步脚本
    systemd/             # systemd 单元
  docs/                  # 完整运维文档
  config.example.yaml    # bootstrap schema 示例
  tests/                 # 单元 + docker-compose 集成 + 截图 + OPSEC lint
```

### 快速开始（local mode）

前置：Go 1.25+，`$PATH` 中有 Tor。

```bash
make build
cp config.example.yaml config.yaml
# 修改 config.yaml：mode: local、node_type: local、domain、tenants。
./bin/gateway-torpool -config config.yaml
./bin/gateway-proxy -config config.yaml
```

生产（Linux，root）：

```bash
make build
sudo bash deploy/install.sh
sudo systemctl start gateway-torpool gateway-proxy
```

remote 模式先装 Hub 再装各 edge，见 [`docs/deployment.md`](docs/deployment.md)。

### 配置

bootstrap schema 与行内注释见 [`config.example.yaml`](config.example.yaml)。租户与 feature 配置位于 Hub 的 runtime 目录，文档在 [`docs/tenants.md`](docs/tenants.md) 与 [`docs/features.md`](docs/features.md)。

### 监控

`metrics.enabled: true` 时，Prometheus 计数器暴露在 `metrics.listen`。绑定到私有地址，指标端点不可对外。租户标签默认哈希，原始 host 仅通过 admin API 可见。OpenTelemetry 采样在 `metrics.tracing` 开启，导出器配置见 [`docs/tracing.md`](docs/tracing.md)。

核心指标系列：

- `gateway_requests_total{tenant,method,status}`
- `gateway_request_duration_seconds{tenant,method}`
- `gateway_cache_total{tenant,result}`
- `gateway_active_connections`
- `gateway_tor_pool_instances{state}`
- `gateway_tor_circuit_breaker_state{port}`

### 门与镜像健康（P2）

P2 新增第四个二进制 `gateway-door` 以及 Hub 上的镜像健康注册表。门是一次性重定向器：在 `/` 上返回掩护页（cover page），在少量不透明的 slug 路径上以 HTTP 302 将用户重定向到当前可用的租户镜像之一。门没有 `.onion` 出口、没有后端清单，也没有自己的 admin 接口；它通过已有的 config-stream 从 Hub 读取 slug 列表与镜像快照。cover 页类型、slug 路由和选择策略见 [`docs/door.md`](docs/door.md)。

Hub 从运维人员选定的区域调用 check-host.net，了解某个镜像在 Hub 自身视角之外是否仍可达。结果合成每个镜像的裁决 (`live`、`degraded`、`blocked`、`unknown`)；门在挑选重定向目标时读取该裁决。注册表结构与管理操作见 [`docs/mirrors.md`](docs/mirrors.md)，API 映射、限速和区域调优见 [`docs/checkhost.md`](docs/checkhost.md)。

### 路线图

P1 已交付：多租户 host 路由、local/remote 模式、三种传输、租户注册表、热加载、feature 开关、v3 校验器、negative cache、正则黑名单、GeoIP、per-tenant 速率限制、block 响应模式、proxy header 规则、content sanitizer、stealth HS、OPSEC 安全指标、TTL 黑名单、abuse API、static pre-cache、分阶段安装器、edge-to-hub mTLS。

P2 已交付：带 cover 页与 slug 路由的 `gateway-door`、镜像健康注册表、按区域接入 check-host.net、手工 override 屏蔽、通过既有 stream 下发的门运行时配置。

P3 已交付：带 cookie 会话与 sliding-refresh TTL 的隐藏 admin gate 处理器、双层 per-IP-hash lockout、变更方法的 CSRF 保护、带 BoltDB 索引的 append-only JSONL 审计日志、按节点类型分流的 API 路由（hub-only 路由在 edge 节点返回 403）。

P4 已交付：作为嵌入式单页应用的管理 Web 界面，仅通过 admin gate 对外提供；拟物化 dark 与 light 双主题，支持手动切换并写入 localStorage；界面语言为英语 / 俄语 / 简体中文，可通过 URL 与 localStorage 覆盖；页面涵盖 Dashboard / Tenants / Mirrors / Blocklist / Features / Nodes / Metrics / Audit 以及 Auto-Domains 占位；无框架、无构建步骤。

P5 已交付：完整的运维文档集（deployment、troubleshooting、upgrade）、三语 README，以及随管理 UI 一同分发的 i18n 目录。完整文档索引见英文章节顶部。

后续计划：Hub 间联邦（暂缓）。

### 许可证

MIT
