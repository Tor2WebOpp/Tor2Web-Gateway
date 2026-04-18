# TOR Gateway

**High-performance Tor routing gateway** — a two-component system that manages a dynamic pool of Tor instances and routes HTTP/HTTPS traffic through them with automatic TLS, caching, rate limiting, and health-based load balancing.

**[English](#english)** | **[Русский](#русский)** | **[中文](#中文)**

---

## English

### What is this?

TOR Gateway sits between your clients (optionally behind Cloudflare) and your upstream backends. All outbound traffic to backends is routed through Tor, providing network-level anonymity for the proxy layer. The system automatically manages Tor instances, scales them based on load, replaces dead ones, and balances traffic across them.

### Architecture

The system consists of two independent processes communicating via a Unix socket:

```
                    ┌─────────────────────────────────────────────┐
                    │               gateway-proxy                  │
  Client ──HTTPS──▶ │  Middleware Stack ──▶ TorTransport            │
                    │  (CF check, rate    (select best Tor         │
                    │   limit, cache,      instance, SOCKS5 dial,  │
                    │   security headers)  retry on failure)        │
                    └───────┬──────────────────────┬───────────────┘
                            │ polls /backends       │ SOCKS5
                            │ every 2s              │
                    ┌───────▼───────────┐   ┌──────▼──────┐
                    │  gateway-torpool   │   │ Tor process │──▶ Backend
                    │  (manager, health, │   │ Tor process │──▶ Backend
                    │   scaler, API)     │   │ Tor process │──▶ Backend
                    └───────────────────┘   └─────────────┘
```

**gateway-proxy** — client-facing reverse proxy with a full middleware stack:
1. Prometheus metrics collection
2. Cloudflare IP validation (optional)
3. Security headers (HSTS, X-Frame-Options, X-Content-Type-Options)
4. Blocked paths (/.env, /wp-admin, /phpmyadmin) and methods (TRACE, TRACK)
5. Request body size limit (4 MB)
6. Panic recovery
7. Per-IP and global rate limiting
8. In-memory response cache (Ristretto, for static files)
9. Reverse proxy with `TorTransport` — routes through the best available Tor instance

**gateway-torpool** — Tor process lifecycle manager:
1. Spawns and monitors Tor instances (configurable min 3 / max 12)
2. Health checker probes each instance every 30s, replaces dead ones
3. Auto-scaler adjusts instance count based on load (scale up at 80% capacity, down at 20%)
4. Exposes a JSON API on a Unix socket (`/backends`, `/health`, `/scale`, `/stats`)

### Why these decisions?

| Decision | Rationale |
|---|---|
| **Two separate processes** | Torpool can restart without dropping client connections. Each component has a single responsibility and can be updated independently. |
| **Unix socket API** | No network exposure for internal communication. Proxy polls torpool every 2 seconds for the current backend list — loose coupling, no shared memory. |
| **Score-based load balancing** | `score = (active_conns × 2) + (latency_ms / 100) + (error_rate × 10)`. Lower is better. Considers real-time load, not just round-robin. |
| **Circuit breaker per Tor instance** | Each SOCKS port gets its own breaker (opens at 50% failure rate over 10+ requests). One bad Tor instance doesn't cascade to others. |
| **In-place instance replacement** | Dead instances are replaced on the same SOCKS port. The proxy doesn't need to know — port stays constant. |
| **Retry on gateway errors** | 502/503/504 trigger retry on a different Tor instance (up to 3 attempts). Transient Tor circuit failures are masked from the client. |
| **CertMagic for TLS** | Automatic ACME certificate management. No manual cert rotation. HTTP-01 challenges on port 80, auto-redirect to HTTPS. |
| **Ristretto cache with dedup** | Concurrent cache misses for the same key are serialized (inflight map), preventing thundering herd. Static files cached up to 5 MB each. |
| **Cloudflare IP validation** | When enabled, only Cloudflare IPs can reach the proxy. IP lists are refreshed from Cloudflare's public endpoint every 24 hours. |
| **Systemd hardening** | Both services run as an unprivileged `gateway` user with ProtectSystem=strict, ProtectHome=yes, PrivateTmp, NoNewPrivileges. Proxy gets CAP_NET_BIND_SERVICE for ports 80/443. |

### Project structure

```
gateway/
├── cmd/
│   ├── gateway-proxy/main.go        # Proxy entry point
│   └── gateway-torpool/main.go      # Torpool entry point
├── internal/
│   ├── config/config.go             # YAML config loading + validation
│   ├── shared/types.go              # Shared types (BackendInfo, PoolHealth, etc.)
│   ├── proxy/
│   │   ├── server.go                # HTTP server, middleware chain
│   │   ├── transport.go             # TorTransport (SOCKS5, retries, circuit breaker)
│   │   ├── cache.go                 # Ristretto response cache
│   │   ├── ratelimit.go             # Per-IP + global rate limiter
│   │   ├── security.go              # Security headers, blocked paths/methods
│   │   ├── cloudflare.go            # CF IP validation
│   │   ├── metrics.go               # Prometheus metrics
│   │   ├── errors.go                # Embedded error pages (429, 502, 503, 504)
│   │   └── static/                  # HTML error page templates
│   └── torpool/
│       ├── manager.go               # Tor instance spawning + lifecycle
│       ├── health.go                # Health probes + dead instance replacement
│       ├── balancer.go              # Auto-scaler (load-based)
│       └── api.go                   # Unix socket management API
├── deploy/
│   ├── install.sh                   # Production installer (idempotent)
│   ├── gateway-proxy.service        # Systemd unit
│   └── gateway-torpool.service      # Systemd unit
├── config.example.yaml              # Configuration template
├── Makefile                         # build / test / clean
└── go.mod
```

### Quick start

**Prerequisites**: Go 1.25+, Tor installed and on `$PATH`.

```bash
# Build
make build

# Configure
cp config.example.yaml config.yaml
# Edit config.yaml — set your domain, email, proxy_secret (openssl rand -hex 32), backends

# Run (development — two terminals)
./bin/gateway-torpool -config config.yaml
./bin/gateway-proxy -config config.yaml

# Run tests
make test
```

**Production deployment** (Linux, root):
```bash
make build
sudo bash deploy/install.sh
# Edit /etc/gateway/config.yaml
sudo systemctl start gateway-torpool gateway-proxy
```

### Configuration

See [`config.example.yaml`](config.example.yaml) for all options with comments. Key settings:

| Setting | Default | Description |
|---|---|---|
| `domain` | *(required)* | Public FQDN for TLS |
| `proxy_secret` | *(required, 32+ chars)* | Shared secret between proxy and torpool |
| `backends[].addr` | *(required)* | Upstream backend addresses |
| `tor.min_instances` | 3 | Minimum Tor instances |
| `tor.max_instances` | 12 | Maximum Tor instances |
| `cloudflare.enabled` | false | Validate inbound IPs against Cloudflare ranges |
| `cache.enabled` | true | In-memory response cache |
| `rate_limit.per_ip_rps` | 10 | Requests per second per client IP |
| `metrics.listen` | :9090 | Prometheus metrics endpoint |

### Monitoring

When `metrics.enabled: true`, Prometheus metrics are exposed at `http://localhost:9090/metrics`:

- `gateway_requests_total` — request counter (by method, status)
- `gateway_request_duration_seconds` — latency histogram
- `gateway_cache_total` — cache hit/miss counter
- `gateway_active_connections` — current connection gauge

### Roadmap

- [ ] Graceful Tor circuit rotation on schedule
- [ ] WebSocket passthrough support
- [ ] Multi-region torpool federation
- [ ] Dashboard UI for pool management
- [ ] .onion backend support (hidden service to hidden service)
- [ ] Config hot-reload without restart
- [ ] gRPC backend protocol support

### License

MIT

---

## Русский

### Что это?

TOR Gateway — это высокопроизводительный шлюз маршрутизации через Tor. Система из двух компонентов: прокси-сервер и менеджер пула Tor-инстансов, которые общаются через Unix-сокет.

### Архитектура

Система состоит из двух независимых процессов:

**gateway-proxy** — обратный прокси с полным стеком middleware:
- Валидация IP Cloudflare (опционально)
- Заголовки безопасности (HSTS, X-Frame-Options и др.)
- Блокировка опасных путей (/.env, /wp-admin) и методов (TRACE)
- Лимит размера тела запроса (4 МБ)
- Rate limiting по IP и глобальный
- In-memory кэш ответов (Ristretto) для статических файлов
- Маршрутизация через лучший доступный Tor-инстанс с circuit breaker и retry

**gateway-torpool** — менеджер жизненного цикла Tor-процессов:
- Запуск и мониторинг Tor-инстансов (от 3 до 12, настраивается)
- Проверка здоровья каждые 30 секунд, замена мёртвых инстансов
- Автоскейлинг по нагрузке (вверх при 80% загрузки, вниз при 20%)
- JSON API на Unix-сокете для управления пулом

### Почему такие решения?

| Решение | Обоснование |
|---|---|
| **Два отдельных процесса** | Torpool можно перезапустить без потери клиентских соединений. Каждый компонент обновляется независимо. |
| **Unix-сокет для IPC** | Нет сетевого экспонирования внутренних API. Прокси опрашивает torpool каждые 2 секунды — слабая связанность. |
| **Балансировка по score** | `score = (активные_конн × 2) + (латентность_мс / 100) + (ошибки × 10)`. Меньше — лучше. Учитывает реальную нагрузку, а не просто round-robin. |
| **Circuit breaker на каждый инстанс** | Каждый SOCKS-порт имеет свой breaker (открывается при 50% ошибок на 10+ запросах). Один сбойный инстанс не каскадирует на остальные. |
| **Замена инстансов на том же порту** | Мёртвые инстансы заменяются на том же SOCKS-порту. Прокси не нужно об этом знать. |
| **Retry при ошибках шлюза** | 502/503/504 вызывают повтор на другом инстансе (до 3 попыток). Транзиентные сбои Tor-цепочек скрыты от клиента. |
| **Автоматический TLS через CertMagic** | ACME-сертификаты получаются и обновляются автоматически. Без ручной ротации. |
| **Кэш с дедупликацией** | Параллельные промахи по одному ключу сериализуются, предотвращая thundering herd. |
| **Hardening через systemd** | Оба сервиса работают под непривилегированным пользователем с ProtectSystem=strict, NoNewPrivileges, PrivateTmp. |

### Быстрый старт

**Требования**: Go 1.25+, Tor в `$PATH`.

```bash
# Сборка
make build

# Настройка
cp config.example.yaml config.yaml
# Отредактируйте config.yaml — домен, email, proxy_secret, бэкенды

# Запуск (разработка — два терминала)
./bin/gateway-torpool -config config.yaml
./bin/gateway-proxy -config config.yaml

# Тесты
make test
```

**Production (Linux, root)**:
```bash
make build
sudo bash deploy/install.sh
# Отредактируйте /etc/gateway/config.yaml
sudo systemctl start gateway-torpool gateway-proxy
```

### Мониторинг

При `metrics.enabled: true` метрики Prometheus доступны на `http://localhost:9090/metrics`:

- `gateway_requests_total` — счётчик запросов (метод, статус)
- `gateway_request_duration_seconds` — гистограмма латентности
- `gateway_cache_total` — попадания/промахи кэша
- `gateway_active_connections` — текущие соединения

### Что планируется

- [ ] Плановая ротация Tor-цепочек
- [ ] Поддержка WebSocket passthrough
- [ ] Федерация torpool между регионами
- [ ] UI-дашборд для управления пулом
- [ ] Поддержка .onion бэкендов (hidden service → hidden service)
- [ ] Hot-reload конфигурации без перезапуска
- [ ] Поддержка gRPC-бэкендов

---

## 中文

### 这是什么？

TOR Gateway 是一个高性能的 Tor 路由网关。该系统由两个组件组成：代理服务器和 Tor 实例池管理器，通过 Unix 套接字通信。

### 架构

系统由两个独立进程组成：

**gateway-proxy** — 反向代理，具有完整的中间件栈：
- Cloudflare IP 验证（可选）
- 安全头部（HSTS、X-Frame-Options 等）
- 阻止危险路径（/.env、/wp-admin）和方法（TRACE）
- 请求体大小限制（4 MB）
- 按 IP 和全局速率限制
- 内存响应缓存（Ristretto），用于静态文件
- 通过最佳可用 Tor 实例路由，带断路器和重试

**gateway-torpool** — Tor 进程生命周期管理器：
- 启动和监控 Tor 实例（3 到 12 个，可配置）
- 每 30 秒健康检查，替换失效实例
- 基于负载自动扩缩容（80% 负载时扩容，20% 时缩容）
- Unix 套接字上的 JSON API 用于池管理

### 为什么这样设计？

| 决策 | 理由 |
|---|---|
| **两个独立进程** | Torpool 可以独立重启而不断开客户端连接。每个组件可以独立更新。 |
| **Unix 套接字通信** | 内部通信无网络暴露。代理每 2 秒轮询 torpool — 松耦合设计。 |
| **基于评分的负载均衡** | `score = (活跃连接 × 2) + (延迟毫秒 / 100) + (错误率 × 10)`。越低越好。基于实时负载，而非简单轮询。 |
| **每实例断路器** | 每个 SOCKS 端口有独立断路器（10+ 请求中 50% 失败率时触发）。一个故障实例不会影响其他实例。 |
| **原地替换实例** | 失效实例在同一 SOCKS 端口上替换。代理无需感知变化。 |
| **网关错误重试** | 502/503/504 触发在不同实例上重试（最多 3 次）。Tor 链路的瞬态故障对客户端透明。 |
| **CertMagic 自动 TLS** | ACME 证书自动获取和续期。无需手动轮换。 |
| **缓存去重** | 同一键的并发缓存未命中被序列化，防止惊群效应。 |
| **systemd 安全加固** | 两个服务都以非特权用户运行，启用 ProtectSystem=strict、NoNewPrivileges、PrivateTmp。 |

### 快速开始

**前置要求**：Go 1.25+，Tor 已安装并在 `$PATH` 中。

```bash
# 构建
make build

# 配置
cp config.example.yaml config.yaml
# 编辑 config.yaml — 设置域名、邮箱、proxy_secret、后端地址

# 运行（开发环境 — 两个终端）
./bin/gateway-torpool -config config.yaml
./bin/gateway-proxy -config config.yaml

# 测试
make test
```

**生产部署（Linux，root）**：
```bash
make build
sudo bash deploy/install.sh
# 编辑 /etc/gateway/config.yaml
sudo systemctl start gateway-torpool gateway-proxy
```

### 监控

当 `metrics.enabled: true` 时，Prometheus 指标在 `http://localhost:9090/metrics` 可用：

- `gateway_requests_total` — 请求计数器（按方法、状态码）
- `gateway_request_duration_seconds` — 延迟直方图
- `gateway_cache_total` — 缓存命中/未命中计数
- `gateway_active_connections` — 当前连接数

### 路线图

- [ ] 定时 Tor 链路轮换
- [ ] WebSocket 透传支持
- [ ] 多区域 torpool 联邦
- [ ] 池管理 UI 仪表板
- [ ] .onion 后端支持（隐藏服务到隐藏服务）
- [ ] 无需重启的配置热加载
- [ ] gRPC 后端协议支持
