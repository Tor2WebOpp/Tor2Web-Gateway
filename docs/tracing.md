# Tracing

The gateway emits OpenTelemetry (OTel) traces for every request it handles. This document describes how to enable tracing, what the spans look like, how they interact with the OPSEC rules that apply to metric labels, and sample configurations for the collectors most operators use.

Tracing is off by default. When disabled, there is no overhead: the tracer is a no-op implementation and no spans are created.

## Configuration

The bootstrap config has a `metrics.tracing` block:

```yaml
metrics:
  enabled: true
  listen: "10.0.0.42:9090"
  opsec:
    hash_tenant_labels: true
    tenant_label_salt_file: /etc/gateway/metrics-salt
  tracing:
    enabled: false
    endpoint: "otel-collector.internal:4317"
    protocol: grpc              # grpc | http
    sample_ratio: 0.05          # 0.0 .. 1.0
    service_name: "gateway"     # overrides default; keep neutral
    insecure: false             # allow plaintext; only on a trusted network
    headers:                    # optional, passed to the exporter
      X-Auth-Token: "..."
```

Fields:

- `enabled` — master switch for the tracer. Required to be true for any span to be produced.
- `endpoint` — OTLP endpoint. Hostname:port. Path is not included for gRPC; for HTTP the path is `/v1/traces`.
- `protocol` — `grpc` for OTLP/gRPC on port 4317 (default for most collectors) or `http` for OTLP/HTTP on port 4318.
- `sample_ratio` — fraction of traces to sample. Applied by `sdktrace.ParentBased(TraceIDRatioBased(n))`. 0.05 means 5% of requests sampled.
- `service_name` — string attached to every span as `service.name`. Use a neutral value; do not include the tenant host.
- `insecure` — when true, the exporter uses plaintext gRPC or HTTP. Use only on a private network; never over the public internet.
- `headers` — optional headers added to every export request, typically for a tenant token at a managed collector.

## What gets traced

Each incoming request creates a root span at the edge:

```
span: http.request
  attributes:
    http.method: "GET"
    http.host_hash: "sha256-hex[:16]"     # never raw host
    http.scheme: "https"
    http.status_code: 200
    net.peer.ip_hash: "sha256-hex[:16]"   # never raw client ip
    gateway.node_id: "edge-7a3c"
    gateway.tenant_id: "sha256-hex[:16]"  # hashed, matches metrics label
```

Child spans are emitted for each significant step:

- `middleware.blocklist_regex` — duration of regex matching.
- `middleware.geoip` — country lookup on the client IP.
- `middleware.rate_limit` — bucket check.
- `middleware.ttl_blocklist` — live entry check.
- `middleware.static_cache` — cache lookup; `gateway.cache.result` attribute is `hit` or `miss`.
- `upstream.dial` — SOCKS5 dial through the transport to the hub. Attributes: `gateway.backend_port`, `gateway.dial_attempt`.
- `upstream.response` — upstream request and response. Attributes: `http.response.body_bytes`, `http.status_code`.
- `middleware.content_sanitizer` — duration and bytes processed.

On the hub, a complementary span tree is produced on admin-API calls. Config-stream long-polls are not traced beyond the initial handshake because the stream is long-lived; tracing it would produce enormous traces.

Span attributes never include raw hostnames, raw client IPs, or raw tenant identifiers. Anywhere a tenant or a client IP appears, it is the hashed form identical to the metrics label hash. This keeps traces at parity with metrics for OPSEC.

Exception: the `http.url` attribute is not emitted. Full URLs include query strings which may contain PII, so the gateway omits this attribute entirely. The `http.path` attribute is emitted but with any configured PII paths stripped.

## Sample collector configurations

### OpenTelemetry Collector (local, writing to a file for inspection)

`otel-collector-local.yaml`:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:
    timeout: 5s
  memory_limiter:
    check_interval: 1s
    limit_percentage: 75
    spike_limit_percentage: 25

exporters:
  file:
    path: /var/log/otel/traces.jsonl
    rotation:
      max_megabytes: 100
      max_days: 7

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [file]
```

Run this collector on the hub (or an adjacent machine), point the gateway at it, and inspect `/var/log/otel/traces.jsonl` directly. Useful for local debugging without a full telemetry stack.

### OpenTelemetry Collector (forwarding to a remote backend)

`otel-collector-forward.yaml`:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  batch:
  memory_limiter:
    check_interval: 1s
    limit_percentage: 75
    spike_limit_percentage: 25
  attributes/strip_sensitive:
    actions:
      - key: http.url
        action: delete
      - key: http.request.header.cookie
        action: delete
      - key: http.request.header.authorization
        action: delete

exporters:
  otlphttp:
    endpoint: "https://telemetry.your-domain.example/v1/traces"
    headers:
      X-Auth-Token: "${env:TELEMETRY_TOKEN}"
    tls:
      insecure: false

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, attributes/strip_sensitive, batch]
      exporters: [otlphttp]
```

The `attributes/strip_sensitive` processor is a defense-in-depth layer: the gateway does not emit these attributes, but if a future version does, the collector will strip them before export.

### Grafana Tempo

If you run Tempo directly, point the gateway at the Tempo OTLP receiver (default `:4317`):

```yaml
metrics:
  tracing:
    enabled: true
    endpoint: "tempo.your-domain.example:4317"
    protocol: grpc
    sample_ratio: 0.05
    insecure: true           # only if tempo is on your private network
```

A simple Tempo config listening for OTLP:

```yaml
server:
  http_listen_port: 3200
  grpc_listen_port: 9095

distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: 0.0.0.0:4317

ingester:
  max_block_duration: 5m

storage:
  trace:
    backend: local
    local:
      path: /var/tempo/blocks
```

The gateway's spans land in Tempo with `service.name = "gateway"` and hashed tenant labels, so Grafana queries use the same tenant-id hash that appears in Prometheus dashboards. Join traces and metrics on the `gateway.tenant_id` attribute.

### Jaeger

Jaeger accepts OTLP natively since version 1.35. Endpoint is the same:

```yaml
metrics:
  tracing:
    enabled: true
    endpoint: "jaeger.your-domain.example:4317"
    protocol: grpc
    sample_ratio: 0.1
```

No special configuration on the Jaeger side beyond its default OTLP receiver.

## Sampling

The gateway uses `ParentBased(TraceIDRatioBased(sample_ratio))`. If an upstream client sends a `traceparent` header indicating the request is part of a sampled trace, the gateway respects it (sampled). If the client sends an unsampled trace, the gateway continues with unsampled. If the client sends nothing, the gateway samples at the configured ratio.

Typical values:

- `0.0` — tracing disabled (but metrics and logs still work).
- `0.01` — 1%, fine for high-traffic production where you only want spot checks.
- `0.05` — 5%, default starting point.
- `0.1`..`0.25` — debugging mode, higher cardinality.
- `1.0` — all traces, only on development or a low-traffic canary.

Be aware: higher sampling means higher volume at the collector and higher storage cost. For a 1000 RPS edge at 5% sampling, expect roughly 50 traces per second with 10–20 spans each.

## Propagation

The gateway propagates W3C Trace Context headers (`traceparent`, `tracestate`) on upstream requests to tenant backends. Backends that support OTel see the edge's trace ID and can continue the trace with their own spans. Backends that do not support it see opaque headers they can ignore.

Baggage propagation is disabled. Baggage headers from the client are not forwarded upstream. This is an OPSEC decision: baggage can carry arbitrary key-value pairs added by intermediaries and is a potential vector for data exfiltration. If a tenant needs baggage support, they must explicitly enable it in a future config field (planned for P3 with per-tenant opt-in).

## Tracing the hub

The hub has the same configuration block. Enable it on the hub for visibility into admin-API latency, config-stream propagation time, and torpool spawn times:

```yaml
# On the hub:
metrics:
  tracing:
    enabled: true
    endpoint: "otel-collector.internal:4317"
    sample_ratio: 1.0   # low volume on admin API, so full sampling is fine
    service_name: "gateway-hub"
```

Hub spans include `gateway.component = "hub"` so they are easy to separate from edge spans in queries.

## OPSEC in traces

Traces carry two specific hazards that metrics do not: the parent-child tree reveals causal structure (which can be more identifying than aggregate metrics), and span attributes can accidentally leak raw values if a developer forgets the hash helper.

Mitigations:

1. The `gateway.tenant_id` and `net.peer.ip_hash` attributes are the only way tenant and client identifiers appear in spans. The code does not expose unhashed equivalents.
2. `http.url` is not emitted; `http.path` is passed through a `redactPath` helper that strips known PII patterns (UUID-like path segments are replaced with `{uuid}`, query strings are dropped).
3. The tracer never emits request or response bodies.
4. Span events (logs inside spans) go through the same IP anonymization helper as the regular logger.
5. The `sample_ratio` parameter is enforced at span creation; a span that is not sampled is not even allocated, so in-process data cannot leak via a span that is later dropped.

The OTel exporter itself does not encrypt data by default when `insecure: true`. Never run an insecure exporter across the public internet. Either use `insecure: false` with a real TLS cert on the collector, or run the collector on a private network (typically the same wg overlay used for the transport).

## Disabling tracing cleanly

Set `metrics.tracing.enabled: false` and restart. All span creation becomes no-op; `go tool trace` overhead is effectively zero. Existing traces at the collector are unaffected.

Do not try to disable tracing by pointing `endpoint` at a non-existent address. The exporter will retry and log errors; memory use will grow as batches queue. Use the enabled flag.
