// Package tracing provides the gateway's OpenTelemetry integration.
//
// It exposes three building blocks that proxy/hub/torpool wire in on
// their own schedule:
//
//   - Init installs a global TracerProvider with a selectable exporter
//     ("otlp", "stdout", or "none") and returns a shutdown function.
//   - HTTPMiddleware starts a server span per inbound request, tags it
//     with an OPSEC-safe tenant label (via a caller-supplied LabelerFn),
//     and records method, route, and response status.
//   - ClientInstrumentation wraps an outbound http.RoundTripper so hub
//     API calls and torpool lookups propagate trace context.
//
// # OPSEC
//
// Tenant hostnames never appear as raw strings in span attributes. The
// LabelerFn passed to HTTPMiddleware is expected to be the same hash
// helper used for Prometheus labels (internal/metrics.Labeler.Tenant).
// When the labeler is nil the attribute is omitted entirely — this is
// preferred over a partial raw value.
//
// # Wiring (reference)
//
// The proxy server wires the middleware directly inside its handler
// chain, ideally as the outermost middleware so every downstream step
// records its own event on the same span:
//
//	shutdown, err := tracing.Init(ctx, tracing.Config{
//	    Enabled:     cfg.Tracing.Enabled,
//	    ServiceName: "gateway-proxy",
//	    Exporter:    cfg.Tracing.Exporter,
//	    Endpoint:    cfg.Tracing.Endpoint,
//	    SampleRate:  cfg.Tracing.SampleRate,
//	})
//	defer shutdown(context.Background())
//
//	handler = tracing.HTTPMiddleware(labeler.Tenant, handler)
//
// For outbound calls to the hub or torpool:
//
//	client := &http.Client{Transport: tracing.ClientInstrumentation(base)}
//
// Actual wiring in proxy/hub lives in those packages; this package only
// offers the abstraction so callers can stay independent of the otel
// module path.
package tracing
