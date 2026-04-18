package tracing

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"

	"gateway/internal/feature"
)

// LabelerFn rewrites a raw tenant host into a metrics-safe label.
// The tracing package never calls attribute.String with a raw host;
// all tenant values are passed through LabelerFn first so the OPSEC
// guarantees of the metrics package extend to spans.
//
// Implementations should be safe for concurrent use — typically they
// are backed by the shared *metrics.Labeler.
type LabelerFn func(host string) string

// TenantAttrKey is the span attribute used for the labelled tenant
// value. Kept as a constant so dashboards and the hub admin UI can
// agree on the name without coupling.
const TenantAttrKey = "gateway.tenant"

// OperationName is the default span name used when the HTTPMiddleware
// wraps a handler without a caller-supplied route.
const OperationName = "gateway.http"

// statusRecorder captures the status code that a downstream handler
// wrote so that HTTPMiddleware can record it as a span attribute
// after the request completes.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

// WriteHeader stores the status and forwards to the wrapped writer.
func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

// Write captures an implicit 200 status that would otherwise bypass
// WriteHeader. Matches net/http semantics.
func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status = http.StatusOK
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}

// HTTPMiddleware returns a middleware that wraps next in an OpenTelemetry
// span. The span is started via otelhttp for consistent context
// propagation, then an inner handler tags the span with the tenant label
// (via labeler), method, route (if set on the request), and the final
// status code. When the status indicates a server-side error the span's
// status is set to codes.Error so exporters classify the trace properly.
//
// labeler may be nil; in that case the tenant attribute is omitted. This
// keeps the package usable before a real Labeler has been constructed
// (e.g. during installer bring-up).
func HTTPMiddleware(labeler LabelerFn, next http.Handler) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		span := trace.SpanFromContext(r.Context())

		// Record OPSEC-safe tenant attr when a labeler is configured
		// and a tenant has been placed on the context. Never record
		// the raw host; the tenant attribute always goes through the
		// labeler so operators see the same hashed identifier as in
		// Prometheus metrics.
		if labeler != nil {
			if tenant := feature.TenantFromContext(r.Context()); tenant != nil && tenant.Host != "" {
				span.SetAttributes(attribute.String(TenantAttrKey, labeler(tenant.Host)))
			}
		}

		// Standard HTTP attributes. otelhttp already sets some of
		// these, but we re-assert them so span shape is stable
		// across otelhttp versions.
		span.SetAttributes(semconv.HTTPRequestMethodOriginal(r.Method))
		if r.URL != nil && r.URL.Path != "" {
			span.SetAttributes(semconv.HTTPRoute(r.URL.Path))
		}

		next.ServeHTTP(rec, r)

		span.SetAttributes(semconv.HTTPResponseStatusCode(rec.status))
		if rec.status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(rec.status))
		}
	})

	// otelhttp.NewHandler starts a server span and injects it into
	// the request context. Our inner handler then decorates that
	// span — this keeps the otelhttp semantic conventions intact
	// while letting us add gateway-specific attributes on top.
	return otelhttp.NewHandler(inner, OperationName)
}

// ClientInstrumentation wraps an http.RoundTripper with otelhttp's
// client-side instrumentation, so outbound calls (hub API, torpool
// socket, configuration stream) propagate trace context and emit
// client spans without further wiring.
//
// The returned RoundTripper is safe to share concurrently.
func ClientInstrumentation(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(base)
}
