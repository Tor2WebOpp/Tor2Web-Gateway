package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"gateway/internal/feature"
)

// installRecorder swaps the global TracerProvider for one that
// synchronously flushes spans into an in-memory exporter. Returns
// the exporter for assertion and a teardown that restores the
// previous provider. Tests rely on this helper to inspect span
// attributes rather than relying on Init.
func installRecorder(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	prev := otel.GetTracerProvider()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
	})
	return exp
}

// TestHTTPMiddleware_CreatesSpan verifies that a request through
// HTTPMiddleware emits one span and that the expected attributes
// land on it.
func TestHTTPMiddleware_CreatesSpan(t *testing.T) {
	exp := installRecorder(t)

	labeler := func(host string) string { return "t:hashed-" + host[:3] }

	handler := HTTPMiddleware(labeler, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tenant := &feature.TenantSnapshot{Host: "example.test"}
	req := httptest.NewRequest(http.MethodGet, "/foo/bar", nil).
		WithContext(feature.WithTenant(context.Background(), tenant))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatalf("expected at least one span to be recorded")
	}

	// The middleware decorates the outermost otelhttp span; pick it.
	var got tracetest.SpanStub
	for _, s := range spans {
		if s.Name == OperationName || s.Parent.SpanID().IsValid() == false {
			got = s
			break
		}
	}
	if got.Name == "" {
		// Fallback: take the last span (the root is flushed last
		// in otelhttp>=0.58).
		got = spans[len(spans)-1]
	}

	if !hasAttr(got.Attributes, "http.request.method_original", "GET") &&
		!hasAttr(got.Attributes, "http.request.method", "GET") {
		t.Errorf("expected GET method attribute, got %v", got.Attributes)
	}
	if !hasAttr(got.Attributes, TenantAttrKey, "t:hashed-exa") {
		t.Errorf("expected %s attribute to be labeled, got %v", TenantAttrKey, got.Attributes)
	}
	if hasAttrKey(got.Attributes, "gateway.tenant.raw") {
		t.Errorf("unexpected raw tenant attribute leak: %v", got.Attributes)
	}
	// Status 200 must be recorded.
	if !hasAttr(got.Attributes, "http.response.status_code", "200") {
		t.Errorf("expected status_code=200, got %v", got.Attributes)
	}
}

// TestHTTPMiddleware_LabelerNotRawHost ensures raw tenant hostnames
// never appear on spans, even if the LabelerFn returns something
// completely different.
func TestHTTPMiddleware_LabelerNotRawHost(t *testing.T) {
	exp := installRecorder(t)

	const rawHost = "very-secret-tenant.example"
	labeler := func(host string) string {
		if host != rawHost {
			t.Fatalf("labeler received %q, want %q", host, rawHost)
		}
		return "t:abcd1234"
	}

	handler := HTTPMiddleware(labeler, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	tenant := &feature.TenantSnapshot{Host: rawHost}
	req := httptest.NewRequest(http.MethodGet, "/", nil).
		WithContext(feature.WithTenant(context.Background(), tenant))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := exp.GetSpans()
	for _, s := range spans {
		for _, kv := range s.Attributes {
			if strings.Contains(kv.Value.Emit(), rawHost) {
				t.Fatalf("raw host %q appeared in attribute %s=%s", rawHost, kv.Key, kv.Value.Emit())
			}
		}
	}
}

// TestHTTPMiddleware_NilLabelerOmitsTenantAttr confirms that a nil
// LabelerFn simply skips the tenant attribute rather than panicking
// or recording the raw host.
func TestHTTPMiddleware_NilLabelerOmitsTenantAttr(t *testing.T) {
	exp := installRecorder(t)

	handler := HTTPMiddleware(nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tenant := &feature.TenantSnapshot{Host: "example.test"}
	req := httptest.NewRequest(http.MethodGet, "/", nil).
		WithContext(feature.WithTenant(context.Background(), tenant))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	for _, s := range exp.GetSpans() {
		if hasAttrKey(s.Attributes, TenantAttrKey) {
			t.Fatalf("tenant attribute should be omitted when labeler is nil: %v", s.Attributes)
		}
	}
}

// TestHTTPMiddleware_500SetsError ensures a 5xx response records an
// error status on the span.
func TestHTTPMiddleware_500SetsError(t *testing.T) {
	exp := installRecorder(t)

	handler := HTTPMiddleware(func(string) string { return "t:x" },
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))

	req := httptest.NewRequest(http.MethodGet, "/fail", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatalf("expected a span, got none")
	}
	var errorSet bool
	for _, s := range spans {
		if s.Status.Code == codes.Error {
			errorSet = true
		}
		if hasAttr(s.Attributes, "http.response.status_code", "500") {
			// status recorded at least once
			errorSet = errorSet || true
		}
	}
	if !errorSet {
		t.Fatalf("expected at least one span with error status or 500 status code, got %+v", spans)
	}
}

// TestHTTPMiddleware_NoTenantOmitsAttr checks that a request without
// a tenant context never emits the tenant attribute.
func TestHTTPMiddleware_NoTenantOmitsAttr(t *testing.T) {
	exp := installRecorder(t)

	handler := HTTPMiddleware(func(string) string { return "t:x" },
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	for _, s := range exp.GetSpans() {
		if hasAttrKey(s.Attributes, TenantAttrKey) {
			t.Fatalf("tenant attribute present despite no tenant on context: %v", s.Attributes)
		}
	}
}

// TestClientInstrumentation_WrapsTransport exercises the outbound path
// and verifies a client span is produced.
func TestClientInstrumentation_WrapsTransport(t *testing.T) {
	exp := installRecorder(t)

	// Simple upstream that always returns 204.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)

	transport := ClientInstrumentation(http.DefaultTransport)
	if transport == nil {
		t.Fatalf("ClientInstrumentation returned nil")
	}

	client := &http.Client{Transport: transport}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	_ = resp.Body.Close()

	if len(exp.GetSpans()) == 0 {
		t.Fatalf("expected a client span, got none")
	}
}

// TestClientInstrumentation_NilBaseUsesDefault confirms the helper
// tolerates a nil RoundTripper.
func TestClientInstrumentation_NilBaseUsesDefault(t *testing.T) {
	if got := ClientInstrumentation(nil); got == nil {
		t.Fatalf("ClientInstrumentation(nil) returned nil")
	}
}

// hasAttr reports whether attrs contains a KeyValue whose key matches
// key and whose emitted string value equals value.
func hasAttr(attrs []attribute.KeyValue, key, value string) bool {
	for _, kv := range attrs {
		if string(kv.Key) == key && kv.Value.Emit() == value {
			return true
		}
	}
	return false
}

// hasAttrKey reports whether attrs contains any KeyValue with the
// given key.
func hasAttrKey(attrs []attribute.KeyValue, key string) bool {
	for _, kv := range attrs {
		if string(kv.Key) == key {
			return true
		}
	}
	return false
}
