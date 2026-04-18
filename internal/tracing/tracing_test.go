package tracing

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
)

// TestInit_NoopDefault verifies that the zero-valued Config installs
// a noop provider and returns a shutdown that does not fail.
func TestInit_NoopDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	shutdown, err := Init(ctx, Config{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer shutdown(ctx)

	// With no enabled exporter we must have a noop provider. Starting
	// a span on a noop provider returns a span whose context is not
	// recording.
	tracer := otel.Tracer("test")
	_, span := tracer.Start(ctx, "noop")
	if span.IsRecording() {
		t.Fatalf("expected noop span, got recording span")
	}
	span.End()

	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

// TestInit_NoneExporterDisabled covers the explicit "none" exporter
// path (Enabled=true but Exporter=none) — it must still install a
// noop provider and not fail.
func TestInit_NoneExporterDisabled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	shutdown, err := Init(ctx, Config{Enabled: true, Exporter: ExporterNone, ServiceName: "t"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(ctx) })

	tracer := otel.Tracer("test")
	_, span := tracer.Start(ctx, "none")
	if span.IsRecording() {
		t.Fatalf("expected noop span, got recording span")
	}
	span.End()
}

// TestInit_StdoutExporter_Produces_Output verifies spans flow through
// the configured stdout exporter.
func TestInit_StdoutExporter_Produces_Output(t *testing.T) {
	var buf bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	shutdown, err := Init(ctx, Config{
		Enabled:      true,
		ServiceName:  "gateway-test",
		Exporter:     ExporterStdout,
		SampleRate:   1,
		StdoutWriter: &buf,
	})
	if err != nil {
		t.Fatalf("Init stdout: %v", err)
	}

	tracer := otel.Tracer("test")
	_, span := tracer.Start(ctx, "stdout-span")
	span.End()

	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	out := buf.String()
	if out == "" {
		t.Fatalf("expected stdout exporter to write span data, got empty output")
	}
	if !strings.Contains(out, "stdout-span") {
		t.Fatalf("expected span name in exporter output, got: %s", out)
	}
	if !strings.Contains(out, "gateway-test") {
		t.Fatalf("expected service name in exporter output, got: %s", out)
	}
}

// TestInit_Idempotent_SecondCallReplacesPipeline verifies that calling
// Init a second time shuts down the first pipeline cleanly and installs
// a new one.
func TestInit_Idempotent_SecondCallReplacesPipeline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var firstBuf bytes.Buffer
	_, err := Init(ctx, Config{
		Enabled:      true,
		ServiceName:  "first",
		Exporter:     ExporterStdout,
		SampleRate:   1,
		StdoutWriter: &firstBuf,
	})
	if err != nil {
		t.Fatalf("first Init: %v", err)
	}

	// Emit a span on the first pipeline so it has something to flush.
	tr1 := otel.Tracer("test")
	_, s1 := tr1.Start(ctx, "first-span")
	s1.End()

	// Second init should shut down the first pipeline (flushing
	// first-span) and replace it. We only care that Init succeeds.
	var secondBuf bytes.Buffer
	shutdown, err := Init(ctx, Config{
		Enabled:      true,
		ServiceName:  "second",
		Exporter:     ExporterStdout,
		SampleRate:   1,
		StdoutWriter: &secondBuf,
	})
	if err != nil {
		t.Fatalf("second Init: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(ctx) })

	// Emit a span via the newly installed global provider.
	tr2 := otel.Tracer("test")
	_, s2 := tr2.Start(ctx, "second-span")
	s2.End()

	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// The first-span flushed into firstBuf when the second Init tore
	// down the first pipeline.
	if !strings.Contains(firstBuf.String(), "first-span") {
		t.Fatalf("first pipeline should have flushed first-span, got: %s", firstBuf.String())
	}
	// The second pipeline owns second-span.
	if !strings.Contains(secondBuf.String(), "second-span") {
		t.Fatalf("second pipeline should contain second-span, got: %s", secondBuf.String())
	}
}

// TestInit_OTLPRequiresEndpoint verifies validation of the OTLP
// exporter configuration.
func TestInit_OTLPRequiresEndpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := Init(ctx, Config{
		Enabled:    true,
		Exporter:   ExporterOTLP,
		SampleRate: 1,
	})
	if err == nil {
		t.Fatalf("expected error for OTLP without Endpoint, got nil")
	}

	// Reset the state so later tests aren't influenced by a partial
	// install. Calling Init with a noop Config does this.
	shutdown, err := Init(ctx, Config{})
	if err != nil {
		t.Fatalf("reset Init: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(ctx) })
}

// TestSamplerChoice verifies the ratio-to-sampler mapping.
func TestSamplerChoice(t *testing.T) {
	cases := []struct {
		ratio float64
		want  string
	}{
		{-1, "AlwaysOffSampler"},
		{0, "AlwaysOffSampler"},
		{0.5, "ParentBased"},
		{1, "AlwaysOnSampler"},
		{1.5, "AlwaysOnSampler"},
	}
	for _, tc := range cases {
		got := sampler(tc.ratio).Description()
		if !strings.Contains(got, tc.want) {
			t.Errorf("sampler(%v).Description()=%q, want substring %q", tc.ratio, got, tc.want)
		}
	}
}

// TestTracerHelpers verifies that Tracer and SpanFromContext simply
// delegate to the global provider.
func TestTracerHelpers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	shutdown, err := Init(ctx, Config{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(ctx) })

	tr := Tracer("unit")
	if tr == nil {
		t.Fatalf("Tracer returned nil")
	}
	spanCtx, span := tr.Start(ctx, "s")
	defer span.End()
	if SpanFromContext(spanCtx).SpanContext().SpanID() != span.SpanContext().SpanID() {
		t.Fatalf("SpanFromContext returned a different span than Start produced")
	}
}
