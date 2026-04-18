package tracing

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Exporter names accepted in Config.Exporter.
const (
	ExporterOTLP   = "otlp"
	ExporterStdout = "stdout"
	ExporterNone   = "none"
)

// Config controls Init. The zero value installs a noop provider.
type Config struct {
	// Enabled switches the whole pipeline on or off. When false, Init
	// still runs but installs a noop provider. The returned shutdown
	// function is safe to call.
	Enabled bool

	// ServiceName is published as the service.name resource attribute.
	// Recommended: "gateway-proxy", "gateway-hub", "gateway-door".
	// Empty string defaults to "gateway".
	ServiceName string

	// Exporter selects the span exporter: "otlp", "stdout", or "none".
	// Empty string is treated as "none".
	Exporter string

	// Endpoint is the destination for the OTLP exporter. Ignored for
	// other exporter kinds. Example: "collector.internal:4318".
	Endpoint string

	// SampleRate is a parent-based ratio sampler between 0.0 and 1.0.
	// Zero or negative disables sampling (NeverSample). Values >=1 are
	// clamped to AlwaysSample. Only used when the exporter is not
	// "none" and Enabled is true.
	SampleRate float64

	// StdoutWriter overrides the writer used by the stdout exporter.
	// Primarily used by tests. When nil, os.Stderr is used so that
	// spans do not pollute structured stdout logs.
	StdoutWriter io.Writer

	// Insecure, when true, configures the OTLP HTTP exporter to use
	// plain HTTP instead of HTTPS. For use on WireGuard overlays or
	// loopback collectors; production off-box endpoints should use
	// TLS and leave this false.
	Insecure bool
}

// ShutdownFunc is returned by Init and must be called on process
// shutdown to flush buffered spans. Calling it twice is safe; the
// second call is a no-op.
type ShutdownFunc func(context.Context) error

// state holds the currently installed SDK provider (if any) so that a
// second call to Init can cleanly replace the previous pipeline
// without leaking span processors. Tests rely on this path.
var state struct {
	mu        sync.Mutex
	installed bool
	shutdown  ShutdownFunc
}

// Init installs a global TracerProvider according to cfg and returns
// a ShutdownFunc that flushes buffered spans. Calling Init more than
// once is supported: the previous provider is shut down before the
// new one is installed. A background context passed to the shutdown
// returned by a previous call performs a no-op, since ownership has
// transferred to the new pipeline.
func Init(ctx context.Context, cfg Config) (ShutdownFunc, error) {
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.installed && state.shutdown != nil {
		// Previous pipeline must flush before we tear it down.
		_ = state.shutdown(ctx)
		state.installed = false
		state.shutdown = nil
	}

	// Install propagator in every path; context propagation is
	// independent of whether we export anything.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if !cfg.Enabled || cfg.Exporter == "" || cfg.Exporter == ExporterNone {
		provider := noop.NewTracerProvider()
		otel.SetTracerProvider(provider)
		shutdown := func(context.Context) error { return nil }
		state.installed = true
		state.shutdown = shutdown
		return shutdown, nil
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "gateway"
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: build resource: %w", err)
	}

	exporter, err := newExporter(ctx, cfg)
	if err != nil {
		return nil, err
	}

	sampler := sampler(cfg.SampleRate)

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)
	otel.SetTracerProvider(tp)

	var once sync.Once
	shutdown := ShutdownFunc(func(sctx context.Context) error {
		var err error
		once.Do(func() {
			flushErr := tp.ForceFlush(sctx)
			stopErr := tp.Shutdown(sctx)
			err = errors.Join(flushErr, stopErr)
		})
		return err
	})
	state.installed = true
	state.shutdown = shutdown
	return shutdown, nil
}

// newExporter constructs the configured span exporter.
func newExporter(ctx context.Context, cfg Config) (sdktrace.SpanExporter, error) {
	switch cfg.Exporter {
	case ExporterStdout:
		w := cfg.StdoutWriter
		if w == nil {
			w = os.Stderr
		}
		exp, err := stdouttrace.New(
			stdouttrace.WithWriter(w),
			stdouttrace.WithoutTimestamps(),
		)
		if err != nil {
			return nil, fmt.Errorf("tracing: stdout exporter: %w", err)
		}
		return exp, nil
	case ExporterOTLP:
		if cfg.Endpoint == "" {
			return nil, errors.New("tracing: otlp exporter requires Endpoint")
		}
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(cfg.Endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		client := otlptracehttp.NewClient(opts...)
		exp, err := otlptrace.New(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("tracing: otlp exporter: %w", err)
		}
		return exp, nil
	default:
		return nil, fmt.Errorf("tracing: unknown exporter %q", cfg.Exporter)
	}
}

// sampler picks a concrete SDK sampler based on the requested ratio.
// Ratios outside [0,1] saturate to NeverSample / AlwaysSample.
func sampler(ratio float64) sdktrace.Sampler {
	switch {
	case ratio <= 0:
		return sdktrace.NeverSample()
	case ratio >= 1:
		return sdktrace.AlwaysSample()
	default:
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
	}
}

// Tracer returns a named tracer from the globally installed provider.
// Using this helper keeps callers decoupled from the otel package.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

// SpanFromContext mirrors trace.SpanFromContext so that callers don't
// have to import go.opentelemetry.io/otel/trace directly when only
// annotating the current span.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}
