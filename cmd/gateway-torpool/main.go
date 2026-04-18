package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"gateway/internal/config"
	"gateway/internal/torpool"
	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(buildLogWriter(cfg.Logging), &slog.HandlerOptions{Level: parseLogLevel(cfg.Logging.Level)}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	mgr := torpool.NewManager(cfg)
	if err := mgr.Start(ctx); err != nil {
		slog.Error("failed to start manager", "error", err)
		os.Exit(1)
	}

	hc := torpool.NewHealthCheckerWithGrace(mgr, cfg.Pool.HealthCheckInterval, cfg.Pool.QuarantineGrace)
	// Wire the health checker's per-port cleanup hook so scale-down does
	// not leave stale failure counters / probe transports bound to a port
	// that a future scale-up may rebind (bug 7.3).
	mgr.SetPortForgetter(hc)
	go hc.Run(ctx)

	scaler := torpool.NewScaler(mgr, cfg)
	go scaler.Run(ctx)

	api := torpool.NewAPI(mgr, cfg.Admin.Socket)
	go func() {
		if err := api.Serve(); err != nil {
			slog.Error("API serve error", "error", err)
		}
	}()

	slog.Info("gateway-torpool started", "min", cfg.Tor.MinInstances, "max", cfg.Tor.MaxInstances)
	<-ctx.Done()
	slog.Info("gateway-torpool shutting down")

	// Outage-1.5 fix: drain in-flight HealthChecker replace goroutines
	// BEFORE tearing the manager down. Without this, a replace goroutine
	// the HC already launched (Tor spawn can take up to 60-130s) will try
	// to call mgr.ReplaceInstance on a shut manager and spray errors into
	// a logger whose underlying writer may already be closed. Cap the
	// wait at 30s so a stuck goroutine cannot block systemd shutdown.
	shutdownHealthChecker(hc, 30*time.Second)
	mgr.Shutdown()
	api.Close()
}

// shutdownHealthChecker blocks on hc.Wait() with an upper bound. Exposed as
// a named func so cmd-level tests can assert ordering against mgr.Shutdown.
func shutdownHealthChecker(hc *torpool.HealthChecker, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		hc.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("gateway-torpool: health checker did not drain within timeout; proceeding with shutdown", "timeout", timeout)
	}
}

// buildLogWriter returns the io.Writer backing the slog handler. "stdout"
// and "stderr" (and an empty string, which config.fillDefaults rewrites to
// "stdout") bypass lumberjack — otherwise lumberjack creates a regular file
// named literally "stdout" in CWD and torpool logs are silently discarded.
// This is the outage-1.1 fix; mirrors cmd/gateway-proxy/buildLogger.
func buildLogWriter(cfg config.LoggingConf) io.Writer {
	switch cfg.Output {
	case "stdout", "":
		return os.Stdout
	case "stderr":
		return os.Stderr
	default:
		return &lumberjack.Logger{
			Filename:   cfg.Output,
			MaxSize:    cfg.MaxSizeMB,
			MaxBackups: cfg.MaxBackups,
		}
	}
}

// parseLogLevel maps the config's level string to an slog.Level. An unknown
// string falls back to LevelWarn to match the pre-fix behaviour.
func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "error":
		return slog.LevelError
	default:
		return slog.LevelWarn
	}
}
