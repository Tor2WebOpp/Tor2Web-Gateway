package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"gateway/internal/config"
	"gateway/internal/proxy"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	memlimitBytes = 1 << 30 // 1 GB
	shutdownGrace = 15 * time.Second
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	// Tune runtime.
	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetMemoryLimit(memlimitBytes)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}

	// Set up structured logging.
	logger := buildLogger(cfg)
	slog.SetDefault(logger)

	// Optionally start a dedicated metrics server (localhost only).
	if cfg.Metrics.Enabled {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", proxy.MetricsHandler())
			srv := &http.Server{
				Addr:         cfg.Metrics.Listen,
				Handler:      mux,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
			}
			slog.Info("metrics server listening", "addr", cfg.Metrics.Listen)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("metrics server", "err", err)
			}
		}()
	}

	// Build the reverse-proxy server.
	srv, err := proxy.NewServer(cfg)
	if err != nil {
		slog.Error("build server", "err", err)
		os.Exit(1)
	}

	// Start pool poller if an admin socket is configured.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if cfg.Admin.Socket != "" {
		go srv.PollPool(ctx, cfg.Admin.Socket)
	}

	// Start serving in a goroutine so we can wait for signals below.
	errCh := make(chan error, 1)
	go func() {
		slog.Info("proxy starting", "mode", cfg.Cloudflare.Mode)
		var serveErr error
		if cfg.Cloudflare.Mode == "full_strict" {
			serveErr = srv.ListenAndServeTLS(cfg.Domain, cfg.Email)
		} else {
			serveErr = srv.ListenAndServe(":80")
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			errCh <- serveErr
		}
	}()

	// Wait for SIGINT / SIGTERM or a fatal server error.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		slog.Info("received signal, shutting down", "signal", sig)
	case err := <-errCh:
		slog.Error("server error", "err", err)
	}

	cancel() // stop pool poller

	shutCtx, shutCancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer shutCancel()

	if err := srv.Shutdown(shutCtx); err != nil {
		slog.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
	slog.Info("server stopped cleanly")
}

// buildLogger constructs an slog.Logger according to the logging config.
func buildLogger(cfg *config.Config) *slog.Logger {
	var w io.Writer = os.Stdout

	if cfg.Logging.Output != "" && cfg.Logging.Output != "stdout" {
		w = &lumberjack.Logger{
			Filename:   cfg.Logging.Output,
			MaxSize:    cfg.Logging.MaxSizeMB,
			MaxBackups: cfg.Logging.MaxBackups,
		}
	}

	var level slog.Level
	switch cfg.Logging.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if cfg.Logging.Format == "text" {
		handler = slog.NewTextHandler(w, opts)
	} else {
		handler = slog.NewJSONHandler(w, opts)
	}

	return slog.New(handler)
}
