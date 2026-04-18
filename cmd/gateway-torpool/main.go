package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

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

	// Setup structured JSON logging with rotation
	logWriter := &lumberjack.Logger{
		Filename:   cfg.Logging.Output,
		MaxSize:    cfg.Logging.MaxSizeMB,
		MaxBackups: cfg.Logging.MaxBackups,
	}
	var level slog.Level
	switch cfg.Logging.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelWarn
	}
	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	mgr := torpool.NewManager(cfg)
	if err := mgr.Start(ctx); err != nil {
		slog.Error("failed to start manager", "error", err)
		os.Exit(1)
	}
	defer mgr.Shutdown()

	hc := torpool.NewHealthCheckerWithGrace(mgr, cfg.Pool.HealthCheckInterval, cfg.Pool.QuarantineGrace)
	go hc.Run(ctx)

	scaler := torpool.NewScaler(mgr, cfg)
	go scaler.Run(ctx)

	api := torpool.NewAPI(mgr, cfg.Admin.Socket)
	go func() {
		if err := api.Serve(); err != nil {
			slog.Error("API serve error", "error", err)
		}
	}()
	defer api.Close()

	slog.Info("gateway-torpool started", "min", cfg.Tor.MinInstances, "max", cfg.Tor.MaxInstances)
	<-ctx.Done()
	slog.Info("gateway-torpool shutting down")
}
