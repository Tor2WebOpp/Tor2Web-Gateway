// gateway-door is the door-node binary: a stateless redirector that
// serves a benign cover page on "/" and rewrites "/<slug>..." into a
// 302 toward a currently-healthy mirror domain. It does not run the
// Tor pool, does not resolve tenant state, and never names its
// redirect target at INFO log level.
//
// The binary is deliberately tiny: main() parses flags + signal
// plumbing, run() wires every subsystem, and runWithListener lets
// tests supply a pre-bound listener so no privileged ports or ACME
// plumbing are needed in the unit tests. The shape mirrors
// cmd/gateway-proxy/main.go so operators see the same lifecycle on
// every binary.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	"gateway/internal/admin"
	"gateway/internal/config"
	"gateway/internal/door"
	"gateway/internal/metrics"
	"gateway/internal/transport"
)

const (
	memlimitBytes = 1 << 30 // 1 GB
	shutdownGrace = 15 * time.Second
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetMemoryLimit(memlimitBytes)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gateway-door: load config: %v\n", err)
		os.Exit(1)
	}

	logger := buildLogger(cfg)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		slog.Error("gateway-door failed", "err", err)
		os.Exit(1)
	}
	slog.Info("gateway-door stopped cleanly")
}

// run is the test-visible entry point. It wires the door subsystems,
// blocks until ctx is cancelled or the HTTP server returns a fatal
// error, and tears everything down inside shutdownGrace on exit.
func run(ctx context.Context, cfg *config.Config) error {
	return RunWithListener(ctx, cfg, nil)
}

// RunWithListener is run()'s test-friendly sibling. When ln is non-nil
// the HTTP server is bound to the caller's listener instead of :443 or
// :80; this lets tests allocate ephemeral ports without going through
// certmagic. Exported (capital R) so the test binary can drive it.
func RunWithListener(ctx context.Context, cfg *config.Config, ln net.Listener) error {
	if cfg == nil {
		return errors.New("gateway-door: nil config")
	}
	if cfg.NodeType != config.NodeTypeDoor {
		return fmt.Errorf("gateway-door: node_type must be %q, got %q",
			config.NodeTypeDoor, cfg.NodeType)
	}
	if err := validateDoorBootstrap(cfg); err != nil {
		return err
	}

	logger := slog.Default()

	// 1. Metrics labeler — hashes client IPs for OPSEC-safe metrics.
	// Non-fatal if a salt file cannot be loaded; doors run with a
	// per-process salt by default.
	labeler, err := metrics.NewLabeler(metrics.Config{
		HashTenantLabels: cfg.Metrics.OPSEC.HashTenantLabels,
		SaltFile:         cfg.Metrics.OPSEC.TenantLabelSaltFile,
	})
	if err != nil {
		return fmt.Errorf("metrics labeler: %w", err)
	}

	// 2. Admin gate — same constant-time carve-out the proxy uses.
	gate := admin.New(admin.Config{
		Enabled: cfg.Admin.Enabled,
		Slug:    cfg.Admin.Slug,
		Token1:  cfg.Admin.Token1,
		Token2:  cfg.Admin.Token2,
	})

	// 2a. P3 admin handler. Door is an edge node: no HubAccess, only
	// the local audit/labeler/session chain. The router answers
	// /api/tenants and /api/mirrors with 403 because Hub is nil, which
	// is the desired behaviour from a door — operators editing tenants
	// must talk to the hub directly.
	var (
		adminSessions *admin.SessionStore
		adminLockout  *admin.Lockout
		adminAudit    *admin.Log
	)
	if cfg.Admin.Enabled {
		adminSessions = admin.NewSessionStore(cfg.Admin.SessionIdleTTL, cfg.Admin.SessionAbsoluteTTL)
		adminLockout = admin.NewLockout(admin.LockoutConfig{
			SoftThreshold: cfg.Admin.Lockout.SoftThreshold,
			SoftWindow:    cfg.Admin.Lockout.SoftWindow,
			SoftBackoff:   cfg.Admin.Lockout.SoftBackoff,
			HardThreshold: cfg.Admin.Lockout.HardThreshold,
			HardWindow:    cfg.Admin.Lockout.HardWindow,
			HardBan:       cfg.Admin.Lockout.HardBan,
		})
		al, err := admin.OpenLog(cfg.Admin.AuditDataDir)
		if err != nil {
			return fmt.Errorf("admin audit log: %w", err)
		}
		adminAudit = al

		apiRouter := admin.NewRouter(admin.Routes{
			NodeID:   cfg.NodeID,
			NodeType: cfg.NodeType,
			Hub:      nil,
			Features: nil,
			Metrics:  nil,
			Audit:    admin.AuditFromLog(adminAudit),
			Labeler:  labeler,
		})
		handler, err := admin.NewHandler(admin.HandlerConfig{
			NodeID:     cfg.NodeID,
			NodeType:   cfg.NodeType,
			PathPrefix: gate.Prefix(),
			Sessions:   adminSessions,
			Lockout:    adminLockout,
			Audit:      adminAudit,
			Labeler:    labeler,
			UI:         admin.UIFS,
			APIRouter:  apiRouter,
		})
		if err != nil {
			_ = adminAudit.Close()
			return fmt.Errorf("admin handler: %w", err)
		}
		gate.SetHandler(handler)
		go adminSessions.StartGC(ctx)
		go adminLockout.StartGC(ctx)
	}

	// 3. Transport — doors dial the hub for the mirror-health SSE
	// stream. Any of the P1 transport kinds is acceptable.
	tr, err := buildTransport(cfg)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}

	// 4. Mirror selector — fed by the snapshot client.
	sel := door.NewSelector()

	// 5. HTTP server.
	srv, err := door.NewServer(cfg, sel, gate, labeler)
	if err != nil {
		closeTransport(tr)
		return fmt.Errorf("server: %w", err)
	}

	// 6. Snapshot client. Only spawned when a HubURL is configured and
	// a listener is not supplied; tests that run offline set ln and
	// skip the hub subscription.
	var snapClient *door.SnapshotClient
	if ln == nil && cfg.HubURL != "" {
		snapClient = door.NewSnapshotClient(cfg, tr, sel)
		if err := snapClient.Start(ctx); err != nil {
			closeTransport(tr)
			return fmt.Errorf("snapshot client: %w", err)
		}
	}

	// 7. Main listener. In certmagic mode we bind :443 + :80 through
	// the door's ListenAndServeTLS. Tests supply ln and bypass TLS
	// entirely.
	errCh := make(chan error, 1)
	go func() {
		logger.Info("gateway-door starting",
			"mode", cfg.Mode,
			"node_type", cfg.NodeType,
			"transport", cfg.Transport.Kind,
		)
		var serveErr error
		switch {
		case ln != nil:
			serveErr = serveWithListener(srv, ln)
		case cfg.Domain != "":
			serveErr = srv.ListenAndServeTLS(cfg.Domain, cfg.Email)
		default:
			serveErr = srv.ListenAndServe(":80")
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			errCh <- serveErr
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		logger.Info("gateway-door received shutdown signal")
	case err, ok := <-errCh:
		if ok && err != nil {
			shutdownAll(srv, snapClient, tr, adminAudit, logger)
			return fmt.Errorf("serve: %w", err)
		}
	}

	shutdownAll(srv, snapClient, tr, adminAudit, logger)
	return nil
}

// validateDoorBootstrap enforces the "no half-configured door" rule:
// the spec mandates HubURL + Transport + MTLS + Admin + at least one
// slug. The top-level config validator accepts a zero-value door
// because other node types don't need it; we lift that check here so
// a mis-configured door fails fast on boot rather than serving an
// empty redirect table.
func validateDoorBootstrap(cfg *config.Config) error {
	if cfg.Mode == config.ModeRemote {
		if cfg.HubURL == "" {
			return errors.New("gateway-door: hub_url is required")
		}
		if cfg.Transport.Kind == "" {
			return errors.New("gateway-door: transport.kind is required")
		}
		if cfg.MTLS.ClientCertFile == "" || cfg.MTLS.ClientKeyFile == "" {
			return errors.New("gateway-door: mtls.client_cert_file and mtls.client_key_file are required")
		}
	}
	if !cfg.Admin.Enabled {
		return errors.New("gateway-door: admin.enabled must be true")
	}
	if err := config.ValidateDoor(&cfg.Door); err != nil {
		return fmt.Errorf("gateway-door: door config: %w", err)
	}
	return nil
}

// shutdownAll tears down every subsystem inside shutdownGrace. Each
// step is idempotent so partial wiring paths are safe.
func shutdownAll(srv *door.Server, snap *door.SnapshotClient, tr transport.Transport, adminAudit *admin.Log, logger *slog.Logger) {
	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	if srv != nil {
		if err := srv.Shutdown(shutCtx); err != nil {
			logger.Warn("door shutdown", "err", err)
		}
	}
	if snap != nil {
		if err := snap.Close(); err != nil {
			logger.Warn("snapshot close", "err", err)
		}
	}
	closeTransport(tr)

	// Admin audit log owns disk handles; sessions/lockout GC goroutines
	// exit on their own when ctx is cancelled.
	if adminAudit != nil {
		if err := adminAudit.Close(); err != nil {
			logger.Warn("admin audit close", "err", err)
		}
	}
}

// buildTransport maps cfg.Transport.Kind to a Transport. Local mode
// without an admin socket returns (nil, nil) so offline tests boot.
func buildTransport(cfg *config.Config) (transport.Transport, error) {
	switch cfg.Transport.Kind {
	case "", string(transport.KindLocal):
		if cfg.Admin.Socket == "" {
			return nil, nil
		}
		return transport.NewLocal(transport.LocalConfig{SocketPath: cfg.Admin.Socket}), nil
	case config.TransportWireguard:
		wgCfg, err := transport.ParseWireguardConfigFromTop(cfg)
		if err != nil {
			return nil, err
		}
		return transport.NewWireguard(wgCfg)
	case config.TransportHTTPSTunnel:
		return transport.NewHTTPSTunnel(transport.HTTPSTunnelConfig{
			HubURL:         cfg.Transport.HTTPSTunnel.HubURL,
			CACertFile:     cfg.Transport.HTTPSTunnel.CACertFile,
			ClientCertFile: cfg.MTLS.ClientCertFile,
			ClientKeyFile:  cfg.MTLS.ClientKeyFile,
		})
	case config.TransportSOCKS5TLS:
		return transport.NewSOCKS5TLS(transport.SOCKS5TLSConfig{
			HubAddr:        cfg.Transport.SOCKS5TLS.HubAddr,
			AdminAddr:      cfg.Transport.SOCKS5TLS.AdminAddr,
			CACertFile:     cfg.Transport.SOCKS5TLS.CACertFile,
			ClientCertFile: cfg.MTLS.ClientCertFile,
			ClientKeyFile:  cfg.MTLS.ClientKeyFile,
		})
	default:
		return nil, fmt.Errorf("unknown transport kind %q", cfg.Transport.Kind)
	}
}

// serveWithListener wraps the door.Server's http.Handler on ln using a
// fresh *http.Server. Only tests exercise this path.
func serveWithListener(srv *door.Server, ln net.Listener) error {
	tSrv := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	return tSrv.Serve(ln)
}

func closeTransport(tr transport.Transport) {
	if tr == nil {
		return
	}
	if err := tr.Close(); err != nil {
		slog.Warn("transport close", "err", err)
	}
}

// buildLogger mirrors proxy/hub so all three binaries log identically.
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
	if cfg.Logging.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}
