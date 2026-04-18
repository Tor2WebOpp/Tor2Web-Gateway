// gateway-proxy is the edge reverse-proxy binary. It composes:
//
//   - OpenTelemetry tracing (disabled by default; P2 wires config)
//   - the metrics Labeler (OPSEC-safe tenant + client-IP hashing)
//   - the admin.Gate (constant-time secret-path carve-out)
//   - the transport.Transport (local unix socket, wireguard, https tunnel,
//     or socks5-over-TLS — selected by cfg.Transport.Kind)
//   - the feature.Registry (populated by proxy.NewServer with the 9 P1
//     features) plus its snapshot client (local fsnotify or remote SSE)
//   - the proxy.Server (reverse proxy + middleware chain)
//
// Structure mirrors cmd/gateway-hub/main.go: main() is a thin shell that
// loads config, builds the signal-cancellable context, and hands off to
// run(ctx, cfg). run() is the test-visible entry point; it wires every
// subsystem, blocks until ctx is cancelled or a fatal serve error fires,
// and tears down every subsystem inside shutdownGrace.
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

	"gateway/internal/admin"
	"gateway/internal/config"
	"gateway/internal/metrics"
	"gateway/internal/proxy"
	"gateway/internal/tracing"
	"gateway/internal/transport"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	// memlimitBytes is the soft memory ceiling communicated to the
	// runtime so that the GC pressure matches the expected deployment.
	memlimitBytes = 1 << 30 // 1 GB

	// shutdownGrace bounds graceful teardown after ctx cancellation.
	shutdownGrace = 15 * time.Second
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	// Tune runtime — mirrors gateway-hub's startup to keep the two
	// binaries behaviourally symmetric.
	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetMemoryLimit(memlimitBytes)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gateway-proxy: load config: %v\n", err)
		os.Exit(1)
	}

	logger := buildLogger(cfg)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		slog.Error("gateway-proxy failed", "err", err)
		os.Exit(1)
	}
	slog.Info("gateway-proxy stopped cleanly")
}

// run is the test-visible entry point. It wires every subsystem, blocks
// until ctx is cancelled or a fatal serve error fires, and then tears
// everything down inside shutdownGrace. Returning nil means a clean
// shutdown; errors are unrecoverable startup failures or fatal serve
// errors.
func run(ctx context.Context, cfg *config.Config) error {
	return runWithListener(ctx, cfg, nil)
}

// runWithListener is run()'s test-friendly sibling: when ln is non-nil
// we serve the HTTP stack on that listener instead of binding :80.
// Tests use this to obtain an ephemeral port without racing with Serve
// and without needing privileged port access.
func runWithListener(ctx context.Context, cfg *config.Config, ln net.Listener) error {
	if cfg == nil {
		return errors.New("gateway-proxy: nil config")
	}

	logger := slog.Default()

	// 1. Tracing. The current config.Config has no dedicated Tracing
	// stanza; until P2 adds one we install a noop provider. The
	// returned shutdown fn is still safe to call, and the propagator is
	// installed so inbound trace context continues to flow through.
	tracingShutdown, err := tracing.Init(ctx, tracing.Config{
		Enabled:     false,
		ServiceName: "gateway-proxy",
	})
	if err != nil {
		return fmt.Errorf("tracing: init: %w", err)
	}

	// 2. Metrics labeler — hashes tenant labels and client IPs to keep
	// exported metrics OPSEC-safe. NewLabeler fails fast on a
	// looser-than-0600 salt file; that surfaces here rather than lazily
	// at first use.
	labeler, err := metrics.NewLabeler(metrics.Config{
		HashTenantLabels: cfg.Metrics.OPSEC.HashTenantLabels,
		SaltFile:         cfg.Metrics.OPSEC.TenantLabelSaltFile,
	})
	if err != nil {
		_ = tracingShutdown(context.Background())
		return fmt.Errorf("metrics labeler: %w", err)
	}

	// 3. Admin gate — constant-time carve-out. admin.New returns a
	// disabled (but still timing-equalised) gate when cfg.Admin.Enabled
	// is false, so this is always a safe call.
	gate := admin.New(admin.Config{
		Enabled: cfg.Admin.Enabled,
		Slug:    cfg.Admin.Slug,
		Token1:  cfg.Admin.Token1,
		Token2:  cfg.Admin.Token2,
	})

	// 3a. P3 admin handler. Skipped entirely when the gate is disabled
	// — the gate then continues to serve the constant-time 404/501 stub
	// regardless of any session/lockout/audit state.
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

		// Proxy is an edge node: no HubAccess, only local features and
		// metrics. The router answers /api/tenants and /api/mirrors with
		// 403 when Hub is nil, so operators querying the wrong endpoint
		// get a clear signal without any gate-disable side channel.
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

	// 4. Transport — same-machine unix socket by default; overridable
	// per cfg.Transport.Kind for remote-hub deployments.
	tr, err := buildTransport(cfg)
	if err != nil {
		_ = tracingShutdown(context.Background())
		return fmt.Errorf("transport: %w", err)
	}
	// tr is nil only in the "local" branch when cfg.Admin.Socket is
	// empty; downstream callers tolerate a nil transport so pre-P1
	// single-tenant deployments still work.

	// 5. Proxy server. The server constructs the feature.Registry,
	// registers every P1 feature (blocklist, ratelimit, geoip,
	// ttlblock, sanitize, headers, abuse, staticcache, negcache), and
	// wires the gate + labeler into the outer middlewares. We feed it
	// a fresh registry so AddReloadObserver hooks land on the same
	// registry the snapshot client will reload.
	srv, err := proxy.NewServer(cfg, tr, nil, gate, labeler)
	if err != nil {
		closeTransport(tr)
		_ = tracingShutdown(context.Background())
		return fmt.Errorf("server: %w", err)
	}

	// 6. Snapshot client. In local mode the hub.Registry is read from
	// cfg.Hub.DataDir and fsnotify drives reloads. In remote mode the
	// transport's admin client subscribes to /v1/config/stream. Legacy
	// single-tenant deployments (Mode==local, empty DataDir) get a
	// noop client via NewSnapshotClient — the synthetic tenant from
	// HostRouterFromConfig covers them.
	snapshotClient := buildSnapshotClient(cfg, tr, srv)
	srv.SetSnapshotClient(snapshotClient)

	// Start the snapshot client BEFORE accepting traffic. A failure here
	// aborts startup: the medium-severity finding about swallowed errors
	// is addressed by surfacing them rather than logging-and-continuing.
	if err := snapshotClient.Start(ctx); err != nil {
		_ = snapshotClient.Close()
		closeTransport(tr)
		_ = tracingShutdown(context.Background())
		return fmt.Errorf("snapshot client: %w", err)
	}

	// 7. TTL blocklist sweeper. The proxy.Server internally calls
	// featttlblock.Start(context.Background()) during registerFeatures,
	// so auto-expiry is already driven by the server. Server.Shutdown
	// calls Stop() symmetrically. Nothing for main to do here.

	// 8. Metrics server — mirrors the existing behaviour: localhost
	// listener that exports Prometheus metrics on /metrics. Bound
	// before the main HTTP(S) listener so scrapes can see startup.
	var metricsServer *http.Server
	if cfg.Metrics.Enabled {
		metricsServer = &http.Server{
			Addr:              cfg.Metrics.Listen,
			Handler:           metricsMux(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      10 * time.Second,
		}
		go func() {
			logger.Info("metrics server listening", "addr", cfg.Metrics.Listen)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("metrics server", "err", err)
			}
		}()
	}

	// 9. Pool poller — keeps the in-memory backend list fresh when an
	// admin unix socket is configured (local mode).
	pollCtx, pollCancel := context.WithCancel(ctx)
	defer pollCancel()
	if cfg.Admin.Socket != "" {
		go srv.PollPool(pollCtx, cfg.Admin.Socket)
	}

	// 10. Main listener. In full-strict mode certmagic manages the cert
	// and serves :443 with a :80 redirect; otherwise we serve plain
	// :80 (legacy mode). Tests supply a pre-bound listener so they can
	// use an ephemeral port and skip certmagic altogether.
	errCh := make(chan error, 1)
	go func() {
		logger.Info("proxy starting",
			"mode", cfg.Mode,
			"node_type", cfg.NodeType,
			"transport", cfg.Transport.Kind,
			"cf_mode", cfg.Cloudflare.Mode,
		)
		var serveErr error
		switch {
		case ln != nil:
			// Adopt the caller's listener verbatim; bypasses certmagic
			// and the :80 bind so tests can run without root.
			serveErr = serveWithListener(srv, ln)
		case cfg.Cloudflare.Mode == "full_strict" && cfg.Domain != "":
			serveErr = srv.ListenAndServeTLS(cfg.Domain, cfg.Email)
		default:
			serveErr = srv.ListenAndServe(":80")
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			errCh <- serveErr
		}
		close(errCh)
	}()

	// Wait for signal or a fatal serve error.
	select {
	case <-ctx.Done():
		logger.Info("gateway-proxy received shutdown signal")
	case err, ok := <-errCh:
		if ok && err != nil {
			shutdownAll(srv, snapshotClient, metricsServer, tr, tracingShutdown, pollCancel, adminAudit, logger)
			return fmt.Errorf("serve: %w", err)
		}
	}

	shutdownAll(srv, snapshotClient, metricsServer, tr, tracingShutdown, pollCancel, adminAudit, logger)
	return nil
}

// shutdownAll tears down every subsystem inside shutdownGrace. Safe to
// call with some subsystems already closed; each step is independent.
// Ordering: stop accepting traffic → close snapshot client → close
// transport → flush tracing. Pool poller is cancelled up front so no
// new admin socket calls race shutdown.
func shutdownAll(
	srv *proxy.Server,
	snapshotClient proxy.SnapshotClient,
	metricsServer *http.Server,
	tr transport.Transport,
	tracingShutdown tracing.ShutdownFunc,
	pollCancel context.CancelFunc,
	adminAudit *admin.Log,
	logger *slog.Logger,
) {
	if pollCancel != nil {
		pollCancel()
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	// 1. Proxy server Shutdown already stops the ratelimit sweeper and
	// closes the snapshot client; calling it first drains in-flight
	// requests before we start tearing down dependencies it relies on.
	if srv != nil {
		if err := srv.Shutdown(shutCtx); err != nil {
			logger.Warn("proxy shutdown", "err", err)
		}
	}

	// 2. Defensive: if the server did not own the snapshot client (e.g.
	// SetSnapshotClient was never called because construction failed
	// earlier), Close it here too. snapshotClient.Close is idempotent.
	if snapshotClient != nil {
		if err := snapshotClient.Close(); err != nil {
			logger.Warn("snapshot close", "err", err)
		}
	}

	// 3. Metrics server — no long-lived streams, so a short grace is
	// plenty.
	if metricsServer != nil {
		mCtx, mCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := metricsServer.Shutdown(mCtx); err != nil {
			logger.Warn("metrics shutdown", "err", err)
		}
		mCancel()
	}

	// 4. Transport — closes idle HTTP connections and any overlay
	// sockets. Idempotent.
	closeTransport(tr)

	// 5. Tracing flush. Non-fatal if it fails.
	if tracingShutdown != nil {
		tCtx, tCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := tracingShutdown(tCtx); err != nil {
			logger.Warn("tracing shutdown", "err", err)
		}
		tCancel()
	}

	// 6. Admin audit log. Sessions and lockout GC goroutines exit on
	// their own when their parent ctx is cancelled; only the audit log
	// owns disk handles that need explicit flushing.
	if adminAudit != nil {
		if err := adminAudit.Close(); err != nil {
			logger.Warn("admin audit close", "err", err)
		}
	}
}

// buildTransport picks the transport implementation that matches
// cfg.Transport.Kind. An empty Kind plus an empty Admin.Socket returns
// (nil, nil) so pre-P1 single-tenant deployments (no torpool socket)
// can still boot.
func buildTransport(cfg *config.Config) (transport.Transport, error) {
	switch cfg.Transport.Kind {
	case "", string(transport.KindLocal):
		if cfg.Admin.Socket == "" {
			// Legacy single-tenant mode without a torpool socket.
			// proxy.NewServer tolerates a nil Transport.
			return nil, nil
		}
		return transport.NewLocal(transport.LocalConfig{
			SocketPath: cfg.Admin.Socket,
		}), nil

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

// serveWithListener serves the proxy.Server's handler on ln using a
// fresh *http.Server. This is only used by tests (runWithListener
// supplies ln); production callers go through Server.ListenAndServe /
// ListenAndServeTLS instead. The wrapping *http.Server has short
// timeouts so tests never deadlock on a hung connection.
func serveWithListener(srv *proxy.Server, ln net.Listener) error {
	tSrv := &http.Server{
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	return tSrv.Serve(ln)
}

// closeTransport is a small nil-safe wrapper around Transport.Close so
// the shutdown path does not need to repeat the guard.
func closeTransport(tr transport.Transport) {
	if tr == nil {
		return
	}
	if err := tr.Close(); err != nil {
		slog.Warn("transport close", "err", err)
	}
}

// buildSnapshotClient picks the snapshot source appropriate for cfg.
// Legacy single-tenant deployments (mode=local, empty DataDir) get a
// noop client via NewSnapshotClient so the registry stays at its
// zero-value snapshot and the synthetic tenant in HostRouterFromConfig
// serves every request.
func buildSnapshotClient(cfg *config.Config, tr transport.Transport, srv *proxy.Server) proxy.SnapshotClient {
	if srv == nil {
		return nil
	}
	reg := srv.Registry()

	switch {
	case cfg.Mode == config.ModeLocal && cfg.Hub.DataDir != "":
		return proxy.NewLocalClient(cfg, reg)
	case cfg.Mode == config.ModeRemote:
		return proxy.NewRemoteClient(cfg, tr, reg)
	default:
		slog.Info("legacy single-tenant mode: no snapshot client",
			"mode", cfg.Mode,
			"hub_data_dir", cfg.Hub.DataDir,
		)
		return proxy.NewSnapshotClient(cfg, tr, reg)
	}
}

// metricsMux builds the /metrics-only mux used by the dedicated metrics
// listener. Kept as a helper so tests can swap it out.
func metricsMux() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", proxy.MetricsHandler())
	return mux
}

// buildLogger constructs an slog.Logger from the Logging config. Mirrors
// the helper used by gateway-hub so behaviour is consistent across
// binaries.
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
