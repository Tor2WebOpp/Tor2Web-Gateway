// gateway-hub is the central controller binary for the P1 "remote" deployment
// mode. It wires together:
//
//   - the torpool Manager (same process spawning N Tor SOCKS instances),
//   - the hub tenant Registry (file-backed, fsnotify-hot-reloaded),
//   - the mTLS CA used to sign edge client certs,
//   - the NodeStore tracking registered edges,
//   - the admin HTTP API (mTLS-authenticated, SSE config-stream).
//
// The binary is additive: the existing gateway-torpool unix-socket API is
// still served so legacy tooling keeps working. Edge nodes talk to the hub
// over the admin API and to the hub's Tor pool over the chosen transport.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"gateway/internal/admin"
	"gateway/internal/config"
	"gateway/internal/hub"
	"gateway/internal/metrics"
	"gateway/internal/torpool"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	// defaultAdminListen is the listener address used when the hub-side
	// bootstrap config leaves Hub.ListenAdmin empty. 10.0.0.1 is the
	// wg-private address the design assumes for wireguard deployments;
	// deployments on other transports override it via Hub.ListenAdmin.
	defaultAdminListen = "10.0.0.1:9080"
	// shutdownGrace bounds how long we wait for in-flight SSE streams and
	// admin requests to drain before closing the registry and killing Tor.
	shutdownGrace = 30 * time.Second
	// serverCertValidity matches the hub root's lifetime. Rotation policy
	// is a P3 concern; for P1 the cert is reissued on every start.
	serverCertValidity = 10 * 365 * 24 * time.Hour
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	configPath := flag.String("config", "", "path to config file (required)")
	dataDirOverride := flag.String("data-dir", "", "override hub.data_dir from config (optional)")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "gateway-hub: -config is required")
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gateway-hub: load config: %v\n", err)
		os.Exit(1)
	}

	if *dataDirOverride != "" {
		cfg.Hub.DataDir = *dataDirOverride
	}

	logger := buildLogger(cfg)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		slog.Error("gateway-hub failed", "err", err)
		os.Exit(1)
	}
	slog.Info("gateway-hub stopped cleanly")
}

// run is the test-visible entry point. It wires every subsystem, blocks
// until ctx is cancelled, and then tears everything down inside
// shutdownGrace. Returning nil means a clean shutdown; errors are
// unrecoverable startup failures.
func run(ctx context.Context, cfg *config.Config) error {
	return runWithListener(ctx, cfg, nil)
}

// runWithListener is run()'s test-friendly sibling: when ln is non-nil we
// serve the admin API on that listener instead of binding Hub.ListenAdmin.
// Tests use this to obtain an ephemeral port without racing with Serve.
func runWithListener(ctx context.Context, cfg *config.Config, ln net.Listener) error {
	if cfg == nil {
		return errors.New("gateway-hub: nil config")
	}
	if cfg.NodeType != config.NodeTypeHub {
		return fmt.Errorf("gateway-hub: node_type must be %q, got %q",
			config.NodeTypeHub, cfg.NodeType)
	}
	if cfg.Hub.DataDir == "" {
		return errors.New("gateway-hub: hub.data_dir is required")
	}

	logger := slog.Default()

	// 1. torpool Manager. Skipped entirely when MinInstances==0 so tests
	// (and hub-only deployments that do not embed Tor) can run without a
	// tor binary on PATH. When enabled we also start the health/scaler
	// loops and the unix-socket admin API, preserving the exact contract
	// gateway-torpool exposes today.
	var (
		torMgr     *torpool.Manager
		torAPI     *torpool.API
		torAPIDone = make(chan struct{})
	)
	torpoolSocket := ""
	if cfg.Tor.MinInstances > 0 {
		torMgr = torpool.NewManager(cfg)
		if err := torMgr.Start(ctx); err != nil {
			return fmt.Errorf("torpool start: %w", err)
		}

		hc := torpool.NewHealthCheckerWithGrace(torMgr, cfg.Pool.HealthCheckInterval, cfg.Pool.QuarantineGrace)
		// Wire the health checker's per-port cleanup hook so scale-down
		// does not leak stale failure counters across port reuse (bug 7.3).
		torMgr.SetPortForgetter(hc)
		go hc.Run(ctx)

		scaler := torpool.NewScaler(torMgr, cfg)
		go scaler.Run(ctx)

		torpoolSocket = cfg.Admin.Socket
		torAPI = torpool.NewAPI(torMgr, torpoolSocket)
		go func() {
			defer close(torAPIDone)
			if err := torAPI.Serve(); err != nil && err != http.ErrServerClosed {
				logger.Error("torpool API serve", "err", err)
			}
		}()
	} else {
		close(torAPIDone)
		logger.Info("torpool skipped", "reason", "tor.min_instances is 0")
	}

	// cleanup captures the best-effort rollback we need if a later
	// wiring step fails. It mirrors shutdown() but without the admin
	// server (which does not exist yet at the call sites below).
	cleanup := func() {
		if torAPI != nil {
			torAPI.Close()
		}
		<-torAPIDone
		if torMgr != nil {
			torMgr.Shutdown()
		}
	}

	// 2. Registry: file-backed tenant + globals store with fsnotify hot-reload.
	registry, err := hub.New(cfg.Hub.DataDir)
	if err != nil {
		cleanup()
		return fmt.Errorf("registry: %w", err)
	}

	// 3. mTLS CA. NewCA loads an existing pair or generates one atomically.
	caCertFile, caKeyFile := resolveCAFiles(cfg)
	if err := os.MkdirAll(filepath.Dir(caCertFile), 0o700); err != nil {
		_ = registry.Close()
		cleanup()
		return fmt.Errorf("mkdir ca dir: %w", err)
	}
	ca, err := hub.NewCA(caCertFile, caKeyFile)
	if err != nil {
		_ = registry.Close()
		cleanup()
		return fmt.Errorf("mtls CA: %w", err)
	}
	// Anchor the serial counter under the hub data dir so restarts never
	// recycle a previously-issued serial. NewCA derives a best-effort dir
	// from the cert path; overriding to the hub data dir is explicit.
	if err := ca.SetDataDir(cfg.Hub.DataDir); err != nil {
		logger.Warn("CA data dir", "err", err)
	}

	// 4. NodeStore — fresh per process; edges (re-)register via CSR.
	nodes := hub.NewNodeStore()

	// 5. Admin API handler composes the registry, CA, node store, and the
	// torpool unix socket (for GET /v1/backends etc). An empty socket path
	// makes the passthrough endpoints return 503 rather than panic.
	api := hub.NewAPI(registry, ca, nodes, torpoolSocket)

	// 5a. Hidden admin gate (P3). The gate's URL is the credential, so
	// we install a constant-time prefix carve-out on the same listener
	// as the v1 mTLS API. Disabled gates still run the same code paths
	// — the timing-equalised compare keeps the carve-out invisible.
	gate := admin.New(admin.Config{
		Enabled: cfg.Admin.Enabled,
		Slug:    cfg.Admin.Slug,
		Token1:  cfg.Admin.Token1,
		Token2:  cfg.Admin.Token2,
	})

	// Hub-side metrics labeler. The labeler's salt file is shared with
	// the proxy-side instance via cfg.Metrics.OPSEC.TenantLabelSaltFile,
	// so identifiers hash consistently across binaries on the same host.
	labeler, err := metrics.NewLabeler(metrics.Config{
		HashTenantLabels: cfg.Metrics.OPSEC.HashTenantLabels,
		SaltFile:         cfg.Metrics.OPSEC.TenantLabelSaltFile,
	})
	if err != nil {
		_ = registry.Close()
		cleanup()
		return fmt.Errorf("metrics labeler: %w", err)
	}

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
		al, openErr := admin.OpenLog(cfg.Admin.AuditDataDir)
		if openErr != nil {
			_ = registry.Close()
			cleanup()
			return fmt.Errorf("admin audit log: %w", openErr)
		}
		adminAudit = al

		// Hub binary owns the full HubAccess adapter. Mirror registry
		// is intentionally nil here — wave-2 wiring will pass the live
		// *hub.MirrorRegistry once the hub binary creates one. Until
		// then ListMirrors returns an empty slice (not 503).
		hubAdapter := &hubAccess{
			reg: registry,
		}
		apiRouter := admin.NewRouter(admin.Routes{
			NodeID:   cfg.NodeID,
			NodeType: cfg.NodeType,
			Hub:      hubAdapter,
			Features: nil,
			Metrics:  nil,
			Audit:    admin.AuditFromLog(adminAudit),
			Labeler:  labeler,
		})
		handler, hErr := admin.NewHandler(admin.HandlerConfig{
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
		if hErr != nil {
			_ = adminAudit.Close()
			_ = registry.Close()
			cleanup()
			return fmt.Errorf("admin handler: %w", hErr)
		}
		gate.SetHandler(handler)
		go adminSessions.StartGC(ctx)
		go adminLockout.StartGC(ctx)
	}

	adminAddr := cfg.Hub.ListenAdmin
	if adminAddr == "" {
		adminAddr = defaultAdminListen
	}

	// Server certificate — signed by the hub CA so edges can verify the
	// hub using the same CA they pin for mTLS. Generated fresh each start
	// since the server cert is not persisted (only the CA root is).
	host, _, splitErr := net.SplitHostPort(adminAddr)
	if splitErr != nil {
		host = adminAddr
	}
	serverCert, err := issueServerCert(ca, host)
	if err != nil {
		_ = registry.Close()
		cleanup()
		return fmt.Errorf("server cert: %w", err)
	}

	// tls.Config intentionally uses VerifyClientCertIfGiven rather than
	// RequireAndVerifyClientCert. The hub has one unauthenticated endpoint
	// (POST /v1/nodes/register) — installers hit it before they have any
	// cert. Every other route is guarded by api.requireMTLS middleware
	// which inspects TLS state and rejects missing/invalid peer certs
	// with 401/403. This matches the pattern used in the hub's own unit
	// tests.
	tlsCfg := &tls.Config{
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    ca.CertPool(),
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
	}

	// Compose the admin gate around the v1 API. On a gate match we
	// delegate to the gate (constant-time-checked, then to the handler
	// installed above when admin.enabled). Otherwise the request falls
	// through to api.Handler() under the existing mTLS guard.
	apiHandler := api.Handler()
	composedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gate.MatchesPrefix(r.URL.Path) {
			gate.ServeHTTP(w, r)
			return
		}
		apiHandler.ServeHTTP(w, r)
	})

	adminServer := &http.Server{
		Addr:              adminAddr,
		Handler:           composedHandler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: the SSE stream is long-lived. ReadHeaderTimeout
		// plus per-handler context cancellation prevent slowloris abuse.
	}

	// Use the caller-supplied listener (tests) or bind ourselves.
	var listener net.Listener
	if ln != nil {
		listener = ln
	} else {
		listener, err = net.Listen("tcp", adminAddr)
		if err != nil {
			_ = registry.Close()
			cleanup()
			return fmt.Errorf("listen %s: %w", adminAddr, err)
		}
	}

	// Expose the actual bound address so tests that pass ":0" can find
	// the ephemeral port without polling.
	setListenAddr(listener.Addr().String())

	adminErr := make(chan error, 1)
	go func() {
		logger.Info("gateway-hub admin listening", "addr", listener.Addr().String())
		err := adminServer.ServeTLS(listener, "", "")
		if err != nil && err != http.ErrServerClosed {
			adminErr <- err
		}
		close(adminErr)
	}()

	logger.Info("gateway-hub started",
		"data_dir", cfg.Hub.DataDir,
		"tor_instances", cfg.Tor.MinInstances,
	)

	// Wait for signal or unrecoverable serve error.
	select {
	case <-ctx.Done():
		logger.Info("gateway-hub received shutdown signal")
	case err, ok := <-adminErr:
		if ok && err != nil {
			shutdown(adminServer, registry, torAPI, torMgr, torAPIDone, adminAudit, logger)
			return fmt.Errorf("admin server: %w", err)
		}
	}

	shutdown(adminServer, registry, torAPI, torMgr, torAPIDone, adminAudit, logger)
	return nil
}

// listenAddr discovery — tests that pass ":0" for the admin listen address
// can observe the actual bound port via getListenAddr().
var (
	listenAddrMu sync.Mutex
	listenAddr   string
)

func setListenAddr(addr string) {
	listenAddrMu.Lock()
	listenAddr = addr
	listenAddrMu.Unlock()
}

// getListenAddr returns the most recent bound admin address. Intended
// for tests; production code reads Hub.ListenAdmin directly.
func getListenAddr() string {
	listenAddrMu.Lock()
	defer listenAddrMu.Unlock()
	return listenAddr
}

// shutdown tears down all wired subsystems inside shutdownGrace. Safe to
// call with some subsystems already closed; each step is independent.
func shutdown(
	adminServer *http.Server,
	registry *hub.Registry,
	torAPI *torpool.API,
	torMgr *torpool.Manager,
	torAPIDone <-chan struct{},
	adminAudit *admin.Log,
	logger *slog.Logger,
) {
	// 1. Stop accepting new admin requests; in-flight requests (including
	// SSE streams) get shutdownGrace to drain.
	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := adminServer.Shutdown(shutCtx); err != nil {
		logger.Warn("admin server shutdown", "err", err)
	}

	// 2. Close the registry (stops fsnotify watcher and subscriber drain
	// goroutines). This also unblocks any still-running SSE handlers.
	if registry != nil {
		if err := registry.Close(); err != nil {
			logger.Warn("registry close", "err", err)
		}
	}

	// 3. Stop the torpool admin socket and then shut down every Tor
	// process. Ordering matters: closing the socket first prevents a
	// confused edge from calling /v1/scale while Tor is mid-teardown.
	if torAPI != nil {
		torAPI.Close()
	}
	<-torAPIDone
	if torMgr != nil {
		torMgr.Shutdown()
	}

	// 4. Admin audit log. Sessions/lockout GC goroutines exit on their
	// own when the parent ctx is cancelled; only the audit log owns
	// disk handles that need explicit flushing.
	if adminAudit != nil {
		if err := adminAudit.Close(); err != nil {
			logger.Warn("admin audit close", "err", err)
		}
	}
}

// resolveCAFiles returns the CA cert/key file paths, falling back to
// sensible defaults under Hub.DataDir so a fresh install without explicit
// paths Just Works.
func resolveCAFiles(cfg *config.Config) (string, string) {
	cert := cfg.Hub.CACertFile
	key := cfg.Hub.CAKeyFile
	if cert == "" {
		cert = filepath.Join(cfg.Hub.DataDir, "ca.crt")
	}
	if key == "" {
		key = filepath.Join(cfg.Hub.DataDir, "ca.key")
	}
	return cert, key
}

// issueServerCert mints a fresh leaf TLS server cert signed by the hub CA.
// The SAN covers the configured host (hostname or IP) plus localhost and
// loopback so local tooling and tests can verify the cert without extra
// plumbing. It delegates to hub.CA.IssueServerCert which handles the
// actual keygen + signing.
func issueServerCert(ca *hub.CA, host string) (tls.Certificate, error) {
	cn := host
	if cn == "" {
		cn = "gateway-hub"
	}
	dnsNames := []string{"localhost", "gateway-hub"}
	ipAddrs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if host != "" && host != "localhost" {
		if ip := net.ParseIP(host); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}
	return ca.IssueServerCert(cn, dnsNames, ipAddrs, serverCertValidity)
}

// buildLogger constructs an slog.Logger from the Logging config. Mirrors
// the helper used by gateway-proxy so behaviour is consistent across
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
