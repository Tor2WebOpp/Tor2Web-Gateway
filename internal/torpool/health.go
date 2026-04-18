package torpool

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// failureTracker counts consecutive failures for a single instance.
type failureTracker struct {
	consecutive int
	threshold   int
	mu          sync.Mutex
}

// recordFailure increments the consecutive failure counter.
func (f *failureTracker) recordFailure() {
	f.mu.Lock()
	f.consecutive++
	f.mu.Unlock()
}

// recordSuccess resets the consecutive failure counter.
func (f *failureTracker) recordSuccess() {
	f.mu.Lock()
	f.consecutive = 0
	f.mu.Unlock()
}

// reset clears the failure counter. Called after a successful replace so
// we don't immediately re-flag the new instance on the next tick.
func (f *failureTracker) reset() {
	f.mu.Lock()
	f.consecutive = 0
	f.mu.Unlock()
}

// isDead reports whether the failure count has reached the threshold.
func (f *failureTracker) isDead() bool {
	f.mu.Lock()
	dead := f.consecutive >= f.threshold
	f.mu.Unlock()
	return dead
}

// quarantineEntry tracks an instance that has been quarantined after its
// failure counter crossed threshold. While quarantined the Tor process stays
// alive and is still probed on every tick; the instance is simply pulled
// out of the load-balancer via Alive=false. If a probe succeeds the
// entry is cleared and traffic resumes. If the grace period elapses with
// no recovery, the instance is replaced.
type quarantineEntry struct {
	since     time.Time
	expiresAt time.Time
}

// HealthChecker periodically probes all Tor instances, quarantines those that
// exceed the failure threshold, and replaces instances that fail to recover
// within the quarantine grace period.
type HealthChecker struct {
	mgr             *Manager
	interval        time.Duration
	quarantineGrace time.Duration
	trackers        sync.Map // port (int) -> *failureTracker
	wg              sync.WaitGroup
	probeTransports sync.Map // port (int) -> *http.Transport
	// replacing guards against a goroutine leak during an outage: without
	// it, every tick that still sees the instance as dead spawns another
	// replace goroutine, producing hundreds of parallel replaces per port.
	// LoadOrStore + CompareAndSwap(false, true) gates entry; defer clears.
	replacing sync.Map // port (int) -> *atomic.Bool
	// quarantined holds ports currently in the quarantine state.
	quarantined sync.Map // port (int) -> *quarantineEntry
}

// NewHealthChecker returns a HealthChecker that checks at the given interval.
// The quarantine grace defaults to 5 minutes; use NewHealthCheckerWithGrace
// to override.
func NewHealthChecker(mgr *Manager, interval time.Duration) *HealthChecker {
	return NewHealthCheckerWithGrace(mgr, interval, 5*time.Minute)
}

// NewHealthCheckerWithGrace returns a HealthChecker with an explicit
// quarantine grace period. When grace is zero or negative the checker
// falls back to the previous replace-on-threshold behaviour.
func NewHealthCheckerWithGrace(mgr *Manager, interval, quarantineGrace time.Duration) *HealthChecker {
	return &HealthChecker{
		mgr:             mgr,
		interval:        interval,
		quarantineGrace: quarantineGrace,
	}
}

// Wait blocks until all in-flight replacement goroutines have finished.
func (h *HealthChecker) Wait() {
	h.wg.Wait()
}

// HCWaitAdd increments the HealthChecker's internal WaitGroup. Exposed only
// for shutdown-ordering tests in cmd/gateway-torpool that need to simulate
// an in-flight replace without actually running the healthcheck loop.
// Do not use in production code paths — replaceAsync is the only legitimate
// source of additions.
func HCWaitAdd(h *HealthChecker, delta int) {
	h.wg.Add(delta)
}

// HCWaitDone decrements the HealthChecker's internal WaitGroup. Companion
// to HCWaitAdd; same caveats apply.
func HCWaitDone(h *HealthChecker) {
	h.wg.Done()
}

// Run starts the health-check ticker loop.  It blocks until ctx is cancelled.
func (h *HealthChecker) Run(ctx context.Context) {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.checkAll(ctx)
		}
	}
}

// checkAll iterates all instances and checks each one in parallel.
func (h *HealthChecker) checkAll(ctx context.Context) {
	instances := h.mgr.Instances()
	var wg sync.WaitGroup
	for _, inst := range instances {
		wg.Add(1)
		go func(inst *TorInstance) {
			defer wg.Done()
			h.checkOne(ctx, inst)
		}(inst)
	}
	wg.Wait()
}

// checkOne probes a single instance and updates its state.
func (h *HealthChecker) checkOne(ctx context.Context, inst *TorInstance) {
	tracker := h.trackerFor(inst.Port)

	start := time.Now()
	err := h.probeTorSOCKS(ctx, inst.Port, inst.Backend)
	latency := time.Since(start).Milliseconds()

	inst.TotalCount.Add(1)

	if err != nil {
		inst.ErrorCount.Add(1)
		tracker.recordFailure()

		if !tracker.isDead() {
			return
		}

		// Threshold crossed. Pull the instance out of the load-balancer
		// immediately (Score() treats Alive=false as infinitely bad) so
		// new requests stop routing here while we wait to see if it
		// recovers. The Tor process keeps running.
		inst.Alive.Store(false)
		h.removeProbeTransport(inst.Port)

		// Tor hidden-service reachability has known 30-60s stall windows
		// during intro-point refresh. A 5-minute quarantine lets these
		// resolve without the expense of killing + bootstrapping a new
		// Tor process. Only if the instance is still failing at grace
		// expiry do we escalate to replacement.
		if h.quarantineGrace <= 0 {
			h.replaceAsync(inst.Port)
			return
		}

		now := time.Now()
		if q, ok := h.quarantinedEntry(inst.Port); ok {
			if now.After(q.expiresAt) {
				slog.Warn("torpool: quarantine grace expired, replacing instance",
					"port", inst.Port, "quarantined_for", now.Sub(q.since).String())
				h.clearQuarantine(inst.Port)
				h.replaceAsync(inst.Port)
			}
			return
		}

		slog.Warn("torpool: instance quarantined after consecutive probe failures",
			"port", inst.Port, "grace", h.quarantineGrace.String(), "probe_error", err.Error())
		h.quarantined.Store(inst.Port, &quarantineEntry{
			since:     now,
			expiresAt: now.Add(h.quarantineGrace),
		})
		return
	}

	tracker.recordSuccess()
	// A successful probe lifts any quarantine in place and restores the
	// instance to the load-balancer without the new-circuit cost of a
	// full replace.
	if _, wasQuarantined := h.quarantinedEntry(inst.Port); wasQuarantined {
		slog.Info("torpool: instance recovered from quarantine", "port", inst.Port)
	}
	h.clearQuarantine(inst.Port)
	inst.Alive.Store(true)
	inst.LatencyMs.Store(latency)
}

// quarantinedEntry returns the current quarantine entry for a port, if any.
func (h *HealthChecker) quarantinedEntry(port int) (*quarantineEntry, bool) {
	v, ok := h.quarantined.Load(port)
	if !ok {
		return nil, false
	}
	return v.(*quarantineEntry), true
}

// clearQuarantine removes the quarantine entry for a port. Safe to call
// when the port is not quarantined.
func (h *HealthChecker) clearQuarantine(port int) {
	h.quarantined.Delete(port)
}

// replaceAsync fires one replacement goroutine per port. The per-port flag
// blocks subsequent ticks from piling on while the first replace is in
// flight; concurrent ticks simply return without scheduling another.
func (h *HealthChecker) replaceAsync(port int) {
	v, _ := h.replacing.LoadOrStore(port, &atomic.Bool{})
	flag := v.(*atomic.Bool)
	if !flag.CompareAndSwap(false, true) {
		return
	}
	slog.Info("torpool: replacing dead instance", "port", port)
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		defer flag.Store(false)
		replaceCtx, cancel := context.WithTimeout(context.Background(), h.mgr.cfg.Tor.BootstrapTimeout+10*time.Second)
		defer cancel()
		if err := h.mgr.ReplaceInstance(replaceCtx, port); err != nil {
			// Keep going — the next tick will re-arm the flag.
			slog.Error("torpool: replace failed, next tick will retry", "port", port, "error", err)
			return
		}
		slog.Info("torpool: replace succeeded", "port", port)
		// Success: reset the failure tracker so we don't immediately
		// flag the fresh instance as dead on the next tick before it
		// has completed its first probe.
		if t, ok := h.trackers.Load(port); ok {
			t.(*failureTracker).reset()
		}
	}()
}

// trackerFor returns (creating if necessary) the failure tracker for a port.
func (h *HealthChecker) trackerFor(port int) *failureTracker {
	v, _ := h.trackers.LoadOrStore(port, &failureTracker{threshold: 3})
	return v.(*failureTracker)
}

// getProbeTransport returns a cached *http.Transport for the given SOCKS port,
// creating one on first use. Returns an error if the dialer does not implement
// proxy.ContextDialer — the non-context fallback ignored cancellation and
// leaked goroutines under timeouts.
func (h *HealthChecker) getProbeTransport(socksPort int) (*http.Transport, error) {
	if v, ok := h.probeTransports.Load(socksPort); ok {
		return v.(*http.Transport), nil
	}

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks5 dialer for port %d: %w", socksPort, err)
	}
	cd, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("socks5 dialer for port %d does not implement ContextDialer", socksPort)
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return cd.DialContext(ctx, network, addr)
		},
	}
	h.probeTransports.Store(socksPort, tr)
	return tr, nil
}

// removeProbeTransport closes idle connections and removes the cached transport
// for the given port.
func (h *HealthChecker) removeProbeTransport(socksPort int) {
	if v, ok := h.probeTransports.LoadAndDelete(socksPort); ok {
		v.(*http.Transport).CloseIdleConnections()
	}
}

// ForgetPort discards all cached state for a port. It is called by the
// torpool.Manager after it kills instances during scale-down so that a
// later scale-up reusing the same port does not inherit stale counters,
// probe transports, or replace-in-flight flags from the previous
// instance. The four sync.Maps cleared here are the full set of
// per-port state owned by HealthChecker.
func (h *HealthChecker) ForgetPort(port int) {
	h.trackers.Delete(port)
	h.removeProbeTransport(port)
	h.replacing.Delete(port)
	h.quarantined.Delete(port)
}

// probeTorSOCKS dials the backend via the Tor SOCKS5 proxy and sends a HEAD
// request.  Any HTTP response counts as success (the circuit is working).
func (h *HealthChecker) probeTorSOCKS(ctx context.Context, socksPort int, backend string) error {
	transport, err := h.getProbeTransport(socksPort)
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	url := fmt.Sprintf("http://%s/", backend)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("probe request failed: %w", err)
	}
	resp.Body.Close()

	// Any HTTP response means the circuit is working.
	return nil
}
