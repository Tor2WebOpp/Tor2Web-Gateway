package torpool

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
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

// isDead reports whether the failure count has reached the threshold.
func (f *failureTracker) isDead() bool {
	f.mu.Lock()
	dead := f.consecutive >= f.threshold
	f.mu.Unlock()
	return dead
}

// HealthChecker periodically probes all Tor instances and replaces dead ones.
type HealthChecker struct {
	mgr      *Manager
	interval time.Duration
	trackers sync.Map // port (int) → *failureTracker
}

// NewHealthChecker returns a HealthChecker that checks at the given interval.
func NewHealthChecker(mgr *Manager, interval time.Duration) *HealthChecker {
	return &HealthChecker{
		mgr:      mgr,
		interval: interval,
	}
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
	err := probeTorSOCKS(ctx, inst.Port, inst.Backend)
	latency := time.Since(start).Milliseconds()

	inst.TotalCount.Add(1)

	if err != nil {
		inst.ErrorCount.Add(1)
		tracker.recordFailure()

		if tracker.isDead() {
			inst.Alive.Store(false)
			// Attempt to replace asynchronously to avoid blocking the check loop.
			go func(port int) {
				replaceCtx, cancel := context.WithTimeout(context.Background(), h.mgr.cfg.Tor.BootstrapTimeout+10*time.Second)
				defer cancel()
				h.mgr.ReplaceInstance(replaceCtx, port) //nolint:errcheck
			}(inst.Port)
		}
		return
	}

	tracker.recordSuccess()
	inst.Alive.Store(true)
	inst.LatencyMs.Store(latency)
}

// trackerFor returns (creating if necessary) the failure tracker for a port.
func (h *HealthChecker) trackerFor(port int) *failureTracker {
	v, _ := h.trackers.LoadOrStore(port, &failureTracker{threshold: 3})
	return v.(*failureTracker)
}

// probeTorSOCKS dials the backend via the Tor SOCKS5 proxy and sends a HEAD
// request.  Any HTTP response counts as success (the circuit is working).
func probeTorSOCKS(ctx context.Context, socksPort int, backend string) error {
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("create socks5 dialer: %w", err)
	}

	var dialFn func(ctx context.Context, network, addr string) (net.Conn, error)

	if cd, ok := dialer.(proxy.ContextDialer); ok {
		dialFn = cd.DialContext
	} else {
		dialFn = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dialFn,
		},
		Timeout: 30 * time.Second,
	}

	url := fmt.Sprintf("http://%s/", backend)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("probe request failed: %w", err)
	}
	resp.Body.Close()

	// Any HTTP response means the circuit is working.
	return nil
}
