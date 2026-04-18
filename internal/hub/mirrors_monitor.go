package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// NodeCheck is the per-vantage-point result returned by a check-host.net
// CheckNow call. It is redeclared here (rather than imported from
// internal/checkhost) so this package does not take a build-time dependency
// on the client type. The client may be provided at runtime via any object
// that satisfies MonitorClient; see mirrors_client.go for the interface.
type NodeCheck struct {
	Status    string
	LatencyMs int
}

// MonitorClient is the minimal interface the Monitor needs from a
// check-host.net client. Keeping it narrow means production wiring can use
// the concrete *checkhost.Client, and tests can pass a fake that just fills
// the result map. The host argument is the mirror domain being probed;
// regions and maxNodes bound the work; poll/maxWait tune the polling loop
// inside the client.
type MonitorClient interface {
	CheckNow(ctx context.Context, host string, regions []string, maxNodes int, poll time.Duration, maxWait time.Duration) (map[string]NodeCheck, error)
}

// Defaults applied when a settings field is zero. These are conservative and
// match the values in the P2 spec.
const (
	defaultInterval     = 5 * time.Minute
	defaultMaxNodes     = 5
	defaultThresholdPct = 0.5
	defaultPoll         = 2 * time.Second
	defaultMaxWait      = 30 * time.Second
)

// MonitorConfig controls Monitor behaviour. Client is required — the Monitor
// does not attempt any network itself. Settings are normally persisted via
// LoadCheckHostSettings so an operator can hot-edit intervals without
// restarting the hub; static values can still be set here for tests or
// early-boot bootstrapping.
type MonitorConfig struct {
	Enabled      bool
	Interval     time.Duration
	Regions      []string
	MaxNodes     int
	ThresholdPct float64
	Client       MonitorClient
	// Poll/MaxWait are passed straight through to Client.CheckNow. Zero
	// values are replaced with defaultPoll/defaultMaxWait.
	Poll    time.Duration
	MaxWait time.Duration
}

// Monitor runs the mirror-health probe loop. Each tick it re-reads
// CheckHostSettings from disk (if a DataDir is set) so changes to the YAML
// take effect without a restart. CheckOnce exposes a manual trigger used by
// both the admin API and the tests.
type Monitor struct {
	reg *MirrorRegistry
	cfg MonitorConfig

	mu      sync.Mutex
	running bool
	stop    chan struct{}
	done    chan struct{}

	logger *slog.Logger
}

// NewMonitor returns a Monitor bound to reg and cfg. cfg.Client must be
// non-nil; callers that do not have a client yet should gate construction.
func NewMonitor(reg *MirrorRegistry, cfg MonitorConfig) *Monitor {
	return &Monitor{
		reg:    reg,
		cfg:    cfg,
		logger: slog.Default().With("component", "hub.mirrors.monitor"),
	}
}

// Start spawns the ticker goroutine. The first check runs immediately and
// then on every Interval. Start is idempotent: calling it twice returns nil
// and leaves the existing goroutine intact. ctx cancellation stops the loop
// cleanly; Stop does the same via an internal channel.
func (m *Monitor) Start(ctx context.Context) error {
	if m.reg == nil {
		return errors.New("hub mirrors monitor: registry is nil")
	}
	if m.cfg.Client == nil {
		return errors.New("hub mirrors monitor: client is nil")
	}

	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = true
	m.stop = make(chan struct{})
	m.done = make(chan struct{})
	stop := m.stop
	done := m.done
	m.mu.Unlock()

	go func() {
		defer close(done)
		// Immediate first run so operators observe state without waiting
		// for a full interval after the hub starts.
		if err := m.CheckOnce(ctx); err != nil {
			m.logger.Warn("hub mirrors monitor: initial check failed", "err", err)
		}
		// Each loop iteration re-resolves the interval so a settings edit
		// mid-run takes effect on the next tick without a restart.
		for {
			interval := m.effectiveInterval()
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-stop:
				timer.Stop()
				return
			case <-timer.C:
				if err := m.CheckOnce(ctx); err != nil {
					m.logger.Warn("hub mirrors monitor: tick failed", "err", err)
				}
			}
		}
	}()
	return nil
}

// Stop signals the run loop to exit and blocks until it does. Safe to call
// multiple times. Stop is safe to call before Start (no-op) so shutdown code
// doesn't need to guard.
func (m *Monitor) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	stop := m.stop
	done := m.done
	m.stop = nil
	m.done = nil
	m.mu.Unlock()

	close(stop)
	<-done
}

// CheckOnce runs a single probe cycle. It enumerates every non-manually-
// blocked mirror, asks the client for results, aggregates them into
// RegionStatus entries, and calls UpdateHealth on the registry. Errors from
// individual mirrors are logged but do not abort the batch: a single
// unreachable mirror should not prevent others from being updated.
func (m *Monitor) CheckOnce(ctx context.Context) error {
	if m.reg == nil {
		return errors.New("hub mirrors monitor: registry is nil")
	}
	if m.cfg.Client == nil {
		return errors.New("hub mirrors monitor: client is nil")
	}

	cfg := m.resolveSettings()
	if !cfg.Enabled {
		return nil
	}

	mirrors := m.reg.List()
	if len(mirrors) == 0 {
		return nil
	}

	poll := m.cfg.Poll
	if poll == 0 {
		poll = defaultPoll
	}
	maxWait := m.cfg.MaxWait
	if maxWait == 0 {
		maxWait = defaultMaxWait
	}

	var errs []error
	for _, mh := range mirrors {
		if mh.ManualBlock {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		results, err := m.cfg.Client.CheckNow(ctx, mh.Host, cfg.Regions, cfg.MaxNodes, poll, maxWait)
		if err != nil {
			m.logger.Warn("hub mirrors monitor: CheckNow failed", "host", mh.Host, "err", err)
			errs = append(errs, fmt.Errorf("check %s: %w", mh.Host, err))
			continue
		}

		now := time.Now().UTC()
		regionResults := make(map[string]RegionStatus, len(results))
		for nodeID, nc := range results {
			regionResults[nodeID] = RegionStatus{
				Status:    nc.Status,
				LatencyMs: nc.LatencyMs,
				At:        now,
			}
		}
		if err := m.reg.UpdateHealth(ctx, mh.Host, regionResults, cfg.ThresholdPct); err != nil {
			m.logger.Warn("hub mirrors monitor: UpdateHealth failed", "host", mh.Host, "err", err)
			errs = append(errs, fmt.Errorf("update %s: %w", mh.Host, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// effectiveInterval returns the interval to sleep before the next tick. It
// prefers the value persisted on disk (so hot-reload works) and falls back
// to the config value, then the package default.
func (m *Monitor) effectiveInterval() time.Duration {
	cfg := m.resolveSettings()
	if cfg.Interval > 0 {
		return cfg.Interval
	}
	return defaultInterval
}

// resolveSettings merges three sources in priority order: the on-disk YAML,
// the MonitorConfig struct, and the package defaults. Reading the YAML every
// call is the cheap way to support hot-reload — a few milliseconds per tick
// is negligible compared to the network round-trips that follow.
func (m *Monitor) resolveSettings() MonitorConfig {
	out := m.cfg
	if m.reg != nil {
		if s, err := LoadCheckHostSettings(m.reg.DataDir()); err == nil {
			// Only override when the on-disk value is non-zero so an empty
			// YAML does not reset an explicit cfg override.
			if s.Interval > 0 {
				out.Interval = s.Interval
			}
			if s.MaxNodes > 0 {
				out.MaxNodes = s.MaxNodes
			}
			if s.ThresholdPct > 0 {
				out.ThresholdPct = s.ThresholdPct
			}
			if len(s.Regions) > 0 {
				out.Regions = append([]string(nil), s.Regions...)
			}
			// Enabled is special: a false value on disk should count even
			// when cfg.Enabled=true, so operators can disable the monitor
			// without redeploying. We only apply when the settings file
			// exists (non-zero interval or explicit regions), otherwise a
			// missing file would always disable.
			if s.Interval > 0 || len(s.Regions) > 0 || s.MaxNodes > 0 || s.ThresholdPct > 0 {
				out.Enabled = s.Enabled
			}
		}
	}
	if out.MaxNodes == 0 {
		out.MaxNodes = defaultMaxNodes
	}
	if out.ThresholdPct == 0 {
		out.ThresholdPct = defaultThresholdPct
	}
	return out
}
