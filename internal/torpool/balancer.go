package torpool

import (
	"context"
	"log/slog"
	"time"

	"gateway/internal/config"
	"gateway/internal/shared"
)

// pickBest returns the alive backend with the lowest Score().
// Returns nil if all backends are dead.
func pickBest(backends []shared.BackendInfo) *shared.BackendInfo {
	var best *shared.BackendInfo
	for i := range backends {
		b := &backends[i]
		if !b.Alive {
			continue
		}
		if best == nil || b.Score() < best.Score() {
			best = b
		}
	}
	return best
}

// scaleDirection returns 1 (scale up), -1 (scale down), or 0 (stay).
func scaleDirection(load float64, upThreshold, downThreshold float64) int {
	if load > upThreshold {
		return 1
	}
	if load < downThreshold {
		return -1
	}
	return 0
}

// Scaler evaluates pool load and scales up or down as needed.
type Scaler struct {
	mgr       *Manager
	cfg       *config.Config
	lastScale time.Time
}

// NewScaler creates a new Scaler.
func NewScaler(mgr *Manager, cfg *config.Config) *Scaler {
	return &Scaler{
		mgr: mgr,
		cfg: cfg,
	}
}

// Run starts the rebalance ticker loop. It blocks until ctx is cancelled.
func (s *Scaler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Pool.RebalanceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.evaluate(ctx)
		}
	}
}

// evaluate checks cooldown, calculates load, and scales if needed.
func (s *Scaler) evaluate(ctx context.Context) {
	cooldown := s.cfg.Pool.ScaleCooldown
	if cooldown == 0 {
		cooldown = 60 * time.Second
	}
	if !s.lastScale.IsZero() && time.Since(s.lastScale) < cooldown {
		return
	}

	total, alive := s.mgr.Count()
	if alive == 0 {
		return
	}

	// Sum active connections across all instances.
	var totalActiveConns int
	instances := s.mgr.Instances()
	for _, inst := range instances {
		totalActiveConns += int(inst.ActiveConns.Load())
	}

	// Load = totalActiveConns / (alive * 70)
	load := float64(totalActiveConns) / float64(alive*70)

	upThreshold := s.cfg.Pool.ScaleUpThreshold
	downThreshold := s.cfg.Pool.ScaleDownThreshold
	if upThreshold == 0 {
		upThreshold = 0.8
	}
	if downThreshold == 0 {
		downThreshold = 0.2
	}

	dir := scaleDirection(load, upThreshold, downThreshold)
	if dir == 0 {
		return
	}

	step := s.scaleStep(load)
	newTarget := total
	if dir == 1 {
		newTarget = total + step
	} else {
		newTarget = total - step
		if newTarget < s.cfg.Tor.MinInstances {
			newTarget = s.cfg.Tor.MinInstances
		}
	}

	if newTarget == total {
		return
	}

	slog.Info("scaler: adjusting pool size",
		"current", total,
		"target", newTarget,
		"load", load,
		"direction", dir,
	)

	if err := s.mgr.ScaleTo(ctx, newTarget); err != nil {
		slog.Error("scaler: scale failed", "error", err)
		return
	}

	s.lastScale = time.Now()
}

// scaleStep returns 3 if load > 0.9, else 1.
func (s *Scaler) scaleStep(load float64) int {
	if load > 0.9 {
		return 3
	}
	return 1
}
