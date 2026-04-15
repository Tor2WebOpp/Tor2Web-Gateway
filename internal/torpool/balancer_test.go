package torpool

import (
	"testing"

	"gateway/internal/shared"
)

func TestPickBest_LeastScore(t *testing.T) {
	backends := []shared.BackendInfo{
		{Port: 9050, Alive: true, ActiveConns: 10, LatencyMs: 200, ErrorRate: 0.1},
		{Port: 9051, Alive: true, ActiveConns: 2, LatencyMs: 50, ErrorRate: 0.0},
		{Port: 9052, Alive: false, ActiveConns: 0, LatencyMs: 10, ErrorRate: 0.0},
	}

	best := pickBest(backends)
	if best == nil {
		t.Fatal("expected a backend, got nil")
	}
	if best.Port != 9051 {
		t.Errorf("expected port 9051 (lowest score), got %d", best.Port)
	}
}

func TestPickBest_SkipsDead(t *testing.T) {
	backends := []shared.BackendInfo{
		{Port: 9050, Alive: false, ActiveConns: 0, LatencyMs: 0, ErrorRate: 0.0},
		{Port: 9051, Alive: false, ActiveConns: 0, LatencyMs: 0, ErrorRate: 0.0},
	}

	best := pickBest(backends)
	if best != nil {
		t.Errorf("expected nil when all dead, got port %d", best.Port)
	}
}

func TestShouldScale(t *testing.T) {
	cases := []struct {
		name          string
		alive         int
		activeConns   int
		upThreshold   float64
		downThreshold float64
		want          int
	}{
		{
			name:          "scale up: 5 alive, 400 active (load=400/350≈1.14 > 0.7)",
			alive:         5,
			activeConns:   400,
			upThreshold:   0.7,
			downThreshold: 0.3,
			want:          1,
		},
		{
			name:          "scale down: 15 alive, 100 active (load=100/1050≈0.095 < 0.3)",
			alive:         15,
			activeConns:   100,
			upThreshold:   0.7,
			downThreshold: 0.3,
			want:          -1,
		},
		{
			name:          "stay: 10 alive, 500 active (load=500/700≈0.71, within thresholds)",
			alive:         10,
			activeConns:   500,
			upThreshold:   0.8,
			downThreshold: 0.2,
			want:          0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			load := float64(tc.activeConns) / float64(tc.alive*70)
			got := scaleDirection(load, tc.upThreshold, tc.downThreshold)
			if got != tc.want {
				t.Errorf("load=%.4f upThreshold=%.1f downThreshold=%.1f: got %d, want %d",
					load, tc.upThreshold, tc.downThreshold, got, tc.want)
			}
		})
	}
}
