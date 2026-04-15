package proxy

import (
	"testing"

	"gateway/internal/shared"
)

func TestSelectBackend_LeastScore(t *testing.T) {
	pool := []shared.BackendInfo{
		{Port: 9050, Alive: true, ActiveConns: 5, LatencyMs: 200, ErrorRate: 0.1},  // score = 10 + 2 + 1 = 13
		{Port: 9051, Alive: true, ActiveConns: 1, LatencyMs: 50, ErrorRate: 0.0},   // score = 2 + 0.5 + 0 = 2.5 (lowest)
		{Port: 9052, Alive: false, ActiveConns: 0, LatencyMs: 10, ErrorRate: 0.0},  // dead
	}

	got := selectBackend(pool)
	if got == nil {
		t.Fatal("expected a backend, got nil")
	}
	if got.Port != 9051 {
		t.Errorf("expected port 9051 (lowest score), got port %d", got.Port)
	}
}

func TestSelectBackend_AllDead(t *testing.T) {
	pool := []shared.BackendInfo{
		{Port: 9050, Alive: false},
		{Port: 9051, Alive: false},
		{Port: 9052, Alive: false},
	}

	got := selectBackend(pool)
	if got != nil {
		t.Errorf("expected nil, got backend on port %d", got.Port)
	}
}
