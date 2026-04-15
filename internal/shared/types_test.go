package shared

import (
	"math"
	"testing"
)

func TestScore_Basic(t *testing.T) {
	// conns=23, latency=340, error=0 → (23*2) + (340/100) + (0*10) = 46 + 3.4 + 0 = 49.4
	b := BackendInfo{
		ActiveConns: 23,
		LatencyMs:   340,
		ErrorRate:   0,
	}
	got := b.Score()
	want := 49.4
	if math.Abs(got-want) > 0.0001 {
		t.Errorf("Score() = %v, want %v", got, want)
	}
}

func TestScore_WithErrors(t *testing.T) {
	// conns=10, latency=200, error=25 → (10*2) + (200/100) + (25*10) = 20 + 2 + 250 = 272
	b := BackendInfo{
		ActiveConns: 10,
		LatencyMs:   200,
		ErrorRate:   25,
	}
	got := b.Score()
	want := 272.0
	if math.Abs(got-want) > 0.0001 {
		t.Errorf("Score() = %v, want %v", got, want)
	}
}
