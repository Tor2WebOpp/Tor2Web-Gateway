package door

import (
	"testing"

	"gateway/internal/config"
	"gateway/internal/shared"
)

func liveMirror(host string, weight int) shared.MirrorInfo {
	return shared.MirrorInfo{
		Host:    host,
		Verdict: "live",
		Weight:  weight,
	}
}

func TestSelector_EmptyReturnsFalse(t *testing.T) {
	s := NewSelector()
	host, ok := s.Pick(config.SlugConf{Strategy: config.StrategyRandom})
	if ok || host != "" {
		t.Fatalf("empty selector = (%q, %v), want (\"\", false)", host, ok)
	}
}

func TestSelector_FiltersOutNonLive(t *testing.T) {
	s := NewSelector()
	s.UpdateMirrors([]shared.MirrorInfo{
		{Host: "live.example", Verdict: "live"},
		{Host: "blocked.example", Verdict: "blocked"},
		{Host: "degraded.example", Verdict: "degraded"},
		{Host: "unknown.example", Verdict: "unknown"},
	})
	for i := 0; i < 20; i++ {
		h, ok := s.Pick(config.SlugConf{Strategy: config.StrategyRandom})
		if !ok || h != "live.example" {
			t.Fatalf("iter %d: got (%q, %v)", i, h, ok)
		}
	}
}

func TestSelector_FiltersManualBlock(t *testing.T) {
	s := NewSelector()
	s.UpdateMirrors([]shared.MirrorInfo{
		{Host: "a.example", Verdict: "live", ManualBlock: true},
		{Host: "b.example", Verdict: "live"},
	})
	for i := 0; i < 20; i++ {
		h, ok := s.Pick(config.SlugConf{Strategy: config.StrategyRandom})
		if !ok || h != "b.example" {
			t.Fatalf("iter %d: got (%q, %v)", i, h, ok)
		}
	}
}

func TestSelector_ExcludesRegions(t *testing.T) {
	s := NewSelector()
	s.UpdateMirrors([]shared.MirrorInfo{
		{Host: "ru-blocked.example", Verdict: "live", BlockedRegions: []string{"RU", "CN"}},
		{Host: "global.example", Verdict: "live"},
	})
	slug := config.SlugConf{Strategy: config.StrategyRandom, ExcludeRegions: []string{"RU"}}
	for i := 0; i < 20; i++ {
		h, ok := s.Pick(slug)
		if !ok || h != "global.example" {
			t.Fatalf("iter %d: got (%q, %v)", i, h, ok)
		}
	}
}

func TestSelector_TargetTenantsIntersection(t *testing.T) {
	s := NewSelector()
	s.UpdateMirrors([]shared.MirrorInfo{
		{Host: "a.example", Verdict: "live", TargetTenants: []string{"site-a"}},
		{Host: "b.example", Verdict: "live", TargetTenants: []string{"site-b"}},
		{Host: "ab.example", Verdict: "live", TargetTenants: []string{"site-a", "site-b"}},
	})
	slug := config.SlugConf{Strategy: config.StrategyRandom, TargetTenants: []string{"site-a"}}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		h, ok := s.Pick(slug)
		if !ok {
			t.Fatalf("iter %d: no candidate", i)
		}
		seen[h] = true
	}
	if seen["b.example"] {
		t.Error("b.example should be filtered out")
	}
	if !seen["a.example"] || !seen["ab.example"] {
		t.Errorf("expected a.example and ab.example, saw %v", seen)
	}
}

func TestSelector_EmptyTargetTenantsAdmitsAll(t *testing.T) {
	s := NewSelector()
	s.UpdateMirrors([]shared.MirrorInfo{
		{Host: "a.example", Verdict: "live", TargetTenants: []string{"site-a"}},
		{Host: "b.example", Verdict: "live"},
	})
	slug := config.SlugConf{Strategy: config.StrategyRandom}
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		h, ok := s.Pick(slug)
		if !ok {
			t.Fatal("no candidate")
		}
		seen[h] = true
	}
	if !seen["a.example"] || !seen["b.example"] {
		t.Errorf("expected both mirrors visible, saw %v", seen)
	}
}

func TestSelector_RoundRobinCycles(t *testing.T) {
	s := NewSelector()
	s.UpdateMirrors([]shared.MirrorInfo{
		liveMirror("a", 1),
		liveMirror("b", 1),
		liveMirror("c", 1),
	})
	slug := config.SlugConf{Strategy: config.StrategyRoundRobin}
	seq := make([]string, 6)
	for i := range seq {
		h, ok := s.Pick(slug)
		if !ok {
			t.Fatalf("iter %d: no pick", i)
		}
		seq[i] = h
	}
	// Three distinct hosts should appear and the sequence should
	// repeat after len(candidates).
	if seq[0] == seq[1] || seq[1] == seq[2] {
		t.Errorf("round_robin produced duplicates: %v", seq)
	}
	if seq[0] != seq[3] || seq[1] != seq[4] || seq[2] != seq[5] {
		t.Errorf("round_robin did not cycle: %v", seq)
	}
}

func TestSelector_Weighted_FavoursHeavier(t *testing.T) {
	s := NewSelector()
	s.UpdateMirrors([]shared.MirrorInfo{
		liveMirror("heavy", 9),
		liveMirror("light", 1),
	})
	slug := config.SlugConf{Strategy: config.StrategyWeighted}
	counts := map[string]int{}
	const runs = 1000
	for i := 0; i < runs; i++ {
		h, ok := s.Pick(slug)
		if !ok {
			t.Fatal("no pick")
		}
		counts[h]++
	}
	// heavy should win at least 5x as often as light. Expected ratio
	// is 9:1 but we allow a wide margin so this test never flakes on
	// adverse crypto/rand outputs.
	if counts["heavy"] < 5*counts["light"] {
		t.Errorf("weighted ratio too flat: heavy=%d light=%d", counts["heavy"], counts["light"])
	}
}

func TestSelector_Weighted_ZeroWeightTreatedAsOne(t *testing.T) {
	s := NewSelector()
	s.UpdateMirrors([]shared.MirrorInfo{
		liveMirror("a", 0),
		liveMirror("b", 0),
	})
	slug := config.SlugConf{Strategy: config.StrategyWeighted}
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		h, ok := s.Pick(slug)
		if !ok {
			t.Fatal("no pick")
		}
		seen[h] = true
	}
	if !seen["a"] || !seen["b"] {
		t.Errorf("expected both mirrors reachable, saw %v", seen)
	}
}

func TestSelector_Random_DeterministicWithSource(t *testing.T) {
	s := NewSelector()
	s.UpdateMirrors([]shared.MirrorInfo{
		liveMirror("a", 1),
		liveMirror("b", 1),
		liveMirror("c", 1),
	})
	// Inject a deterministic source so we can assert selection order.
	s.randSource = func(n int) int { return 1 }
	slug := config.SlugConf{Strategy: config.StrategyRandom}
	h, ok := s.Pick(slug)
	if !ok || h != "b" {
		t.Fatalf("expected b, got (%q, %v)", h, ok)
	}
}

func TestSelector_UpsertReplacesExisting(t *testing.T) {
	s := NewSelector()
	s.UpdateMirrors([]shared.MirrorInfo{
		{Host: "a.example", Verdict: "live"},
	})
	s.UpsertMirror(shared.MirrorInfo{Host: "a.example", Verdict: "blocked"})
	if _, ok := s.Pick(config.SlugConf{Strategy: config.StrategyRandom}); ok {
		t.Fatal("expected no pick after upsert to blocked verdict")
	}
	s.UpsertMirror(shared.MirrorInfo{Host: "b.example", Verdict: "live"})
	h, ok := s.Pick(config.SlugConf{Strategy: config.StrategyRandom})
	if !ok || h != "b.example" {
		t.Fatalf("after insert, got (%q, %v)", h, ok)
	}
}

func TestSelector_Remove(t *testing.T) {
	s := NewSelector()
	s.UpdateMirrors([]shared.MirrorInfo{
		{Host: "a.example", Verdict: "live"},
		{Host: "b.example", Verdict: "live"},
	})
	s.RemoveMirror("a.example")
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		h, ok := s.Pick(config.SlugConf{Strategy: config.StrategyRandom})
		if !ok {
			t.Fatal("no pick after remove")
		}
		seen[h] = true
	}
	if seen["a.example"] {
		t.Error("removed mirror resurfaced")
	}
}
