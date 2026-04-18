package feature

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"gateway/internal/shared"
)

// recordingFeature appends its Name to a shared slice when invoked and
// honours an atomic enabled flag updated by a reload observer.
type recordingFeature struct {
	name    string
	log     *[]string
	logMu   *sync.Mutex
	enabled atomic.Bool
	// validateErr, if non-nil, is returned for every Validate call.
	validateErr error
	// panicIfInvoked causes the middleware body to panic when enabled.
	panicIfInvoked bool
}

func newRecordingFeature(name string, log *[]string, mu *sync.Mutex) *recordingFeature {
	return &recordingFeature{name: name, log: log, logMu: mu}
}

func (f *recordingFeature) Name() string { return f.name }

func (f *recordingFeature) Middleware(resolver Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !f.enabled.Load() {
				next.ServeHTTP(w, r)
				return
			}
			if f.panicIfInvoked {
				panic("recordingFeature " + f.name + " middleware invoked while enabled")
			}
			if f.log != nil {
				f.logMu.Lock()
				*f.log = append(*f.log, f.name)
				f.logMu.Unlock()
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (f *recordingFeature) Validate(cfg shared.FeatureSnapshot) error {
	return f.validateErr
}

// attachReload binds the feature's atomic flag to the registry's reload
// observer so tests can toggle state by invoking Reload.
func (f *recordingFeature) attachReload(reg *Registry) {
	reg.AddReloadObserver(f.name, func(snap shared.FeatureSnapshot) {
		f.enabled.Store(snap.Enabled)
	})
}

func TestRegisterPreservesRegistrationOrder(t *testing.T) {
	reg := NewRegistry()
	var log []string
	var mu sync.Mutex

	names := []string{"alpha", "beta", "gamma", "delta"}
	for _, n := range names {
		f := newRecordingFeature(n, &log, &mu)
		f.enabled.Store(true)
		reg.Register(f)
	}

	got := reg.Names()
	if len(got) != len(names) {
		t.Fatalf("Names() len = %d, want %d", len(got), len(names))
	}
	for i, n := range names {
		if got[i] != n {
			t.Fatalf("Names()[%d] = %q, want %q", i, got[i], n)
		}
	}

	var innerCalled atomic.Bool
	chain := reg.BuildChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled.Store(true)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if !innerCalled.Load() {
		t.Fatalf("inner handler not invoked")
	}
	if len(log) != len(names) {
		t.Fatalf("log len = %d (%v), want %d", len(log), log, len(names))
	}
	for i, n := range names {
		if log[i] != n {
			t.Fatalf("log[%d] = %q, want %q — chain order not preserved", i, log[i], n)
		}
	}
}

func TestRegisterPanicsOnDuplicateName(t *testing.T) {
	reg := NewRegistry()
	reg.Register(newRecordingFeature("dup", nil, nil))

	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic on duplicate registration")
		}
	}()
	reg.Register(newRecordingFeature("dup", nil, nil))
}

func TestRegisterPanicsOnNil(t *testing.T) {
	reg := NewRegistry()
	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic on nil Feature")
		}
	}()
	reg.Register(nil)
}

func TestRegisterPanicsOnEmptyName(t *testing.T) {
	reg := NewRegistry()
	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic on empty name")
		}
	}()
	reg.Register(newRecordingFeature("", nil, nil))
}

func TestReloadValidationAggregatesErrors(t *testing.T) {
	reg := NewRegistry()

	good := newRecordingFeature("good", nil, nil)
	bad1 := newRecordingFeature("bad1", nil, nil)
	bad1.validateErr = errors.New("bad1 failed")
	bad2 := newRecordingFeature("bad2", nil, nil)
	bad2.validateErr = errors.New("bad2 failed")

	reg.Register(good)
	reg.Register(bad1)
	reg.Register(bad2)

	// Seed a known-good snapshot so we can check that it's preserved.
	if err := reg.Reload(GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			"good": {Enabled: true, Version: 1},
		},
	}, nil); err == nil {
		// The previous Reload intentionally fails because bad1/bad2 report
		// validation errors — so we expect err != nil here. Fall through.
		t.Fatalf("expected first Reload to fail due to bad features")
	}

	// Now remove the faulty features to reach a baseline good state.
	good.validateErr = nil
	bad1.validateErr = nil
	bad2.validateErr = nil

	if err := reg.Reload(GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			"good": {Enabled: true, Version: 1},
			"bad1": {Enabled: true, Version: 1},
			"bad2": {Enabled: true, Version: 1},
		},
	}, nil); err != nil {
		t.Fatalf("expected baseline Reload to succeed, got %v", err)
	}
	baseline := reg.Globals()

	// Now make both fail again, across a tenant override too.
	bad1.validateErr = errors.New("bad1 failed")
	bad2.validateErr = errors.New("bad2 failed")

	tenants := map[string]TenantSnapshot{
		"host-a.tld": {
			Host:    "host-a.tld",
			Enabled: true,
			Features: map[string]shared.FeatureSnapshot{
				"bad1": {Enabled: true, Version: 2},
			},
		},
	}

	err := reg.Reload(GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			"good": {Enabled: true, Version: 2},
			"bad1": {Enabled: true, Version: 2},
			"bad2": {Enabled: true, Version: 2},
		},
	}, tenants)
	if err == nil {
		t.Fatalf("expected Reload to return error when features fail validation")
	}

	// Expected errors: bad1 globals, bad1 tenant-a, bad2 globals, bad2 tenant-a (since tenant-a
	// does not override bad2 so it inherits globals which also fails).
	expectSubstrings := []string{
		`feature "bad1" globals`,
		`feature "bad1" tenant "host-a.tld"`,
		`feature "bad2" globals`,
		`feature "bad2" tenant "host-a.tld"`,
	}
	msg := err.Error()
	for _, s := range expectSubstrings {
		if !strings.Contains(msg, s) {
			t.Errorf("joined error missing substring %q; got: %s", s, msg)
		}
	}

	// errors.Is should find at least one of the underlying errors when
	// the failing feature's error is in the chain.
	if !errors.Is(err, bad1.validateErr) {
		// errors.Join wraps via the %w pattern through fmt.Errorf so Is
		// must traverse. If our Join invocation ever changes this check
		// will catch it.
		t.Errorf("expected errors.Is to find bad1 validateErr in joined error")
	}

	// Old snapshot must still be live: baseline's good-version=1 persists.
	current := reg.Globals()
	if current.Features["good"].Version != baseline.Features["good"].Version {
		t.Errorf("expected old snapshot to be preserved after failed Reload; got version %d want %d",
			current.Features["good"].Version, baseline.Features["good"].Version)
	}
}

func TestBuildChainWithDisabledFeatureIsPassThrough(t *testing.T) {
	reg := NewRegistry()

	// A feature whose middleware panics if ever invoked while enabled.
	trap := newRecordingFeature("trap", nil, nil)
	trap.panicIfInvoked = true
	trap.attachReload(reg)

	reg.Register(trap)

	if err := reg.Reload(GlobalsSnapshot{
		Features: map[string]shared.FeatureSnapshot{
			"trap": {Enabled: false},
		},
	}, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	var innerCalled atomic.Bool
	chain := reg.BuildChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled.Store(true)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if !innerCalled.Load() {
		t.Fatalf("inner handler not invoked with disabled trap feature")
	}
}

func TestReloadAtomicityUnderConcurrency(t *testing.T) {
	reg := NewRegistry()

	const featureCount = 5
	feats := make([]*recordingFeature, featureCount)
	for i := 0; i < featureCount; i++ {
		f := newRecordingFeature(fmt.Sprintf("f%d", i), nil, nil)
		f.attachReload(reg)
		reg.Register(f)
		feats[i] = f
	}

	// Start with every feature enabled so middleware doesn't short-circuit.
	initial := GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
	for _, f := range feats {
		initial.Features[f.Name()] = shared.FeatureSnapshot{Enabled: true, Version: 0}
	}
	if err := reg.Reload(initial, nil); err != nil {
		t.Fatalf("initial Reload: %v", err)
	}

	chain := reg.BuildChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	var (
		wg          sync.WaitGroup
		stop        atomic.Bool
		reloads     atomic.Int64
		requests    atomic.Int64
		reloadErrs  atomic.Int64
		requestErrs atomic.Int64
	)

	// 50 request goroutines.
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
				// Attach a tenant so the resolver touches tenant map.
				req = req.WithContext(WithTenant(req.Context(), &TenantSnapshot{
					Host:    "example.tld",
					Enabled: true,
					Features: map[string]shared.FeatureSnapshot{
						"f0": {Enabled: true, Version: 1},
					},
				}))
				rec := httptest.NewRecorder()
				func() {
					defer func() {
						if r := recover(); r != nil {
							requestErrs.Add(1)
						}
					}()
					chain.ServeHTTP(rec, req)
				}()
				if rec.Code != http.StatusOK {
					requestErrs.Add(1)
				}
				requests.Add(1)
			}
		}()
	}

	// Reload driver: 100 reloads, alternating state.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		for i := 0; i < 100; i++ {
			g := GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
			for j, f := range feats {
				g.Features[f.Name()] = shared.FeatureSnapshot{
					Enabled: (i+j)%2 == 0,
					Version: uint64(i + 1),
				}
			}
			if err := reg.Reload(g, nil); err != nil {
				reloadErrs.Add(1)
			}
			reloads.Add(1)
		}
	}()

	wg.Wait()

	if reloadErrs.Load() != 0 {
		t.Fatalf("Reload returned error %d times", reloadErrs.Load())
	}
	if requestErrs.Load() != 0 {
		t.Fatalf("request goroutines observed %d errors/panics", requestErrs.Load())
	}
	if reloads.Load() != 100 {
		t.Fatalf("expected 100 reloads, got %d", reloads.Load())
	}
	if requests.Load() == 0 {
		t.Fatalf("no requests ran during concurrency test")
	}
}

func TestReloadObserverReceivesGlobalsSnapshot(t *testing.T) {
	reg := NewRegistry()
	var received []shared.FeatureSnapshot
	var mu sync.Mutex

	f := newRecordingFeature("obs", nil, nil)
	reg.Register(f)
	reg.AddReloadObserver("obs", func(snap shared.FeatureSnapshot) {
		mu.Lock()
		received = append(received, snap)
		mu.Unlock()
	})

	first := shared.FeatureSnapshot{Enabled: true, Version: 1}
	second := shared.FeatureSnapshot{Enabled: false, Version: 2}

	if err := reg.Reload(GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{"obs": first}}, nil); err != nil {
		t.Fatalf("first Reload: %v", err)
	}
	if err := reg.Reload(GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{"obs": second}}, nil); err != nil {
		t.Fatalf("second Reload: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("observer called %d times, want 2", len(received))
	}
	if !snapshotEqual(received[0], first) {
		t.Errorf("first call got %+v want %+v", received[0], first)
	}
	if !snapshotEqual(received[1], second) {
		t.Errorf("second call got %+v want %+v", received[1], second)
	}
}

// snapshotEqual compares two FeatureSnapshot values by scalar fields plus
// Params length — tests in this package only ever use empty Params, so a
// length check is sufficient and lets us avoid pulling reflect.DeepEqual.
func snapshotEqual(a, b shared.FeatureSnapshot) bool {
	if a.Enabled != b.Enabled || a.Version != b.Version {
		return false
	}
	return len(a.Params) == len(b.Params)
}

func TestReloadObserverAcrossMultipleFeaturesFiresIndependently(t *testing.T) {
	reg := NewRegistry()

	fA := newRecordingFeature("a", nil, nil)
	fB := newRecordingFeature("b", nil, nil)
	reg.Register(fA)
	reg.Register(fB)

	var (
		calls sync.Map
	)
	reg.AddReloadObserver("a", func(snap shared.FeatureSnapshot) {
		v, _ := calls.LoadOrStore("a", new(atomic.Int64))
		v.(*atomic.Int64).Add(1)
	})
	reg.AddReloadObserver("b", func(snap shared.FeatureSnapshot) {
		v, _ := calls.LoadOrStore("b", new(atomic.Int64))
		v.(*atomic.Int64).Add(1)
	})

	if err := reg.Reload(GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{
		"a": {Enabled: true},
		"b": {Enabled: false},
	}}, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	for _, k := range []string{"a", "b"} {
		v, ok := calls.Load(k)
		if !ok {
			t.Fatalf("observer for %q not called", k)
		}
		if got := v.(*atomic.Int64).Load(); got != 1 {
			t.Errorf("observer for %q called %d times, want 1", k, got)
		}
	}
}

func TestReloadHandlesNilFeaturesMap(t *testing.T) {
	reg := NewRegistry()
	f := newRecordingFeature("x", nil, nil)
	reg.Register(f)
	if err := reg.Reload(GlobalsSnapshot{}, nil); err != nil {
		t.Fatalf("Reload with nil features map: %v", err)
	}
	if reg.Globals().Features == nil {
		t.Fatalf("Globals().Features is nil after Reload")
	}
}
