package admin

import (
	"bytes"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	validSlug   = "abcdefghijklmnopqrstuvwxyz012345"
	validToken1 = "TOKENONEaaaaaaaaaaaaaaaaaaaaaaaa"
	validToken2 = "TOKENTWObbbbbbbbbbbbbbbbbbbbbbbb"
)

func validCfg() Config {
	return Config{
		Enabled: true,
		Slug:    validSlug,
		Token1:  validToken1,
		Token2:  validToken2,
	}
}

func serve(g *Gate, path string) *http.Response {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	return rec.Result()
}

func TestMatchValidPath(t *testing.T) {
	g := New(validCfg())
	path := "/" + validSlug + "/" + validToken1 + "/" + validToken2
	if !g.MatchesPrefix(path) {
		t.Fatalf("expected MatchesPrefix true for exact match")
	}
	resp := serve(g, path)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("want 501, got %d", resp.StatusCode)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "0" {
		t.Fatalf("want Content-Length 0, got %q", cl)
	}
}

func TestMatchValidPathWithTail(t *testing.T) {
	g := New(validCfg())
	path := "/" + validSlug + "/" + validToken1 + "/" + validToken2 + "/api/v1/tenants"
	if !g.MatchesPrefix(path) {
		t.Fatalf("expected MatchesPrefix true when extra segments follow")
	}
	if serve(g, path).StatusCode != http.StatusNotImplemented {
		t.Fatalf("want 501 for matched path with tail")
	}
}

func TestWrongSlug(t *testing.T) {
	g := New(validCfg())
	// flip one char in slug
	bad := "Abcdefghijklmnopqrstuvwxyz012345"
	path := "/" + bad + "/" + validToken1 + "/" + validToken2
	if g.MatchesPrefix(path) {
		t.Fatalf("expected false for wrong slug")
	}
	expect404(t, serve(g, path))
}

func TestWrongToken1(t *testing.T) {
	g := New(validCfg())
	bad := "XOKENONEaaaaaaaaaaaaaaaaaaaaaaaa"
	path := "/" + validSlug + "/" + bad + "/" + validToken2
	if g.MatchesPrefix(path) {
		t.Fatalf("expected false for wrong token1")
	}
	expect404(t, serve(g, path))
}

func TestWrongToken2(t *testing.T) {
	g := New(validCfg())
	bad := "XOKENTWObbbbbbbbbbbbbbbbbbbbbbbb"
	path := "/" + validSlug + "/" + validToken1 + "/" + bad
	if g.MatchesPrefix(path) {
		t.Fatalf("expected false for wrong token2")
	}
	expect404(t, serve(g, path))
}

func TestTooFewSegments(t *testing.T) {
	g := New(validCfg())
	cases := []string{
		"/",
		"/" + validSlug,
		"/" + validSlug + "/" + validToken1,
		"/" + validSlug + "/" + validToken1 + "/",
	}
	for _, p := range cases {
		if g.MatchesPrefix(p) {
			t.Fatalf("path %q should not match", p)
		}
		expect404(t, serve(g, p))
	}
}

func TestEmptyPath(t *testing.T) {
	g := New(validCfg())
	if g.MatchesPrefix("") {
		t.Fatal("empty path must not match")
	}
	expect404(t, serve(g, "/"))
}

func TestDisabledGateIgnoresCorrectPath(t *testing.T) {
	cfg := validCfg()
	cfg.Enabled = false
	g := New(cfg)
	if g.Enabled() {
		t.Fatal("Enabled() should be false")
	}
	path := "/" + validSlug + "/" + validToken1 + "/" + validToken2
	if g.MatchesPrefix(path) {
		t.Fatal("disabled gate must never match")
	}
	expect404(t, serve(g, path))
}

func TestDisabledIfAnySecretEmpty(t *testing.T) {
	for _, cfg := range []Config{
		{Enabled: true, Slug: "", Token1: validToken1, Token2: validToken2},
		{Enabled: true, Slug: validSlug, Token1: "", Token2: validToken2},
		{Enabled: true, Slug: validSlug, Token1: validToken1, Token2: ""},
	} {
		g := New(cfg)
		if g.Enabled() {
			t.Fatalf("cfg %+v should produce disabled gate", cfg)
		}
	}
}

func TestNoLogOutput(t *testing.T) {
	// Capture all slog output for the duration of this test. A well-behaved
	// gate must emit zero log lines, let alone lines containing secrets.
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	g := New(validCfg())
	good := "/" + validSlug + "/" + validToken1 + "/" + validToken2
	bad := "/" + validSlug + "/WRONG/" + validToken2

	// httptest.NewRequest rejects the empty string, so exercise MatchesPrefix
	// directly for the truly-empty path and go through ServeHTTP for the rest.
	g.MatchesPrefix("")
	for _, p := range []string{good, bad, "/", "/only/two"} {
		serve(g, p)
	}

	out := buf.String()
	if out != "" {
		t.Fatalf("gate produced log output: %q", out)
	}
	// Belt-and-braces: secrets must never surface even if someone adds
	// unrelated logging elsewhere in the package later.
	for _, secret := range []string{validSlug, validToken1, validToken2} {
		if strings.Contains(out, secret) {
			t.Fatalf("log output leaked secret %q", secret)
		}
	}
}

func TestEnabledAccessor(t *testing.T) {
	if !New(validCfg()).Enabled() {
		t.Fatal("valid cfg should report Enabled() true")
	}
	cfg := validCfg()
	cfg.Enabled = false
	if New(cfg).Enabled() {
		t.Fatal("disabled cfg should report Enabled() false")
	}
}

// TestTiming is the long-mode timing test. It is intentionally slow because
// constant-time assertions require enough iterations to reject noise. The
// assertion is deliberately loose (3x stddev, i.e. ~99.7% under a normal
// assumption) — the goal is to catch order-of-magnitude regressions like a
// naive byte loop that bails on first mismatch, not to prove cryptographic
// bounds.
func TestTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}
	g := New(validCfg())
	disabledG := New(Config{Enabled: false})

	const iters = 1000

	// correct path
	correct := "/" + validSlug + "/" + validToken1 + "/" + validToken2
	// mismatch at byte 0 of slug
	slugByte0 := []byte(validSlug)
	slugByte0[0] ^= 0xFF
	mismatch0 := "/" + string(slugByte0) + "/" + validToken1 + "/" + validToken2
	// mismatch at byte 31 of slug (last byte)
	slugByte31 := []byte(validSlug)
	slugByte31[len(slugByte31)-1] ^= 0xFF
	mismatch31 := "/" + string(slugByte31) + "/" + validToken1 + "/" + validToken2
	// disabled with correctly-shaped path
	disabledPath := correct

	// Warm caches, branch predictor, etc. Discard results.
	for i := 0; i < 2000; i++ {
		g.MatchesPrefix(correct)
		g.MatchesPrefix(mismatch0)
		g.MatchesPrefix(mismatch31)
		disabledG.MatchesPrefix(disabledPath)
	}

	// Per-call latency is on the order of tens of nanoseconds; Windows'
	// time.Now resolution can be coarser than that, so each "sample" runs
	// batchSize calls and reports the mean nanoseconds per call. That gets
	// the distribution into a range where stddev is meaningful.
	const batchSize = 2000

	measure := func(gate *Gate, path string) (mean, stddev float64) {
		samples := make([]float64, iters)
		for i := 0; i < iters; i++ {
			start := time.Now()
			for j := 0; j < batchSize; j++ {
				gate.MatchesPrefix(path)
			}
			samples[i] = float64(time.Since(start).Nanoseconds()) / float64(batchSize)
		}
		var sum float64
		for _, v := range samples {
			sum += v
		}
		mean = sum / float64(iters)
		var sq float64
		for _, v := range samples {
			d := v - mean
			sq += d * d
		}
		stddev = math.Sqrt(sq / float64(iters))
		return
	}

	meanA, stdA := measure(disabledG, disabledPath)
	meanB, stdB := measure(g, mismatch0)
	meanC, stdC := measure(g, mismatch31)
	meanD, stdD := measure(g, correct)

	diffBC := math.Abs(meanC - meanB)
	// 3-sigma of the byte-0 distribution. Tightening further produces
	// flaky CI on shared runners.
	threshold := 3 * stdB

	t.Logf("disabled:    mean=%.1fns stddev=%.1fns", meanA, stdA)
	t.Logf("mismatch@0:  mean=%.1fns stddev=%.1fns", meanB, stdB)
	t.Logf("mismatch@31: mean=%.1fns stddev=%.1fns", meanC, stdC)
	t.Logf("correct:     mean=%.1fns stddev=%.1fns", meanD, stdD)
	t.Logf("|mean(c)-mean(b)| = %.1fns   3*stddev(b) = %.1fns   ratio = %.3f",
		diffBC, threshold, meanC/meanB)

	if diffBC >= threshold {
		t.Fatalf("byte-0 vs byte-31 mismatch timings differ by %.1fns, exceeds 3*stddev=%.1fns",
			diffBC, threshold)
	}
}

// TestGate_DisabledEqualsMismatchTiming asserts that calling
// MatchesPrefix on a valid path against a disabled gate takes roughly
// the same time as calling it with a mismatched path on an enabled
// gate. An attacker probing the edge can see only wall-clock latency;
// if the disabled branch were faster than the enabled-but-wrong branch,
// they could distinguish a not-yet-provisioned admin from one whose
// secrets they simply haven't guessed, which leaks deployment state.
//
// The assertion uses a 3-sigma envelope on the enabled-mismatch
// population, matching the looseness of TestTiming — the goal is to
// catch order-of-magnitude regressions, not to prove cryptographic
// bounds. Skipped in short mode.
func TestGate_DisabledEqualsMismatchTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	enabled := New(validCfg())
	disabled := New(Config{Enabled: false})

	good := "/" + validSlug + "/" + validToken1 + "/" + validToken2
	// Mismatch at byte 0 of slug — the canonical "wrong" path that
	// still structurally parses as three segments.
	slugByte0 := []byte(validSlug)
	slugByte0[0] ^= 0xFF
	mismatch := "/" + string(slugByte0) + "/" + validToken1 + "/" + validToken2

	// Warm caches, branch predictor, JIT paths.
	for i := 0; i < 1000; i++ {
		disabled.MatchesPrefix(good)
		enabled.MatchesPrefix(good)
		enabled.MatchesPrefix(mismatch)
	}

	// The spec asks for 2000 iterations per scenario. Each "iter" is a
	// timed batch so the noise floor is well above time.Now resolution;
	// batchSize=200 keeps the per-scenario cost manageable under the
	// race detector while still giving several microseconds of call
	// work per sample (well above Windows clock resolution).
	const iters = 2000
	const batchSize = 200

	measure := func(gate *Gate, path string) (mean, stddev float64) {
		samples := make([]float64, iters)
		for i := 0; i < iters; i++ {
			start := time.Now()
			for j := 0; j < batchSize; j++ {
				gate.MatchesPrefix(path)
			}
			samples[i] = float64(time.Since(start).Nanoseconds()) / float64(batchSize)
		}
		var sum float64
		for _, v := range samples {
			sum += v
		}
		mean = sum / float64(iters)
		var sq float64
		for _, v := range samples {
			d := v - mean
			sq += d * d
		}
		stddev = math.Sqrt(sq / float64(iters))
		return
	}

	meanA, stdA := measure(disabled, good)                // (a) valid path, gate disabled
	meanB, stdB := measure(enabled, good)                 // (b) valid path, gate enabled (match)
	meanC, stdC := measure(enabled, mismatch)             // (c) invalid path, gate enabled (mismatch)

	diffAC := math.Abs(meanA - meanC)
	threshold := 3 * stdC

	t.Logf("(a) disabled+valid:   mean=%.1fns stddev=%.1fns", meanA, stdA)
	t.Logf("(b) enabled +valid:   mean=%.1fns stddev=%.1fns", meanB, stdB)
	t.Logf("(c) enabled +invalid: mean=%.1fns stddev=%.1fns", meanC, stdC)
	t.Logf("|mean(a)-mean(c)| = %.1fns   3*stddev(c) = %.1fns   ratio = %.3f",
		diffAC, threshold, meanA/meanC)

	if diffAC >= threshold {
		t.Fatalf("disabled+valid vs enabled+invalid timings differ by %.1fns, exceeds 3*stddev=%.1fns",
			diffAC, threshold)
	}
}

// TestGate_DelegateWithHandlerStripsPrefix verifies that SetHandler
// installs a backend and that ServeHTTP delivers requests to it with
// the gate prefix removed from r.URL.Path. The backend records the
// observed path so the assertion is on the slug-stripped form.
func TestGate_DelegateWithHandlerStripsPrefix(t *testing.T) {
	g := New(validCfg())

	var seen string
	g.SetHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct{ in, want string }{
		{"/" + validSlug + "/" + validToken1 + "/" + validToken2, "/"},
		{"/" + validSlug + "/" + validToken1 + "/" + validToken2 + "/", "/"},
		{"/" + validSlug + "/" + validToken1 + "/" + validToken2 + "/api/me", "/api/me"},
	}
	for _, tc := range cases {
		seen = ""
		resp := serve(g, tc.in)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("path %q: want 200, got %d", tc.in, resp.StatusCode)
		}
		if seen != tc.want {
			t.Fatalf("path %q: backend saw %q, want %q", tc.in, seen, tc.want)
		}
	}
}

// TestGate_NoHandlerReturns501 confirms the backward-compatible default:
// a Gate with no installed handler still emits the P1 501 stub on a
// matching path.
func TestGate_NoHandlerReturns501(t *testing.T) {
	g := New(validCfg())
	path := "/" + validSlug + "/" + validToken1 + "/" + validToken2
	resp := serve(g, path)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("want 501 with no handler, got %d", resp.StatusCode)
	}
}

// TestGate_HandlerCleared confirms SetHandler(nil) reverts to the 501
// fallback. The pointer must be cleared atomically with respect to
// in-flight requests; this just covers the visibility of the unset.
func TestGate_HandlerCleared(t *testing.T) {
	g := New(validCfg())
	g.SetHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	g.SetHandler(nil)
	path := "/" + validSlug + "/" + validToken1 + "/" + validToken2
	resp := serve(g, path)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("after clear: want 501, got %d", resp.StatusCode)
	}
}

// TestGate_DelegateMismatchStill404 confirms that installing a handler
// does not weaken mismatch handling — a non-matching path still gets
// the stealth 404 even when a backend is wired.
func TestGate_DelegateMismatchStill404(t *testing.T) {
	g := New(validCfg())
	called := false
	g.SetHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	resp := serve(g, "/wrong/path/segments/api")
	expect404(t, resp)
	if called {
		t.Fatal("backend invoked on a mismatched path")
	}
}

// TestGate_TimingWithHandler is the timing-parity guard for the new
// SetHandler code path. We compare three populations: disabled, enabled
// with no handler, and enabled with a no-op handler installed. The
// difference between enabled-no-handler and enabled-with-handler must
// stay inside 3-sigma of the no-handler distribution because the
// handler load is the only branch added to the hot path.
//
// Skipped in short mode.
func TestGate_TimingWithHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	disabled := New(Config{Enabled: false})
	noHandler := New(validCfg())
	withHandler := New(validCfg())
	withHandler.SetHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	good := "/" + validSlug + "/" + validToken1 + "/" + validToken2

	for i := 0; i < 1000; i++ {
		disabled.MatchesPrefix(good)
		noHandler.MatchesPrefix(good)
		withHandler.MatchesPrefix(good)
	}

	const iters = 1000
	const batchSize = 500

	measure := func(gate *Gate, path string) (mean, stddev float64) {
		samples := make([]float64, iters)
		for i := 0; i < iters; i++ {
			start := time.Now()
			for j := 0; j < batchSize; j++ {
				gate.MatchesPrefix(path)
			}
			samples[i] = float64(time.Since(start).Nanoseconds()) / float64(batchSize)
		}
		var sum float64
		for _, v := range samples {
			sum += v
		}
		mean = sum / float64(iters)
		var sq float64
		for _, v := range samples {
			d := v - mean
			sq += d * d
		}
		stddev = math.Sqrt(sq / float64(iters))
		return
	}

	meanD, stdD := measure(disabled, good)
	meanN, stdN := measure(noHandler, good)
	meanH, stdH := measure(withHandler, good)

	t.Logf("disabled:    mean=%.1fns stddev=%.1fns", meanD, stdD)
	t.Logf("no handler:  mean=%.1fns stddev=%.1fns", meanN, stdN)
	t.Logf("w/ handler:  mean=%.1fns stddev=%.1fns", meanH, stdH)

	// MatchesPrefix is unchanged across the no-handler/with-handler
	// boundary — handler delegation lives in ServeHTTP. The assertion
	// here is just that adding SetHandler() didn't accidentally
	// regress the prefix-match hot path.
	diff := math.Abs(meanH - meanN)
	threshold := 3 * stdN
	if diff >= threshold {
		t.Fatalf("MatchesPrefix timings differ by %.1fns between no-handler/with-handler, exceeds 3*stddev=%.1fns",
			diff, threshold)
	}
}

func expect404(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "0" {
		t.Fatalf("want Content-Length 0, got %q", cl)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		t.Fatalf("404 response should have no Content-Type, got %q", ct)
	}
	if s := resp.Header.Get("Server"); s != "" {
		t.Fatalf("404 response should have no Server header, got %q", s)
	}
	if resp.ContentLength > 0 {
		t.Fatalf("404 must have empty body, got ContentLength=%d", resp.ContentLength)
	}
}
