package door

import (
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gateway/internal/config"
	"gateway/internal/shared"
)

func newRedirectHarness(t *testing.T) (*RedirectHandler, *Selector) {
	t.Helper()
	sel := NewSelector()
	sel.UpdateMirrors([]shared.MirrorInfo{
		{Host: "mirror-a.example", Verdict: "live"},
	})
	slugs := []config.SlugConf{
		{Slug: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Strategy: config.StrategyRandom, Status: 302},
		{Slug: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Strategy: config.StrategyRandom, Status: 307},
	}
	return NewRedirectHandler(slugs, sel), sel
}

func TestRedirect_Match_Hits(t *testing.T) {
	h, _ := newRedirectHarness(t)
	slug, rest, ok := h.Match("/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/some/path")
	if !ok {
		t.Fatal("expected match")
	}
	if rest != "/some/path" {
		t.Errorf("rest = %q", rest)
	}
	if slug.Status != 302 {
		t.Errorf("slug status = %d", slug.Status)
	}
}

func TestRedirect_Match_NoSlugsNoMatch(t *testing.T) {
	sel := NewSelector()
	h := NewRedirectHandler(nil, sel)
	if _, _, ok := h.Match("/anything"); ok {
		t.Fatal("no-slug handler must always report false")
	}
}

func TestRedirect_Match_MismatchShort(t *testing.T) {
	h, _ := newRedirectHarness(t)
	if _, _, ok := h.Match("/short"); ok {
		t.Fatal("mismatch accepted")
	}
}

func TestRedirect_Match_MismatchLong(t *testing.T) {
	h, _ := newRedirectHarness(t)
	if _, _, ok := h.Match("/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaEXTRA/x"); ok {
		t.Fatal("too-long segment accepted")
	}
}

func TestRedirect_Match_RootPathNoMatch(t *testing.T) {
	h, _ := newRedirectHarness(t)
	if _, _, ok := h.Match("/"); ok {
		t.Fatal("root path matched a slug")
	}
}

func TestRedirect_ServeGET_WritesLocationAndStatus(t *testing.T) {
	h, _ := newRedirectHarness(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/landing?x=1", nil)
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	want := "https://mirror-a.example/landing?x=1"
	if loc != want {
		t.Errorf("Location = %q, want %q", loc, want)
	}
}

func TestRedirect_ServeGET_307OnConfiguredStatus(t *testing.T) {
	sel := NewSelector()
	sel.UpdateMirrors([]shared.MirrorInfo{{Host: "m.example", Verdict: "live"}})
	slugs := []config.SlugConf{
		{Slug: "ss", Strategy: config.StrategyRandom, Status: 307},
	}
	h := NewRedirectHandler(slugs, sel)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ss", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", rec.Code)
	}
}

func TestRedirect_ServeHEAD_200Empty(t *testing.T) {
	h, _ := newRedirectHarness(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if len(body) != 0 {
		t.Errorf("HEAD body must be empty, got %q", body)
	}
}

func TestRedirect_ServePOST_Returns405(t *testing.T) {
	h, _ := newRedirectHarness(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/whatever", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestRedirect_NonMatchingGET_Returns404(t *testing.T) {
	h, _ := newRedirectHarness(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/does-not-match", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestRedirect_NoLiveMirror_Returns503(t *testing.T) {
	sel := NewSelector() // empty
	slugs := []config.SlugConf{{Slug: "xx", Strategy: config.StrategyRandom, Status: 302}}
	h := NewRedirectHandler(slugs, sel)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/xx", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestRedirect_UpdateSlugs_HotReload(t *testing.T) {
	sel := NewSelector()
	sel.UpdateMirrors([]shared.MirrorInfo{{Host: "m.example", Verdict: "live"}})
	h := NewRedirectHandler(nil, sel)
	if _, _, ok := h.Match("/new"); ok {
		t.Fatal("empty handler must not match anything")
	}
	h.UpdateSlugs([]config.SlugConf{{Slug: "new", Strategy: config.StrategyRandom, Status: 302}})
	if _, _, ok := h.Match("/new"); !ok {
		t.Fatal("hot-reload did not activate slug")
	}
}

// TestRedirect_ConstantTimeMatch runs each scenario many times and
// verifies that the compare cost does not depend on where the first
// mismatch byte lies. Three inputs are measured:
//
//   - exact match,
//   - mismatch at byte 0,
//   - mismatch at byte 31 (last byte).
//
// A non-constant-time implementation would let the byte-31 variant
// take measurably longer than byte-0. We assert the wall-clock means
// are within the same order of magnitude — Windows clock resolution
// is ~15ms, so each measurement must encompass many millions of
// compares to avoid 0-duration samples. Order-of-magnitude ratio
// assertions are enough to catch any accidentally-reintroduced
// early-return.
func TestRedirect_ConstantTimeMatch(t *testing.T) {
	sel := NewSelector()
	slug := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 bytes
	h := NewRedirectHandler([]config.SlugConf{
		{Slug: slug, Strategy: config.StrategyRandom, Status: 302},
	}, sel)

	match := "/" + slug
	mismatch0 := "/" + "z" + slug[1:]
	mismatch31 := "/" + slug[:31] + "z"

	// 200_000 compares per sample ensures each measurement is well
	// above Windows' 15ms clock floor. We take the min over several
	// trials to reduce noise from scheduler pre-emption.
	const perTrial = 200_000
	const trials = 5
	measure := func(path string) time.Duration {
		best := time.Hour
		for trial := 0; trial < trials; trial++ {
			start := time.Now()
			for i := 0; i < perTrial; i++ {
				_, _, _ = h.Match(path)
			}
			dur := time.Since(start)
			if dur < best {
				best = dur
			}
		}
		return best
	}

	tMatch := measure(match)
	tM0 := measure(mismatch0)
	tM31 := measure(mismatch31)

	maxT := max3(tMatch, tM0, tM31)
	minT := min3(tMatch, tM0, tM31)
	if minT == 0 {
		// Extremely unlikely with perTrial=200_000, but guard so
		// division can't produce Inf.
		t.Fatalf("measurement too coarse: match=%v m0=%v m31=%v", tMatch, tM0, tM31)
	}
	ratio := float64(maxT) / float64(minT)
	// A non-constant-time compare would show ratio >> 1 between the
	// byte-0 and byte-31 mismatches. We accept up to 4x wall-clock
	// slack to absorb scheduler jitter; the constant-time
	// implementation routinely sits within 1.5x.
	if ratio > 4.0 {
		t.Fatalf("non-constant-time compare detected: ratio=%.2f match=%v mismatch0=%v mismatch31=%v",
			ratio, tMatch, tM0, tM31)
	}
	if math.IsInf(ratio, 0) {
		t.Fatalf("bad ratio math: match=%v m0=%v m31=%v", tMatch, tM0, tM31)
	}
}

func max3(a, b, c time.Duration) time.Duration {
	m := a
	if b > m {
		m = b
	}
	if c > m {
		m = c
	}
	return m
}

func min3(a, b, c time.Duration) time.Duration {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
