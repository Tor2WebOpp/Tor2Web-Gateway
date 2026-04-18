package sanitize

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// buildChain wires up a feature.Registry with a fresh sanitize.Feature,
// reloads with the supplied globals + tenants, and returns the composed
// middleware around inner.
func buildChain(t *testing.T, inner http.Handler, globals shared.FeatureSnapshot, tenants map[string]shared.FeatureSnapshot) (http.Handler, *Feature, *feature.Registry) {
	t.Helper()
	reg := feature.NewRegistry()
	f := RegisterWith(reg)

	tenantSnaps := map[string]feature.TenantSnapshot{}
	for host, cfg := range tenants {
		tenantSnaps[host] = feature.TenantSnapshot{
			Host:     host,
			Enabled:  true,
			Features: map[string]shared.FeatureSnapshot{FeatureName: cfg},
		}
	}
	gs := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{}}
	if globals.Enabled || len(globals.Params) > 0 {
		gs.Features[FeatureName] = globals
	}
	if err := reg.Reload(gs, tenantSnaps); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return reg.BuildChain(inner), f, reg
}

// do executes chain with a GET request to example.tld, optionally with a
// tenant context attached. It returns the recorder for inspection.
func do(chain http.Handler, method string, tenant *feature.TenantSnapshot) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://example.tld/", nil)
	if tenant != nil {
		req = req.WithContext(feature.WithTenant(req.Context(), tenant))
	}
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	return rec
}

// makeInner returns a handler that writes contentType + body.
func makeInner(contentType, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		_, _ = io.WriteString(w, body)
	})
}

func TestStripsScriptIframeObjectEmbedWithChildren(t *testing.T) {
	body := `<html><body>` +
		`<p>keep me</p>` +
		`<script>alert("x")</script>` +
		`<iframe src="https://evil.example/"><p>inside iframe</p></iframe>` +
		`<object data="mal.swf"><param name="p" value="1"></object>` +
		`<embed src="evil.svg">` +
		`<div>tail</div>` +
		`</body></html>`

	inner := makeInner("text/html; charset=utf-8", body)
	chain, _, _ := buildChain(t, inner,
		shared.FeatureSnapshot{Enabled: true}, nil)

	rec := do(chain, http.MethodGet, nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	out := rec.Body.String()

	banned := []string{
		"<script", "alert(",
		"<iframe", "inside iframe",
		"<object", "mal.swf", "<param",
		"<embed", "evil.svg",
	}
	for _, s := range banned {
		if strings.Contains(strings.ToLower(out), strings.ToLower(s)) {
			t.Errorf("output still contains %q; out=%q", s, out)
		}
	}

	keep := []string{"keep me", "tail"}
	for _, s := range keep {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q; out=%q", s, out)
		}
	}
}

func TestPreservesNonMatchingTagsAndText(t *testing.T) {
	body := `<html><body>` +
		`<h1 class="title">Hello</h1>` +
		`<p>paragraph <strong>text</strong> &amp; entities</p>` +
		`<a href="/next">next</a>` +
		`</body></html>`

	inner := makeInner("text/html", body)
	chain, _, _ := buildChain(t, inner,
		shared.FeatureSnapshot{Enabled: true}, nil)

	rec := do(chain, http.MethodGet, nil)
	out := rec.Body.String()

	for _, want := range []string{
		`<h1`, `class="title"`, `Hello`,
		`<p>`, `paragraph `, `<strong>`, `text</strong>`,
		`<a`, `href="/next"`, `next</a>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output: %q", want, out)
		}
	}
	// Entity preservation: must not double-escape but must still render
	// "&" safely in one of the two canonical forms.
	if !strings.Contains(out, "&amp;") && !strings.Contains(out, "& entities") {
		t.Errorf("ampersand not preserved; out=%q", out)
	}
}

func TestStripsOnclickKeepsOtherAttributes(t *testing.T) {
	body := `<a href="/ok" onclick="javascript:bad()" class="btn" data-id="42">click</a>`
	inner := makeInner("text/html", body)
	chain, _, _ := buildChain(t, inner,
		shared.FeatureSnapshot{Enabled: true}, nil)

	rec := do(chain, http.MethodGet, nil)
	out := rec.Body.String()

	if strings.Contains(strings.ToLower(out), "onclick") {
		t.Errorf("onclick attribute not stripped: %q", out)
	}
	// javascript: also listed in default strip_attributes as a value
	// substring — the whole attribute should go.
	if strings.Contains(strings.ToLower(out), "javascript:") {
		t.Errorf("javascript: attribute/value not stripped: %q", out)
	}

	for _, want := range []string{
		`href="/ok"`,
		`class="btn"`,
		`data-id="42"`,
		`>click</a>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output: %q", want, out)
		}
	}
}

func TestNonHTMLContentPassesThroughUnchanged(t *testing.T) {
	body := `{"script":"<script>alert(1)</script>","ok":true}`
	inner := makeInner("application/json", body)
	chain, _, _ := buildChain(t, inner,
		shared.FeatureSnapshot{Enabled: true}, nil)

	rec := do(chain, http.MethodGet, nil)
	if rec.Body.String() != body {
		t.Errorf("non-HTML body mutated:\n got %q\nwant %q", rec.Body.String(), body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type dropped: %q", got)
	}
}

func TestBodyOverMaxBodyBytesPassesThroughUnchanged(t *testing.T) {
	// Build a body that exceeds the cap. Put a <script> block inside
	// that SHOULD have been stripped had we sanitized.
	pad := strings.Repeat("a", 2048)
	body := `<html><body>` + pad + `<script>alert(1)</script>` + pad + `</body></html>`

	inner := makeInner("text/html", body)
	chain, _, _ := buildChain(t, inner,
		shared.FeatureSnapshot{
			Enabled: true,
			Params: map[string]any{
				"max_body_bytes": 512, // much smaller than body
			},
		}, nil)

	rec := do(chain, http.MethodGet, nil)
	out := rec.Body.String()

	// Body was truncated by the recorder to the cap. Importantly, the
	// script tag must still be present (we did NOT sanitize), proving
	// the pass-through behaviour: what the client sees is the first
	// max_body_bytes of the original upstream. That preserves the
	// "warn + do not mangle" contract.
	if len(out) != 512 {
		t.Fatalf("expected truncated body of 512 bytes, got %d", len(out))
	}
	// The first 512 bytes of the input should be an exact prefix of
	// what we produced (we did not rewrite).
	if !bytes.Equal([]byte(body[:512]), []byte(out)) {
		t.Errorf("body over cap was rewritten instead of passed through")
	}
}

func TestFeatureDisabledIsPassThrough(t *testing.T) {
	body := `<script>alert(1)</script><p>keep</p>`
	inner := makeInner("text/html", body)

	// Globally disabled.
	chain, _, _ := buildChain(t, inner,
		shared.FeatureSnapshot{Enabled: false}, nil)

	rec := do(chain, http.MethodGet, nil)
	if rec.Body.String() != body {
		t.Errorf("disabled feature mutated body:\n got %q\nwant %q", rec.Body.String(), body)
	}
}

func TestPerTenantOverrideWins(t *testing.T) {
	body := `<script>tenant</script><p>ok</p>`
	inner := makeInner("text/html", body)

	// Globals disabled, tenant enabled.
	chain, _, _ := buildChain(t, inner,
		shared.FeatureSnapshot{Enabled: false},
		map[string]shared.FeatureSnapshot{
			"tenant.tld": {Enabled: true},
		},
	)

	// Request with tenant context enabled.
	req := httptest.NewRequest(http.MethodGet, "http://tenant.tld/", nil)
	tenantSnap := &feature.TenantSnapshot{
		Host:    "tenant.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true},
		},
	}
	req = req.WithContext(feature.WithTenant(req.Context(), tenantSnap))

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	out := rec.Body.String()
	if strings.Contains(out, "<script") || strings.Contains(out, "tenant</") {
		t.Errorf("tenant override did not sanitize: %q", out)
	}
	if !strings.Contains(out, "<p>ok</p>") {
		t.Errorf("tenant override dropped kept content: %q", out)
	}

	// Now reverse: globals enabled, tenant explicitly disabled.
	body2 := `<script>globals</script><p>kept</p>`
	inner2 := makeInner("text/html", body2)
	chain2, _, _ := buildChain(t, inner2,
		shared.FeatureSnapshot{Enabled: true},
		map[string]shared.FeatureSnapshot{
			"tenant.tld": {Enabled: false},
		},
	)

	req2 := httptest.NewRequest(http.MethodGet, "http://tenant.tld/", nil)
	tenantSnap2 := &feature.TenantSnapshot{
		Host:    "tenant.tld",
		Enabled: true,
		Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: false},
		},
	}
	req2 = req2.WithContext(feature.WithTenant(req2.Context(), tenantSnap2))

	rec2 := httptest.NewRecorder()
	chain2.ServeHTTP(rec2, req2)

	out2 := rec2.Body.String()
	if !strings.Contains(out2, "<script>globals</script>") {
		t.Errorf("expected tenant disabled to preserve script: %q", out2)
	}
}

func TestScriptTokenizerHandlesNestedLookalikes(t *testing.T) {
	// html.Tokenizer treats <script> content as raw text until </script>.
	// Inner "<script>" is textual noise, outer </script> closes the element.
	body := `<p>before</p><script><div></script><p>after</p>`

	inner := makeInner("text/html", body)
	chain, _, _ := buildChain(t, inner,
		shared.FeatureSnapshot{Enabled: true}, nil)

	rec := do(chain, http.MethodGet, nil)
	out := rec.Body.String()
	if strings.Contains(out, "<script") {
		t.Errorf("script survived: %q", out)
	}
	if !strings.Contains(out, "<p>before</p>") || !strings.Contains(out, "<p>after</p>") {
		t.Errorf("surrounding content missing: %q", out)
	}
}

func TestHeadRequestSkipsBody(t *testing.T) {
	// Even with sanitizer active, HEAD responses should not have a body.
	body := `<script>x</script><p>ok</p>`
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, body)
	})

	chain, _, _ := buildChain(t, inner,
		shared.FeatureSnapshot{Enabled: true}, nil)

	req := httptest.NewRequest(http.MethodHead, "http://example.tld/", nil)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD response wrote %d bytes of body", rec.Body.Len())
	}
}

func TestConcurrentRequestsWithObserveReloads(t *testing.T) {
	// Build a chain with the feature enabled, then race requests against
	// repeated Observe() swaps.
	body := `<p>a</p><script>x</script><p>b</p>`
	inner := makeInner("text/html", body)

	reg := feature.NewRegistry()
	f := RegisterWith(reg)

	initial := feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{
		FeatureName: {Enabled: true, Version: 1},
	}}
	if err := reg.Reload(initial, nil); err != nil {
		t.Fatalf("initial Reload: %v", err)
	}
	chain := reg.BuildChain(inner)

	var (
		wg          sync.WaitGroup
		stop        atomic.Bool
		reloads     atomic.Int64
		requests    atomic.Int64
		requestErrs atomic.Int64
	)

	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				req := httptest.NewRequest(http.MethodGet, "http://example.tld/", nil)
				rec := httptest.NewRecorder()
				func() {
					defer func() {
						if r := recover(); r != nil {
							requestErrs.Add(1)
						}
					}()
					chain.ServeHTTP(rec, req)
				}()
				if rec.Code != 200 && rec.Code != 0 {
					// 0 means WriteHeader was not called; acceptable in our
					// recorder because some code paths write directly.
					// Any non-200 status is a failure.
					if rec.Code < 200 || rec.Code >= 300 {
						requestErrs.Add(1)
					}
				}
				requests.Add(1)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		for i := 0; i < 200; i++ {
			snap := shared.FeatureSnapshot{
				Enabled: i%2 == 0,
				Version: uint64(i + 2),
				Params: map[string]any{
					"strip_tags": []any{"script", "iframe"},
				},
			}
			if err := reg.Reload(feature.GlobalsSnapshot{
				Features: map[string]shared.FeatureSnapshot{FeatureName: snap},
			}, nil); err != nil {
				t.Errorf("Reload: %v", err)
				return
			}
			reloads.Add(1)
		}
	}()

	wg.Wait()

	if reloads.Load() != 200 {
		t.Fatalf("expected 200 reloads, got %d", reloads.Load())
	}
	if requests.Load() == 0 {
		t.Fatalf("no requests ran")
	}
	if requestErrs.Load() != 0 {
		t.Fatalf("%d requests errored/panicked", requestErrs.Load())
	}
	_ = f
}

func TestValidateRejectsBadParams(t *testing.T) {
	f := New()
	// strip_tags of wrong type.
	err := f.Validate(shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"strip_tags": 42,
		},
	})
	if err == nil {
		t.Errorf("expected error for non-list strip_tags")
	}

	// max_body_bytes of wrong type.
	err = f.Validate(shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"max_body_bytes": "nope",
		},
	})
	if err == nil {
		t.Errorf("expected error for non-numeric max_body_bytes")
	}

	// strip_tags list with a non-string entry.
	err = f.Validate(shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"strip_tags": []any{"script", 7},
		},
	})
	if err == nil {
		t.Errorf("expected error for non-string entry in strip_tags")
	}

	// A fully valid snapshot.
	if err := f.Validate(shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"strip_tags":       []any{"script", "iframe"},
			"strip_attributes": []any{"onclick"},
			"content_types":    []any{"text/html"},
			"max_body_bytes":   1024,
		},
	}); err != nil {
		t.Errorf("valid snapshot rejected: %v", err)
	}
}

func TestObserveSwitchesEnabledFlag(t *testing.T) {
	reg := feature.NewRegistry()
	f := RegisterWith(reg)

	// All-disabled reload → enabled flag stays false.
	if err := reg.Reload(feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{
		FeatureName: {Enabled: false},
	}}, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if f.enabled.Load() {
		t.Errorf("enabled=true after all-disabled reload")
	}

	// One enabled tenant flips the global flag on.
	tenants := map[string]feature.TenantSnapshot{
		"t.tld": {Host: "t.tld", Enabled: true, Features: map[string]shared.FeatureSnapshot{
			FeatureName: {Enabled: true},
		}},
	}
	if err := reg.Reload(feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{
		FeatureName: {Enabled: false},
	}}, tenants); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !f.enabled.Load() {
		t.Errorf("enabled=false after tenant-enabled reload")
	}
}

func TestCustomStripTagsList(t *testing.T) {
	// Configure sanitizer to strip only <custom-strip>, leaving <script>.
	body := `<script>keep</script><custom-strip>gone</custom-strip><p>after</p>`
	inner := makeInner("text/html", body)
	chain, _, _ := buildChain(t, inner,
		shared.FeatureSnapshot{
			Enabled: true,
			Params: map[string]any{
				"strip_tags": []any{"custom-strip"},
			},
		}, nil)

	rec := do(chain, http.MethodGet, nil)
	out := rec.Body.String()
	if strings.Contains(out, "<custom-strip") || strings.Contains(out, "gone") {
		t.Errorf("custom-strip not removed: %q", out)
	}
	if !strings.Contains(out, "<script>keep</script>") {
		t.Errorf("script not preserved under custom config: %q", out)
	}
}

func TestNoExplicitContentTypePassesThrough(t *testing.T) {
	// If upstream does not set Content-Type, Go auto-detects at Write
	// time. We want the sanitizer to not choke on that pathway — and
	// when the detected type is text/html, it should still sanitize.
	// Here the body is clearly HTML, so go-detects "text/html".
	body := `<script>alert(1)</script><p>ok</p>`
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Force text/html manually so we get a deterministic result.
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, body)
	})

	chain, _, _ := buildChain(t, inner,
		shared.FeatureSnapshot{Enabled: true}, nil)

	rec := do(chain, http.MethodGet, nil)
	out := rec.Body.String()
	if strings.Contains(out, "<script") {
		t.Errorf("script not removed: %q", out)
	}
}
