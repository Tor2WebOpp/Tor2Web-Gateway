package abuse

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gateway/internal/feature"
	"gateway/internal/shared"
)

// validOnion is a syntactically valid v3 .onion (56 base32 chars + ".onion").
const validOnion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"

// newTestFeature returns a Feature wired to a freshly opened store in a
// temp dir plus a snapshot with onion+reason required, enabled, and a
// tenant context helper. A per-test store path is used so tests may run
// in parallel safely.
func newTestFeature(t *testing.T) (*Feature, *Store, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "abuse.jsonl")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	f, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.SetStore(s)
	t.Cleanup(func() { _ = f.Close() })
	return f, s, path
}

// buildHandler assembles the handler chain used across tests: the
// abuse Feature middleware wrapping a downstream 404 responder. A
// direct-pointer resolver is used so tests control the effective
// snapshot without going through a Registry.
func buildHandler(f *Feature, tenantHost string, cfg shared.FeatureSnapshot) http.Handler {
	res := staticResolver{snap: cfg}
	mw := f.Middleware(&res)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	wrapped := mw(inner)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tenantHost != "" {
			r = r.WithContext(feature.WithTenant(r.Context(), &feature.TenantSnapshot{
				Host:    tenantHost,
				Enabled: true,
				Features: map[string]shared.FeatureSnapshot{
					FeatureName: cfg,
				},
			}))
		}
		wrapped.ServeHTTP(w, r)
	})
}

// staticResolver returns a pre-set snapshot for any request.
type staticResolver struct {
	snap shared.FeatureSnapshot
}

func (r *staticResolver) Resolve(_ *http.Request, _ string) shared.FeatureSnapshot {
	return r.snap
}

// enable sets the feature's atomic flag without going through a full
// Reload cycle. Matches what Observe would do after a global enable.
func enable(f *Feature) {
	f.enabled.Store(true)
}

func makeRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "203.0.113.7:51000"
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

func defaultSnapshot() shared.FeatureSnapshot {
	return shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"path":                "/_abuse",
			"rate_limit_per_hour": 10,
			"require_fields":      []any{"onion", "reason"},
		},
	}
}

func TestPostValidReturns204AndWritesEntry(t *testing.T) {
	f, _, path := newTestFeature(t)
	enable(f)

	snap := defaultSnapshot()
	h := buildHandler(f, "tenant.example", snap)

	body, _ := json.Marshal(map[string]string{
		"onion":   validOnion,
		"reason":  "phishing site targeting customers of my org",
		"contact": "ops@example.org",
		"details": "screenshot attached in separate channel",
	})
	req := makeRequest(http.MethodPost, "/_abuse", string(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Server") != "" {
		t.Errorf("Server header should be empty; got %q", rec.Header().Get("Server"))
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("store lines = %d, want 1; raw=%q", len(lines), raw)
	}
	var got Entry
	if err := json.Unmarshal(lines[0], &got); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}
	if got.Onion != validOnion {
		t.Errorf("Onion = %q, want %q", got.Onion, validOnion)
	}
	if got.Reason == "" {
		t.Errorf("Reason is empty")
	}
	if got.Tenant != "tenant.example" {
		t.Errorf("Tenant = %q, want %q", got.Tenant, "tenant.example")
	}
	if got.ClientIPHash == "" {
		t.Errorf("ClientIPHash is empty")
	}
	if strings.Contains(string(raw), "203.0.113.7") {
		t.Errorf("raw IP leaked into store entry: %s", raw)
	}
}

func TestGetReturns405(t *testing.T) {
	f, _, _ := newTestFeature(t)
	enable(f)
	h := buildHandler(f, "tenant.example", defaultSnapshot())

	req := makeRequest(http.MethodGet, "/_abuse", "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "POST" {
		t.Errorf("Allow = %q, want POST", allow)
	}
}

func TestMissingRequiredFieldReturns400(t *testing.T) {
	f, _, _ := newTestFeature(t)
	enable(f)
	h := buildHandler(f, "tenant.example", defaultSnapshot())

	// Missing "reason".
	body, _ := json.Marshal(map[string]string{"onion": validOnion})
	req := makeRequest(http.MethodPost, "/_abuse", string(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	// Response body must not echo onion or any request content beyond
	// the fixed generic message.
	if strings.Contains(rec.Body.String(), validOnion) {
		t.Errorf("response echoed onion: %q", rec.Body.String())
	}
}

func TestOversizeFieldReturns400(t *testing.T) {
	f, _, _ := newTestFeature(t)
	enable(f)
	h := buildHandler(f, "tenant.example", defaultSnapshot())

	bigReason := strings.Repeat("x", maxReasonMax+1)
	body, _ := json.Marshal(map[string]string{
		"onion":  validOnion,
		"reason": bigReason,
	})
	req := makeRequest(http.MethodPost, "/_abuse", string(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversize reason: status = %d, want 400", rec.Code)
	}

	// Oversize contact.
	body2, _ := json.Marshal(map[string]string{
		"onion":   validOnion,
		"reason":  "ok",
		"contact": strings.Repeat("c", maxContactMax+1),
	})
	req2 := makeRequest(http.MethodPost, "/_abuse", string(body2))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("oversize contact: status = %d, want 400", rec2.Code)
	}

	// Oversize details.
	body3, _ := json.Marshal(map[string]string{
		"onion":   validOnion,
		"reason":  "ok",
		"details": strings.Repeat("d", maxDetailsMax+1),
	})
	req3 := makeRequest(http.MethodPost, "/_abuse", string(body3))
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("oversize details: status = %d, want 400", rec3.Code)
	}

	// Bad onion length.
	body4, _ := json.Marshal(map[string]string{
		"onion":  "tooshort.onion",
		"reason": "ok",
	})
	req4 := makeRequest(http.MethodPost, "/_abuse", string(body4))
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusBadRequest {
		t.Fatalf("short onion: status = %d, want 400", rec4.Code)
	}
}

func TestRateLimitExceedReturns429WithRetryAfter(t *testing.T) {
	f, _, _ := newTestFeature(t)
	enable(f)

	// Freeze time so the limiter's window is deterministic.
	var frozen atomic.Int64
	frozen.Store(time.Now().UnixNano())
	f.now = func() time.Time { return time.Unix(0, frozen.Load()) }

	snap := shared.FeatureSnapshot{
		Enabled: true,
		Params: map[string]any{
			"path":                "/_abuse",
			"rate_limit_per_hour": 2, // tight cap for the test
			"require_fields":      []any{"onion", "reason"},
		},
	}
	h := buildHandler(f, "tenant.example", snap)

	body, _ := json.Marshal(map[string]string{
		"onion":  validOnion,
		"reason": "ok",
	})

	for i := 0; i < 2; i++ {
		req := makeRequest(http.MethodPost, "/_abuse", string(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("request %d: status = %d, want 204", i, rec.Code)
		}
	}

	req := makeRequest(http.MethodPost, "/_abuse", string(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit: status = %d, want 429", rec.Code)
	}
	retry := rec.Header().Get("Retry-After")
	if retry == "" {
		t.Fatalf("Retry-After not set on 429 response")
	}
	n, err := strconv.Atoi(retry)
	if err != nil || n <= 0 {
		t.Fatalf("Retry-After = %q, want positive integer seconds", retry)
	}
}

func TestHashOfClientIPIsUsedNotRawIP(t *testing.T) {
	f, _, path := newTestFeature(t)
	enable(f)
	h := buildHandler(f, "tenant.example", defaultSnapshot())

	body, _ := json.Marshal(map[string]string{
		"onion":  validOnion,
		"reason": "ok",
	})
	req := makeRequest(http.MethodPost, "/_abuse", string(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if bytes.Contains(raw, []byte("203.0.113.7")) {
		t.Fatalf("raw client IP present in stored record: %s", raw)
	}

	var entry Entry
	line := bytes.TrimRight(raw, "\n")
	if err := json.Unmarshal(line, &entry); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}
	if len(entry.ClientIPHash) != 64 {
		t.Errorf("ClientIPHash len = %d, want 64 (sha256 hex)", len(entry.ClientIPHash))
	}
	// Computing the hash with a fresh salt must produce a different
	// digest — proves the stored value depended on the process salt.
	other, _ := New("")
	if other.hashIP("203.0.113.7") == entry.ClientIPHash {
		t.Errorf("hash is independent of salt; expected different digest from a fresh Feature")
	}
}

func TestFeatureDisabledPassesThroughTo404(t *testing.T) {
	f, _, _ := newTestFeature(t)
	// Feature struct exists but enabled=false.

	snap := shared.FeatureSnapshot{Enabled: false}
	h := buildHandler(f, "tenant.example", snap)

	req := makeRequest(http.MethodPost, "/_abuse", `{"onion":"x","reason":"y"}`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled feature: status = %d, want 404 (pass-through)", rec.Code)
	}
}

func TestNonMatchingPathFallsThrough(t *testing.T) {
	f, _, _ := newTestFeature(t)
	enable(f)
	h := buildHandler(f, "tenant.example", defaultSnapshot())

	req := makeRequest(http.MethodPost, "/something-else", `{"onion":"x","reason":"y"}`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-match path: status = %d, want 404", rec.Code)
	}
}

func TestConcurrentWritesProduceConsistentFile(t *testing.T) {
	f, _, path := newTestFeature(t)
	enable(f)
	h := buildHandler(f, "tenant.example", defaultSnapshot())

	const workers = 20
	const perWorker = 5
	var wg sync.WaitGroup
	var successes atomic.Int64

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				body, _ := json.Marshal(map[string]string{
					"onion":  validOnion,
					"reason": "worker-" + strconv.Itoa(id) + "-" + strconv.Itoa(i),
				})
				req := httptest.NewRequest(http.MethodPost, "/_abuse", bytes.NewReader(body))
				// Vary RemoteAddr so we don't hit the rate limit.
				req.RemoteAddr = "198.51.100." + strconv.Itoa(id+1) + ":54321"
				req.Header.Set("Content-Type", "application/json")
				req = req.WithContext(feature.WithTenant(req.Context(), &feature.TenantSnapshot{
					Host:    "tenant.example",
					Enabled: true,
				}))
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code == http.StatusNoContent {
					successes.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()

	if got, want := successes.Load(), int64(workers*perWorker); got != want {
		t.Fatalf("successful writes = %d, want %d", got, want)
	}

	// Every line in the file must be valid JSON with the expected
	// fields. This verifies no interleaving corrupted the output.
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		var entry Entry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("line %d: invalid JSON: %v; raw=%q", count, err, scanner.Text())
		}
		if entry.Onion != validOnion {
			t.Fatalf("line %d: Onion = %q", count, entry.Onion)
		}
		count++
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		t.Fatalf("scanner error: %v", err)
	}
	if count != workers*perWorker {
		t.Fatalf("line count = %d, want %d", count, workers*perWorker)
	}
}

func TestMalformedJSONReturns400(t *testing.T) {
	f, _, _ := newTestFeature(t)
	enable(f)
	h := buildHandler(f, "tenant.example", defaultSnapshot())

	req := makeRequest(http.MethodPost, "/_abuse", `{"onion": "x", "reason":`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON: status = %d, want 400", rec.Code)
	}
}

func TestValidateAcceptsDisabledSnapshotWithoutParams(t *testing.T) {
	f, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := f.Validate(shared.FeatureSnapshot{Enabled: false}); err != nil {
		t.Errorf("Validate(disabled) = %v, want nil", err)
	}
}

func TestValidateRejectsBadPath(t *testing.T) {
	f, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bad := shared.FeatureSnapshot{
		Enabled: true,
		Params:  map[string]any{"path": "no-leading-slash"},
	}
	if err := f.Validate(bad); err == nil {
		t.Errorf("expected Validate to reject path without leading slash")
	}
}

func TestObserveUpdatesEnabledFlag(t *testing.T) {
	f, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if f.enabled.Load() {
		t.Fatalf("enabled should start false")
	}
	f.Observe(feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{
		FeatureName: {Enabled: true, Params: map[string]any{}},
	}}, nil)
	if !f.enabled.Load() {
		t.Fatalf("enabled should be true after Observe")
	}

	f.Observe(feature.GlobalsSnapshot{Features: map[string]shared.FeatureSnapshot{
		FeatureName: {Enabled: false},
	}}, nil)
	if f.enabled.Load() {
		t.Fatalf("enabled should be false after disabled Observe")
	}
}

func TestStoreAppendCreatesWellFormedJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "abuse.jsonl")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	for i := 0; i < 3; i++ {
		if err := s.Append(Entry{
			Tenant:       "t",
			Onion:        validOnion,
			Reason:       "r" + strconv.Itoa(i),
			ClientIPHash: "h",
		}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := s.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	for i, line := range lines {
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("line %d unmarshal: %v", i, err)
		}
		if e.Timestamp.IsZero() {
			t.Errorf("line %d: timestamp not set", i)
		}
	}
}

func TestStoreFileMode0600(t *testing.T) {
	// File mode bits are Unix-specific; on Windows the mode-bit check
	// is meaningless but os.Stat reports the ACL-derived mode. Skip
	// the check on Windows to avoid a spurious failure while still
	// exercising the code path everywhere else.
	if runtimeIsWindows() {
		t.Skip("file mode check is Unix-specific")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "abuse.jsonl")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("file mode = %#o, want 0600", mode)
	}
}

// runtimeIsWindows detects the Windows build without pulling in the
// full runtime package in test file front-matter.
func runtimeIsWindows() bool {
	// os.PathSeparator is '\\' on Windows, '/' elsewhere. Using this
	// instead of runtime.GOOS keeps the import set tight.
	return os.PathSeparator == '\\'
}
