package checkhost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient builds a Client wired to the given httptest server with a
// very generous rate limit so tests do not spend most of their time waiting
// for the limiter.
func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	return NewClient(Config{
		BaseURL:    srv.URL,
		Timeout:    5 * time.Second,
		RatePerMin: 6000, // 100/sec: effectively unlimited for tests
		UserAgent:  "gateway-checkhost-test",
		HTTPClient: srv.Client(),
	})
}

func TestStartHTTPCheck_Success(t *testing.T) {
	var gotHost, gotMaxNodes string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/check-http" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %q", r.Method)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("missing Accept header: %q", r.Header.Get("Accept"))
		}
		gotHost = r.URL.Query().Get("host")
		gotMaxNodes = r.URL.Query().Get("max_nodes")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"ok": 1,
			"request_id": "abc-123",
			"nodes": {
				"ru3.node.check-host.net": ["Russia", "Moscow", "RU", "msk1"],
				"us1.node.check-host.net": ["United States", "Dallas", "US", "dfw1"]
			},
			"permanent_node_names": {
				"ru3.node.check-host.net": "ru3",
				"us1.node.check-host.net": "us1"
			}
		}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	res, err := c.StartHTTPCheck(context.Background(), "example.com", nil, 4)
	if err != nil {
		t.Fatalf("StartHTTPCheck: %v", err)
	}
	if res.RequestID != "abc-123" {
		t.Errorf("RequestID = %q, want abc-123", res.RequestID)
	}
	if len(res.Nodes) != 2 {
		t.Fatalf("len(Nodes) = %d, want 2", len(res.Nodes))
	}
	ru := res.Nodes["ru3.node.check-host.net"]
	if ru.Country != "RU" || ru.City != "Moscow" || ru.Name != "ru3" {
		t.Errorf("ru node = %+v", ru)
	}
	if gotHost != "example.com" {
		t.Errorf("host query = %q", gotHost)
	}
	if gotMaxNodes != "4" {
		t.Errorf("max_nodes query = %q", gotMaxNodes)
	}
}

func TestStartHTTPCheck_RegionsQueryParam(t *testing.T) {
	var gotNodes []string
	var gotMaxNodes string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotNodes = r.URL.Query()["node"]
		gotMaxNodes = r.URL.Query().Get("max_nodes")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":1,"request_id":"rq","nodes":{},"permanent_node_names":{}}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	_, err := c.StartHTTPCheck(context.Background(), "example.com",
		[]string{"ru3.node.check-host.net", "us1.node.check-host.net"}, 8)
	if err != nil {
		t.Fatalf("StartHTTPCheck: %v", err)
	}
	if len(gotNodes) != 2 {
		t.Fatalf("got %d node params, want 2: %v", len(gotNodes), gotNodes)
	}
	if gotNodes[0] != "ru3.node.check-host.net" || gotNodes[1] != "us1.node.check-host.net" {
		t.Errorf("nodes = %v", gotNodes)
	}
	if gotMaxNodes != "" {
		t.Errorf("max_nodes must not be sent when regions set, got %q", gotMaxNodes)
	}
}

func TestStartHTTPCheck_RateLimited429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	_, err := c.StartHTTPCheck(context.Background(), "example.com", nil, 0)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var rl ErrRateLimited
	if !errors.As(err, &rl) {
		t.Fatalf("expected ErrRateLimited, got %T: %v", err, err)
	}
	if rl.RetryAfter != 7*time.Second {
		t.Errorf("RetryAfter = %v, want 7s", rl.RetryAfter)
	}
}

func TestGetResult_NotReady_NullBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/check-result/") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`null`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	res, ready, err := c.GetResult(context.Background(), "rq-xyz")
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if ready {
		t.Errorf("ready = true, want false")
	}
	if res != nil {
		t.Errorf("res = %v, want nil", res)
	}
}

func TestGetResult_MixedNodeStatuses(t *testing.T) {
	body := `{
		"ok.node":      [["1", 0.123, "HTTP/1.1 200 OK"]],
		"timeout.node": [["0", 10.0, "Connection timed out"]],
		"error.node":   [["0", 0.5, "Malformed HTTP response"]],
		"refused.node": [["0", 0.01, "Connection refused"]],
		"pending.node": null
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	res, ready, err := c.GetResult(context.Background(), "rq-mixed")
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if ready {
		t.Errorf("ready = true, want false because pending.node is null")
	}
	cases := map[string]string{
		"ok.node":      "ok",
		"timeout.node": "timeout",
		"error.node":   "error",
		"refused.node": "refused",
		"pending.node": "pending",
	}
	for node, want := range cases {
		got, ok := res[node]
		if !ok {
			t.Errorf("missing result for %q", node)
			continue
		}
		if got.Status != want {
			t.Errorf("%s: status = %q, want %q (full=%+v)", node, got.Status, want, got)
		}
	}
	if res["ok.node"].LatencyMs != 123 {
		t.Errorf("ok.node latency = %d, want 123", res["ok.node"].LatencyMs)
	}
}

func TestGetResult_AllReady(t *testing.T) {
	body := `{
		"a.node": [["1", 0.05]],
		"b.node": [["1", 0.10]]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	_, ready, err := c.GetResult(context.Background(), "rq-ready")
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if !ready {
		t.Errorf("ready = false, want true")
	}
}

func TestCheckNow_PollsUntilReady(t *testing.T) {
	var pollCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/check-http":
			_, _ = w.Write([]byte(`{"ok":1,"request_id":"poll-rq","nodes":{"a.node":["US"]},"permanent_node_names":{}}`))
		case strings.HasPrefix(r.URL.Path, "/check-result/"):
			n := atomic.AddInt32(&pollCount, 1)
			if n < 3 {
				_, _ = w.Write([]byte(`{"a.node": null}`))
				return
			}
			_, _ = w.Write([]byte(`{"a.node": [["1", 0.02]]}`))
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := c.CheckNow(ctx, "example.com", nil, 2, 10*time.Millisecond, 2*time.Second)
	if err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if res["a.node"].Status != "ok" {
		t.Errorf("a.node status = %q, want ok", res["a.node"].Status)
	}
	if atomic.LoadInt32(&pollCount) < 3 {
		t.Errorf("pollCount = %d, want >= 3", pollCount)
	}
}

func TestCheckNow_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/check-http":
			_, _ = w.Write([]byte(`{"ok":1,"request_id":"cancel-rq","nodes":{},"permanent_node_names":{}}`))
		case strings.HasPrefix(r.URL.Path, "/check-result/"):
			_, _ = w.Write([]byte(`{"a.node": null}`))
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay so Start succeeds and polling begins.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := c.CheckNow(ctx, "example.com", nil, 0, 20*time.Millisecond, 5*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestContextCancellation_ImmediateOnStart(t *testing.T) {
	// If the context is already cancelled, Start should fail before doing
	// any HTTP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be reached")
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.StartHTTPCheck(ctx, "example.com", nil, 0)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestUserAgentHeader_SetOnEveryRequest(t *testing.T) {
	var mu int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua != "my-custom-ua/1.0" {
			t.Errorf("User-Agent = %q, want my-custom-ua/1.0", ua)
		}
		atomic.AddInt32(&mu, 1)
		switch {
		case r.URL.Path == "/check-http":
			_, _ = w.Write([]byte(`{"ok":1,"request_id":"ua-rq","nodes":{},"permanent_node_names":{}}`))
		case strings.HasPrefix(r.URL.Path, "/check-result/"):
			_, _ = w.Write([]byte(`{"x.node": [["1", 0.01]]}`))
		}
	}))
	defer srv.Close()

	c := NewClient(Config{
		BaseURL:    srv.URL,
		Timeout:    5 * time.Second,
		RatePerMin: 6000,
		UserAgent:  "my-custom-ua/1.0",
		HTTPClient: srv.Client(),
	})
	if _, err := c.StartHTTPCheck(context.Background(), "x", nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.GetResult(context.Background(), "ua-rq"); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&mu) != 2 {
		t.Errorf("handler hit %d times, want 2", mu)
	}
}

func TestRateLimiter_EnforcesGap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":1,"request_id":"rl","nodes":{},"permanent_node_names":{}}`))
	}))
	defer srv.Close()

	// 60 per minute = 1 per second. With burst 1, the second call must
	// wait ~1s.
	c := NewClient(Config{
		BaseURL:    srv.URL,
		Timeout:    5 * time.Second,
		RatePerMin: 60,
		UserAgent:  "rl",
		HTTPClient: srv.Client(),
	})

	ctx := context.Background()
	// First call consumes the initial token.
	if _, err := c.StartHTTPCheck(ctx, "a", nil, 0); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if _, err := c.StartHTTPCheck(ctx, "b", nil, 0); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	// Be generous: clocks, GC, Windows timer resolution, etc. Sub-second
	// windows are still clear evidence the limiter blocked (the bare HTTP
	// round-trip to localhost is sub-millisecond).
	if elapsed < 500*time.Millisecond {
		t.Errorf("second call took %v, expected at least 500ms (rate limiter should have blocked)", elapsed)
	}
}

func TestGetResult_EmptyRequestID(t *testing.T) {
	c := NewClient(Config{})
	_, _, err := c.GetResult(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty request_id")
	}
}

func TestStartHTTPCheck_EmptyHost(t *testing.T) {
	c := NewClient(Config{})
	_, err := c.StartHTTPCheck(context.Background(), "", nil, 0)
	if err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestStartHTTPCheck_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`boom`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	_, err := c.StartHTTPCheck(context.Background(), "example.com", nil, 0)
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error does not mention status code: %v", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if d := parseRetryAfter("12"); d != 12*time.Second {
		t.Errorf("seconds: got %v", d)
	}
	if d := parseRetryAfter(""); d != 0 {
		t.Errorf("empty: got %v", d)
	}
	if d := parseRetryAfter("not-a-date"); d != 0 {
		t.Errorf("garbage: got %v", d)
	}
}

// Ensure the JSON decoding handles code as a JSON number too — seen in some
// historical check-host.net responses.
func TestGetResult_NumericCode(t *testing.T) {
	body := `{"x.node": [[1, 0.05]]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	res, _, err := c.GetResult(context.Background(), "rq")
	if err != nil {
		t.Fatal(err)
	}
	if res["x.node"].Status != "ok" {
		t.Errorf("numeric code 1 should map to ok, got %+v", res["x.node"])
	}
}

// Sanity: round-trip encode -> decode with json package so a regression in
// the raw JSON used above is obvious.
func TestFixture_SampleJSONValid(t *testing.T) {
	samples := []string{
		`{"ok":1,"request_id":"x","nodes":{},"permanent_node_names":{}}`,
		`{"x.node": [[["1", 0.05]]]}`,
		`null`,
	}
	for _, s := range samples {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			t.Errorf("sample %q is invalid JSON: %v", s, err)
		}
	}
}
