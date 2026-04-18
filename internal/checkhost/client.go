package checkhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// Default configuration values used when Config leaves a field zero.
const (
	defaultBaseURL   = "https://check-host.net"
	defaultTimeout   = 30 * time.Second
	defaultRatePerMin = 12 // one call every five seconds
	defaultUserAgent = "gateway-checkhost"
)

// Config captures the knobs relevant for talking to check-host.net.
//
// Zero-valued fields are replaced by sensible defaults in NewClient, so the
// common case is NewClient(Config{}).
type Config struct {
	// BaseURL overrides the check-host.net endpoint (handy for tests).
	BaseURL string
	// Timeout bounds a single HTTP request. Polling timeouts live on the
	// per-call CheckNow arguments, not here.
	Timeout time.Duration
	// RatePerMin caps the number of outbound requests per minute across the
	// entire Client.
	RatePerMin int
	// UserAgent is sent on every request. Leave blank for the default.
	UserAgent string
	// HTTPClient lets tests inject a custom *http.Client. If nil a fresh
	// client is constructed with Timeout.
	HTTPClient *http.Client
	// Logger receives warnings (parse errors, unexpected shapes). Defaults
	// to slog.Default() when nil.
	Logger *slog.Logger
}

// Client speaks the two check-host.net endpoints this package cares about.
// It is safe for concurrent use.
type Client struct {
	baseURL     string
	http        *http.Client
	rateLimiter *rate.Limiter
	userAgent   string
	logger      *slog.Logger
}

// NewClient builds a Client from cfg, substituting defaults for zero fields.
func NewClient(cfg Config) *Client {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	rpm := cfg.RatePerMin
	if rpm <= 0 {
		rpm = defaultRatePerMin
	}

	ua := cfg.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}

	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: timeout}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// rate.Limiter takes events-per-second; convert from per-minute.
	perSecond := rate.Limit(float64(rpm) / 60.0)
	limiter := rate.NewLimiter(perSecond, 1)

	return &Client{
		baseURL:     baseURL,
		http:        hc,
		rateLimiter: limiter,
		userAgent:   ua,
		logger:      logger,
	}
}

// ErrRateLimited is returned when check-host.net answers HTTP 429. If the
// server provided a Retry-After header its value is parsed into RetryAfter;
// otherwise RetryAfter is zero.
type ErrRateLimited struct {
	RetryAfter time.Duration
}

func (e ErrRateLimited) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("check-host.net rate limited, retry after %s", e.RetryAfter)
	}
	return "check-host.net rate limited"
}

// NodeInfo describes a single check-host.net vantage point in StartResult.
type NodeInfo struct {
	Name    string
	Country string // ISO alpha-2 where provided
	City    string
}

// StartResult is returned by StartHTTPCheck.
type StartResult struct {
	RequestID string
	Nodes     map[string]NodeInfo
}

// NodeCheck is the decoded form of one element of check-host.net's per-node
// result tuple. Status is one of:
//
//	"ok"       – HTTP reply observed, code indicated success
//	"timeout"  – connection/read timed out
//	"refused"  – connection refused
//	"error"    – any other failure (malformed response, DNS, etc.)
//	"pending"  – check-host.net has not reported for this node yet
type NodeCheck struct {
	Status    string
	LatencyMs int
	Error     string
}

// startResponse mirrors the JSON body of /check-http.
type startResponse struct {
	OK                 int                        `json:"ok"`
	RequestID          string                     `json:"request_id"`
	PermanentNodeNames map[string]string          `json:"permanent_node_names"`
	Nodes              map[string][]string        `json:"nodes"`
}

// StartHTTPCheck issues POST /check-http. If regions is non-empty, nodes are
// filtered to those whose country (ISO-3166 alpha-2, upper-cased) matches
// one of the given codes; the selected node IDs are sent via repeated
// ?node=<id> query parameters as required by check-host.net.
//
// A non-zero maxNodes sets the max_nodes query parameter. If regions is
// non-empty the server performs no node filtering of its own, so maxNodes is
// only forwarded when regions is empty.
//
// On HTTP 429 returns ErrRateLimited.
func (c *Client) StartHTTPCheck(ctx context.Context, host string, regions []string, maxNodes int) (StartResult, error) {
	if host == "" {
		return StartResult{}, errors.New("checkhost: host is required")
	}

	q := url.Values{}
	q.Set("host", host)
	if len(regions) == 0 && maxNodes > 0 {
		q.Set("max_nodes", strconv.Itoa(maxNodes))
	}
	for _, id := range c.filterNodesByRegions(ctx, regions) {
		q.Add("node", id)
	}

	body, status, header, err := c.do(ctx, http.MethodPost, "/check-http", q, nil)
	if err != nil {
		return StartResult{}, err
	}
	if status == http.StatusTooManyRequests {
		return StartResult{}, ErrRateLimited{RetryAfter: parseRetryAfter(header.Get("Retry-After"))}
	}
	if status < 200 || status >= 300 {
		return StartResult{}, fmt.Errorf("checkhost: /check-http returned %d: %s", status, truncate(string(body), 256))
	}

	var raw startResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return StartResult{}, fmt.Errorf("checkhost: decode /check-http: %w", err)
	}

	out := StartResult{
		RequestID: raw.RequestID,
		Nodes:     make(map[string]NodeInfo, len(raw.Nodes)),
	}
	for id, fields := range raw.Nodes {
		info := NodeInfo{}
		// nodes entries are heterogeneous arrays; historically the first
		// few positions are [country_en, city_en, country_code, ...].
		switch len(fields) {
		case 0:
		case 1:
			info.Country = fields[0]
		case 2:
			info.Country = fields[0]
			info.City = fields[1]
		default:
			info.Country = strings.ToUpper(firstNonEmpty(fields[2], fields[0]))
			info.City = fields[1]
		}
		if name, ok := raw.PermanentNodeNames[id]; ok {
			info.Name = name
		}
		out.Nodes[id] = info
	}
	return out, nil
}

// filterNodesByRegions currently returns an empty slice because the
// /check-http endpoint will pick nodes itself when no `node` parameter is
// given. The hub layer is responsible for choosing node IDs for a given
// region set via /nodes/hosts (future), and passes them in as `regions`
// holding node IDs directly. To keep the surface simple for wave 2 we
// treat `regions` as already-resolved node IDs and forward them verbatim.
func (c *Client) filterNodesByRegions(_ context.Context, regions []string) []string {
	if len(regions) == 0 {
		return nil
	}
	out := make([]string, 0, len(regions))
	for _, r := range regions {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// GetResult issues GET /check-result/<request_id>. Returns (results, ready,
// err). ready=false means check-host.net has not finished all nodes yet; in
// that case results and err are both nil. Individual nodes for which the
// server returned null become a NodeCheck with Status "pending".
func (c *Client) GetResult(ctx context.Context, requestID string) (map[string]NodeCheck, bool, error) {
	if requestID == "" {
		return nil, false, errors.New("checkhost: request_id is required")
	}

	body, status, header, err := c.do(ctx, http.MethodGet, "/check-result/"+url.PathEscape(requestID), nil, nil)
	if err != nil {
		return nil, false, err
	}
	if status == http.StatusTooManyRequests {
		return nil, false, ErrRateLimited{RetryAfter: parseRetryAfter(header.Get("Retry-After"))}
	}
	if status < 200 || status >= 300 {
		return nil, false, fmt.Errorf("checkhost: /check-result returned %d: %s", status, truncate(string(body), 256))
	}

	trim := strings.TrimSpace(string(body))
	if trim == "" || trim == "null" {
		return nil, false, nil
	}

	// Response shape: map[node_id] -> either null or an array of result
	// tuples. Each tuple is [code, time, message] (lengths vary). We decode
	// permissively via json.RawMessage so node-level parse errors do not
	// abort the whole response.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trim), &raw); err != nil {
		return nil, false, fmt.Errorf("checkhost: decode /check-result: %w", err)
	}

	out := make(map[string]NodeCheck, len(raw))
	allReady := true
	for node, rm := range raw {
		if len(rm) == 0 || string(rm) == "null" {
			out[node] = NodeCheck{Status: "pending"}
			allReady = false
			continue
		}
		out[node] = c.decodeNodeResult(node, rm)
	}
	return out, allReady, nil
}

// decodeNodeResult decodes one node's result payload. The response is an
// array of per-attempt tuples; we take the first and interpret it.
func (c *Client) decodeNodeResult(node string, rm json.RawMessage) NodeCheck {
	var attempts []json.RawMessage
	if err := json.Unmarshal(rm, &attempts); err != nil {
		c.logger.Warn("checkhost: decode node array",
			slog.String("node", node),
			slog.String("err", err.Error()))
		return NodeCheck{Status: "error", Error: "decode: " + err.Error()}
	}
	if len(attempts) == 0 {
		return NodeCheck{Status: "pending"}
	}
	// The first attempt drives status; subsequent attempts are retries we
	// ignore for now.
	first := attempts[0]
	if len(first) == 0 || string(first) == "null" {
		return NodeCheck{Status: "pending"}
	}

	var tuple []json.RawMessage
	if err := json.Unmarshal(first, &tuple); err != nil {
		c.logger.Warn("checkhost: decode node tuple",
			slog.String("node", node),
			slog.String("err", err.Error()))
		return NodeCheck{Status: "error", Error: "decode: " + err.Error()}
	}
	if len(tuple) == 0 {
		return NodeCheck{Status: "pending"}
	}

	// code: "1" on success, "0" (or similar) on failure.
	var code string
	if err := json.Unmarshal(tuple[0], &code); err != nil {
		// Some responses use a number; coerce.
		var n float64
		if err2 := json.Unmarshal(tuple[0], &n); err2 == nil {
			code = strconv.FormatFloat(n, 'f', -1, 64)
		} else {
			code = strings.Trim(string(tuple[0]), `"`)
		}
	}

	latencyMs := 0
	if len(tuple) >= 2 {
		var t float64
		if err := json.Unmarshal(tuple[1], &t); err == nil {
			latencyMs = int(t * 1000)
		}
	}

	message := ""
	if len(tuple) >= 3 {
		var s string
		if err := json.Unmarshal(tuple[2], &s); err == nil {
			message = s
		}
	}

	return interpret(code, latencyMs, message)
}

// interpret turns a (code, latency, message) triple into a NodeCheck whose
// Status reflects the coarse outcome.
func interpret(code string, latencyMs int, message string) NodeCheck {
	lower := strings.ToLower(message)
	switch {
	case code == "1":
		return NodeCheck{Status: "ok", LatencyMs: latencyMs}
	case strings.Contains(lower, "timed out"), strings.Contains(lower, "timeout"):
		return NodeCheck{Status: "timeout", LatencyMs: latencyMs, Error: message}
	case strings.Contains(lower, "refused"):
		return NodeCheck{Status: "refused", LatencyMs: latencyMs, Error: message}
	default:
		return NodeCheck{Status: "error", LatencyMs: latencyMs, Error: message}
	}
}

// CheckNow is a convenience that issues StartHTTPCheck, then polls GetResult
// every pollInterval until every node has reported or maxWait elapses. The
// last snapshot observed is returned even if not all nodes reported before
// maxWait.
//
// ctx cancellation is honoured promptly between polls.
func (c *Client) CheckNow(ctx context.Context, host string, regions []string, maxNodes int, pollInterval time.Duration, maxWait time.Duration) (map[string]NodeCheck, error) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	if maxWait <= 0 {
		maxWait = 30 * time.Second
	}

	start, err := c.StartHTTPCheck(ctx, host, regions, maxNodes)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(maxWait)
	var lastSnapshot map[string]NodeCheck

	for {
		res, ready, err := c.GetResult(ctx, start.RequestID)
		if err != nil {
			return lastSnapshot, err
		}
		if res != nil {
			lastSnapshot = res
		}
		if ready {
			return res, nil
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return lastSnapshot, nil
		}
		wait := pollInterval
		if wait > remaining {
			wait = remaining
		}
		select {
		case <-ctx.Done():
			return lastSnapshot, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// do performs one HTTP round-trip, with rate limiting and common headers.
// Returns body, status code, response headers, or an error.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body io.Reader) ([]byte, int, http.Header, error) {
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, 0, nil, err
	}

	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("checkhost: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("checkhost: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("checkhost: read body: %w", err)
	}
	return raw, resp.StatusCode, resp.Header, nil
}

// parseRetryAfter accepts either a delta-seconds integer or an HTTP-date.
func parseRetryAfter(h string) time.Duration {
	if h = strings.TrimSpace(h); h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
