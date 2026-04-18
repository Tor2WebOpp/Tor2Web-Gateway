package proxy

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// refreshInterval is the normal success-path cadence for pulling the
// Cloudflare ranges. It is a var (not const) so tests can shrink it.
var refreshInterval = 24 * time.Hour

// retryBaseInterval is the first retry delay after a refresh failure.
// Subsequent failures back off exponentially (base, base*2, base*4, ...)
// but never exceed refreshInterval.
var retryBaseInterval = 1 * time.Minute

// CFValidator validates that incoming requests originate from Cloudflare IPs.
type CFValidator struct {
	nets    []*net.IPNet
	mu      sync.RWMutex
	enabled bool
}

// NewCFValidator creates a CFValidator. When enabled, it fetches the current
// Cloudflare IP ranges on startup and refreshes them every 24 hours.
func NewCFValidator(enabled bool) *CFValidator {
	v := &CFValidator{enabled: enabled}
	if enabled {
		_ = v.refresh()
		go v.refreshLoop()
	}
	return v
}

// refresh fetches the Cloudflare IPv4 and IPv6 ranges and replaces the local
// copy. It refuses partial commits: if either list fails to fetch or parse,
// the in-memory set is left unchanged and a non-nil error is returned so the
// caller can schedule a short-term retry. This prevents every IPv6-origin
// Cloudflare request from getting 403 for 24 hours after a transient IPv6
// endpoint failure.
func (v *CFValidator) refresh() error {
	nets4, err := fetchCFRanges("https://www.cloudflare.com/ips-v4")
	if err != nil {
		slog.Error("CF refresh: ipv4 fetch failed, keeping previous ranges", "error", err)
		return fmt.Errorf("cf ipv4 refresh: %w", err)
	}
	nets6, err := fetchCFRanges("https://www.cloudflare.com/ips-v6")
	if err != nil {
		slog.Error("CF refresh: ipv6 fetch failed, keeping previous ranges", "error", err)
		return fmt.Errorf("cf ipv6 refresh: %w", err)
	}

	combined := make([]*net.IPNet, 0, len(nets4)+len(nets6))
	combined = append(combined, nets4...)
	combined = append(combined, nets6...)
	if len(combined) == 0 {
		slog.Error("CF refresh: both endpoints returned zero ranges, keeping previous")
		return fmt.Errorf("cf refresh: empty result from both endpoints")
	}

	v.mu.Lock()
	v.nets = combined
	v.mu.Unlock()
	slog.Info("CF IP ranges loaded", "count", len(combined), "v4", len(nets4), "v6", len(nets6))
	return nil
}

// fetchCFRanges pulls one of the Cloudflare CIDR list endpoints and returns
// the parsed nets. Returns an error on any HTTP or parse failure; the
// caller uses this to decide whether the whole refresh should be committed.
func fetchCFRanges(url string) ([]*net.IPNet, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get %s: status %d", url, resp.StatusCode)
	}
	var nets []*net.IPNet
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		nets = append(nets, cidr)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", url, err)
	}
	if len(nets) == 0 {
		return nil, fmt.Errorf("%s: no CIDRs parsed", url)
	}
	return nets, nil
}

// refreshLoop periodically re-fetches Cloudflare IP ranges. On a success it
// schedules the next tick at refreshInterval. On failure it backs off
// exponentially starting from retryBaseInterval, doubling each attempt, but
// never exceeding refreshInterval. Any successful refresh resets the retry
// counter.
func (v *CFValidator) refreshLoop() {
	timer := time.NewTimer(refreshInterval)
	defer timer.Stop()
	failures := 0
	for {
		<-timer.C
		if err := v.refresh(); err != nil {
			failures++
			next := retryBaseInterval
			for i := 1; i < failures; i++ {
				next *= 2
				if next >= refreshInterval {
					next = refreshInterval
					break
				}
			}
			slog.Warn("CF refresh: scheduling retry", "in", next, "consecutive_failures", failures)
			timer.Reset(next)
			continue
		}
		failures = 0
		timer.Reset(refreshInterval)
	}
}

// IsCloudflareIP reports whether ipStr belongs to a known Cloudflare range.
// When the validator is disabled it returns true for all IPs.
func (v *CFValidator) IsCloudflareIP(ipStr string) bool {
	if !v.enabled {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, cidr := range v.nets {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// Middleware rejects requests that do not originate from Cloudflare IPs.
// hashIP, when non-nil, is called on the client IP before it is logged so
// raw IP addresses never reach the slog sink. Production callers wire in
// metrics.Labeler.ClientIP; tests and pre-OPSEC callers may pass nil, in
// which case the raw IP is logged (legacy behaviour).
func (v *CFValidator) Middleware(hashIP func(string) string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !v.enabled {
			next.ServeHTTP(w, r)
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !v.IsCloudflareIP(ip) {
			logIP := ip
			if hashIP != nil {
				logIP = hashIP(ip)
			}
			slog.Warn("non-CF request blocked", "ip", logIP)
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
