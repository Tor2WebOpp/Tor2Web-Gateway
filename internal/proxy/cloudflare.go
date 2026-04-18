package proxy

import (
	"bufio"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

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
		v.refresh()
		go v.refreshLoop()
	}
	return v
}

// refresh fetches the Cloudflare IPv4 and IPv6 ranges and replaces the local copy.
func (v *CFValidator) refresh() {
	urls := []string{
		"https://www.cloudflare.com/ips-v4",
		"https://www.cloudflare.com/ips-v6",
	}
	var nets []*net.IPNet
	client := &http.Client{Timeout: 10 * time.Second}
	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			slog.Error("failed to fetch CF IPs", "url", url, "error", err)
			continue
		}
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
		resp.Body.Close()
	}
	if len(nets) > 0 {
		v.mu.Lock()
		v.nets = nets
		v.mu.Unlock()
		slog.Info("CF IP ranges loaded", "count", len(nets))
	}
}

// refreshLoop periodically re-fetches Cloudflare IP ranges.
func (v *CFValidator) refreshLoop() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		v.refresh()
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
