package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto/v2"
)

const maxCacheBodySize = 5 * 1024 * 1024 // 5 MB

// cachedResponse holds the captured response data for a cache entry.
type cachedResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Cache wraps a ristretto cache for HTTP responses.
type Cache struct {
	store      *ristretto.Cache[string, *cachedResponse]
	ttl        time.Duration
	extensions map[string]struct{}
}

// NewCache creates a Cache with a ristretto backing store.
// maxSizeMB is the approximate maximum size of the cache in megabytes.
func NewCache(maxSizeMB int, ttl time.Duration, exts []string) (*Cache, error) {
	maxBytes := int64(maxSizeMB) * 1024 * 1024
	cfg := &ristretto.Config[string, *cachedResponse]{
		NumCounters: 1e7,
		MaxCost:     maxBytes,
		BufferItems: 64,
		Cost: func(val *cachedResponse) int64 {
			n := int64(len(val.Body))
			if n == 0 {
				return 1
			}
			return n
		},
	}

	store, err := ristretto.NewCache(cfg)
	if err != nil {
		return nil, fmt.Errorf("cache: create ristretto: %w", err)
	}

	extSet := make(map[string]struct{}, len(exts))
	for _, e := range exts {
		e = strings.ToLower(strings.TrimPrefix(e, "."))
		extSet[e] = struct{}{}
	}

	return &Cache{
		store:      store,
		ttl:        ttl,
		extensions: extSet,
	}, nil
}

// isStaticPath returns true if the request path has one of the registered extensions.
func isStaticPath(path string, extensions map[string]struct{}) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return false
	}
	ext = strings.TrimPrefix(ext, ".")
	_, ok := extensions[ext]
	return ok
}

// Middleware returns an http.Handler that serves cached responses on GET hits
// and stores cacheable 200 responses in the cache.
func (c *Cache) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !isStaticPath(r.URL.Path, c.extensions) {
			next.ServeHTTP(w, r)
			return
		}

		key := r.URL.RequestURI()

		if cached, ok := c.store.Get(key); ok {
			// Cache HIT — serve from cache.
			w.Header().Set("X-Cache", "HIT")
			for k, vals := range cached.Header {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(cached.StatusCode)
			_, _ = w.Write(cached.Body)
			return
		}

		// Cache MISS — proxy and potentially store.
		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		if rec.statusCode == http.StatusOK && rec.body.Len() <= maxCacheBodySize {
			// Copy headers, excluding hop-by-hop fields.
			hdrs := make(http.Header)
			for k, vals := range w.Header() {
				hdrs[k] = vals
			}
			entry := &cachedResponse{
				StatusCode: rec.statusCode,
				Header:     hdrs,
				Body:       rec.body.Bytes(),
			}
			c.store.SetWithTTL(key, entry, int64(len(entry.Body)), c.ttl)
		}
	})
}

// responseRecorder wraps http.ResponseWriter to capture the response body and status code.
type responseRecorder struct {
	http.ResponseWriter
	body       bytes.Buffer
	statusCode int
	written    bool
}

func (rr *responseRecorder) WriteHeader(code int) {
	if rr.written {
		return
	}
	rr.statusCode = code
	rr.written = true
	rr.ResponseWriter.WriteHeader(code)
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	if !rr.written {
		rr.WriteHeader(http.StatusOK)
	}
	rr.body.Write(b)
	return rr.ResponseWriter.Write(b)
}
