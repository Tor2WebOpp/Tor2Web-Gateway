package proxy

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_requests_total",
			Help: "Total number of HTTP requests processed.",
		},
		[]string{"method", "status"},
	)

	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gateway_request_duration_seconds",
			Help:    "HTTP request latency in seconds (Tor-appropriate buckets).",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10, 30},
		},
		[]string{"cached"},
	)

	cacheTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_cache_total",
			Help: "Cache hit/miss counts.",
		},
		[]string{"result"}, // "hit" or "miss"
	)

	activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "gateway_active_connections",
			Help: "Number of currently active HTTP connections.",
		},
	)
)

func init() {
	prometheus.MustRegister(requestsTotal, requestDuration, cacheTotal, activeConnections)
}

// statusRecorder wraps http.ResponseWriter to capture the written status code.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if sr.written {
		return
	}
	sr.statusCode = code
	sr.written = true
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	if !sr.written {
		sr.WriteHeader(http.StatusOK)
	}
	return sr.ResponseWriter.Write(b)
}

// metricsMiddleware records Prometheus metrics for each request.
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activeConnections.Inc()
		defer activeConnections.Dec()

		rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		// Use a timer to measure total request duration.
		timer := prometheus.NewTimer(prometheus.ObserverFunc(func(d float64) {
			cached := "false"
			if rec.Header().Get("X-Cache") == "HIT" {
				cached = "true"
			}
			requestDuration.WithLabelValues(cached).Observe(d)
		}))

		next.ServeHTTP(rec, r)
		timer.ObserveDuration()

		status := strconv.Itoa(rec.statusCode)
		requestsTotal.WithLabelValues(r.Method, status).Inc()

		// Record cache hit/miss based on X-Cache header set by cache middleware.
		switch rec.Header().Get("X-Cache") {
		case "HIT":
			cacheTotal.WithLabelValues("hit").Inc()
		case "MISS":
			cacheTotal.WithLabelValues("miss").Inc()
		}
	})
}

// MetricsHandler returns the Prometheus HTTP handler.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
