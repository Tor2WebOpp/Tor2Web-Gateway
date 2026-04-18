package proxy

import (
	"log/slog"
	"net/http"

	"gateway/internal/admin"
)

// securityHeadersMiddleware adds hardening response headers before calling next.
// Information-leaking upstream headers (Server, X-Powered-By, Via) must be
// stripped in the ReverseProxy's ModifyResponse, not here, because they are
// written by the upstream before this middleware can delete them.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
}

// writeProbe is a thin ResponseWriter wrapper used solely by
// recoveryMiddleware to know whether anything has already been committed
// to the wire when a panic fires. It does NOT swallow duplicate writes —
// the underlying writer's WriteHeader policy is preserved — it only
// records the fact that bytes/headers have flowed downstream.
type writeProbe struct {
	http.ResponseWriter
	written bool
}

func (p *writeProbe) WriteHeader(code int) {
	p.written = true
	p.ResponseWriter.WriteHeader(code)
}

func (p *writeProbe) Write(b []byte) (int, error) {
	p.written = true
	return p.ResponseWriter.Write(b)
}

// recoveryMiddleware catches panics from downstream handlers, logs them with
// a stack trace, and returns a 500 response instead of crashing the server.
// When gate is non-nil and enabled, the logged path has any admin slug/token
// segments redacted so a panic from anywhere in the chain cannot leak the
// gate's secret path components.
//
// If the panic fires AFTER any byte has already been committed to the
// client (status line or body), we cannot safely write a 500: the second
// write would smuggle a fake header inline into the chunked body the
// client is parsing. In that case we log and return; the deferred
// connection close surfaces a truncated body to the client, which is
// strictly safer than corrupted framing.
func recoveryMiddleware(gate *admin.Gate, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probe := &writeProbe{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered",
					"panic", rec,
					"path", redactPath(gate, r.URL.Path),
					"already_written", probe.written,
				)
				if probe.written {
					// Headers/body already in flight — do not call
					// http.Error; the second WriteHeader would corrupt
					// the chunked stream. The client sees a truncated
					// body when the connection closes.
					return
				}
				http.Error(probe, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(probe, r)
	})
}

// maxBodyMiddleware limits the size of incoming request bodies.
func maxBodyMiddleware(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}
