package proxy

import (
	"log/slog"
	"net/http"
	"strings"
)

// blockedPathsMiddleware returns a 404 for requests whose path starts with any
// of the given prefixes.
func blockedPathsMiddleware(paths []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range paths {
			if strings.HasPrefix(r.URL.Path, p) {
				http.NotFound(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// blockedMethodsMiddleware returns 405 for requests that use one of the
// disallowed HTTP methods.
func blockedMethodsMiddleware(methods []string, next http.Handler) http.Handler {
	blocked := make(map[string]struct{}, len(methods))
	for _, m := range methods {
		blocked[strings.ToUpper(m)] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := blocked[r.Method]; ok {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

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

// recoveryMiddleware catches panics from downstream handlers, logs them with
// a stack trace, and returns a 500 response instead of crashing the server.
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered", "panic", rec, "path", r.URL.Path)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// maxBodyMiddleware limits the size of incoming request bodies.
func maxBodyMiddleware(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}
