package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestBlockedPaths(t *testing.T) {
	blocked := []string{"/.env", "/.git", "/app/config.php"}
	handler := blockedPathsMiddleware(blocked, okHandler())

	tests := []struct {
		path string
		want int
	}{
		{"/.env", http.StatusNotFound},
		{"/.git/config", http.StatusNotFound},
		{"/app/config.php", http.StatusNotFound},
		{"/", http.StatusOK},
		{"/login", http.StatusOK},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != tt.want {
			t.Errorf("path %q: got %d, want %d", tt.path, rr.Code, tt.want)
		}
	}
}

func TestBlockedMethods(t *testing.T) {
	handler := blockedMethodsMiddleware([]string{"TRACE", "CONNECT"}, okHandler())

	tests := []struct {
		method string
		want   int
	}{
		{"TRACE", http.StatusMethodNotAllowed},
		{"GET", http.StatusOK},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, "/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != tt.want {
			t.Errorf("method %q: got %d, want %d", tt.method, rr.Code, tt.want)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	handler := securityHeadersMiddleware(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if v := rr.Header().Get("X-Frame-Options"); v != "DENY" {
		t.Errorf("X-Frame-Options: got %q, want %q", v, "DENY")
	}
	if v := rr.Header().Get("X-Content-Type-Options"); v != "nosniff" {
		t.Errorf("X-Content-Type-Options: got %q, want %q", v, "nosniff")
	}
}
