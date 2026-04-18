// Package main implements a tiny HTTP backend used by the P1 integration
// harness. It echoes the Host header and a BACKEND_TAG env var so the
// driver can distinguish per-tenant routing and verify isolation.
//
// This binary is intentionally minimal: no deps beyond the standard
// library so the Docker image builds in seconds from a scratch base.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// main wires a single mux covering all paths and listens on :8080.
func main() {
	tag := os.Getenv("BACKEND_TAG")
	if tag == "" {
		tag = "unknown"
	}
	addr := os.Getenv("BACKEND_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	mux := http.NewServeMux()

	// /healthz is hit by Docker healthcheck and by the driver as the
	// canonical "is this backend alive" endpoint.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK tenant=%s host=%s\n", tag, r.Host)
	})

	// /big-static.css emits a largish payload to exercise the proxy cache
	// path. Content is deterministic so the driver can match hits.
	mux.HandleFunc("/big-static.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		// ~64 KB of deterministic filler.
		body := strings.Repeat(fmt.Sprintf("/* tenant=%s */\nbody { color: #abc; }\n", tag), 1024)
		_, _ = w.Write([]byte(body))
	})

	// /echo returns the request's Host + tag for the driver to assert
	// routing. Intentionally simple.
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "tenant=%s host=%s path=%s method=%s\n",
			tag, r.Host, r.URL.Path, r.Method)
	})

	// Catch-all — any other path echoes the same shape so blocklist
	// tests can differentiate "request reached backend" from "blocked
	// before backend".
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "tenant=%s host=%s path=%s\n", tag, r.Host, r.URL.Path)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	log.Printf("integration backend starting tag=%s addr=%s", tag, addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("backend: %v", err)
	}
}
