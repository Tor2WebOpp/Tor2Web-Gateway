package torpool

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"gateway/internal/shared"
)

// API serves a Unix socket HTTP API for pool management.
type API struct {
	mgr        *Manager
	socketPath string
	listener   net.Listener
	server     *http.Server
}

// NewAPI creates an API with a mux wired to the four management routes.
func NewAPI(mgr *Manager, socketPath string) *API {
	a := &API{
		mgr:        mgr,
		socketPath: socketPath,
	}

	mux := http.NewServeMux()

	// GET /backends — JSON array of BackendInfo from all instances.
	mux.HandleFunc("GET /backends", func(w http.ResponseWriter, r *http.Request) {
		instances := mgr.Instances()
		infos := make([]shared.BackendInfo, 0, len(instances))
		for _, inst := range instances {
			infos = append(infos, inst.Info())
		}
		writeJSON(w, http.StatusOK, infos)
	})

	// GET /health — JSON PoolHealth (aggregate counts).
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		instances := mgr.Instances()
		health := shared.PoolHealth{
			Instances: len(instances),
		}
		var latencySum int
		var aliveCount int
		for _, inst := range instances {
			info := inst.Info()
			health.TotalStreams += info.ActiveConns
			if info.Alive {
				aliveCount++
				latencySum += info.LatencyMs
			}
		}
		health.Alive = aliveCount
		if aliveCount > 0 {
			health.AvgLatencyMs = latencySum / aliveCount
		}
		writeJSON(w, http.StatusOK, health)
	})

	// POST /scale — reads ScaleRequest JSON, calls manager.ScaleTo.
	mux.HandleFunc("POST /scale", func(w http.ResponseWriter, r *http.Request) {
		if mgr.IsShuttingDown() {
			http.Error(w, "manager is shutting down", http.StatusServiceUnavailable)
			return
		}
		var req shared.ScaleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := mgr.ScaleTo(r.Context(), req.Target); err != nil {
			if errors.Is(err, ErrShuttingDown) {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "scale failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// GET /stats — JSON PoolStats (uptime).
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		stats := shared.PoolStats{
			UptimeSec: mgr.UptimeSec(),
		}
		writeJSON(w, http.StatusOK, stats)
	})

	a.server = &http.Server{Handler: mux}
	return a
}

// Serve removes any stale socket, listens, chmod 0600, and serves.
// The admin socket is a single-user control plane — 0660 group access
// was a historical leftover that broadened the privilege surface.
func (a *API) Serve() error {
	// Remove stale socket file if present.
	if err := os.Remove(a.socketPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	ln, err := net.Listen("unix", a.socketPath)
	if err != nil {
		return err
	}
	a.listener = ln

	if err := os.Chmod(a.socketPath, 0600); err != nil {
		slog.Warn("api: chmod socket failed", "path", a.socketPath, "error", err)
	}

	if err := a.server.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Close shuts down the HTTP server gracefully with a 5s deadline and
// removes the socket file. Uses a default context; callers who need a
// different deadline should call CloseContext directly.
func (a *API) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a.CloseContext(ctx)
}

// CloseContext performs a graceful shutdown bounded by ctx. Existing
// in-flight requests are allowed to complete before the listener is
// torn down; if ctx fires first the server is force-closed.
func (a *API) CloseContext(ctx context.Context) {
	if a.server != nil {
		if err := a.server.Shutdown(ctx); err != nil {
			// Shutdown returned an error (usually ctx deadline) — fall
			// back to Close to force the listener down so Serve returns.
			a.server.Close() //nolint:errcheck
		}
	}
	os.Remove(a.socketPath) //nolint:errcheck
}

// writeJSON encodes v as JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("api: encode response", "error", err)
	}
}
