package torpool

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"

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
		var req shared.ScaleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := mgr.ScaleTo(r.Context(), req.Target); err != nil {
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

// Serve removes any stale socket, listens, chmod 0660, and serves.
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

	if err := os.Chmod(a.socketPath, 0660); err != nil {
		slog.Warn("api: chmod socket failed", "path", a.socketPath, "error", err)
	}

	if err := a.server.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Close shuts down the HTTP server and removes the socket file.
func (a *API) Close() {
	if a.server != nil {
		a.server.Close() //nolint:errcheck
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
