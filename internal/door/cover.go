package door

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"gateway/internal/config"
)

// CoverHandler serves the "/" path for the door. Three modes are
// supported: static_file (stream a file with configured Content-Type +
// headers), static_html (serve a precomputed byte slice loaded from a
// path on disk), and passthrough_404 (an empty 404 mimicking an
// un-configured nginx).
//
// No Server / X-Powered-By / ETag fingerprint-distinguishing header is
// emitted unless the operator explicitly sets one via cfg.Headers. The
// ETag + Last-Modified that static_file emits derive from file mtime
// and content hash so they match what a plain nginx static file would
// emit.
type CoverHandler struct {
	cfg      config.CoverConf
	body     []byte
	modTime  time.Time
	etag     string
}

// NewCoverHandler builds a CoverHandler from cfg. For file-backed
// kinds, the file is read eagerly at construction time; if it cannot be
// read the error is returned so the door fails fast rather than
// silently serving 500s later.
//
// When cfg.Enabled is false the returned handler still implements
// http.Handler but answers every request with a passthrough 404.
func NewCoverHandler(cfg config.CoverConf) (*CoverHandler, error) {
	h := &CoverHandler{cfg: cfg}
	if !cfg.Enabled || cfg.Kind == config.CoverKindPassthrough404 {
		return h, nil
	}
	if cfg.Path == "" {
		return nil, errors.New("cover: path is required when cover is enabled and kind != passthrough_404")
	}
	body, info, err := readFileWithStat(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("cover: load %s: %w", cfg.Path, err)
	}
	h.body = body
	h.modTime = info.ModTime().UTC()
	sum := sha256.Sum256(body)
	// Weak ETag since we derive it from content — clients treat W/"..."
	// as a correctness hint, matching what nginx emits for static files.
	h.etag = `W/"` + hex.EncodeToString(sum[:8]) + `"`
	return h, nil
}

// ServeHTTP implements http.Handler.
func (h *CoverHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.Enabled || h.cfg.Kind == config.CoverKindPassthrough404 {
		writeEmpty(w, http.StatusNotFound)
		return
	}
	// Only GET / HEAD are meaningful for a cover page. Other verbs fall
	// through to a generic 405, matching the nginx default static-site
	// posture.
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		writeEmpty(w, http.StatusMethodNotAllowed)
		return
	}

	// Apply configured headers first so content-type defaults below do
	// not clobber them. Skip empty values so operators can delete a
	// default by assigning "".
	hdr := w.Header()
	for k, v := range h.cfg.Headers {
		if v == "" {
			hdr.Del(k)
			continue
		}
		hdr.Set(k, v)
	}

	if ct := h.cfg.ContentType; ct != "" {
		hdr.Set("Content-Type", ct)
	} else if h.cfg.Kind == config.CoverKindStaticHTML {
		hdr.Set("Content-Type", "text/html; charset=utf-8")
	}

	hdr.Set("ETag", h.etag)
	hdr.Set("Last-Modified", h.modTime.Format(http.TimeFormat))

	// Honour conditional GETs the same way nginx does — a matching
	// If-None-Match short-circuits to 304 with an empty body.
	if inm := r.Header.Get("If-None-Match"); inm != "" && inm == h.etag {
		writeEmpty(w, http.StatusNotModified)
		return
	}

	hdr.Set("Content-Length", fmt.Sprintf("%d", len(h.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, bytes.NewReader(h.body))
}

// readFileWithStat is a small helper that returns both the body and
// the FileInfo so callers can derive mtime-based headers without a
// second stat call.
func readFileWithStat(path string) ([]byte, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	return body, info, nil
}

// writeEmpty writes status with a zero-length body. Mirrors
// admin.writeEmpty so door 404s and admin 404s are indistinguishable on
// the wire.
func writeEmpty(w http.ResponseWriter, status int) {
	h := w.Header()
	h.Set("Content-Length", "0")
	w.WriteHeader(status)
}
