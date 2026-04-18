package door

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gateway/internal/config"
)

func writeCoverFile(t *testing.T, body, ext string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "cover."+ext)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write cover: %v", err)
	}
	return path
}

func TestCover_StaticFile_ServesBytesWithContentType(t *testing.T) {
	p := writeCoverFile(t, "JPEGBYTES", "jpg")
	h, err := NewCoverHandler(config.CoverConf{
		Enabled:     true,
		Kind:        config.CoverKindStaticFile,
		Path:        p,
		ContentType: "image/jpeg",
		Headers: map[string]string{
			"Cache-Control": "public, max-age=3600",
		},
	})
	if err != nil {
		t.Fatalf("NewCoverHandler: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/jpeg" {
		t.Errorf("Content-Type = %q, want image/jpeg", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q", cc)
	}
	if resp.Header.Get("Server") != "" {
		t.Error("Server header leaked")
	}
	if string(body) != "JPEGBYTES" {
		t.Errorf("body = %q, want JPEGBYTES", body)
	}
	if resp.Header.Get("ETag") == "" {
		t.Error("missing ETag")
	}
	if resp.Header.Get("Last-Modified") == "" {
		t.Error("missing Last-Modified")
	}
}

func TestCover_StaticHTML_ServesHTMLContentType(t *testing.T) {
	p := writeCoverFile(t, "<html><body>Nothing to see.</body></html>", "html")
	h, err := NewCoverHandler(config.CoverConf{
		Enabled: true,
		Kind:    config.CoverKindStaticHTML,
		Path:    p,
	})
	if err != nil {
		t.Fatalf("NewCoverHandler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(string(body), "Nothing to see.") {
		t.Errorf("body missing expected text: %q", body)
	}
	if resp.Header.Get("Server") != "" {
		t.Error("Server header leaked")
	}
}

func TestCover_Passthrough404_Returns404Empty(t *testing.T) {
	h, err := NewCoverHandler(config.CoverConf{
		Enabled: true,
		Kind:    config.CoverKindPassthrough404,
	})
	if err != nil {
		t.Fatalf("NewCoverHandler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if len(body) != 0 {
		t.Errorf("expected empty body, got %q", body)
	}
	if resp.Header.Get("Server") != "" {
		t.Error("Server header leaked")
	}
	if resp.Header.Get("Content-Type") != "" {
		t.Errorf("Content-Type leaked: %q", resp.Header.Get("Content-Type"))
	}
}

func TestCover_DisabledReturns404(t *testing.T) {
	h, err := NewCoverHandler(config.CoverConf{Enabled: false})
	if err != nil {
		t.Fatalf("NewCoverHandler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestCover_HEAD_OnStaticFile_ReturnsNoBody(t *testing.T) {
	p := writeCoverFile(t, "HELLO", "html")
	h, err := NewCoverHandler(config.CoverConf{
		Enabled: true,
		Kind:    config.CoverKindStaticHTML,
		Path:    p,
	})
	if err != nil {
		t.Fatalf("NewCoverHandler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/", nil))
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(body) != 0 {
		t.Errorf("HEAD must return empty body, got %q", body)
	}
}

func TestCover_IfNoneMatchReturns304(t *testing.T) {
	p := writeCoverFile(t, "HELLO", "html")
	h, err := NewCoverHandler(config.CoverConf{
		Enabled: true,
		Kind:    config.CoverKindStaticHTML,
		Path:    p,
	})
	if err != nil {
		t.Fatalf("NewCoverHandler: %v", err)
	}
	// first GET to learn the ETag
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	etag := rec.Result().Header.Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}
	// second GET with If-None-Match
	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("If-None-Match", etag)
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", rec2.Code)
	}
}

func TestCover_POST_Returns405(t *testing.T) {
	p := writeCoverFile(t, "HELLO", "html")
	h, err := NewCoverHandler(config.CoverConf{
		Enabled: true,
		Kind:    config.CoverKindStaticHTML,
		Path:    p,
	})
	if err != nil {
		t.Fatalf("NewCoverHandler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("nope")))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestCover_MissingFile_Errors(t *testing.T) {
	_, err := NewCoverHandler(config.CoverConf{
		Enabled: true,
		Kind:    config.CoverKindStaticFile,
		Path:    "/nonexistent/really.jpg",
	})
	if err == nil {
		t.Fatal("expected error for missing cover file")
	}
}
