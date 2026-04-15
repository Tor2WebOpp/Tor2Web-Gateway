package proxy

import (
	"embed"
	"fmt"
	"net/http"
)

//go:embed static
var staticFiles embed.FS

// serveErrorPage writes an embedded HTML error page with the given HTTP status code.
// If the page file is not found it falls back to a plain-text response.
func serveErrorPage(w http.ResponseWriter, code int) {
	filename := fmt.Sprintf("static/%d.html", code)
	data, err := staticFiles.ReadFile(filename)
	if err != nil {
		http.Error(w, http.StatusText(code), code)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = w.Write(data)
}
