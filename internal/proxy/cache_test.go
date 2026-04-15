package proxy

import "testing"

func TestIsStaticAsset(t *testing.T) {
	exts := map[string]struct{}{
		"css":  {},
		"js":   {},
		"png":  {},
		"jpg":  {},
		"jpeg": {},
		"gif":  {},
		"ico":  {},
		"svg":  {},
		"woff": {},
		"woff2": {},
	}

	tests := []struct {
		path string
		want bool
	}{
		{"/style.css", true},
		{"/app.js", true},
		{"/logo.png", true},
		{"/api/login", false},
		{"/", false},
		{"/page.php", false},
	}

	for _, tt := range tests {
		got := isStaticPath(tt.path, exts)
		if got != tt.want {
			t.Errorf("isStaticPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
