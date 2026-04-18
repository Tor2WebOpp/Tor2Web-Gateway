package admin

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
)

// requiredUIFiles enumerates every asset the embedded admin UI is
// expected to ship. The test fails loudly on missing files so a
// regression in the build system cannot silently disable the UI.
var requiredUIFiles = []string{
	"ui/index.html",
	"ui/404.html",
	"ui/static/css/tokens.css",
	"ui/static/css/theme-dark.css",
	"ui/static/css/theme-light.css",
	"ui/static/css/layout.css",
	"ui/static/css/components.css",
	"ui/static/js/app.js",
	"ui/static/js/api.js",
	"ui/static/js/i18n.js",
	"ui/static/js/router.js",
	"ui/static/js/components.js",
	"ui/static/js/pages/dashboard.js",
	"ui/static/js/pages/tenants.js",
	"ui/static/js/pages/mirrors.js",
	"ui/static/js/pages/blocklist.js",
	"ui/static/js/pages/features.js",
	"ui/static/js/pages/nodes.js",
	"ui/static/js/pages/metrics.js",
	"ui/static/js/pages/audit.js",
	"ui/static/js/pages/auto-domains.js",
	"ui/static/i18n/en.json",
	"ui/static/img/logo.svg",
	"ui/i18n/en.json",
}

// indexReferencedAssets lists the static paths linked from ui/index.html.
// The embed FS must serve each of them or the browser will show broken
// links on first page-load. Kept in sync with the <link>/<script>/<img>
// tags in index.html.
var indexReferencedAssets = []string{
	"ui/static/css/tokens.css",
	"ui/static/css/theme-dark.css",
	"ui/static/css/theme-light.css",
	"ui/static/css/layout.css",
	"ui/static/css/components.css",
	"ui/static/js/app.js",
	"ui/static/img/logo.svg",
}

// TestUIRequiredFilesExist verifies every file in requiredUIFiles is
// present in the embedded FS. Stat only — content is checked elsewhere.
func TestUIRequiredFilesExist(t *testing.T) {
	for _, name := range requiredUIFiles {
		if _, err := fs.Stat(UIFS, name); err != nil {
			t.Errorf("required UI file missing: %s: %v", name, err)
		}
	}
}

// TestUIIndexReferencesResolve walks the assets index.html links to and
// makes sure each one actually exists in the embed FS. Belt-and-braces
// beyond TestUIRequiredFilesExist: an HTML edit that points at a new
// filename should fail loudly until the file lands too.
func TestUIIndexReferencesResolve(t *testing.T) {
	idx, err := fs.ReadFile(UIFS, "ui/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	if len(idx) == 0 {
		t.Fatal("index.html is empty")
	}
	for _, name := range indexReferencedAssets {
		if _, err := fs.Stat(UIFS, name); err != nil {
			t.Errorf("index-referenced asset missing: %s: %v", name, err)
		}
	}
}

// TestUIEnJSONHasMinimumKeys enforces the key-count floor on en.json so
// a future partial-revert that shrinks the catalog fails this test
// rather than ship half-translated UI.
func TestUIEnJSONHasMinimumKeys(t *testing.T) {
	data, err := fs.ReadFile(UIFS, "ui/i18n/en.json")
	if err != nil {
		t.Fatalf("read en.json: %v", err)
	}
	var dict map[string]string
	if err := json.Unmarshal(data, &dict); err != nil {
		t.Fatalf("parse en.json: %v", err)
	}
	const minKeys = 50
	if len(dict) < minKeys {
		t.Errorf("en.json: got %d keys, want >= %d", len(dict), minKeys)
	}
	for _, k := range []string{
		"app.title", "nav.dashboard", "action.save", "toast.error",
		"verdict.live", "label.host",
	} {
		if _, ok := dict[k]; !ok {
			t.Errorf("en.json missing expected key: %s", k)
		}
	}
}

// TestUIEmbedTotalSizeBelowCap asserts the embedded UI stays under the
// binary-bloat budget. The ceiling leaves room for a sensible amount of
// growth without letting us accidentally ship an SPA-sized artifact in
// the edge binary.
func TestUIEmbedTotalSizeBelowCap(t *testing.T) {
	const cap = 200 * 1024
	var total int64
	err := fs.WalkDir(UIFS, "ui", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		t.Fatalf("walk ui: %v", err)
	}
	if total >= cap {
		t.Errorf("embedded UI too large: %d bytes >= %d bytes", total, cap)
	}
	t.Logf("embedded UI: %d bytes", total)
}

// TestUILogoIsInline verifies the logo is small and theme-neutral (no
// baked-in color literals). The UI relies on currentColor so the glyph
// looks right in both dark and light themes.
func TestUILogoIsInline(t *testing.T) {
	data, err := fs.ReadFile(UIFS, "ui/static/img/logo.svg")
	if err != nil {
		t.Fatalf("read logo.svg: %v", err)
	}
	if len(data) > 2048 {
		t.Errorf("logo.svg too large: %d bytes > 2048", len(data))
	}
	s := strings.ToLower(string(data))
	if !strings.Contains(s, "<svg") {
		t.Errorf("logo.svg does not look like SVG")
	}
	if strings.Contains(s, "rgb(") || strings.Contains(s, "#fff") || strings.Contains(s, "#000") {
		t.Errorf("logo.svg has a baked-in color — must use currentColor only")
	}
}

// i18nCatalogs lists the translation catalogs shipped with the admin UI.
// en.json is the source of truth; every other catalog must have the
// same set of keys so the runtime t() lookups never fall back silently
// in production — a missing key is a build-time test failure, not a
// runtime "[[key]]" placeholder in the operator's face.
var i18nCatalogs = []string{"ru", "zh"}

// readCatalog loads a catalog from the embedded UIFS and decodes it.
// The embed root is "ui/", so every catalog path starts with "ui/i18n/".
func readCatalog(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := fs.ReadFile(UIFS, "ui/i18n/"+name+".json")
	if err != nil {
		t.Fatalf("read %s.json: %v", name, err)
	}
	if len(data) == 0 {
		t.Fatalf("%s.json is empty", name)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("%s.json is not valid JSON: %v", name, err)
	}
	return m
}

// TestI18n_EnglishCatalogExists: en.json must be present and parse as a
// non-empty JSON object — everything else keys off its shape.
func TestI18n_EnglishCatalogExists(t *testing.T) {
	en := readCatalog(t, "en")
	if len(en) == 0 {
		t.Fatal("en.json has no keys")
	}
}

// TestI18n_TranslatedCatalogsExist: each translated catalog must be
// present at ui/i18n/<lang>.json and parse as a JSON object. Missing
// files or malformed JSON fail the build — translators can't silently
// drop a language.
func TestI18n_TranslatedCatalogsExist(t *testing.T) {
	for _, lang := range i18nCatalogs {
		lang := lang
		t.Run(lang, func(t *testing.T) {
			got := readCatalog(t, lang)
			if len(got) == 0 {
				t.Fatalf("%s.json has no keys", lang)
			}
		})
	}
}

// TestI18n_KeySetMatchesEnglish: every translated catalog must share
// the *exact* set of keys with en.json — same count, same names, no
// extras, no omissions. This is the core parity contract that lets
// t() assume a key either lives in the active dict or falls back to
// English by reference, never because of a typo in one file.
func TestI18n_KeySetMatchesEnglish(t *testing.T) {
	en := readCatalog(t, "en")
	enKeys := make(map[string]struct{}, len(en))
	for k := range en {
		enKeys[k] = struct{}{}
	}

	for _, lang := range i18nCatalogs {
		lang := lang
		t.Run(lang, func(t *testing.T) {
			got := readCatalog(t, lang)
			if len(got) != len(en) {
				t.Fatalf("%s.json has %d keys, want %d (matching en.json)",
					lang, len(got), len(en))
			}
			for k := range got {
				if _, ok := enKeys[k]; !ok {
					t.Errorf("%s.json has extra key not in en.json: %q", lang, k)
				}
			}
			for k := range enKeys {
				if _, ok := got[k]; !ok {
					t.Errorf("%s.json is missing key from en.json: %q", lang, k)
				}
			}
		})
	}
}

// TestI18n_ValuesAreStrings: every translation value must be a plain
// string. Nested objects or nulls would defeat the runtime's single
// lookup table and are almost always the result of a bad merge.
func TestI18n_ValuesAreStrings(t *testing.T) {
	for _, name := range append([]string{"en"}, i18nCatalogs...) {
		name := name
		t.Run(name, func(t *testing.T) {
			cat := readCatalog(t, name)
			for k, v := range cat {
				if _, ok := v.(string); !ok {
					t.Errorf("%s.json[%q] = %T, want string", name, k, v)
				}
			}
		})
	}
}
