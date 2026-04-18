package i18n

import (
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writeCatalogs writes a map of Lang -> raw JSON bytes into dir. Empty
// bytes produce a literal "{}" file, matching the shipped catalogs.
func writeCatalogs(t *testing.T, dir string, files map[Lang]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for lang, body := range files {
		if body == "" {
			body = "{}"
		}
		path := filepath.Join(dir, string(lang)+".json")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %q: %v", path, err)
		}
	}
}

func TestLoadEmptyCatalogs(t *testing.T) {
	dir := t.TempDir()
	writeCatalogs(t, dir, map[Lang]string{
		LangEN: "{}",
		LangRU: "{}",
		LangZH: "{}",
	})

	c := NewCatalog()
	if err := c.Load(dir); err != nil {
		t.Fatalf("Load: %v", err)
	}

	got := c.Languages()
	want := []Lang{LangEN, LangRU, LangZH}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Languages() = %v, want %v", got, want)
	}

	// Empty catalogs should fall through to the key-as-string path.
	if v := c.T("hello", LangEN); v != "hello" {
		t.Fatalf("T on empty catalog = %q, want %q", v, "hello")
	}
}

func TestTranslatesKnownKey(t *testing.T) {
	dir := t.TempDir()
	writeCatalogs(t, dir, map[Lang]string{
		LangEN: `{"hello":"Hello"}`,
		LangRU: `{"hello":"Привет"}`,
		LangZH: `{}`,
	})

	c := NewCatalog()
	if err := c.Load(dir); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if v := c.T("hello", LangRU); v != "Привет" {
		t.Fatalf("T(hello, ru) = %q, want %q", v, "Привет")
	}
	if !c.Has("hello", LangRU) {
		t.Fatalf("Has(hello, ru) = false, want true")
	}
	if c.Has("hello", LangZH) {
		t.Fatalf("Has(hello, zh) = true, want false")
	}
}

func TestFallsBackToEnglish(t *testing.T) {
	dir := t.TempDir()
	writeCatalogs(t, dir, map[Lang]string{
		LangEN: `{"hello":"Hello"}`,
		LangRU: `{"hello":"Привет"}`,
		LangZH: `{}`,
	})

	c := NewCatalog()
	if err := c.Load(dir); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// zh has no entry, must fall back to en.
	if v := c.T("hello", LangZH); v != "Hello" {
		t.Fatalf("T(hello, zh) = %q, want %q", v, "Hello")
	}
}

func TestFallsBackToKeyWhenEnglishMissing(t *testing.T) {
	dir := t.TempDir()
	writeCatalogs(t, dir, map[Lang]string{
		LangEN: `{}`,
		LangRU: `{"hello":"Привет"}`,
		LangZH: `{}`,
	})

	c := NewCatalog()
	if err := c.Load(dir); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if v := c.T("hello", LangZH); v != "hello" {
		t.Fatalf("T(hello, zh) = %q, want key %q", v, "hello")
	}
}

func TestUnknownKeyReturnsKey(t *testing.T) {
	dir := t.TempDir()
	writeCatalogs(t, dir, map[Lang]string{
		LangEN: `{"hello":"Hello"}`,
	})

	c := NewCatalog()
	if err := c.Load(dir); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if v := c.T("does.not.exist", LangEN); v != "does.not.exist" {
		t.Fatalf("T(missing, en) = %q, want key", v)
	}
	if v := c.T("does.not.exist", LangRU); v != "does.not.exist" {
		t.Fatalf("T(missing, ru) = %q, want key", v)
	}
}

func TestLoadRejectsBadJSON(t *testing.T) {
	dir := t.TempDir()
	writeCatalogs(t, dir, map[Lang]string{LangEN: `{"ok":"ok"}`})

	c := NewCatalog()
	if err := c.Load(dir); err != nil {
		t.Fatalf("initial Load: %v", err)
	}

	// Overwrite en.json with invalid JSON and re-Load; expect error and
	// the previous snapshot kept.
	bad := filepath.Join(dir, "en.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := c.Load(dir); err == nil {
		t.Fatalf("Load accepted bad JSON")
	}
	if v := c.T("ok", LangEN); v != "ok" {
		t.Fatalf("previous catalog lost after failed reload: got %q", v)
	}
}

func TestConcurrentReadsDuringReload(t *testing.T) {
	dir := t.TempDir()
	writeCatalogs(t, dir, map[Lang]string{
		LangEN: `{"hello":"Hello"}`,
		LangRU: `{"hello":"Привет"}`,
		LangZH: `{}`,
	})

	c := NewCatalog()
	if err := c.Load(dir); err != nil {
		t.Fatalf("Load: %v", err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				// Two of the three results are acceptable; we only
				// assert that T returns one of them and never panics.
				v := c.T("hello", LangRU)
				if v != "Привет" && v != "Hello" && v != "hello" {
					t.Errorf("unexpected T result: %q", v)
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50 && !stop.Load(); i++ {
			if err := c.Load(dir); err != nil {
				t.Errorf("concurrent Load: %v", err)
				return
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
}
