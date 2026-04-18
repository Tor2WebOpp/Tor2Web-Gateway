package i18n

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Lang is a catalog identifier. It matches the stem of a catalog file on
// disk (e.g. "en" for en.json). Kept as a string so callers can pass
// request-time values directly.
type Lang string

const (
	LangEN Lang = "en"
	LangRU Lang = "ru"
	LangZH Lang = "zh"
)

// Catalog is a concurrent string table keyed by language and message key.
// The zero value is usable but empty; use NewCatalog for clarity.
type Catalog struct {
	mu       sync.RWMutex
	messages map[Lang]map[string]string
}

// NewCatalog returns an empty Catalog ready for Load.
func NewCatalog() *Catalog {
	return &Catalog{messages: make(map[Lang]map[string]string)}
}

// Load replaces the catalog with the contents of dir. Every *.json file in
// dir is parsed as a flat object of string->string; the filename stem
// becomes the Lang. An empty object is a valid (and expected) catalog in
// P1. Load is atomic: on any parse error the previous contents are kept.
func (c *Catalog) Load(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("i18n: read dir %q: %w", dir, err)
	}

	next := make(map[Lang]map[string]string)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}
		stem := strings.TrimSuffix(name, ".json")
		if stem == "" {
			continue
		}

		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("i18n: read %q: %w", path, err)
		}

		// Tolerate a completely empty file as an empty catalog; stdlib
		// json rejects an empty byte slice.
		m := map[string]string{}
		if len(strings.TrimSpace(string(data))) > 0 {
			if err := json.Unmarshal(data, &m); err != nil {
				return fmt.Errorf("i18n: parse %q: %w", path, err)
			}
		}
		next[Lang(stem)] = m
	}

	c.mu.Lock()
	c.messages = next
	c.mu.Unlock()
	return nil
}

// T looks up key for lang and falls back in the order lang, English, the
// key itself. The key-as-string fallback lets callers use plain English
// sentences as keys during development without crashing on a miss.
func (c *Catalog) T(key string, lang Lang) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if m, ok := c.messages[lang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	if lang != LangEN {
		if m, ok := c.messages[LangEN]; ok {
			if v, ok := m[key]; ok {
				return v
			}
		}
	}
	return key
}

// Has reports whether key is defined for the exact lang (no fallback).
func (c *Catalog) Has(key string, lang Lang) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	m, ok := c.messages[lang]
	if !ok {
		return false
	}
	_, ok = m[key]
	return ok
}

// Languages returns the languages currently loaded, sorted.
func (c *Catalog) Languages() []Lang {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]Lang, 0, len(c.messages))
	for l := range c.messages {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
