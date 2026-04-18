// Package i18n holds the translation catalogs used by user-facing surfaces
// of the gateway (admin UI in P4, installer messages, and the P5 README).
//
// P1 ships only the machinery: a catalog loader that reads a directory of
// flat JSON files (one per language, filename = BCP-47 tag) and a lookup
// with a fixed fallback chain of requested-lang then English then the raw
// key. The shipped catalogs (en, ru, zh) are intentionally empty; they are
// populated as later phases introduce the strings that need translating.
//
// Loads are atomic: a failed Load never leaves the catalog in a partially
// updated state. T is safe for concurrent use alongside Load so the admin
// surface can hot-reload catalogs without pausing traffic.
package i18n
