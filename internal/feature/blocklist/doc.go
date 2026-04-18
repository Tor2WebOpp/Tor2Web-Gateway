// Package blocklist implements the "blocklist_regex" feature: a compiled
// set of regular expressions matched against the request path (and,
// optionally, selected headers) with configurable block actions.
//
// Actions mirror shared.BlockAction:
//
//   - drop    — hijack the underlying connection and close it silently.
//     Falls back to a deliberate 400 with an empty body when the
//     ResponseWriter does not support http.Hijacker.
//   - 404     — write 404 Not Found with an empty body.
//   - 429     — write 429 Too Many Requests with an empty body.
//   - timeout — sleep for the configured default timeout then close or
//     emit a 408. Intended to tie up hostile clients without
//     issuing a visible block signal.
//
// Each pattern entry may specify its own action; entries without one fall
// back to default_action declared at the feature-snapshot level, which in
// turn falls back to drop when nothing is configured.
//
// Configuration is sourced from the feature registry's reload pipeline.
// Regex compilation happens exactly once per reload in Observe; the
// middleware hot-path only consults a pre-compiled, atomically published
// rule set and never allocates or compiles per request.
package blocklist
