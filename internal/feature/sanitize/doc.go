// Package sanitize implements the "content_sanitizer" feature: a response
// middleware that filters HTML bodies through golang.org/x/net/html's
// tokenizer, removing tag elements whose names appear in the configured
// strip_tags list and attributes whose keys or unescaped values match any
// entry in strip_attributes.
//
// The middleware activates only for responses whose Content-Type matches
// one of the configured content_types (default: text/html). Every other
// response is passed through verbatim — no buffering, no copy, no rewrite.
//
// # Limitations (P1)
//
//   - Not zero-copy. Sanitization requires the full response body in
//     memory because the upstream writer has no signal for "end of body"
//     until the handler returns; we therefore wrap ResponseWriter with an
//     in-memory recorder, run the tokenizer over the captured bytes, and
//     copy the result to the real writer after the handler completes.
//   - A body larger than max_body_bytes is forwarded unchanged and a
//     structured warn log is emitted. This is the safer failure mode for
//     very large HTML (think 8MiB+ SSR dumps): losing sanitization is
//     worse than losing memory, and operators can raise the cap.
//   - Content-Length is stripped on sanitized responses because the
//     filtered length is not knowable ahead of time without buffering the
//     original plus the rewrite; Go's HTTP server falls back to
//     chunked-transfer. This is acceptable for P1.
//
// # Configuration
//
// A FeatureSnapshot with Enabled=true is interpreted as follows:
//
//	strip_tags        []string   default: [script, object, embed, iframe, link, meta, form, input]
//	strip_attributes  []string   default: [onclick, onload, onerror, javascript:]
//	                              Each entry matches either as a literal attribute key
//	                              (compared lower-case) or as a substring of the
//	                              unescaped attribute value (case-insensitive).
//	content_types     []string   default: [text/html]   matched by prefix against the
//	                              response Content-Type header's media-type portion.
//	max_body_bytes    int        default: 8 MiB (8*1024*1024). Values <=0 disable the
//	                              cap (not recommended).
//
// # Hot path
//
// An atomic.Bool guards every request: when no tenant or globals snapshot
// carries Enabled=true, the middleware short-circuits to next.ServeHTTP
// with a single atomic load. When enabled, the per-tenant policy is
// resolved once at request entry and pinned for the life of that request.
package sanitize
