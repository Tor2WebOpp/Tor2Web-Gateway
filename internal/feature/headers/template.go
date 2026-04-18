package headers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// variable names accepted by the template engine.
const (
	varClientIP   = "client_ip"
	varTenantHost = "tenant_host"
	varRequestID  = "request_id"
	varNowRFC3339 = "now_rfc3339"
	// varHeaderPrefix is the prefix for {{header:Name}} — the name
	// portion is looked up verbatim against r.Header.Get.
	varHeaderPrefix = "header:"
)

// partKind enumerates the two flavours of a rendered template segment.
// A kindLiteral is copied to the output as-is; a kindVar is expanded at
// Render time based on the RenderCtx and the variable identifier.
type partKind uint8

const (
	kindLiteral partKind = iota
	kindVar
)

// templatePart is one segment of a parsed template — either a literal
// string or a variable reference. Storing the header name separately for
// the {{header:X}} form avoids a per-render string split.
type templatePart struct {
	kind partKind
	// For kindLiteral, literal is the fixed string.
	// For kindVar, name is the canonical variable name (e.g. "client_ip")
	// and header is populated iff name == varHeader (i.e. {{header:X}}).
	literal string
	name    string
	header  string
}

// Template is a parsed header value template. Templates with no variable
// references are rendered by returning the pre-joined literal.
type Template struct {
	// fastPath is non-empty when the template has no variables; Render
	// returns it directly with zero allocations.
	fastPath string

	parts []templatePart
}

// RenderCtx bundles every input that Render may consult. Callers fill in
// only the fields relevant to the current request; unset fields render as
// the empty string (except Now, which defaults to time.Now when zero).
type RenderCtx struct {
	ClientIP   string
	TenantHost string
	RequestID  string
	Req        *http.Request
	Now        time.Time
}

// Parse compiles s into a Template. All variables must be recognised at
// parse time — an unknown {{foo}} returns a non-nil error so that the
// mistake surfaces during feature validation rather than at render time.
func Parse(s string) (Template, error) {
	if s == "" {
		return Template{fastPath: ""}, nil
	}

	var parts []templatePart
	i := 0
	for i < len(s) {
		open := strings.Index(s[i:], "{{")
		if open < 0 {
			// No more variables; the remainder is a literal.
			parts = append(parts, templatePart{kind: kindLiteral, literal: s[i:]})
			break
		}
		open += i
		if open > i {
			parts = append(parts, templatePart{kind: kindLiteral, literal: s[i:open]})
		}
		close := strings.Index(s[open:], "}}")
		if close < 0 {
			return Template{}, fmt.Errorf("template: unterminated variable starting at offset %d", open)
		}
		close += open
		varName := strings.TrimSpace(s[open+2 : close])
		if varName == "" {
			return Template{}, fmt.Errorf("template: empty variable at offset %d", open)
		}
		part, err := parseVar(varName)
		if err != nil {
			return Template{}, err
		}
		parts = append(parts, part)
		i = close + 2
	}

	// If there is exactly one literal part and nothing else, use fastPath.
	if len(parts) == 1 && parts[0].kind == kindLiteral {
		return Template{fastPath: parts[0].literal}, nil
	}
	// If there are zero parts at all (impossible given s != ""), still
	// return an empty fastPath to avoid a nil slice surprise downstream.
	if len(parts) == 0 {
		return Template{fastPath: ""}, nil
	}
	return Template{parts: parts}, nil
}

// parseVar validates a variable identifier extracted from {{...}} and
// returns the corresponding templatePart. Unknown identifiers become a
// hard error.
func parseVar(name string) (templatePart, error) {
	switch name {
	case varClientIP, varTenantHost, varRequestID, varNowRFC3339:
		return templatePart{kind: kindVar, name: name}, nil
	}
	if strings.HasPrefix(name, varHeaderPrefix) {
		h := strings.TrimSpace(strings.TrimPrefix(name, varHeaderPrefix))
		if h == "" {
			return templatePart{}, fmt.Errorf("template: empty header name in {{%s}}", name)
		}
		return templatePart{kind: kindVar, name: varHeaderPrefix, header: h}, nil
	}
	return templatePart{}, fmt.Errorf("template: unknown variable {{%s}}", name)
}

// Render evaluates t against ctx and returns the expanded string. A
// Template with no variables always returns the cached fastPath.
func (t Template) Render(ctx RenderCtx) string {
	if len(t.parts) == 0 {
		return t.fastPath
	}

	// Pre-size the builder with a reasonable guess so small templates
	// avoid the first grow.
	var b strings.Builder
	b.Grow(32)

	for i := range t.parts {
		p := &t.parts[i]
		if p.kind == kindLiteral {
			b.WriteString(p.literal)
			continue
		}
		switch p.name {
		case varClientIP:
			b.WriteString(ctx.ClientIP)
		case varTenantHost:
			b.WriteString(ctx.TenantHost)
		case varRequestID:
			if ctx.RequestID != "" {
				b.WriteString(ctx.RequestID)
			} else {
				b.WriteString(newRequestID())
			}
		case varNowRFC3339:
			now := ctx.Now
			if now.IsZero() {
				now = time.Now()
			}
			b.WriteString(now.UTC().Format(time.RFC3339))
		case varHeaderPrefix:
			if ctx.Req != nil && p.header != "" {
				b.WriteString(ctx.Req.Header.Get(p.header))
			}
		}
	}
	return b.String()
}

// HasVariables reports whether Render will consult ctx at all; callers can
// use this to decide whether to compute expensive context fields.
func (t Template) HasVariables() bool {
	return len(t.parts) > 0
}

// newRequestID produces a fresh 16-hex-char token per call. Falls back to
// a time-nanoseconds encoding if crypto/rand is ever unavailable so the
// function never panics and never returns the empty string.
func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Extremely unlikely; derive a last-resort id from the clock.
		ns := time.Now().UnixNano()
		for i := 0; i < 8; i++ {
			b[i] = byte(ns >> (i * 8))
		}
	}
	return hex.EncodeToString(b[:])
}
