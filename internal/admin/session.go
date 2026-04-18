package admin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// CookieName is the name of the session cookie issued to admin clients.
// It is intentionally generic so that it does not advertise the gateway
// product name to passive observers.
const CookieName = "gw_adm"

// gcInterval is the period at which the SessionStore garbage collector
// scans for and evicts expired sessions.
const gcInterval = 60 * time.Second

// sessionIDBytes is the entropy size of a session id, in bytes.
// 32 bytes (256 bits) is enough that an online guesser would need
// astronomical traffic to land on a live session.
const sessionIDBytes = 32

// csrfBytes is the entropy size of a CSRF token, in bytes.
const csrfBytes = 32

// Session is the in-memory record describing one logged-in admin
// session. All fields are populated at creation; CreatedAt and
// ExpiresAt are immutable for the life of the session, while LastSeen
// slides forward on each Refresh.
type Session struct {
	ID        string    // base64url 32-byte random
	IPHash    string    // from Labeler.ClientIP
	CreatedAt time.Time
	LastSeen  time.Time
	CSRFToken string    // base64url 32-byte
	ExpiresAt time.Time // absolute (default 8h)
}

// SessionStore is an in-memory map of active sessions keyed by id.
// All operations are safe for concurrent use. Sessions expire on two
// dimensions: idleTTL (refreshed by Refresh) and absoluteTTL (a hard
// upper bound set at creation).
type SessionStore struct {
	mu          sync.RWMutex
	sessions    map[string]*Session
	idleTTL     time.Duration
	absoluteTTL time.Duration

	// nowFn is the clock used for expiry comparisons. Tests override
	// it for deterministic verification; the zero value resolves to
	// time.Now.
	nowFn func() time.Time
}

// NewSessionStore returns a SessionStore configured with the given
// idle and absolute TTLs. Both must be positive; the spec defaults are
// 15min idle and 8h absolute, but the gateway bootstrap may override.
func NewSessionStore(idleTTL, absoluteTTL time.Duration) *SessionStore {
	return &SessionStore{
		sessions:    make(map[string]*Session),
		idleTTL:     idleTTL,
		absoluteTTL: absoluteTTL,
	}
}

// SetClock replaces the internal now function. Intended for tests.
// A nil clock restores time.Now.
func (s *SessionStore) SetClock(now func() time.Time) {
	s.mu.Lock()
	s.nowFn = now
	s.mu.Unlock()
}

func (s *SessionStore) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

// Create issues a fresh session for the supplied IP hash. The session
// id and CSRF token are 256 bits of cryptographic randomness encoded
// as base64url. CreatedAt and LastSeen equal the store's current
// clock; ExpiresAt is CreatedAt + absoluteTTL.
func (s *SessionStore) Create(ipHash string) (*Session, error) {
	id, err := randomToken(sessionIDBytes)
	if err != nil {
		return nil, fmt.Errorf("admin: generate session id: %w", err)
	}
	csrf, err := randomToken(csrfBytes)
	if err != nil {
		return nil, fmt.Errorf("admin: generate csrf token: %w", err)
	}
	s.mu.Lock()
	now := s.now()
	sess := &Session{
		ID:        id,
		IPHash:    ipHash,
		CreatedAt: now,
		LastSeen:  now,
		CSRFToken: csrf,
		ExpiresAt: now.Add(s.absoluteTTL),
	}
	s.sessions[id] = sess
	s.mu.Unlock()
	return sess, nil
}

// Get returns a copy of the session record for id, if present and not
// expired. The lookup walks every entry in the map and uses
// ConstantTimeCompare on the id, so the wall-clock cost of resolving
// a present id is the same as resolving a non-existent one with the
// same store size — making session-id enumeration impossible to
// distinguish from random probes.
func (s *SessionStore) Get(id string) (*Session, bool) {
	idBytes := []byte(id)
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()

	var match *Session
	// Allocate one comparison buffer per fetch so the work scales with
	// the configured key length, not the (variable) caller input.
	cmp := make([]byte, sessionIDBytes*2) // base64url of 32 bytes is 43 chars; oversize for safety
	for sid, sess := range s.sessions {
		// pad both sides to identical length before constant-time compare
		a := padTo(idBytes, cmp[:0])
		b := padTo([]byte(sid), cmp[:0])
		if subtle.ConstantTimeCompare(a, b) == 1 {
			// Cannot break early without leaking timing — record and
			// continue. Inlining this branch is fine because match is
			// only the most recent collision (ids are unique anyway).
			match = sess
		}
	}
	if match == nil {
		return nil, false
	}
	if !match.ExpiresAt.After(now) {
		return nil, false
	}
	if now.Sub(match.LastSeen) >= s.idleTTL {
		return nil, false
	}
	// Return a defensive copy so callers cannot mutate store state.
	cp := *match
	return &cp, true
}

// padTo copies src into a fresh buffer sized to max(len(src), len(dst-cap)).
// The dst argument is used purely to share the same backing array for
// a sequence of compares; it is reset on every call. The returned slice
// is a fresh allocation so concurrent callers never contend on it.
func padTo(src, _ []byte) []byte {
	const sz = 64
	out := make([]byte, sz)
	copy(out, src)
	return out
}

// Refresh extends the LastSeen timestamp of an existing session, if
// present and not absolutely expired. Returns true on success, false
// when the session is missing or has crossed either expiry boundary.
// On absolute expiry the session is also deleted.
func (s *SessionStore) Refresh(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return false
	}
	now := s.now()
	if !sess.ExpiresAt.After(now) {
		// Absolute expiry — evict.
		delete(s.sessions, id)
		return false
	}
	if now.Sub(sess.LastSeen) >= s.idleTTL {
		// Idle expiry — evict.
		delete(s.sessions, id)
		return false
	}
	sess.LastSeen = now
	return true
}

// Delete removes a session by id. Returns true if the session existed.
func (s *SessionStore) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[id]; !ok {
		return false
	}
	delete(s.sessions, id)
	return true
}

// StartGC runs an eviction loop in the current goroutine until ctx is
// cancelled. Callers typically launch it as `go store.StartGC(ctx)`
// once at startup. Eviction frequency is fixed at gcInterval (60s).
func (s *SessionStore) StartGC(ctx context.Context) {
	t := time.NewTicker(gcInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.gcOnce()
		}
	}
}

// gcOnce sweeps expired sessions in a single pass under the write lock.
func (s *SessionStore) gcOnce() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, sess := range s.sessions {
		if !sess.ExpiresAt.After(now) || now.Sub(sess.LastSeen) >= s.idleTTL {
			delete(s.sessions, id)
		}
	}
}

// Snapshot returns a copy of every active session record. The slice
// order is unspecified. Intended for the admin UI's session list and
// for audit-time review. Expired sessions are filtered out.
func (s *SessionStore) Snapshot() []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	out := make([]Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		if !sess.ExpiresAt.After(now) || now.Sub(sess.LastSeen) >= s.idleTTL {
			continue
		}
		out = append(out, *sess)
	}
	return out
}

// SetSessionCookie writes the session cookie to w. The cookie is
// HttpOnly, Secure, SameSite=Strict, scoped to pathPrefix, and given
// a Max-Age equal to the store's idleTTL via the session's idle
// window. The path prefix should be the full admin URL prefix, e.g.
// "/<slug>/<token1>/<token2>".
func SetSessionCookie(w http.ResponseWriter, pathPrefix string, s *Session, idleTTL time.Duration) {
	if pathPrefix == "" {
		pathPrefix = "/"
	}
	c := &http.Cookie{
		Name:     CookieName,
		Value:    s.ID,
		Path:     pathPrefix,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(idleTTL.Seconds()),
	}
	http.SetCookie(w, c)
}

// ClearSessionCookie writes a Max-Age=0 cookie with the same name and
// path as the live session cookie, instructing the browser to evict
// it. Path must match the path used at SetSessionCookie time or the
// browser will keep the original cookie.
func ClearSessionCookie(w http.ResponseWriter, pathPrefix string) {
	if pathPrefix == "" {
		pathPrefix = "/"
	}
	c := &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     pathPrefix,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}
	http.SetCookie(w, c)
}

// SessionIDFromRequest returns the session id from the gw_adm cookie
// in r, or the empty string if absent.
func SessionIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// randomToken returns n bytes of cryptographic randomness encoded as
// base64url without padding. The result is suitable for use in URLs
// and HTTP headers.
func randomToken(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("admin: token size must be positive")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
