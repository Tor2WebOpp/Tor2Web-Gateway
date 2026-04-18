package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T, idle, abs time.Duration) *SessionStore {
	t.Helper()
	return NewSessionStore(idle, abs)
}

func TestSessionStore_CreateIssuesIDAndCSRF(t *testing.T) {
	st := newTestStore(t, 15*time.Minute, 8*time.Hour)
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	st.SetClock(func() time.Time { return now })

	s, err := st.Create("hash-abc")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.ID == "" {
		t.Fatal("session ID must be non-empty")
	}
	if s.CSRFToken == "" {
		t.Fatal("CSRF token must be non-empty")
	}
	if s.IPHash != "hash-abc" {
		t.Fatalf("IPHash = %q, want hash-abc", s.IPHash)
	}
	if !s.CreatedAt.Equal(now) {
		t.Fatalf("CreatedAt = %v, want %v", s.CreatedAt, now)
	}
	if !s.LastSeen.Equal(now) {
		t.Fatalf("LastSeen = %v, want %v", s.LastSeen, now)
	}
	if !s.ExpiresAt.Equal(now.Add(8 * time.Hour)) {
		t.Fatalf("ExpiresAt = %v, want %v", s.ExpiresAt, now.Add(8*time.Hour))
	}
}

func TestSessionStore_CreateIssuesUniqueIDs(t *testing.T) {
	st := newTestStore(t, 15*time.Minute, time.Hour)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		s, err := st.Create("ip")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if seen[s.ID] {
			t.Fatalf("duplicate session id %q", s.ID)
		}
		seen[s.ID] = true
	}
}

func TestSessionStore_Get(t *testing.T) {
	st := newTestStore(t, 15*time.Minute, time.Hour)
	s, err := st.Create("ip")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, ok := st.Get(s.ID)
	if !ok {
		t.Fatal("Get returned ok=false for live session")
	}
	if got.ID != s.ID || got.CSRFToken != s.CSRFToken {
		t.Fatal("Get returned wrong session contents")
	}
	if _, ok := st.Get("nonexistent"); ok {
		t.Fatal("Get returned ok=true for missing id")
	}
}

func TestSessionStore_RefreshExtendsLastSeen(t *testing.T) {
	st := newTestStore(t, 15*time.Minute, 8*time.Hour)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	clock := t0
	st.SetClock(func() time.Time { return clock })

	s, err := st.Create("ip")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	clock = t0.Add(5 * time.Minute)
	if !st.Refresh(s.ID) {
		t.Fatal("Refresh returned false for live session")
	}
	got, ok := st.Get(s.ID)
	if !ok {
		t.Fatal("Get after Refresh returned not-ok")
	}
	if !got.LastSeen.Equal(clock) {
		t.Fatalf("LastSeen = %v, want %v", got.LastSeen, clock)
	}
}

func TestSessionStore_RefreshAbsoluteExpiryEvicts(t *testing.T) {
	st := newTestStore(t, 15*time.Minute, time.Hour)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	clock := t0
	st.SetClock(func() time.Time { return clock })

	s, err := st.Create("ip")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	clock = t0.Add(2 * time.Hour) // past absolute TTL
	if st.Refresh(s.ID) {
		t.Fatal("Refresh returned true past absolute TTL")
	}
	if _, ok := st.Get(s.ID); ok {
		t.Fatal("session should have been evicted after absolute expiry")
	}
}

func TestSessionStore_RefreshIdleExpiryEvicts(t *testing.T) {
	st := newTestStore(t, 5*time.Minute, time.Hour)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	clock := t0
	st.SetClock(func() time.Time { return clock })

	s, err := st.Create("ip")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	clock = t0.Add(10 * time.Minute) // past idle TTL
	if st.Refresh(s.ID) {
		t.Fatal("Refresh returned true past idle TTL")
	}
	if _, ok := st.Get(s.ID); ok {
		t.Fatal("session should have been evicted after idle expiry")
	}
}

func TestSessionStore_Delete(t *testing.T) {
	st := newTestStore(t, 15*time.Minute, time.Hour)
	s, _ := st.Create("ip")
	if !st.Delete(s.ID) {
		t.Fatal("Delete returned false for live session")
	}
	if _, ok := st.Get(s.ID); ok {
		t.Fatal("Get after Delete returned ok=true")
	}
	if st.Delete(s.ID) {
		t.Fatal("Delete returned true on second call")
	}
	if st.Delete("missing") {
		t.Fatal("Delete returned true for non-existent id")
	}
}

func TestSetSessionCookieAttrs(t *testing.T) {
	rec := httptest.NewRecorder()
	s := &Session{ID: "abc123"}
	SetSessionCookie(rec, "/x/y/z", s, 15*time.Minute)
	resp := rec.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != CookieName {
		t.Errorf("Name = %q, want %q", c.Name, CookieName)
	}
	if c.Value != "abc123" {
		t.Errorf("Value = %q, want abc123", c.Value)
	}
	if c.Path != "/x/y/z" {
		t.Errorf("Path = %q, want /x/y/z", c.Path)
	}
	if !c.HttpOnly {
		t.Error("HttpOnly must be true")
	}
	if !c.Secure {
		t.Error("Secure must be true")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", c.SameSite)
	}
	if c.MaxAge != int((15 * time.Minute).Seconds()) {
		t.Errorf("MaxAge = %d, want %d", c.MaxAge, int((15 * time.Minute).Seconds()))
	}
}

func TestClearSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	ClearSessionCookie(rec, "/x/y/z")
	resp := rec.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != CookieName {
		t.Errorf("Name = %q", c.Name)
	}
	if c.Path != "/x/y/z" {
		t.Errorf("Path = %q, want /x/y/z", c.Path)
	}
	// MaxAge=0 means "no Max-Age attribute"; we want explicit eviction.
	// http.Cookie translates MaxAge<0 to Max-Age=0 on the wire.
	if c.MaxAge >= 0 {
		t.Errorf("MaxAge = %d, want negative for clear semantics", c.MaxAge)
	}
}

func TestSessionIDFromRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := SessionIDFromRequest(r); got != "" {
		t.Errorf("missing-cookie request returned %q", got)
	}
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "the-id"})
	if got := SessionIDFromRequest(r); got != "the-id" {
		t.Errorf("got %q, want the-id", got)
	}
	if got := SessionIDFromRequest(nil); got != "" {
		t.Errorf("nil request returned %q", got)
	}
}

func TestSessionStore_GCRemovesExpired(t *testing.T) {
	st := newTestStore(t, 5*time.Minute, time.Hour)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	clock := t0
	st.SetClock(func() time.Time { return clock })

	live, _ := st.Create("ip-live")
	old, _ := st.Create("ip-old")

	clock = t0.Add(10 * time.Minute) // both past idle TTL
	st.gcOnce()
	if _, ok := st.Get(live.ID); ok {
		t.Fatal("live session should have been evicted past idle TTL")
	}
	if _, ok := st.Get(old.ID); ok {
		t.Fatal("old session should have been evicted past idle TTL")
	}
}

func TestSessionStore_StartGCStopsOnContextCancel(t *testing.T) {
	st := newTestStore(t, 15*time.Minute, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		st.StartGC(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartGC did not return after context cancel")
	}
}

func TestSessionStore_SnapshotFiltersExpired(t *testing.T) {
	st := newTestStore(t, 5*time.Minute, time.Hour)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	clock := t0
	st.SetClock(func() time.Time { return clock })

	s1, _ := st.Create("ip1")
	_, _ = st.Create("ip2")

	clock = t0.Add(10 * time.Minute)
	snap := st.Snapshot()
	if len(snap) != 0 {
		t.Fatalf("Snapshot returned %d sessions, want 0 (all expired)", len(snap))
	}

	clock = t0.Add(2 * time.Minute)
	// At t0+2m, recreate fresh sessions (the t0 ones are still alive
	// at t0+2m since idle=5m).
	clock = t0
	_ = s1 // suppress unused
	snap = st.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot returned %d sessions, want 2", len(snap))
	}
}

func TestSessionStore_ConcurrentAccess(t *testing.T) {
	st := newTestStore(t, 15*time.Minute, time.Hour)

	const workers = 16
	const ops = 200
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ids := make([]string, 0, ops)
			for j := 0; j < ops; j++ {
				s, err := st.Create("ip")
				if err != nil {
					t.Errorf("Create: %v", err)
					return
				}
				ids = append(ids, s.ID)
			}
			for _, sid := range ids {
				st.Get(sid)
				st.Refresh(sid)
			}
			for _, sid := range ids {
				st.Delete(sid)
			}
		}(i)
	}
	wg.Wait()
}
