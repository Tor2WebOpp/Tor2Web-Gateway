package admin

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func tempLog(t *testing.T) (*Log, string) {
	t.Helper()
	dir := t.TempDir()
	l, err := OpenLog(dir)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, dir
}

func TestOpenLog_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLog(dir)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	defer l.Close()

	auditDir := filepath.Join(dir, "audit")
	info, err := os.Stat(auditDir)
	if err != nil {
		t.Fatalf("stat audit dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("audit path must be a directory")
	}
	if runtime.GOOS != "windows" {
		// Permission bits aren't reliable on Windows.
		mode := info.Mode().Perm()
		if mode&0o077 != 0 {
			t.Fatalf("audit dir mode = %#o, want owner-only (0700)", mode)
		}
	}
}

func TestOpenLog_RejectsEmptyDataDir(t *testing.T) {
	if _, err := OpenLog(""); err == nil {
		t.Fatal("OpenLog(\"\") must return an error")
	}
}

func TestLogWrite_AppendsJSONL(t *testing.T) {
	l, dir := tempLog(t)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	e := Event{
		Time:   t0,
		Actor:  "actor-hash",
		NodeID: "hub-main",
		Action: "tenant.upsert",
		Target: "shop.example",
	}
	if err := l.Write(e); err != nil {
		t.Fatalf("Write: %v", err)
	}

	day := t0.UTC().Format("2006-01-02") + ".jsonl"
	got, err := readJSONL(filepath.Join(dir, "audit", day))
	if err != nil {
		t.Fatalf("readJSONL: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Action != "tenant.upsert" {
		t.Errorf("Action = %q", got[0].Action)
	}
	if got[0].Target != "shop.example" {
		t.Errorf("Target = %q", got[0].Target)
	}
}

func TestLogWrite_ZeroTimeFilledIn(t *testing.T) {
	l, dir := tempLog(t)
	before := time.Now()
	if err := l.Write(Event{Action: "x"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	after := time.Now()

	day := time.Now().UTC().Format("2006-01-02") + ".jsonl"
	got, err := readJSONL(filepath.Join(dir, "audit", day))
	if err != nil {
		t.Fatalf("readJSONL: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].Time.Before(before) || got[0].Time.After(after) {
		t.Fatalf("auto-stamped time %v not in [%v, %v]", got[0].Time, before, after)
	}
}

func TestLogQuery_SinceFiltersOlder(t *testing.T) {
	l, _ := tempLog(t)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)

	for i, ts := range []time.Time{
		t0,
		t0.Add(time.Second),
		t0.Add(2 * time.Second),
		t0.Add(3 * time.Second),
	} {
		if err := l.Write(Event{Time: ts, Action: "a", Target: pad(i)}); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}

	got, err := l.Query(t0.Add(time.Second), 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}
	// Should be in ascending order.
	if !got[0].Time.Equal(t0.Add(2*time.Second)) || !got[1].Time.Equal(t0.Add(3*time.Second)) {
		t.Fatalf("Query order wrong: %+v", got)
	}
}

func TestLogQuery_LimitRespected(t *testing.T) {
	l, _ := tempLog(t)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if err := l.Write(Event{Time: t0.Add(time.Duration(i) * time.Second), Action: "a"}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	got, err := l.Query(time.Time{}, 3)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Query limit=3 returned %d events", len(got))
	}
}

func TestLogClose_Idempotent(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLog(dir)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestLogWrite_AfterCloseFails(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLog(dir)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.Write(Event{Action: "x"}); err == nil {
		t.Fatal("Write after Close must return an error")
	}
}

func TestLog_ConcurrentWriteAndQuery(t *testing.T) {
	l, _ := tempLog(t)
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)

	const writers = 8
	const perWriter = 50
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				ts := t0.Add(time.Duration(w*1000+j) * time.Microsecond)
				if err := l.Write(Event{Time: ts, Action: "a", Actor: pad(w)}); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
			}
		}(w)
	}

	// Concurrent readers
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for i := 0; i < 30; i++ {
			if _, err := l.Query(time.Time{}, 0); err != nil {
				t.Errorf("Query: %v", err)
				return
			}
		}
	}()

	wg.Wait()
	<-readDone

	all, err := l.Query(time.Time{}, 0)
	if err != nil {
		t.Fatalf("final Query: %v", err)
	}
	if got, want := len(all), writers*perWriter; got != want {
		t.Fatalf("final event count = %d, want %d", got, want)
	}
}

func TestLog_RawLeakChecker(t *testing.T) {
	dir := t.TempDir()
	leakErr := errors.New("raw IP leaked")
	leakCk := func(payload []byte) error {
		if bytes.Contains(payload, []byte("203.0.113.42")) {
			return leakErr
		}
		return nil
	}
	l, err := OpenLogWithChecker(dir, leakCk)
	if err != nil {
		t.Fatalf("OpenLogWithChecker: %v", err)
	}
	defer l.Close()

	// Clean event passes.
	if err := l.Write(Event{Action: "a", Target: "shop.example"}); err != nil {
		t.Fatalf("clean Write: %v", err)
	}

	// Event with raw IP in Diff is rejected.
	leaky := Event{
		Action: "a",
		Target: "shop.example",
		Diff: map[string]any{
			"client_ip": "203.0.113.42",
		},
	}
	if err := l.Write(leaky); !errors.Is(err, leakErr) {
		t.Fatalf("leaky Write: err = %v, want %v", err, leakErr)
	}

	// And a Target with the raw value is rejected too — checker
	// inspects the full payload.
	if err := l.Write(Event{Action: "a", Target: "203.0.113.42"}); !errors.Is(err, leakErr) {
		t.Fatalf("Target-leaked Write: err = %v, want %v", err, leakErr)
	}
}

func TestLog_NanoCollisionDoesNotDropEvents(t *testing.T) {
	l, _ := tempLog(t)
	// Force 5 events to share an exact timestamp.
	t0 := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if err := l.Write(Event{Time: t0, Action: "a", Actor: pad(i)}); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}
	got, err := l.Query(time.Time{}, 0)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d events, want 5 (collision suffix should preserve all)", len(got))
	}
}

// pad returns a small distinct string for index i. Used to give test
// events distinguishable bodies without pulling in fmt.
func pad(i int) string {
	return string(rune('A' + (i % 26)))
}
