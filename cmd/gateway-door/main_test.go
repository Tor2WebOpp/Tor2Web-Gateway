package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway/internal/config"
)

func buildSmokeCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	coverPath := filepath.Join(dir, "cover.html")
	if err := os.WriteFile(coverPath, []byte("<html>door</html>"), 0o600); err != nil {
		t.Fatalf("write cover: %v", err)
	}
	return &config.Config{
		Mode:     config.ModeLocal, // bypasses the HubURL/transport requirement
		NodeType: config.NodeTypeDoor,
		Admin: config.AdminConf{
			Enabled: true,
			Slug:    strings.Repeat("a", 32),
			Token1:  strings.Repeat("b", 32),
			Token2:  strings.Repeat("c", 32),
			// P3 admin handler defaults — point AuditDataDir at a
			// writable temp dir so OpenLog does not bail on the test
			// host's lack of /var/lib/gateway access.
			SessionIdleTTL:     15 * time.Minute,
			SessionAbsoluteTTL: 8 * time.Hour,
			AuditDataDir:       filepath.Join(dir, "audit"),
			Lockout: config.LockoutConf{
				SoftThreshold: 3,
				SoftWindow:    60 * time.Second,
				SoftBackoff:   30 * time.Second,
				HardThreshold: 10,
				HardWindow:    10 * time.Minute,
				HardBan:       1 * time.Hour,
			},
		},
		Door: config.DoorConf{
			Cover: config.CoverConf{
				Enabled: true,
				Kind:    config.CoverKindStaticHTML,
				Path:    coverPath,
			},
			Slugs: []config.SlugConf{
				{Slug: "slug32slug32slug32slug32slug32ss", Strategy: config.StrategyRandom, Status: 302},
			},
		},
	}
}

// TestRun_StartsAndHeadsAndCancels boots gateway-door end-to-end via
// RunWithListener (no certmagic, no hub), issues HEAD + GET /, cancels
// ctx, and confirms the binary exits cleanly inside shutdownGrace.
func TestRun_StartsAndHeadsAndCancels(t *testing.T) {
	cfg := buildSmokeCfg(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		runDone <- RunWithListener(ctx, cfg, ln)
	}()

	// Wait until the listener is accepting by polling a HEAD request.
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodHead, "http://"+addr+"/", nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				lastErr = nil
				break
			}
			lastErr = nil
		} else {
			lastErr = err
		}
		time.Sleep(25 * time.Millisecond)
	}
	if lastErr != nil {
		cancel()
		<-runDone
		t.Fatalf("HEAD never succeeded: %v", lastErr)
	}

	// GET / should return the cover body.
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		<-runDone
		t.Fatalf("GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		<-runDone
		t.Fatalf("GET / status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "<html>door</html>") {
		cancel()
		<-runDone
		t.Fatalf("cover body mismatch: %q", body)
	}

	// Trigger shutdown and confirm exit inside 3s.
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("RunWithListener returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("RunWithListener did not exit within 3s of cancel")
	}
}

// TestRun_AdminGate_IssuesCookieAndServesAPIMe boots gateway-door with
// the P3 admin gate enabled and confirms the bootstrap path: a fresh
// request to /<slug>/<token1>/<token2> issues a session cookie and
// 302s; a second request with that cookie to /api/me returns 200.
func TestRun_AdminGate_IssuesCookieAndServesAPIMe(t *testing.T) {
	cfg := buildSmokeCfg(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() {
		runDone <- RunWithListener(ctx, cfg, ln)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(3 * time.Second):
			t.Logf("door run did not exit within 3s of cancel")
		}
	})

	prefix := "/" + cfg.Admin.Slug + "/" + cfg.Admin.Token1 + "/" + cfg.Admin.Token2
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	deadline := time.Now().Add(3 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		r, err := client.Get("http://" + addr + prefix)
		if err == nil {
			resp = r
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if resp == nil {
		t.Fatalf("first admin GET never succeeded")
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("admin first hit: status = %d, want 302", resp.StatusCode)
	}
	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "gw_adm" {
			sessionCookie = c
			break
		}
	}
	resp.Body.Close()
	if sessionCookie == nil {
		t.Fatalf("first admin hit did not issue gw_adm cookie")
	}

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+prefix+"/api/me", nil)
	req.AddCookie(&http.Cookie{Name: "gw_adm", Value: sessionCookie.Value})
	r2, err := client.Do(req)
	if err != nil {
		t.Fatalf("/api/me GET: %v", err)
	}
	body, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("/api/me status = %d, body = %q", r2.StatusCode, body)
	}
	if !strings.Contains(string(body), `"node_type"`) {
		t.Fatalf("/api/me body missing node_type: %q", body)
	}
}

// TestRun_RejectsNonDoorNodeType confirms the role check in run().
func TestRun_RejectsNonDoorNodeType(t *testing.T) {
	cfg := buildSmokeCfg(t)
	cfg.NodeType = config.NodeTypeProxy
	err := run(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected node_type rejection")
	}
	if !strings.Contains(err.Error(), "node_type") {
		t.Fatalf("expected node_type error, got %v", err)
	}
}

// TestRun_RejectsNilConfig checks the defensive guard.
func TestRun_RejectsNilConfig(t *testing.T) {
	if err := run(context.Background(), nil); err == nil {
		t.Fatal("expected error on nil config")
	}
}

// TestRun_RejectsMissingSlugs catches the "at least one slug" rule.
func TestRun_RejectsMissingSlugs(t *testing.T) {
	cfg := buildSmokeCfg(t)
	cfg.Door.Slugs = nil
	err := run(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error on missing slugs")
	}
	if !strings.Contains(err.Error(), "slug") {
		t.Fatalf("expected slug-related error, got %v", err)
	}
}

// TestRun_RejectsDisabledAdmin covers the "admin.enabled must be true"
// bootstrap rule.
func TestRun_RejectsDisabledAdmin(t *testing.T) {
	cfg := buildSmokeCfg(t)
	cfg.Admin.Enabled = false
	err := run(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected admin.enabled rejection")
	}
	if !strings.Contains(err.Error(), "admin") {
		t.Fatalf("expected admin error, got %v", err)
	}
}

// TestRun_RemoteModeRequiresHubURL confirms the remote-mode validation
// fires before any listener starts.
func TestRun_RemoteModeRequiresHubURL(t *testing.T) {
	cfg := buildSmokeCfg(t)
	cfg.Mode = config.ModeRemote
	cfg.Transport.Kind = config.TransportWireguard
	cfg.MTLS.ClientCertFile = "x"
	cfg.MTLS.ClientKeyFile = "y"
	cfg.HubURL = ""
	err := run(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected hub_url rejection")
	}
	if !strings.Contains(err.Error(), "hub_url") {
		t.Fatalf("expected hub_url error, got %v", err)
	}
}
