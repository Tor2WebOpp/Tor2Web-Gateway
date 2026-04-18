// Reproducible screenshot runner for the admin UI.
//
// Boots an in-process admin handler with mock data, exposes it on a
// random localhost port via httptest, and drives a headless Chrome
// session through chromedp to capture one PNG per
// (page x theme x language) combination.
//
// Output filenames: docs/screenshots/<page>-<theme>-<lang>.png
//
// Exit codes:
//
//	0 - all screenshots written
//	1 - hard failure (mock setup, server bind, navigation error)
//	2 - graceful degradation (no Chrome found on PATH); a placeholder
//	    file is written so callers know the feature is set up but
//	    cannot run on this host.
//
// No external services are contacted. Mock hosts are *.example only.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gateway/internal/admin"
	"gateway/internal/metrics"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

const (
	screenshotSlug   = "screenshots"
	screenshotToken1 = "tokenone"
	screenshotToken2 = "tokentwo"
	defaultViewportW = 1440
	defaultViewportH = 900

	// pageReadyTimeout caps how long we wait for #content to populate
	// after a route change before bailing on the screenshot.
	pageReadyTimeout = 10 * time.Second
)

// allPages enumerates the routes registered in app.js. These map 1:1 to
// hash routes the SPA renders into #content.
var allPages = []string{
	"dashboard",
	"tenants",
	"mirrors",
	"blocklist",
	"features",
	"nodes",
	"metrics",
	"audit",
	"auto-domains",
}

func main() {
	out := flag.String("out", "docs/screenshots", "output directory for PNGs")
	themesArg := flag.String("themes", "dark,light", "comma-separated theme list")
	langsArg := flag.String("langs", "en,ru,zh", "comma-separated language list")
	pagesArg := flag.String("pages", "all", "comma-separated page list, or 'all'")
	flag.Parse()

	themes := splitCSV(*themesArg)
	langs := splitCSV(*langsArg)
	pages := allPages
	if *pagesArg != "" && *pagesArg != "all" {
		pages = splitCSV(*pagesArg)
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fail("mkdir output dir: %v", err)
	}

	srv, prefix, err := startMockServer()
	if err != nil {
		fail("start mock server: %v", err)
	}
	defer srv.Close()
	baseURL := srv.URL + prefix + "/"
	fmt.Printf("[screenshots] mock admin listening on %s (prefix=%s)\n", srv.URL, prefix)

	// Pre-flight Chrome detection. Surfaces a clear graceful-degrade
	// message rather than a deep chromedp stack trace when no browser
	// is installed.
	chromePath, found := findChrome()
	if !found {
		writePlaceholder(*out)
		fmt.Fprintf(os.Stderr, "[screenshots] no Chrome/Chromium found in any of:\n")
		for _, p := range candidateChromePaths() {
			fmt.Fprintf(os.Stderr, "  %s\n", p)
		}
		fmt.Fprintf(os.Stderr, "[screenshots] wrote placeholder %s\n", filepath.Join(*out, ".placeholder"))
		os.Exit(2)
	}
	fmt.Printf("[screenshots] using browser: %s\n", chromePath)

	if err := captureAll(baseURL, chromePath, *out, themes, langs, pages); err != nil {
		fail("capture loop: %v", err)
	}
	fmt.Printf("[screenshots] wrote %d PNGs to %s\n", len(themes)*len(langs)*len(pages), *out)
}

// splitCSV trims and discards empty entries.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// fail prints to stderr and exits 1.
func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[screenshots] error: "+format+"\n", a...)
	os.Exit(1)
}

// startMockServer wires the admin handler with mock collaborators and
// installs it behind a Gate at a fixed slug/tokens prefix. Returns the
// running httptest server plus the URL path prefix the caller should
// append before /, /api/..., etc.
//
// A session is minted up-front and injected into every incoming request
// by a wrapper handler. We cannot rely on the browser to round-trip the
// session cookie that admin.SetSessionCookie emits because that cookie
// has Secure=true and httptest serves plain HTTP — Chrome would discard
// it on the way back.
func startMockServer() (*httptest.Server, string, error) {
	tmp, err := os.MkdirTemp("", "screenshots-admin-*")
	if err != nil {
		return nil, "", fmt.Errorf("tempdir: %w", err)
	}
	auditLog, err := admin.OpenLog(tmp)
	if err != nil {
		return nil, "", fmt.Errorf("open audit log: %w", err)
	}
	labeler, err := metrics.NewLabeler(metrics.Config{
		HashTenantLabels: true,
		SaltFile:         filepath.Join(tmp, "salt"),
	})
	if err != nil {
		_ = auditLog.Close()
		return nil, "", fmt.Errorf("labeler: %w", err)
	}

	gate := admin.New(admin.Config{
		Enabled: true,
		Slug:    screenshotSlug,
		Token1:  screenshotToken1,
		Token2:  screenshotToken2,
	})
	prefix := gate.Prefix()

	api := admin.NewRouter(admin.Routes{
		NodeID:   "screenshot-node",
		NodeType: "hub",
		Hub:      newMockHub(),
		Features: newMockFeatures(),
		Metrics:  newMockMetrics(),
		Audit:    newMockAudit(),
		Labeler:  labeler,
	})

	sessions := admin.NewSessionStore(8*time.Hour, 12*time.Hour)
	lockout := admin.NewLockout(admin.LockoutConfig{
		SoftThreshold: 100, SoftWindow: time.Minute, SoftBackoff: time.Second,
		HardThreshold: 1000, HardWindow: time.Hour, HardBan: time.Second,
	})

	innerHandler, err := admin.NewHandler(admin.HandlerConfig{
		NodeID:     "screenshot-node",
		NodeType:   "hub",
		PathPrefix: prefix,
		Sessions:   sessions,
		Lockout:    lockout,
		Audit:      auditLog,
		Labeler:    labeler,
		UI:         admin.UIFS,
		APIRouter:  api,
	})
	if err != nil {
		_ = auditLog.Close()
		return nil, "", fmt.Errorf("admin handler: %w", err)
	}
	gate.SetHandler(innerHandler)

	// Mint a session up-front and remember its id. The wrapper below
	// adds a gw_adm cookie to every incoming request so the inner
	// handler resolves the session and never hits its issue-and-redirect
	// path.
	sess, err := sessions.Create("screenshot-fixed-ip-hash")
	if err != nil {
		_ = auditLog.Close()
		return nil, "", fmt.Errorf("session create: %w", err)
	}

	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always inject the pre-minted session cookie. The Secure flag
		// only matters on the wire; the inner handler simply reads the
		// value via r.Cookie regardless.
		if _, err := r.Cookie(admin.CookieName); err != nil {
			r.AddCookie(&http.Cookie{Name: admin.CookieName, Value: sess.ID})
		}
		gate.ServeHTTP(w, r)
	})

	srv := httptest.NewServer(wrapped)
	return srv, prefix, nil
}

// captureAll iterates (theme, lang, page) and writes one PNG per
// combination. A single chromedp browser instance is reused across the
// whole loop to avoid the per-screenshot Chrome startup cost.
func captureAll(baseURL, chromePath, out string, themes, langs, pages []string) error {
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.NoSandbox,
		chromedp.WindowSize(defaultViewportW, defaultViewportH),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("mute-audio", true),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	// Cheap warmup: makes sure the browser actually launches before the
	// per-screenshot timer starts ticking.
	if err := chromedp.Run(browserCtx); err != nil {
		return fmt.Errorf("launch browser: %w", err)
	}

	var currentScriptID page.ScriptIdentifier
	for _, theme := range themes {
		for _, lang := range langs {
			// Re-register the localStorage prime script so the next
			// Navigate runs it BEFORE any SPA code, guaranteeing the
			// boot path reads the desired theme/lang.
			id, err := registerPrimeScript(browserCtx, currentScriptID, theme, lang)
			if err != nil {
				return fmt.Errorf("register prime script (%s/%s): %w", theme, lang, err)
			}
			currentScriptID = id
			for _, p := range pages {
				outPath := filepath.Join(out, fmt.Sprintf("%s-%s-%s.png", p, theme, lang))
				if err := capturePage(browserCtx, baseURL, p, lang, outPath); err != nil {
					return fmt.Errorf("capture %s (%s/%s): %w", p, theme, lang, err)
				}
				fmt.Printf("[screenshots] wrote %s\n", outPath)
			}
		}
	}
	return nil
}

// registerPrimeScript installs a one-shot CDP script that runs on every
// new document before any page script. It seeds localStorage with the
// theme and lang the SPA boot path will then pick up.
//
// If a previous script id is supplied it is removed first; CDP scripts
// accumulate across calls otherwise.
func registerPrimeScript(ctx context.Context, prev page.ScriptIdentifier, theme, lang string) (page.ScriptIdentifier, error) {
	if prev != "" {
		_ = chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
			return page.RemoveScriptToEvaluateOnNewDocument(prev).Do(c)
		}))
	}
	src := fmt.Sprintf(`(function(){
		try { window.localStorage.setItem('gw_adm_theme', %q); } catch(e) {}
		try { window.localStorage.setItem('gw_adm_lang', %q); } catch(e) {}
	})();`, theme, lang)
	var id page.ScriptIdentifier
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
		newID, err := page.AddScriptToEvaluateOnNewDocument(src).Do(c)
		if err != nil {
			return err
		}
		id = newID
		return nil
	}))
	return id, err
}

// capturePage navigates to the requested route, waits for the SPA to
// populate #content, and writes a full-page PNG to outPath.
//
// Each call uses a unique cache-buster query string so chromedp issues
// a true cross-document navigation (and not Chrome's same-document
// hash-only optimisation): that forces the SPA boot path to run fresh
// and pick up whatever theme/lang the on-new-document prime script
// just wrote into localStorage. The lang query parameter is also set
// explicitly because app.js honours it directly when present.
func capturePage(ctx context.Context, baseURL, pageName, lang, outPath string) error {
	nav := fmt.Sprintf("%d", time.Now().UnixNano())
	target := fmt.Sprintf("%s?lang=%s&n=%s#/%s", baseURL, lang, nav, pageName)
	pageCtx, cancel := context.WithTimeout(ctx, pageReadyTimeout)
	defer cancel()

	var buf []byte
	err := chromedp.Run(pageCtx,
		chromedp.EmulateViewport(defaultViewportW, defaultViewportH),
		chromedp.Navigate(target),
		// Soft wait: poll until #content has any rendered text. A short
		// fixed delay smooths over the asynchronous fetches each page
		// fans out to /api/* before painting cards/tables.
		chromedp.Poll(`document.querySelector('#content') && document.querySelector('#content').textContent && document.querySelector('#content').textContent.trim().length > 0`, nil),
		chromedp.Sleep(300*time.Millisecond),
		chromedp.FullScreenshot(&buf, 100),
	)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, buf, 0o644)
}

// candidateChromePaths returns the OS-specific list of locations the
// runner will probe for a Chrome/Chromium binary.
func candidateChromePaths() []string {
	switch runtime.GOOS {
	case "windows":
		userProfile := os.Getenv("USERPROFILE")
		out := []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files\Chromium\Application\chrome.exe`,
		}
		if userProfile != "" {
			out = append(out,
				filepath.Join(userProfile, `AppData\Local\Google\Chrome\Application\chrome.exe`),
				filepath.Join(userProfile, `AppData\Local\Chromium\Application\chrome.exe`),
			)
		}
		return out
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/usr/bin/google-chrome",
			"/usr/local/bin/chromium",
		}
	default:
		return []string{
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/snap/bin/chromium",
			"/usr/local/bin/chromium",
		}
	}
}

// findChrome returns the first existing path from the candidate list
// or, failing that, looks up "chrome"/"chromium" on PATH. The boolean
// is false when no candidate exists.
func findChrome() (string, bool) {
	for _, p := range candidateChromePaths() {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, true
		}
	}
	for _, name := range []string{"chrome", "chromium", "google-chrome", "google-chrome-stable", "chrome.exe"} {
		if path, err := lookPath(name); err == nil {
			return path, true
		}
	}
	return "", false
}

// lookPath is a thin wrapper over exec.LookPath, isolated so the rest
// of the runner does not have to think about its semantics (notably
// the LookPathError shape that bubbles up on Windows when PATHEXT
// doesn't include the binary's suffix).
func lookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// writePlaceholder leaves a marker file explaining how to regenerate
// the real PNGs on a host that has Chrome installed.
func writePlaceholder(dir string) {
	body := `Screenshot generation skipped on this host: no headless Chrome was
found in any of the standard locations. Run ` + "`make screenshots`" + ` (or
` + "`go run ./tests/screenshots -out=docs/screenshots`" + `) on a machine
with stable Google Chrome (or Chromium) installed to populate this
directory with the full set of <page>-<theme>-<lang>.png files.
`
	_ = os.WriteFile(filepath.Join(dir, ".placeholder"), []byte(body), 0o644)
}
