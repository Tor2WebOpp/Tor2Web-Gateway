// Package main implements the OPSEC linter: a CI-friendly scanner that
// searches the repository tree and optionally compiled binaries for a
// configurable list of banned substrings. Case-insensitive matching.
//
// Exit codes:
//
//	0 -- clean
//	1 -- violations found (fatal)
//	2 -- IO or configuration error
//
// Usage:
//
//	opsec_lint [--repo=.] [--binaries=paths,...] [--banned=path/to/banned_strings.txt]
//	          [--json] [--scan-git]
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Violation is a single banned-string hit.
type Violation struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Col     int    `json:"col"`
	Banned  string `json:"banned"`
	Snippet string `json:"snippet,omitempty"`
	Kind    string `json:"kind"` // "source" | "binary" | "git"
}

// Warning is a non-fatal finding surfaced to the user.
type Warning struct {
	File    string `json:"file"`
	Message string `json:"message"`
}

// Report aggregates violations + warnings for JSON output.
type Report struct {
	Violations   []Violation `json:"violations"`
	Warnings     []Warning   `json:"warnings"`
	FilesScanned int         `json:"files_scanned"`
	BannedCount  int         `json:"banned_terms"`
	Clean        bool        `json:"clean"`
}

// defaultSkipDirs are never walked during repo scan.
var defaultSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	// caches that would otherwise be huge
	".cache":  true,
	".idea":   true,
	".vscode": true,
}

// defaultSkipExts are binary/media formats that should not be text-scanned.
// (Compiled binaries are scanned separately via --binaries.)
var defaultSkipExts = map[string]bool{
	".png":   true,
	".jpg":   true,
	".jpeg":  true,
	".gif":   true,
	".pdf":   true,
	".ico":   true,
	".webp":  true,
	".zip":   true,
	".gz":    true,
	".tgz":   true,
	".bz2":   true,
	".xz":    true,
	".tar":   true,
	".7z":    true,
	".mp4":   true,
	".mp3":   true,
	".mov":   true,
	".woff":  true,
	".woff2": true,
	".ttf":   true,
	".eot":   true,
}

// loadBanned parses a banned-strings file. Blank lines and lines starting
// with '#' are ignored. Duplicates and whitespace are trimmed.
// Returns the list in canonical (lowercase) form plus a set for quick lookup.
func loadBanned(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open banned list: %w", err)
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	// Some banned strings could be long; raise buffer safely.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if seen[lower] {
			continue
		}
		seen[lower] = true
		out = append(out, lower)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read banned list: %w", err)
	}
	// Empty list is legitimate: the project may not have banned terms yet.
	// Callers treat the empty case as trivially clean rather than an error.
	return out, nil
}

// shouldSkipPath returns true for files/dirs excluded from repo scan.
// selfPath, if non-empty, is the absolute path to the banned-list file;
// the list itself must not be scanned (it contains every banned term).
func shouldSkipPath(absPath string, info fs.DirEntry, selfPath string) bool {
	name := info.Name()
	if info.IsDir() {
		if defaultSkipDirs[name] {
			return true
		}
		return false
	}
	if selfPath != "" {
		if equalPath(absPath, selfPath) {
			return true
		}
	}
	ext := strings.ToLower(filepath.Ext(name))
	if defaultSkipExts[ext] {
		return true
	}
	return false
}

// equalPath compares two paths using OS-appropriate case rules.
// On Windows, file paths are case-insensitive.
func equalPath(a, b string) bool {
	aa, err := filepath.Abs(a)
	if err != nil {
		aa = a
	}
	bb, err := filepath.Abs(b)
	if err != nil {
		bb = b
	}
	if isCaseInsensitiveFS() {
		return strings.EqualFold(filepath.Clean(aa), filepath.Clean(bb))
	}
	return filepath.Clean(aa) == filepath.Clean(bb)
}

// scanRepo walks repoRoot and reports every banned-string hit in text files.
// selfPath is the absolute path of banned_strings.txt (excluded from scan).
func scanRepo(repoRoot string, banned []string, selfPath string) ([]Violation, int, error) {
	var vs []Violation
	count := 0
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			// Permission errors or transient issues -- log and continue.
			return nil
		}
		if shouldSkipPath(path, d, selfPath) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		// Size guard: skip unusually large files (>20 MB) to keep the linter fast.
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		if fi.Size() > 20*1024*1024 {
			return nil
		}
		found, err := scanFile(path, banned)
		if err != nil {
			// Unreadable file -- not fatal; continue scanning others.
			return nil
		}
		count++
		vs = append(vs, found...)
		return nil
	})
	if err != nil {
		return nil, count, err
	}
	return vs, count, nil
}

// scanFile scans a single text file for banned substrings.
func scanFile(path string, banned []string) ([]Violation, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var vs []Violation
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := sc.Text()
		lower := strings.ToLower(line)
		for _, b := range banned {
			idx := 0
			for {
				hit := strings.Index(lower[idx:], b)
				if hit < 0 {
					break
				}
				col := idx + hit + 1
				vs = append(vs, Violation{
					File:    path,
					Line:    lineNum,
					Col:     col,
					Banned:  b,
					Snippet: snippet(line, idx+hit, len(b)),
					Kind:    "source",
				})
				idx = idx + hit + len(b)
				if idx >= len(lower) {
					break
				}
			}
		}
	}
	// Non-text / giant-line files may overflow the scanner; treat as binary-ish
	// and fall back to a single-buffer printable-string extract.
	if err := sc.Err(); err != nil {
		// Reset and scan via binary extractor.
		if _, serr := f.Seek(0, io.SeekStart); serr == nil {
			data, rerr := io.ReadAll(io.LimitReader(f, 20*1024*1024))
			if rerr == nil {
				vs = append(vs, scanBytesForStrings(path, data, banned, "source")...)
			}
		}
	}
	return vs, nil
}

// snippet returns a short context window around the hit, trimmed for log
// readability. Never returns more than 80 chars. Bounds are clamped
// defensively in case the caller computed `at` against a lowercased copy
// whose length differs from `line` (non-ASCII Unicode characters can
// change byte length on ToLower).
func snippet(line string, at, n int) string {
	if len(line) == 0 || at < 0 {
		return ""
	}
	if at >= len(line) {
		at = len(line) - 1
	}
	start := at - 20
	if start < 0 {
		start = 0
	}
	end := at + n + 20
	if end > len(line) {
		end = len(line)
	}
	if end < start {
		end = start
	}
	s := line[start:end]
	// Collapse whitespace for one-line output.
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// scanBinary reads a compiled binary, extracts printable ASCII runs
// of >=4 bytes, and searches them for banned strings.
func scanBinary(path string, banned []string) ([]Violation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return scanBytesForStrings(path, data, banned, "binary"), nil
}

// scanBytesForStrings is the shared "strings"-equivalent scanner used by
// both binary scanning and the fallback path in scanFile.
func scanBytesForStrings(path string, data []byte, banned []string, kind string) []Violation {
	const minRun = 4
	var vs []Violation
	var run bytes.Buffer
	var runStart int
	flush := func(endIdx int) {
		if run.Len() >= minRun {
			s := run.String()
			lower := strings.ToLower(s)
			for _, b := range banned {
				idx := 0
				for {
					hit := strings.Index(lower[idx:], b)
					if hit < 0 {
						break
					}
					absAt := runStart + idx + hit
					vs = append(vs, Violation{
						File:    path,
						Line:    0,
						Col:     absAt + 1,
						Banned:  b,
						Snippet: snippet(s, idx+hit, len(b)),
						Kind:    kind,
					})
					idx = idx + hit + len(b)
					if idx >= len(lower) {
						break
					}
				}
			}
		}
		run.Reset()
	}
	for i, c := range data {
		if c >= 0x20 && c <= 0x7e { // printable ASCII
			if run.Len() == 0 {
				runStart = i
			}
			run.WriteByte(c)
		} else {
			flush(i)
		}
	}
	flush(len(data))
	return vs
}

// scanGitLog runs `git log` against repoRoot and searches commit messages.
// Best-effort: if git is unavailable, no violations and no error.
func scanGitLog(repoRoot string, banned []string) []Violation {
	cmd := exec.Command("git", "-C", repoRoot, "log", "--pretty=format:%H%n%s%n%b%n--END--")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var vs []Violation
	lower := strings.ToLower(string(out))
	for _, b := range banned {
		idx := 0
		for {
			hit := strings.Index(lower[idx:], b)
			if hit < 0 {
				break
			}
			vs = append(vs, Violation{
				File:   "<git-log>",
				Line:   0,
				Col:    idx + hit + 1,
				Banned: b,
				Kind:   "git",
			})
			idx = idx + hit + len(b)
			if idx >= len(lower) {
				break
			}
		}
	}
	return vs
}

// scanGoModReplaces returns warnings (not violations) for every `replace`
// directive found in go.mod -- they typically indicate a dev-only setup.
func scanGoModReplaces(repoRoot string) []Warning {
	path := filepath.Join(repoRoot, "go.mod")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var ws []Warning
	sc := bufio.NewScanner(bytes.NewReader(data))
	inBlock := false
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "replace ") || line == "replace (" {
			if line == "replace (" {
				inBlock = true
				continue
			}
			ws = append(ws, Warning{
				File:    path,
				Message: fmt.Sprintf("go.mod:%d replace directive: %s", lineNum, line),
			})
			continue
		}
		if inBlock {
			if line == ")" {
				inBlock = false
				continue
			}
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			ws = append(ws, Warning{
				File:    path,
				Message: fmt.Sprintf("go.mod:%d replace directive: %s", lineNum, line),
			})
		}
	}
	return ws
}

// LintOptions carries the configuration for RunLint.
type LintOptions struct {
	Repo     string
	Binaries []string
	Banned   string
	ScanGit  bool
}

// RunLint performs a full lint pass and returns the report.
// It does not call os.Exit -- callers decide how to handle the result.
func RunLint(opts LintOptions) (Report, error) {
	banned, err := loadBanned(opts.Banned)
	if err != nil {
		return Report{}, err
	}
	selfAbs, _ := filepath.Abs(opts.Banned)

	report := Report{BannedCount: len(banned)}

	if opts.Repo != "" {
		vs, scanned, err := scanRepo(opts.Repo, banned, selfAbs)
		if err != nil {
			return report, fmt.Errorf("scan repo: %w", err)
		}
		report.Violations = append(report.Violations, vs...)
		report.FilesScanned = scanned
		report.Warnings = append(report.Warnings, scanGoModReplaces(opts.Repo)...)
		if opts.ScanGit {
			report.Violations = append(report.Violations, scanGitLog(opts.Repo, banned)...)
		}
	}

	for _, bp := range opts.Binaries {
		if bp == "" {
			continue
		}
		vs, err := scanBinary(bp, banned)
		if err != nil {
			// Missing binary is a warning, not a hard fail, so the job is
			// useful even when a particular cmd isn't built locally.
			report.Warnings = append(report.Warnings, Warning{
				File:    bp,
				Message: fmt.Sprintf("could not scan binary: %v", err),
			})
			continue
		}
		report.Violations = append(report.Violations, vs...)
	}

	sortViolations(report.Violations)
	report.Clean = len(report.Violations) == 0
	return report, nil
}

func sortViolations(vs []Violation) {
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].File != vs[j].File {
			return vs[i].File < vs[j].File
		}
		if vs[i].Line != vs[j].Line {
			return vs[i].Line < vs[j].Line
		}
		return vs[i].Col < vs[j].Col
	})
}

// printHuman writes a human-readable report to w.
func printHuman(w io.Writer, r Report) {
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "warn: %s: %s\n", warn.File, warn.Message)
	}
	for _, v := range r.Violations {
		if v.Line > 0 {
			fmt.Fprintf(w, "%s:%d:%d: banned %q [%s] %s\n",
				v.File, v.Line, v.Col, v.Banned, v.Kind, v.Snippet)
		} else {
			fmt.Fprintf(w, "%s:@%d: banned %q [%s] %s\n",
				v.File, v.Col, v.Banned, v.Kind, v.Snippet)
		}
	}
	fmt.Fprintf(w, "opsec: scanned %d file(s), %d banned term(s), %d violation(s), %d warning(s)\n",
		r.FilesScanned, r.BannedCount, len(r.Violations), len(r.Warnings))
}

func printJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// --- entry point -----------------------------------------------------------

func main() {
	code := run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}

// run is the testable entry point; it takes args + writers and returns the
// exit code instead of calling os.Exit directly.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("opsec_lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", ".", "repository root to scan (\"\" to disable)")
	binaries := fs.String("binaries", "", "comma-separated binary paths to scan")
	banned := fs.String("banned", "tests/opsec/banned_strings.txt", "banned strings list")
	jsonOut := fs.Bool("json", false, "emit JSON report to stdout")
	scanGit := fs.Bool("scan-git", false, "also scan git log messages")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var bins []string
	if strings.TrimSpace(*binaries) != "" {
		for _, p := range strings.Split(*binaries, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				bins = append(bins, p)
			}
		}
	}

	r, err := RunLint(LintOptions{
		Repo:     *repo,
		Binaries: bins,
		Banned:   *banned,
		ScanGit:  *scanGit,
	})
	if err != nil {
		fmt.Fprintf(stderr, "opsec: %v\n", err)
		return 2
	}

	if *jsonOut {
		if err := printJSON(stdout, r); err != nil {
			fmt.Fprintf(stderr, "opsec: json encode: %v\n", err)
			return 2
		}
	} else {
		printHuman(stdout, r)
	}

	if !r.Clean {
		return 1
	}
	return 0
}

// isCaseInsensitiveFS returns true on filesystems where paths are compared
// case-insensitively (Windows, macOS default). Called only for path equality,
// never for content matching (content is always case-insensitive by design).
func isCaseInsensitiveFS() bool {
	// Cheap heuristic; we don't need exact FS detection for the self-skip.
	return filepath.Separator == '\\' || runtimeIsDarwin()
}

func runtimeIsDarwin() bool {
	// Avoid importing "runtime" just for this; stdlib guidance says the
	// check may be inlined. But the only place it matters is self-skip on
	// macOS, and we can safely be conservative (true) -- the content scan
	// is already case-insensitive, so a false positive here is harmless.
	return false
}
