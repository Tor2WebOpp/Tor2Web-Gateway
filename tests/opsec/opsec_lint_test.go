package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeFile is a small helper that creates path+content, making parents as needed.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeBannedList writes a canonical banned-strings file with a synthetic
// test token plus some comments/blank lines, exercising loadBanned's filter
// rules. The token is a test-only canary; it does not correspond to any real
// project identifier and is never embedded in production binaries.
func writeBannedList(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "banned_strings.txt")
	writeFile(t, path, `# banned list
# comment

TESTBANNED
# another comment

`)
	return path
}

func TestLoadBanned_SkipsCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.txt")
	writeFile(t, path, "# header\n\nFoo\n#Comment\nBar\n\nFoo\n")
	terms, err := loadBanned(path)
	if err != nil {
		t.Fatalf("loadBanned: %v", err)
	}
	if len(terms) != 2 {
		t.Fatalf("want 2 unique terms, got %d: %v", len(terms), terms)
	}
	// Terms are canonicalized to lowercase.
	if terms[0] != "foo" || terms[1] != "bar" {
		t.Fatalf("unexpected terms: %v", terms)
	}
}

func TestLoadBanned_EmptyListIsTriviallyClean(t *testing.T) {
	// A banned list with only comments or blanks is legitimate: it means
	// the project has no banned terms configured yet. loadBanned must
	// return an empty slice, not an error.
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	writeFile(t, path, "# just a comment\n\n")
	terms, err := loadBanned(path)
	if err != nil {
		t.Fatalf("loadBanned: %v", err)
	}
	if len(terms) != 0 {
		t.Fatalf("expected 0 terms, got %d: %v", len(terms), terms)
	}
}

func TestRunLint_DetectsBannedInRepo(t *testing.T) {
	dir := t.TempDir()
	banned := writeBannedList(t, dir)
	repo := filepath.Join(dir, "repo")
	writeFile(t, filepath.Join(repo, "hello.go"), "package x\n\nvar name = \"testbanned mirror\"\n")

	r, err := RunLint(LintOptions{Repo: repo, Banned: banned})
	if err != nil {
		t.Fatalf("RunLint: %v", err)
	}
	if r.Clean {
		t.Fatal("expected violations, got clean report")
	}
	if len(r.Violations) == 0 {
		t.Fatal("expected at least one violation")
	}
	v := r.Violations[0]
	if v.Line != 3 {
		t.Errorf("expected hit on line 3, got %d", v.Line)
	}
	if v.Banned != "testbanned" {
		t.Errorf("expected banned=testbanned, got %q", v.Banned)
	}
	if v.Kind != "source" {
		t.Errorf("expected kind=source, got %q", v.Kind)
	}
}

func TestRunLint_CleanRepoReportsClean(t *testing.T) {
	dir := t.TempDir()
	banned := writeBannedList(t, dir)
	repo := filepath.Join(dir, "repo")
	writeFile(t, filepath.Join(repo, "ok.go"), "package x\n\nvar name = \"neutral mirror\"\n")

	r, err := RunLint(LintOptions{Repo: repo, Banned: banned})
	if err != nil {
		t.Fatalf("RunLint: %v", err)
	}
	if !r.Clean {
		t.Fatalf("expected clean, got %d violations: %+v", len(r.Violations), r.Violations)
	}
}

func TestRunLint_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	banned := writeBannedList(t, dir)
	repo := filepath.Join(dir, "repo")
	// Three variants that should all be flagged as the single banned term "testbanned".
	writeFile(t, filepath.Join(repo, "a.txt"), "TESTBANNED\n")
	writeFile(t, filepath.Join(repo, "b.txt"), "Testbanned\n")
	writeFile(t, filepath.Join(repo, "c.txt"), "testbanned\n")

	r, err := RunLint(LintOptions{Repo: repo, Banned: banned})
	if err != nil {
		t.Fatalf("RunLint: %v", err)
	}
	if len(r.Violations) != 3 {
		t.Fatalf("expected 3 violations across casing variants, got %d", len(r.Violations))
	}
	for _, v := range r.Violations {
		if v.Banned != "testbanned" {
			t.Errorf("banned term not lowercased: %q", v.Banned)
		}
	}
}

func TestRunLint_SkipsGitVendorAndBinaryExtensions(t *testing.T) {
	dir := t.TempDir()
	banned := writeBannedList(t, dir)
	repo := filepath.Join(dir, "repo")

	// Files inside skipped dirs / with binary extensions must NOT be scanned.
	writeFile(t, filepath.Join(repo, ".git", "sneaky.txt"), "TESTBANNED\n")
	writeFile(t, filepath.Join(repo, "vendor", "mod", "foo.go"), "TESTBANNED\n")
	writeFile(t, filepath.Join(repo, "node_modules", "x", "y.js"), "TESTBANNED\n")
	writeFile(t, filepath.Join(repo, "assets", "logo.png"), "TESTBANNED\n")
	// Canary file that MUST be scanned so we know the test isn't passing trivially.
	writeFile(t, filepath.Join(repo, "visible.go"), "// TESTBANNED\n")

	r, err := RunLint(LintOptions{Repo: repo, Banned: banned})
	if err != nil {
		t.Fatalf("RunLint: %v", err)
	}
	if len(r.Violations) != 1 {
		t.Fatalf("expected exactly 1 violation (canary only); got %d: %+v", len(r.Violations), r.Violations)
	}
	if !strings.HasSuffix(r.Violations[0].File, "visible.go") {
		t.Fatalf("expected canary file, got %s", r.Violations[0].File)
	}
}

func TestRunLint_SkipsBannedListItself(t *testing.T) {
	dir := t.TempDir()
	banned := writeBannedList(t, dir)

	// Point repo at the SAME dir so the banned list is inside the scanned tree;
	// the linter must skip the banned-list file (otherwise it'd match itself).
	writeFile(t, filepath.Join(dir, "code.go"), "// clean\n")

	r, err := RunLint(LintOptions{Repo: dir, Banned: banned})
	if err != nil {
		t.Fatalf("RunLint: %v", err)
	}
	if !r.Clean {
		t.Fatalf("expected clean (banned list should self-skip); got %+v", r.Violations)
	}
}

func TestScanBinary_FindsLiteralInCompiledGoProgram(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go toolchain not available: %v", err)
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "tiny")
	writeFile(t, filepath.Join(src, "main.go"), `package main

import "fmt"

func main() {
	// A literal the OPSEC scanner must find once compiled.
	fmt.Println("codeword-TESTBANNED-leak")
}
`)
	writeFile(t, filepath.Join(src, "go.mod"), "module tiny\n\ngo 1.22\n")

	bin := filepath.Join(dir, "tiny.exe")
	if runtime.GOOS != "windows" {
		bin = filepath.Join(dir, "tiny")
	}
	cmd := exec.Command(goBin, "build", "-o", bin, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var berr bytes.Buffer
	cmd.Stderr = &berr
	if err := cmd.Run(); err != nil {
		t.Skipf("go build failed (env may lack compiler): %v\n%s", err, berr.String())
	}

	bannedPath := writeBannedList(t, dir)
	r, err := RunLint(LintOptions{Repo: "", Binaries: []string{bin}, Banned: bannedPath})
	if err != nil {
		t.Fatalf("RunLint: %v", err)
	}
	if r.Clean {
		t.Fatal("expected violations in compiled binary, got clean")
	}
	sawBinary := false
	for _, v := range r.Violations {
		if v.Kind == "binary" && v.Banned == "testbanned" {
			sawBinary = true
			break
		}
	}
	if !sawBinary {
		t.Fatalf("expected a 'binary' kind hit for testbanned; violations=%+v", r.Violations)
	}
}

func TestScanBytesForStrings_IgnoresRunsShorterThanMin(t *testing.T) {
	// Surround "tb" (too short alone) with non-printables so it's discarded.
	// "testbanned" is the banned term; embed one valid run and one invalidated one.
	data := []byte{
		0x00, 't', 'b', 0x00, // run too short, must not trigger
		'c', 'o', 'd', 'e', '-', 't', 'e', 's', 't', 'b', 'a', 'n', 'n', 'e', 'd', '-', 't', 'a', 'g', 0x00,
	}
	vs := scanBytesForStrings("x", data, []string{"testbanned"}, "binary")
	if len(vs) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(vs), vs)
	}
	if vs[0].Kind != "binary" {
		t.Fatalf("kind=%q", vs[0].Kind)
	}
}

func TestRun_ExitCodes(t *testing.T) {
	dir := t.TempDir()
	bannedPath := writeBannedList(t, dir)

	// Clean repo -> exit 0.
	cleanRepo := filepath.Join(dir, "clean")
	writeFile(t, filepath.Join(cleanRepo, "ok.go"), "package x\n")
	var out, errb bytes.Buffer
	code := run([]string{"--repo=" + cleanRepo, "--banned=" + bannedPath}, &out, &errb)
	if code != 0 {
		t.Fatalf("clean repo: expected exit 0, got %d (stderr=%s)", code, errb.String())
	}

	// Dirty repo -> exit 1.
	dirtyRepo := filepath.Join(dir, "dirty")
	writeFile(t, filepath.Join(dirtyRepo, "bad.go"), "// TESTBANNED\n")
	out.Reset()
	errb.Reset()
	code = run([]string{"--repo=" + dirtyRepo, "--banned=" + bannedPath}, &out, &errb)
	if code != 1 {
		t.Fatalf("dirty repo: expected exit 1, got %d", code)
	}
	if !strings.Contains(out.String(), "banned") {
		t.Fatalf("expected human report to mention \"banned\"; got %q", out.String())
	}

	// Missing banned list -> exit 2.
	out.Reset()
	errb.Reset()
	code = run([]string{"--repo=" + cleanRepo, "--banned=" + filepath.Join(dir, "nope.txt")}, &out, &errb)
	if code != 2 {
		t.Fatalf("missing banned list: expected exit 2, got %d", code)
	}
}

func TestRun_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	bannedPath := writeBannedList(t, dir)
	repo := filepath.Join(dir, "repo")
	writeFile(t, filepath.Join(repo, "x.go"), "TESTBANNED\n")
	var out, errb bytes.Buffer
	code := run([]string{"--repo=" + repo, "--banned=" + bannedPath, "--json"}, &out, &errb)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	s := out.String()
	if !strings.Contains(s, "\"violations\"") || !strings.Contains(s, "\"clean\": false") {
		t.Fatalf("json report missing expected fields: %s", s)
	}
}

func TestScanGoModReplaces_EmitsWarnings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"),
		"module x\n\ngo 1.22\n\nreplace foo => ../foo\n\nreplace (\n\tbar => ../bar\n)\n")
	warns := scanGoModReplaces(dir)
	if len(warns) < 2 {
		t.Fatalf("expected >=2 warnings for replace directives, got %d: %+v", len(warns), warns)
	}
}
