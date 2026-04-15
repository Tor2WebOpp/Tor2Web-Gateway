package torpool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateTorrc(t *testing.T) {
	tmpDir := t.TempDir()
	torrcPath := filepath.Join(tmpDir, "torrc")

	const testPort = 19050

	if err := generateTorrc(tmpDir, torrcPath, testPort); err != nil {
		t.Fatalf("generateTorrc() error = %v", err)
	}

	data, err := os.ReadFile(torrcPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	content := string(data)

	if !strings.Contains(content, "SocksPort 127.0.0.1:19050") {
		t.Errorf("torrc missing SocksPort line; got:\n%s", content)
	}

	if !strings.Contains(content, "DataDirectory") {
		t.Errorf("torrc missing DataDirectory line; got:\n%s", content)
	}

	if !strings.Contains(content, tmpDir) {
		t.Errorf("torrc DataDirectory does not contain %q; got:\n%s", tmpDir, content)
	}
}

func TestInstanceID(t *testing.T) {
	inst := &TorInstance{Port: 9050}
	want := "tor-9050"
	if got := inst.ID(); got != want {
		t.Errorf("ID() = %q, want %q", got, want)
	}

	inst2 := &TorInstance{Port: 19100}
	want2 := "tor-19100"
	if got := inst2.ID(); got != want2 {
		t.Errorf("ID() = %q, want %q", got, want2)
	}
}
