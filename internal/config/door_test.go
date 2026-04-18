package config

import (
	"strings"
	"testing"
)

func TestLoadDoorFile_RoundTrip(t *testing.T) {
	y := `
cover:
  enabled: true
  kind: static_file
  path: /etc/gateway/cover/cat.jpg
  content_type: image/jpeg
  headers:
    Cache-Control: "public, max-age=3600"
slugs:
  - slug: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    strategy: random
    target_tenants: []
    status: 302
    exclude_regions: [RU]
  - slug: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    strategy: round_robin
    target_tenants: [example-a.example]
    status: 307
    weight: 5
`
	path := writeTempFile(t, "door.yaml", y)
	d, err := LoadDoorFile(path)
	if err != nil {
		t.Fatalf("LoadDoorFile: %v", err)
	}
	if !d.Cover.Enabled || d.Cover.Kind != CoverKindStaticFile {
		t.Errorf("cover = %+v", d.Cover)
	}
	if d.Cover.Headers["Cache-Control"] != "public, max-age=3600" {
		t.Errorf("headers = %+v", d.Cover.Headers)
	}
	if len(d.Slugs) != 2 {
		t.Fatalf("expected 2 slugs, got %d", len(d.Slugs))
	}
	if d.Slugs[0].Strategy != StrategyRandom || d.Slugs[0].Status != 302 {
		t.Errorf("slug0 = %+v", d.Slugs[0])
	}
	if d.Slugs[1].Strategy != StrategyRoundRobin || d.Slugs[1].Status != 307 {
		t.Errorf("slug1 = %+v", d.Slugs[1])
	}
	if d.Slugs[0].ExcludeRegions[0] != "RU" {
		t.Errorf("exclude_regions = %v", d.Slugs[0].ExcludeRegions)
	}
}

func TestLoadDoorFile_DefaultsAppliedByValidate(t *testing.T) {
	y := `
slugs:
  - slug: "ccccccccccccccccccccccccccccccccc"
`
	path := writeTempFile(t, "door.yaml", y)
	d, err := LoadDoorFile(path)
	if err != nil {
		t.Fatalf("LoadDoorFile: %v", err)
	}
	if d.Slugs[0].Strategy != StrategyRandom {
		t.Errorf("expected default strategy=random, got %q", d.Slugs[0].Strategy)
	}
	if d.Slugs[0].Status != 302 {
		t.Errorf("expected default status=302, got %d", d.Slugs[0].Status)
	}
}

func TestValidateDoor_RejectsEmptySlugs(t *testing.T) {
	err := ValidateDoor(&DoorConf{})
	if err == nil || !strings.Contains(err.Error(), "at least one slug") {
		t.Fatalf("expected empty-slug rejection, got %v", err)
	}
}

func TestValidateDoor_RejectsBadKind(t *testing.T) {
	d := &DoorConf{
		Cover: CoverConf{Enabled: true, Kind: "nope"},
		Slugs: []SlugConf{{Slug: "x"}},
	}
	err := ValidateDoor(d)
	if err == nil || !strings.Contains(err.Error(), "cover.kind") {
		t.Fatalf("expected cover.kind rejection, got %v", err)
	}
}

func TestValidateDoor_RejectsBadStrategy(t *testing.T) {
	d := &DoorConf{
		Slugs: []SlugConf{{Slug: "x", Strategy: "nope"}},
	}
	err := ValidateDoor(d)
	if err == nil || !strings.Contains(err.Error(), "strategy") {
		t.Fatalf("expected strategy rejection, got %v", err)
	}
}

func TestValidateDoor_RejectsBadStatus(t *testing.T) {
	d := &DoorConf{
		Slugs: []SlugConf{{Slug: "x", Strategy: StrategyRandom, Status: 404}},
	}
	err := ValidateDoor(d)
	if err == nil || !strings.Contains(err.Error(), "status") {
		t.Fatalf("expected status rejection, got %v", err)
	}
}

func TestValidateDoor_StaticFileRequiresPath(t *testing.T) {
	d := &DoorConf{
		Cover: CoverConf{Enabled: true, Kind: CoverKindStaticFile},
		Slugs: []SlugConf{{Slug: "x"}},
	}
	err := ValidateDoor(d)
	if err == nil || !strings.Contains(err.Error(), "cover.path") {
		t.Fatalf("expected cover.path rejection, got %v", err)
	}
}

func TestValidateDoor_Passthrough404AllowsEmptyPath(t *testing.T) {
	d := &DoorConf{
		Cover: CoverConf{Enabled: true, Kind: CoverKindPassthrough404},
		Slugs: []SlugConf{{Slug: "x"}},
	}
	if err := ValidateDoor(d); err != nil {
		t.Fatalf("expected passthrough_404 with empty path to pass, got %v", err)
	}
}

func TestLoadDoorFile_MissingFile(t *testing.T) {
	if _, err := LoadDoorFile("/nonexistent/door.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}
