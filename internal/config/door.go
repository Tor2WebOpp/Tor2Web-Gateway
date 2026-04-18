package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Cover-page kinds accepted by CoverConf.Kind.
const (
	CoverKindStaticFile      = "static_file"
	CoverKindStaticHTML      = "static_html"
	CoverKindPassthrough404  = "passthrough_404"
)

// Slug-selection strategies accepted by SlugConf.Strategy.
const (
	StrategyRandom      = "random"
	StrategyWeighted    = "weighted"
	StrategyRoundRobin  = "round_robin"
)

// DoorConf is the door-specific runtime configuration stanza. A door
// binary is pointless without at least one slug configured; validation
// rejects that case at boot.
type DoorConf struct {
	Cover CoverConf  `yaml:"cover"`
	Slugs []SlugConf `yaml:"slugs"`
}

// CoverConf describes the "/" handler's behaviour: a benign-looking page
// that gives casual scanners nothing to grab onto.
type CoverConf struct {
	Enabled     bool              `yaml:"enabled"`
	Kind        string            `yaml:"kind"`
	Path        string            `yaml:"path"`
	ContentType string            `yaml:"content_type"`
	Headers     map[string]string `yaml:"headers,omitempty"`
}

// SlugConf describes one slug → mirror redirect rule.
//
// Strategy selects between random, weighted, and round-robin mirror
// picks. Status is the HTTP status code written on a match (302 or 307).
// TargetTenants narrows the candidate mirrors to those declaring one of
// the listed hosts; an empty list admits every mirror. ExcludeRegions
// skips mirrors that check-host has flagged as blocked in any of the
// listed ISO-3166 alpha-2 region codes.
type SlugConf struct {
	Slug           string   `yaml:"slug"`
	Strategy       string   `yaml:"strategy"`
	TargetTenants  []string `yaml:"target_tenants,omitempty"`
	Status         int      `yaml:"status"`
	ExcludeRegions []string `yaml:"exclude_regions,omitempty"`
	Weight         int      `yaml:"weight,omitempty"`
}

// LoadDoorFile reads and validates a door runtime config file.
func LoadDoorFile(path string) (*DoorConf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("door: read file %q: %w", path, err)
	}
	var d DoorConf
	if err := yaml.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("door: parse yaml: %w", err)
	}
	if err := ValidateDoor(&d); err != nil {
		return nil, fmt.Errorf("door: validation: %w", err)
	}
	return &d, nil
}

// ValidateDoor inspects d in place. It enforces the "at least one slug"
// rule the spec mandates, and fills in reasonable defaults for strategy
// and status. Exported so main.go can run the same rules against a
// DoorConf loaded out-of-band from a larger config file.
func ValidateDoor(d *DoorConf) error {
	if d == nil {
		return errors.New("door config is required")
	}
	if d.Cover.Enabled {
		if !isValidCoverKind(d.Cover.Kind) {
			return fmt.Errorf("cover.kind must be static_file|static_html|passthrough_404, got %q", d.Cover.Kind)
		}
		if d.Cover.Kind != CoverKindPassthrough404 && d.Cover.Path == "" {
			return errors.New("cover.path is required when cover.enabled and kind != passthrough_404")
		}
	}
	if len(d.Slugs) == 0 {
		return errors.New("at least one slug is required")
	}
	for i := range d.Slugs {
		s := &d.Slugs[i]
		if s.Slug == "" {
			return fmt.Errorf("slugs[%d].slug is required", i)
		}
		if s.Strategy == "" {
			s.Strategy = StrategyRandom
		}
		if !isValidStrategy(s.Strategy) {
			return fmt.Errorf("slugs[%d].strategy must be random|weighted|round_robin, got %q", i, s.Strategy)
		}
		if s.Status == 0 {
			s.Status = 302
		}
		if s.Status != 302 && s.Status != 307 {
			return fmt.Errorf("slugs[%d].status must be 302 or 307, got %d", i, s.Status)
		}
	}
	return nil
}

func isValidCoverKind(k string) bool {
	switch k {
	case CoverKindStaticFile, CoverKindStaticHTML, CoverKindPassthrough404:
		return true
	}
	return false
}

func isValidStrategy(s string) bool {
	switch s {
	case StrategyRandom, StrategyWeighted, StrategyRoundRobin:
		return true
	}
	return false
}
