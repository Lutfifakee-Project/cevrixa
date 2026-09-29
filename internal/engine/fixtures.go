package engine

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

//go:embed fixtures/cve/*.json
//go:embed fixtures/osv/*.json
var embeddedFixtures embed.FS

func loadFixturesFromEmbed() ([]domain.Vulnerability, error) {
	cveVulns, err := loadFixturesFS(embeddedFixtures, "fixtures/cve")
	if err != nil {
		return nil, err
	}
	osvVulns, err := loadFixturesFS(embeddedFixtures, "fixtures/osv")
	if err != nil {
		return nil, err
	}
	return append(cveVulns, osvVulns...), nil
}

// loadVulnerabilities returns vulnerability records from the store when
// available and non-empty, falling back to the embedded fixtures otherwise.
//
// This is the single switch that determines whether detect operates on
// live-synced data or the built-in sample set.
func loadVulnerabilities(opts Options) ([]domain.Vulnerability, error) {
	if opts.Store != nil {
		vulns, err := opts.Store.ListVulnerabilities()
		if err != nil {
			return nil, fmt.Errorf("engine: list from store: %w", err)
		}
		if len(vulns) > 0 {
			return vulns, nil
		}
	}
	return loadFixturesFromEmbed()
}

func loadFixturesFS(fsys fs.FS, dir string) ([]domain.Vulnerability, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("engine: read fixtures dir %q: %w", dir, err)
	}

	var out []domain.Vulnerability
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, fmt.Errorf("engine: read %s: %w", path, err)
		}
		var v domain.Vulnerability
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("engine: parse %s: %w", path, err)
		}
		out = append(out, v)
	}
	return out, nil
}
func EmbeddedFixtureCount() int {
	v, err := loadFixturesFromEmbed()
	if err != nil {
		return 0
	}
	return len(v)
}
