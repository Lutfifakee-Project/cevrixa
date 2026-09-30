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

func loadVulnerabilities(opts Options) ([]domain.Vulnerability, error) {
	fixtures, err := loadFixturesFromEmbed()
	if err != nil {
		return nil, err
	}

	if opts.Store == nil {
		return fixtures, nil
	}

	stored, err := opts.Store.ListVulnerabilities()
	if err != nil {
		return fixtures, nil
	}

	seen := make(map[string]bool)
	var merged []domain.Vulnerability

	for _, v := range stored {
		key := v.Source + "\x00" + v.ID
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, v)
	}
	for _, v := range fixtures {
		key := v.Source + "\x00" + v.ID
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, v)
	}
	return merged, nil
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
