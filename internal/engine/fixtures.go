package engine

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

//go:embed fixtures/cve
//go:embed fixtures/osv
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

func loadVulnerabilities(opts Options) ([]domain.Vulnerability, domain.DatasetInfo, error) {
	fixtures, err := loadFixturesFromEmbed()
	if err != nil {
		return nil, domain.DatasetInfo{}, err
	}

	if opts.Store == nil {
		return fixtures, describeDataset(0, len(fixtures), fixtures), nil
	}

	stored, err := opts.Store.ListVulnerabilities()
	if err != nil {
		// Never fall back silently here: an unreadable local dataset must be
		// reported as an error, not quietly replaced by embedded test fixtures.
		return nil, domain.DatasetInfo{}, fmt.Errorf("engine: read local dataset: %w", err)
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
	return merged, describeDataset(len(stored), len(fixtures), merged), nil
}

// describeDataset records which records a report was computed from, so that a
// zero-finding result can be read as "searched N records and found nothing"
// rather than being indistinguishable from "there was no data".
func describeDataset(storeRecords, fixtureRecords int, vulns []domain.Vulnerability) domain.DatasetInfo {
	info := domain.DatasetInfo{
		StoreRecords:   storeRecords,
		FixtureRecords: fixtureRecords,
	}
	seen := make(map[string]bool)
	for _, v := range vulns {
		if v.Source == "" || seen[v.Source] {
			continue
		}
		seen[v.Source] = true
		info.Sources = append(info.Sources, v.Source)
	}
	sort.Strings(info.Sources)
	return info
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
		p := path.Join(dir, e.Name())
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, fmt.Errorf("engine: read %s: %w", p, err)
		}
		var v domain.Vulnerability
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("engine: parse %s: %w", p, err)
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
