package kev

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

//go:embed fixtures/known_exploited_vulnerabilities.json
var embeddedFixtures embed.FS

const fixturePath = "fixtures/known_exploited_vulnerabilities.json"

type Catalog struct {
	Entries map[string]domain.KEVInfo
}

func LoadEmbedded() (*Catalog, error) {
	raw, err := embeddedFixtures.ReadFile(fixturePath)
	if err != nil {
		return nil, fmt.Errorf("kev: read embedded fixture: %w", err)
	}
	return LoadFromBytes(raw)
}

func LoadFromBytes(raw []byte) (*Catalog, error) {
	var resp apiResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("kev: parse: %w", err)
	}
	return &Catalog{Entries: mapResponse(resp)}, nil
}

func LoadFromReader(r io.Reader) (*Catalog, error) {
	var resp apiResponse
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return nil, fmt.Errorf("kev: decode: %w", err)
	}
	return &Catalog{Entries: mapResponse(resp)}, nil
}

func (c *Catalog) Lookup(cveID string) (domain.KEVInfo, bool) {
	if c == nil {
		return domain.KEVInfo{}, false
	}
	v, ok := c.Entries[cveID]
	return v, ok
}
