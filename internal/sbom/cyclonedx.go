// Package sbom reads Software Bill of Materials files and produces
// Cevrixa targets from them.
package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

type cyclonedxBOM struct {
	BOMFormat   string               `json:"bomFormat"`
	SpecVersion string               `json:"specVersion"`
	Components  []cyclonedxComponent `json:"components"`
}

type cyclonedxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl,omitempty"`
	Group   string `json:"group,omitempty"`
}

// ReadCycloneDX reads a CycloneDX 1.x JSON document from r and returns
// targets derived from its components. Components without a PURL are
// skipped (Cevrixa cannot reliably identify them without a package URL
// or CPE).
func ReadCycloneDX(r io.Reader) ([]domain.Target, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("sbom: read: %w", err)
	}

	var bom cyclonedxBOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		return nil, fmt.Errorf("sbom: parse cyclonedx: %w", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("sbom: not a CycloneDX document (bomFormat=%q)", bom.BOMFormat)
	}

	var targets []domain.Target
	for _, c := range bom.Components {
		if c.PURL == "" {
			continue
		}
		targets = append(targets, domain.Target{PURL: c.PURL})
	}
	return targets, nil
}

// ReadCycloneDXFile is a convenience wrapper for ReadCycloneDX that opens
// and closes the file at path. The path "-" is treated as stdin.
func ReadCycloneDXFile(path string) ([]domain.Target, error) {
	if path == "" || path == "-" {
		return ReadCycloneDX(os.Stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("sbom: open %s: %w", path, err)
	}
	defer f.Close()
	return ReadCycloneDX(f)
}
