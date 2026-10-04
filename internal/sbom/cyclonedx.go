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

// maxSBOMBytes bounds how much of an SBOM is read so a malformed or hostile
// file cannot exhaust memory.
const maxSBOMBytes = 64 << 20

type cyclonedxBOM struct {
	BOMFormat   string               `json:"bomFormat"`
	SpecVersion string               `json:"specVersion"`
	Metadata    cyclonedxMetadata    `json:"metadata"`
	Components  []cyclonedxComponent `json:"components"`
}

type cyclonedxMetadata struct {
	Component *cyclonedxComponent `json:"component"`
}

type cyclonedxComponent struct {
	Type       string               `json:"type"`
	Name       string               `json:"name"`
	Version    string               `json:"version"`
	PURL       string               `json:"purl"`
	Group      string               `json:"group"`
	Components []cyclonedxComponent `json:"components"`
}

// ReadCycloneDX reads a CycloneDX 1.x JSON document from r and returns
// targets derived from its components. Components without a PURL are
// skipped (Cevrixa cannot reliably identify them without a package URL
// or CPE). The metadata.component and nested components are walked too,
// because real SBOMs place dependencies there.
func ReadCycloneDX(r io.Reader) ([]domain.Target, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxSBOMBytes))
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
	seen := make(map[string]bool)
	add := func(c cyclonedxComponent) {
		if c.PURL == "" {
			return
		}
		if seen[c.PURL] {
			return
		}
		seen[c.PURL] = true
		targets = append(targets, domain.Target{PURL: c.PURL})
	}

	if bom.Metadata.Component != nil {
		collectComponent(*bom.Metadata.Component, add)
	}
	for _, c := range bom.Components {
		collectComponent(c, add)
	}
	return targets, nil
}

// collectComponent walks a component and its nested children, adding each
// PURL-bearing component exactly once.
func collectComponent(c cyclonedxComponent, add func(cyclonedxComponent)) {
	add(c)
	for _, child := range c.Components {
		collectComponent(child, add)
	}
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
