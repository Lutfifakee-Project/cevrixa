package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

type spdxDocument struct {
	SPDXVersion string        `json:"spdxVersion"`
	Packages    []spdxPackage `json:"packages"`
}

type spdxPackage struct {
	Name         string            `json:"name"`
	VersionInfo  string            `json:"versionInfo"`
	ExternalRefs []spdxExternalRef `json:"externalRefs"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// ReadSPDX reads an SPDX 2.x JSON document from r and returns targets derived
// from the PURLs in its packages. A package without a PURL external reference
// is skipped, because Cevrixa cannot reliably identify it otherwise.
func ReadSPDX(r io.Reader) ([]domain.Target, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxSBOMBytes))
	if err != nil {
		return nil, fmt.Errorf("sbom: read: %w", err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("sbom: parse spdx: %w", err)
	}
	if doc.SPDXVersion == "" {
		return nil, fmt.Errorf("sbom: not an SPDX document (spdxVersion is empty)")
	}

	var targets []domain.Target
	seen := make(map[string]bool)
	for _, pkg := range doc.Packages {
		purl := packagePURL(pkg)
		if purl == "" || seen[purl] {
			continue
		}
		seen[purl] = true
		targets = append(targets, domain.Target{PURL: purl})
	}
	return targets, nil
}

// packagePURL returns the first purl external reference of a package.
func packagePURL(pkg spdxPackage) string {
	for _, ref := range pkg.ExternalRefs {
		if ref.ReferenceType == "purl" && ref.ReferenceLocator != "" {
			return ref.ReferenceLocator
		}
	}
	return ""
}

// ReadSPDXFile is a convenience wrapper for ReadSPDX that opens and closes the
// file at path. The path "-" is treated as stdin.
func ReadSPDXFile(path string) ([]domain.Target, error) {
	if path == "" || path == "-" {
		return ReadSPDX(os.Stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("sbom: open %s: %w", path, err)
	}
	defer f.Close()
	return ReadSPDX(f)
}
