// Package sbom reads Software Bill of Materials files and produces Cevrixa
// targets from them. CycloneDX and SPDX JSON are both supported; the format is
// detected from the document itself.
package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

// ReadAny detects the SBOM format from the document and reads it. An
// unrecognised format is an error, never a guess: feeding CycloneDX to the SPDX
// reader (or the reverse) would silently yield no targets.
func ReadAny(r io.Reader) ([]domain.Target, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxSBOMBytes))
	if err != nil {
		return nil, fmt.Errorf("sbom: read: %w", err)
	}

	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("sbom: parse: %w", err)
	}

	switch {
	case probe.BOMFormat == "CycloneDX":
		return ReadCycloneDX(bytes.NewReader(raw))
	case probe.SPDXVersion != "":
		return ReadSPDX(bytes.NewReader(raw))
	default:
		return nil, fmt.Errorf("sbom: unrecognised format (not CycloneDX or SPDX)")
	}
}

// ReadAnyFile is a convenience wrapper for ReadAny that opens and closes the
// file at path. The path "-" is treated as stdin.
func ReadAnyFile(path string) ([]domain.Target, error) {
	if path == "" || path == "-" {
		return ReadAny(os.Stdin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("sbom: open %s: %w", path, err)
	}
	defer f.Close()
	return ReadAny(f)
}
