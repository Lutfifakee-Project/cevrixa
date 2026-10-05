package sbom

import (
	"strings"
	"testing"
)

func TestReadSPDXBasic(t *testing.T) {
	raw := `{
      "spdxVersion": "SPDX-2.3",
      "packages": [
        {
          "name": "django",
          "versionInfo": "4.2.0",
          "externalRefs": [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/django@4.2.0"}
          ]
        },
        {
          "name": "lodash",
          "versionInfo": "4.17.20",
          "externalRefs": [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.20"}
          ]
        }
      ]
    }`
	got, err := ReadSPDX(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadSPDX: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(got))
	}
	if got[0].PURL != "pkg:pypi/django@4.2.0" {
		t.Fatalf("target[0] = %q", got[0].PURL)
	}
}

func TestReadSPDXSkipsNoPURL(t *testing.T) {
	raw := `{
      "spdxVersion": "SPDX-2.3",
      "packages": [
        {"name": "unknown", "versionInfo": "1.0"},
        {"name": "lodash", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.20"}]}
      ]
    }`
	got, err := ReadSPDX(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadSPDX: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 target, got %d", len(got))
	}
}

func TestReadSPDXWrongFormat(t *testing.T) {
	raw := `{"bomFormat": "CycloneDX", "packages": []}`
	_, err := ReadSPDX(strings.NewReader(raw))
	if err == nil {
		t.Fatal("expected error for non-SPDX document")
	}
}

func TestReadAnyDetectsCycloneDX(t *testing.T) {
	raw := `{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"purl": "pkg:npm/lodash@4.17.20"}]}`
	got, err := ReadAny(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadAny: %v", err)
	}
	if len(got) != 1 || got[0].PURL != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("got %+v", got)
	}
}

func TestReadAnyDetectsSPDX(t *testing.T) {
	raw := `{"spdxVersion": "SPDX-2.3", "packages": [{"externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/django@4.2.0"}]}]}`
	got, err := ReadAny(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadAny: %v", err)
	}
	if len(got) != 1 || got[0].PURL != "pkg:pypi/django@4.2.0" {
		t.Fatalf("got %+v", got)
	}
}

func TestReadAnyRejectsUnknown(t *testing.T) {
	raw := `{"somethingElse": true}`
	_, err := ReadAny(strings.NewReader(raw))
	if err == nil {
		t.Fatal("expected error for an unrecognised format")
	}
}
