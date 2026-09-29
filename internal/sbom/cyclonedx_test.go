package sbom

import (
	"strings"
	"testing"
)

func TestReadCycloneDXBasic(t *testing.T) {
	raw := `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.4",
      "components": [
        {"type": "library", "name": "django", "version": "4.2.0", "purl": "pkg:pypi/django@4.2.0"},
        {"type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}
      ]
    }`
	got, err := ReadCycloneDX(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadCycloneDX: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(got))
	}
	if got[0].PURL != "pkg:pypi/django@4.2.0" {
		t.Fatalf("target[0] = %q", got[0].PURL)
	}
}

func TestReadCycloneDXSkipsNoPURL(t *testing.T) {
	raw := `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.4",
      "components": [
        {"type": "library", "name": "unknown", "version": "1.0"},
        {"type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}
      ]
    }`
	got, err := ReadCycloneDX(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadCycloneDX: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 target, got %d", len(got))
	}
}

func TestReadCycloneDXWrongFormat(t *testing.T) {
	raw := `{"bomFormat": "SPDX", "components": []}`
	_, err := ReadCycloneDX(strings.NewReader(raw))
	if err == nil {
		t.Fatal("expected error for non-CycloneDX document")
	}
}

func TestReadCycloneDXInvalidJSON(t *testing.T) {
	_, err := ReadCycloneDX(strings.NewReader("{not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestReadCycloneDXEmptyComponents(t *testing.T) {
	raw := `{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}`
	got, err := ReadCycloneDX(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadCycloneDX: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 targets, got %d", len(got))
	}
}
