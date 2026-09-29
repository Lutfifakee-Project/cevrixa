package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSBOMArgsDefaults(t *testing.T) {
	got, err := parseSBOMArgs(nil)
	if err != nil {
		t.Fatalf("parseSBOMArgs: %v", err)
	}
	if got.Input != "-" {
		t.Fatalf("Input = %q", got.Input)
	}
	if got.Output != "human" {
		t.Fatalf("Output = %q", got.Output)
	}
}

func TestParseSBOMArgsPath(t *testing.T) {
	got, err := parseSBOMArgs([]string{"app.cdx.json"})
	if err != nil {
		t.Fatalf("parseSBOMArgs: %v", err)
	}
	if got.Input != "app.cdx.json" {
		t.Fatalf("Input = %q", got.Input)
	}
}

func TestParseSBOMArgsFlags(t *testing.T) {
	got, err := parseSBOMArgs([]string{"--output", "json", "--fail-on", "affected", "--with-kev"})
	if err != nil {
		t.Fatalf("parseSBOMArgs: %v", err)
	}
	if got.Output != "json" || got.FailOn != "affected" || !got.WithKEV {
		t.Fatalf("got %+v", got)
	}
}

func TestReadSBOMIntegration(t *testing.T) {
	raw := `{
      "bomFormat": "CycloneDX",
      "specVersion": "1.4",
      "components": [
        {"type": "library", "name": "django", "version": "4.2.0", "purl": "pkg:pypi/django@4.2.0"}
      ]
    }`
	tmp := filepath.Join(t.TempDir(), "app.cdx.json")
	if err := os.WriteFile(tmp, []byte(raw), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Just verify parsing works end-to-end via cli command path.
	err := runSBOM([]string{tmp, "--output", "jsonl"})
	if err != nil {
		t.Fatalf("runSBOM: %v", err)
	}
}
