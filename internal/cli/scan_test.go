package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseScanArgsDefaults(t *testing.T) {
	got, err := parseScanArgs(nil)
	if err != nil {
		t.Fatalf("parseScanArgs: %v", err)
	}
	if got.Input != "-" {
		t.Fatalf("Input = %q, want -", got.Input)
	}
	if got.Output != "human" {
		t.Fatalf("Output = %q, want human", got.Output)
	}
}

func TestParseScanArgsInputPath(t *testing.T) {
	got, err := parseScanArgs([]string{"targets.json"})
	if err != nil {
		t.Fatalf("parseScanArgs: %v", err)
	}
	if got.Input != "targets.json" {
		t.Fatalf("Input = %q", got.Input)
	}
}

func TestParseScanArgsOutput(t *testing.T) {
	got, err := parseScanArgs([]string{"--output", "jsonl"})
	if err != nil {
		t.Fatalf("parseScanArgs: %v", err)
	}
	if got.Output != "jsonl" {
		t.Fatalf("Output = %q", got.Output)
	}
}

func TestParseScanArgsInvalidOutput(t *testing.T) {
	_, err := parseScanArgs([]string{"--output", "xml"})
	if err == nil {
		t.Fatal("expected error for unsupported output")
	}
}

func TestReadTargetsJSONArray(t *testing.T) {
	raw := `[{"product": "Apache HTTP Server", "version": "2.4.49"}]`
	tmp := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(tmp, []byte(raw), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readTargets(tmp)
	if err != nil {
		t.Fatalf("readTargets: %v", err)
	}
	if len(got) != 1 || got[0].Product != "Apache HTTP Server" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseScanArgsFailOn(t *testing.T) {
	if _, err := parseScanArgs([]string{"--fail-on", "critical"}); err != nil {
		t.Fatalf("severity gate should be accepted: %v", err)
	}
	if _, err := parseScanArgs([]string{"--fail-on", "critcal"}); err == nil {
		t.Fatal("an unknown gate must be rejected instead of silently disabling the check")
	}
}

func TestReadTargetsJSONL(t *testing.T) {
	raw := `{"product": "Apache HTTP Server", "version": "2.4.49"}
{"purl": "pkg:pypi/django@4.2.0"}
`
	tmp := filepath.Join(t.TempDir(), "targets.jsonl")
	if err := os.WriteFile(tmp, []byte(raw), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readTargets(tmp)
	if err != nil {
		t.Fatalf("readTargets: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}
