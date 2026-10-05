package cli

import (
	"strings"
	"testing"
)

func TestReadOneTargetObject(t *testing.T) {
	tgt, err := readOneTarget(strings.NewReader(`{"purl": "pkg:pypi/django@4.2.0"}`))
	if err != nil {
		t.Fatalf("readOneTarget: %v", err)
	}
	if tgt.PURL != "pkg:pypi/django@4.2.0" {
		t.Fatalf("PURL = %q", tgt.PURL)
	}
}

func TestReadOneTargetEmpty(t *testing.T) {
	_, err := readOneTarget(strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestReadOneTargetNoIdentity(t *testing.T) {
	_, err := readOneTarget(strings.NewReader(`{"version": "1.0"}`))
	if err == nil {
		t.Fatal("expected error for a target with no identity")
	}
}

func TestParseDetectStdinFlag(t *testing.T) {
	f, err := parseDetectArgs([]string{"-"})
	if err != nil {
		t.Fatalf("parseDetectArgs: %v", err)
	}
	if !f.Stdin {
		t.Fatal("Stdin should be set")
	}
}

func TestParseDetectStdinWithFlagRejected(t *testing.T) {
	_, err := parseDetectArgs([]string{"-", "--cpe", "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"})
	if err == nil {
		t.Fatal("expected error mixing - with an identity flag")
	}
}

func TestParseScanSnapshotFlag(t *testing.T) {
	f, err := parseScanArgs([]string{"--snapshot", "2026-09-30"})
	if err != nil {
		t.Fatalf("parseScanArgs: %v", err)
	}
	if f.Snapshot != "2026-09-30" {
		t.Fatalf("Snapshot = %q", f.Snapshot)
	}
}

func TestParseScanSnapshotAndDBRejected(t *testing.T) {
	_, err := parseScanArgs([]string{"--snapshot", "x", "--db", "y.db"})
	if err == nil {
		t.Fatal("expected error mixing --snapshot and --db")
	}
}

func TestParseSBOMSnapshotFlag(t *testing.T) {
	f, err := parseSBOMArgs([]string{"--snapshot", "2026-09-30"})
	if err != nil {
		t.Fatalf("parseSBOMArgs: %v", err)
	}
	if f.Snapshot != "2026-09-30" {
		t.Fatalf("Snapshot = %q", f.Snapshot)
	}
}
