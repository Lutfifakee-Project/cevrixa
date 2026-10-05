package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func TestSnapshotMetaRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	meta := SnapshotMeta{
		Name:          "snap",
		EngineVersion: "v0.4.0",
		Digest:        "abc",
		RecordCount:   3,
		Sources:       []string{"nvd", "osv"},
	}
	if err := s.SaveSnapshotMeta(meta); err != nil {
		t.Fatalf("SaveSnapshotMeta: %v", err)
	}

	got, err := s.GetSnapshotMeta()
	if err != nil {
		t.Fatalf("GetSnapshotMeta: %v", err)
	}
	if got.Name != "snap" || got.Digest != "abc" || got.RecordCount != 3 {
		t.Fatalf("meta = %+v", got)
	}
	if len(got.Sources) != 2 || got.Sources[0] != "nvd" {
		t.Fatalf("sources = %v", got.Sources)
	}
}

func TestDigestStable(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	d1, err := s.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	d2, err := s.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if d1 != d2 {
		t.Fatalf("digest changed: %s vs %s", d1, d2)
	}

	if err := s.SaveVulnerability(domain.Vulnerability{ID: "CVE-1", Source: "nvd"}); err != nil {
		t.Fatalf("SaveVulnerability: %v", err)
	}
	d3, err := s.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if d3 == d1 {
		t.Fatal("digest must change when a record is added")
	}
}

func TestCreateSnapshot(t *testing.T) {
	src, err := Open(filepath.Join(t.TempDir(), "src.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer src.Close()
	if err := src.SaveVulnerability(domain.Vulnerability{ID: "CVE-1", Source: "nvd"}); err != nil {
		t.Fatalf("SaveVulnerability: %v", err)
	}

	target := filepath.Join(t.TempDir(), "snap.db")
	meta, err := src.CreateSnapshot(target, "snap", "v0.4.0")
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if meta.Name != "snap" || meta.RecordCount != 1 {
		t.Fatalf("meta = %+v", meta)
	}
	if len(meta.Sources) != 1 || meta.Sources[0] != "nvd" {
		t.Fatalf("sources = %v", meta.Sources)
	}
	if meta.Digest == "" {
		t.Fatal("digest must not be empty")
	}

	// The snapshot must exist and be independently readable.
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("snapshot file: %v", err)
	}
	snap, err := Open(target)
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer snap.Close()
	stored, err := snap.GetSnapshotMeta()
	if err != nil {
		t.Fatalf("snapshot meta: %v", err)
	}
	if stored.Digest != meta.Digest {
		t.Fatalf("snapshot digest = %q, want %q", stored.Digest, meta.Digest)
	}
}
