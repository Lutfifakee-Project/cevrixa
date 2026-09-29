package cli

import (
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

func TestParseSyncArgsDefaults(t *testing.T) {
	got, err := parseSyncArgs(nil)
	if err != nil {
		t.Fatalf("parseSyncArgs: %v", err)
	}
	if got.DBPath != "" {
		t.Fatalf("DBPath = %q, want empty", got.DBPath)
	}
}

func TestParseSyncArgsDBFlag(t *testing.T) {
	got, err := parseSyncArgs([]string{"--db", "/tmp/x.db"})
	if err != nil {
		t.Fatalf("parseSyncArgs: %v", err)
	}
	if got.DBPath != "/tmp/x.db" {
		t.Fatalf("DBPath = %q", got.DBPath)
	}
}

func TestSyncKEVWritesEntries(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sync.db")

	if err := syncKEV(dbPath); err != nil {
		t.Fatalf("syncKEV: %v", err)
	}

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	n, err := s.CountKEV()
	if err != nil {
		t.Fatalf("CountKEV: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least 1 KEV entry")
	}

	// Verify a known fixture entry is present.
	if _, err := s.GetKEV("CVE-2021-41773"); err != nil {
		t.Fatalf("GetKEV(CVE-2021-41773): %v", err)
	}
}

func TestSyncKEVIdempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sync.db")

	if err := syncKEV(dbPath); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	s1, _ := store.Open(dbPath)
	n1, _ := s1.CountKEV()
	s1.Close()

	if err := syncKEV(dbPath); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	s2, _ := store.Open(dbPath)
	defer s2.Close()
	n2, _ := s2.CountKEV()

	if n1 != n2 {
		t.Fatalf("count changed between syncs: %d -> %d", n1, n2)
	}
}

func TestRunSyncRequiresTarget(t *testing.T) {
	err := runSync(nil)
	if err == nil {
		t.Fatal("expected error for missing target")
	}
}

func TestRunSyncUnknownTarget(t *testing.T) {
	err := runSync([]string{"bogus"})
	if err == nil {
		t.Fatal("expected error for unknown target")
	}
}

func TestRunSyncKEVEndToEnd(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "e2e.db")

	if err := runSync([]string{"kev", "--db", dbPath}); err != nil {
		t.Fatalf("runSync: %v", err)
	}

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	n, _ := s.CountKEV()
	if n == 0 {
		t.Fatal("expected at least 1 KEV entry")
	}
}
