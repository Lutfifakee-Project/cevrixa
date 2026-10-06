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
	if err := syncKEV(dbPath, false); err != nil {
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
}

func TestSyncKEVIdempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sync.db")

	if err := syncKEV(dbPath, false); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	s1, _ := store.Open(dbPath)
	n1, _ := s1.CountKEV()
	s1.Close()

	if err := syncKEV(dbPath, false); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	s2, _ := store.Open(dbPath)
	defer s2.Close()
	n2, _ := s2.CountKEV()

	if n1 != n2 {
		t.Fatalf("count changed: %d -> %d", n1, n2)
	}
}

// TestSelectSyncTargetDefaultsToAll covers the default path: no source name
// means sync every source. This is asserted directly on the selector so the
// test never triggers a live sync.
func TestSelectSyncTargetDefaultsToAll(t *testing.T) {
	target, rest := selectSyncTarget(nil)
	if target != "all" {
		t.Fatalf("target = %q, want all", target)
	}
	if len(rest) != 0 {
		t.Fatalf("rest = %v, want empty", rest)
	}
}

func TestSelectSyncTargetNamedSource(t *testing.T) {
	target, rest := selectSyncTarget([]string{"nvd", "--days", "30"})
	if target != "nvd" {
		t.Fatalf("target = %q, want nvd", target)
	}
	if len(rest) != 2 || rest[0] != "--days" {
		t.Fatalf("rest = %v", rest)
	}
}

func TestSelectSyncTargetFlagFirst(t *testing.T) {
	target, rest := selectSyncTarget([]string{"--days", "30"})
	if target != "all" {
		t.Fatalf("target = %q, want all", target)
	}
	if len(rest) != 2 {
		t.Fatalf("rest = %v", rest)
	}
}

func TestRunSyncUnknownTarget(t *testing.T) {
	if err := runSync([]string{"bogus"}); err == nil {
		t.Fatal("expected error")
	}
}
