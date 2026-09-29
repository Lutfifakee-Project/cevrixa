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

func TestRunSyncRequiresTarget(t *testing.T) {
	if err := runSync(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunSyncUnknownTarget(t *testing.T) {
	if err := runSync([]string{"bogus"}); err == nil {
		t.Fatal("expected error")
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
		t.Fatal("expected KEV entries")
	}
}

func TestParseSyncArgsDays(t *testing.T) {
	got, err := parseSyncArgs([]string{"--days", "30"})
	if err != nil {
		t.Fatalf("parseSyncArgs: %v", err)
	}
	if got.Days != 30 {
		t.Fatalf("Days = %d", got.Days)
	}
}

func TestParseSyncArgsDaysInvalid(t *testing.T) {
	for _, bad := range []string{"0", "-5", "abc"} {
		t.Run(bad, func(t *testing.T) {
			if _, err := parseSyncArgs([]string{"--days", bad}); err == nil {
				t.Fatalf("expected error for --days %q", bad)
			}
		})
	}
}

func TestParseSyncArgsFull(t *testing.T) {
	got, err := parseSyncArgs([]string{"--full"})
	if err != nil {
		t.Fatalf("parseSyncArgs: %v", err)
	}
	if !got.Full {
		t.Fatal("Full should be true")
	}
}

func TestParseSyncArgsLive(t *testing.T) {
	got, err := parseSyncArgs([]string{"--live"})
	if err != nil {
		t.Fatalf("parseSyncArgs: %v", err)
	}
	if !got.Live {
		t.Fatal("Live should be true")
	}
}

func TestParseSyncArgsCVE(t *testing.T) {
	got, err := parseSyncArgs([]string{"--cve", "CVE-2021-41773", "--cve", "CVE-2021-42013"})
	if err != nil {
		t.Fatalf("parseSyncArgs: %v", err)
	}
	if len(got.CVEIDs) != 2 || got.CVEIDs[0] != "CVE-2021-41773" || got.CVEIDs[1] != "CVE-2021-42013" {
		t.Fatalf("CVEIDs = %v", got.CVEIDs)
	}
}

func TestParseSyncArgsFromStore(t *testing.T) {
	got, err := parseSyncArgs([]string{"--from-store"})
	if err != nil {
		t.Fatalf("parseSyncArgs: %v", err)
	}
	if !got.FromStore {
		t.Fatal("FromStore should be true")
	}
}

func TestParseSyncArgsLimit(t *testing.T) {
	got, err := parseSyncArgs([]string{"--limit", "50"})
	if err != nil {
		t.Fatalf("parseSyncArgs: %v", err)
	}
	if got.Limit != 50 {
		t.Fatalf("Limit = %d", got.Limit)
	}
}

func TestParseSyncArgsLimitInvalid(t *testing.T) {
	for _, bad := range []string{"-1", "abc"} {
		t.Run(bad, func(t *testing.T) {
			if _, err := parseSyncArgs([]string{"--limit", bad}); err == nil {
				t.Fatalf("expected error for --limit %q", bad)
			}
		})
	}
}

func TestParseSyncArgsInterval(t *testing.T) {
	got, err := parseSyncArgs([]string{"--interval", "500ms"})
	if err != nil {
		t.Fatalf("parseSyncArgs: %v", err)
	}
	if got.Interval.Milliseconds() != 500 {
		t.Fatalf("Interval = %v", got.Interval)
	}
}
