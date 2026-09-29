package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

func TestLoadKEVDisabled(t *testing.T) {
	entries, src, err := loadKEV(false, "")
	if err != nil {
		t.Fatalf("loadKEV: %v", err)
	}
	if entries != nil {
		t.Fatalf("expected nil entries, got %d", len(entries))
	}
	if src != "" {
		t.Fatalf("Source = %q, want empty", src)
	}
}

func TestLoadKEVFromEmbedded(t *testing.T) {
	entries, src, err := loadKEV(true, "")
	if err != nil {
		t.Fatalf("loadKEV: %v", err)
	}
	if src != "embedded" {
		t.Fatalf("Source = %q, want embedded", src)
	}
	if len(entries) == 0 {
		t.Fatal("expected embedded KEV entries")
	}
	if _, ok := entries["CVE-2021-41773"]; !ok {
		t.Fatal("CVE-2021-41773 missing from embedded KEV")
	}
}

func TestLoadKEVFromDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	if err := syncKEV(dbPath, false); err != nil {
		t.Fatalf("syncKEV: %v", err)
	}

	entries, src, err := loadKEV(true, dbPath)
	if err != nil {
		t.Fatalf("loadKEV: %v", err)
	}
	if src != "db" {
		t.Fatalf("Source = %q, want db", src)
	}
	if len(entries) == 0 {
		t.Fatal("expected KEV entries from DB")
	}
}

func TestLoadKEVFromEmptyDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "empty.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.Close()

	_, _, err = loadKEV(true, dbPath)
	if err == nil {
		t.Fatal("expected error for DB with no KEV entries")
	}
}

func TestLoadKEVFallsBackWhenDBMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.db")
	entries, src, err := loadKEV(true, missing)
	if err != nil {
		t.Fatalf("loadKEV: %v", err)
	}
	if src != "embedded" {
		t.Fatalf("Source = %q, want embedded (fallback)", src)
	}
	if len(entries) == 0 {
		t.Fatal("expected embedded entries")
	}
}

func TestOpenStoreIfDBEmpty(t *testing.T) {
	s, err := openStoreIfDB("")
	if err != nil {
		t.Fatalf("openStoreIfDB empty: %v", err)
	}
	if s != nil {
		t.Fatal("expected nil store for empty path")
	}
}

func TestOpenStoreIfDBMissing(t *testing.T) {
	s, err := openStoreIfDB(filepath.Join(t.TempDir(), "missing.db"))
	if err != nil {
		t.Fatalf("openStoreIfDB missing: %v", err)
	}
	if s != nil {
		t.Fatal("expected nil store for missing file")
	}
}

func TestOpenStoreIfDBExisting(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x.db")
	if err := syncKEV(dbPath, false); err != nil {
		t.Fatalf("syncKEV: %v", err)
	}
	s, err := openStoreIfDB(dbPath)
	if err != nil {
		t.Fatalf("openStoreIfDB: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil store")
	}
	defer s.Close()
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("db file: %v", err)
	}
}
