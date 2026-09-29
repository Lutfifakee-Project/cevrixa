package engine

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

func TestFindByIDEmbedded(t *testing.T) {
	v, err := FindByID("CVE-2021-41773", Options{})
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if v.ID != "CVE-2021-41773" {
		t.Fatalf("ID = %q", v.ID)
	}
}

func TestFindByIDCaseInsensitive(t *testing.T) {
	v, err := FindByID("cve-2021-41773", Options{})
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if v.ID != "CVE-2021-41773" {
		t.Fatalf("ID = %q", v.ID)
	}
}

func TestFindByIDAlias(t *testing.T) {
	// GHSA-django-1 has alias CVE-2024-27351.
	v, err := FindByID("CVE-2024-27351", Options{})
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if v.ID != "GHSA-django-1" {
		t.Fatalf("ID = %q, want GHSA-django-1", v.ID)
	}
}

func TestFindByIDNotFound(t *testing.T) {
	_, err := FindByID("CVE-9999-99999", Options{})
	if err == nil {
		t.Fatal("expected error for missing ID")
	}
}

func TestFindByIDEmpty(t *testing.T) {
	_, err := FindByID("", Options{})
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected required error, got %v", err)
	}
}

func TestFindByIDFromStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.SaveVulnerability(domain.Vulnerability{
		ID:      "CVE-STORE-LOOKUP",
		Source:  "nvd",
		Summary: "from store",
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	v, err := FindByID("CVE-STORE-LOOKUP", Options{Store: s})
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if v.Summary != "from store" {
		t.Fatalf("Summary = %q", v.Summary)
	}
}
