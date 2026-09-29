package store

import (
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenCreatesStore(t *testing.T) {
	s := openTestStore(t)
	if s.Path() == "" {
		t.Fatal("Path is empty")
	}
}

func TestOpenEmptyPath(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestSaveAndGetVulnerability(t *testing.T) {
	s := openTestStore(t)
	v := domain.Vulnerability{
		ID:      "CVE-2021-41773",
		Source:  "nvd",
		Status:  "Analyzed",
		Aliases: []string{"GHSA-x"},
	}
	if err := s.SaveVulnerability(v); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.GetVulnerability("CVE-2021-41773", "nvd")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != v.ID || got.Source != v.Source || got.Status != v.Status {
		t.Fatalf("got %+v", got)
	}
	if len(got.Aliases) != 1 || got.Aliases[0] != "GHSA-x" {
		t.Fatalf("aliases = %v", got.Aliases)
	}
}

func TestSaveVulnerabilityUpsert(t *testing.T) {
	s := openTestStore(t)
	v := domain.Vulnerability{ID: "CVE-X", Source: "nvd", Status: "Analyzed"}
	if err := s.SaveVulnerability(v); err != nil {
		t.Fatalf("first save: %v", err)
	}
	v.Status = "Modified"
	if err := s.SaveVulnerability(v); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, _ := s.GetVulnerability("CVE-X", "nvd")
	if got.Status != "Modified" {
		t.Fatalf("Status = %q", got.Status)
	}
	n, _ := s.CountVulnerabilities()
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
}

func TestSaveVulnerabilityRejectsEmpty(t *testing.T) {
	s := openTestStore(t)
	if err := s.SaveVulnerability(domain.Vulnerability{}); err == nil {
		t.Fatal("expected error for empty vuln")
	}
}

func TestListVulnerabilities(t *testing.T) {
	s := openTestStore(t)
	_ = s.SaveVulnerability(domain.Vulnerability{ID: "A", Source: "nvd"})
	_ = s.SaveVulnerability(domain.Vulnerability{ID: "B", Source: "osv"})
	list, err := s.ListVulnerabilities()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2, got %d", len(list))
	}
}

func TestDeleteAllVulnerabilities(t *testing.T) {
	s := openTestStore(t)
	_ = s.SaveVulnerability(domain.Vulnerability{ID: "A", Source: "nvd"})
	if err := s.DeleteAllVulnerabilities(); err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}
	n, _ := s.CountVulnerabilities()
	if n != 0 {
		t.Fatalf("count = %d, want 0", n)
	}
}

func TestSaveAndGetKEV(t *testing.T) {
	s := openTestStore(t)
	info := domain.KEVInfo{
		CVEID:         "CVE-2021-41773",
		VendorProject: "Apache",
		Product:       "HTTP Server",
		DateAdded:     "2021-11-03",
	}
	if err := s.SaveKEV(info); err != nil {
		t.Fatalf("SaveKEV: %v", err)
	}
	got, err := s.GetKEV("CVE-2021-41773")
	if err != nil {
		t.Fatalf("GetKEV: %v", err)
	}
	if got.VendorProject != "Apache" {
		t.Fatalf("VendorProject = %q", got.VendorProject)
	}
	if got.Product != "HTTP Server" {
		t.Fatalf("Product = %q", got.Product)
	}
}

func TestGetKEVNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.GetKEV("CVE-MISSING"); err == nil {
		t.Fatal("expected error for missing KEV")
	}
}

func TestSaveKEVRejectsEmptyCVEID(t *testing.T) {
	s := openTestStore(t)
	if err := s.SaveKEV(domain.KEVInfo{}); err == nil {
		t.Fatal("expected error for empty CVEID")
	}
}

func TestAllKEV(t *testing.T) {
	s := openTestStore(t)
	_ = s.SaveKEV(domain.KEVInfo{CVEID: "CVE-A"})
	_ = s.SaveKEV(domain.KEVInfo{CVEID: "CVE-B"})
	all, err := s.AllKEV()
	if err != nil {
		t.Fatalf("AllKEV: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2, got %d", len(all))
	}
}

func TestKEVUpsert(t *testing.T) {
	s := openTestStore(t)
	_ = s.SaveKEV(domain.KEVInfo{CVEID: "CVE-A", VendorProject: "First"})
	_ = s.SaveKEV(domain.KEVInfo{CVEID: "CVE-A", VendorProject: "Second"})
	got, _ := s.GetKEV("CVE-A")
	if got.VendorProject != "Second" {
		t.Fatalf("VendorProject = %q", got.VendorProject)
	}
	n, _ := s.CountKEV()
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
}

func TestDeleteAllKEV(t *testing.T) {
	s := openTestStore(t)
	_ = s.SaveKEV(domain.KEVInfo{CVEID: "CVE-A"})
	if err := s.DeleteAllKEV(); err != nil {
		t.Fatalf("DeleteAllKEV: %v", err)
	}
	n, _ := s.CountKEV()
	if n != 0 {
		t.Fatalf("count = %d, want 0", n)
	}
}

func TestMigrationIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	s1, err := Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	_ = s1.SaveKEV(domain.KEVInfo{CVEID: "CVE-A"})
	_ = s1.Close()

	// Re-open the same file — migration must not error and data must persist.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer s2.Close()

	n, _ := s2.CountKEV()
	if n != 1 {
		t.Fatalf("persisted count = %d, want 1", n)
	}
}
