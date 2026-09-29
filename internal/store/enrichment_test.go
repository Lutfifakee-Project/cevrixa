package store

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func TestSaveAndGetEnrichment(t *testing.T) {
	s := openTestStore(t)
	e := domain.Enrichment{
		Source:          "dbcve",
		VulnerabilityID: "CVE-2021-41773",
		Status:          "complete",
		Summary:         "test",
		Mitigation:      "upgrade",
	}
	if err := s.SaveEnrichment(e); err != nil {
		t.Fatalf("SaveEnrichment: %v", err)
	}

	got, err := s.GetEnrichment("CVE-2021-41773", "dbcve")
	if err != nil {
		t.Fatalf("GetEnrichment: %v", err)
	}
	if got.Mitigation != "upgrade" || got.Summary != "test" {
		t.Fatalf("got %+v", got)
	}
}

func TestSaveEnrichmentRequiresFields(t *testing.T) {
	s := openTestStore(t)
	if err := s.SaveEnrichment(domain.Enrichment{}); err == nil {
		t.Fatal("expected error for empty enrichment")
	}
	if err := s.SaveEnrichment(domain.Enrichment{VulnerabilityID: "CVE-X"}); err == nil {
		t.Fatal("expected error for missing Source")
	}
}

func TestGetEnrichmentNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.GetEnrichment("CVE-MISSING", "dbcve"); err == nil {
		t.Fatal("expected not found error")
	}
}

func TestEnrichmentUpsert(t *testing.T) {
	s := openTestStore(t)
	_ = s.SaveEnrichment(domain.Enrichment{
		Source: "dbcve", VulnerabilityID: "CVE-X", Mitigation: "first",
	})
	_ = s.SaveEnrichment(domain.Enrichment{
		Source: "dbcve", VulnerabilityID: "CVE-X", Mitigation: "second",
	})

	got, _ := s.GetEnrichment("CVE-X", "dbcve")
	if got.Mitigation != "second" {
		t.Fatalf("Mitigation = %q", got.Mitigation)
	}
	n, _ := s.CountEnrichments()
	if n != 1 {
		t.Fatalf("count = %d", n)
	}
}

func TestGetEnrichmentAny(t *testing.T) {
	s := openTestStore(t)
	_ = s.SaveEnrichment(domain.Enrichment{
		Source: "dbcve", VulnerabilityID: "CVE-X", Mitigation: "x",
	})
	got, err := s.GetEnrichmentAny("CVE-X", "other-source")
	if err != nil {
		t.Fatalf("GetEnrichmentAny: %v", err)
	}
	if got.Source != "dbcve" {
		t.Fatalf("Source = %q", got.Source)
	}
}

func TestCountAndDeleteEnrichments(t *testing.T) {
	s := openTestStore(t)
	_ = s.SaveEnrichment(domain.Enrichment{Source: "a", VulnerabilityID: "CVE-A"})
	_ = s.SaveEnrichment(domain.Enrichment{Source: "b", VulnerabilityID: "CVE-B"})

	n, _ := s.CountEnrichments()
	if n != 2 {
		t.Fatalf("count = %d", n)
	}

	if err := s.DeleteAllEnrichments(); err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}
	n, _ = s.CountEnrichments()
	if n != 0 {
		t.Fatalf("count after delete = %d", n)
	}
}

func TestListCVEIDs(t *testing.T) {
	s := openTestStore(t)
	_ = s.SaveVulnerability(domain.Vulnerability{ID: "CVE-2021-0001", Source: "nvd"})
	_ = s.SaveVulnerability(domain.Vulnerability{ID: "CVE-2021-0002", Source: "nvd"})
	_ = s.SaveVulnerability(domain.Vulnerability{ID: "GHSA-xxxx", Source: "osv"})

	ids, err := s.ListCVEIDs()
	if err != nil {
		t.Fatalf("ListCVEIDs: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 CVE IDs, got %d: %v", len(ids), ids)
	}
	for _, id := range ids {
		if !strings.HasPrefix(id, "CVE-") {
			t.Fatalf("unexpected non-CVE ID: %s", id)
		}
	}
}

func TestListCVEIDsEmpty(t *testing.T) {
	s := openTestStore(t)
	ids, err := s.ListCVEIDs()
	if err != nil {
		t.Fatalf("ListCVEIDs: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected 0, got %d", len(ids))
	}
}
