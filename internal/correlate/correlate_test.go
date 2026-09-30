package correlate

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func TestCorrelateAllEmptyInput(t *testing.T) {
	got := CorrelateAll(nil, nil)
	if len(got) != 0 {
		t.Fatalf("expected empty output, got %d", len(got))
	}
}

func TestCorrelateAllSingleVulnerability(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "CVE-2021-41773",
		Source: "nvd",
		Status: "Analyzed",
	}
	got := CorrelateAll([]domain.Vulnerability{v}, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 group, got %d", len(got))
	}
	if len(got[0].Identifiers) != 1 || got[0].Identifiers[0] != "CVE-2021-41773" {
		t.Fatalf("unexpected identifiers: %v", got[0].Identifiers)
	}
	if len(got[0].Evidence) == 0 {
		t.Fatalf("expected evidence, got none")
	}
}

func TestCorrelateAllTwoVulnsSameID(t *testing.T) {
	a := domain.Vulnerability{ID: "CVE-2021-41773", Source: "nvd", Status: "Analyzed"}
	b := domain.Vulnerability{ID: "CVE-2021-41773", Source: "osv", Status: "Analyzed"}
	got := CorrelateAll([]domain.Vulnerability{a, b}, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 group, got %d", len(got))
	}
	sources := map[string]bool{}
	for _, e := range got[0].Evidence {
		sources[e.Source] = true
	}
	if !sources["nvd"] || !sources["osv"] {
		t.Fatalf("expected evidence from both sources, got %v", sources)
	}
}

func TestCorrelateAllAliasOverlap(t *testing.T) {
	a := domain.Vulnerability{ID: "CVE-2021-41773", Source: "nvd"}
	b := domain.Vulnerability{
		ID:      "GHSA-xxxx-yyyy-zzzz",
		Source:  "osv",
		Aliases: []string{"CVE-2021-41773"},
	}
	got := CorrelateAll([]domain.Vulnerability{a, b}, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 group, got %d", len(got))
	}
	if len(got[0].Identifiers) != 2 {
		t.Fatalf("expected 2 identifiers, got %v", got[0].Identifiers)
	}
}

func TestCorrelateAllEnrichmentAttached(t *testing.T) {
	v := domain.Vulnerability{ID: "CVE-2021-41773", Source: "nvd"}
	e := domain.Enrichment{
		Source:          "example-enricher",
		VulnerabilityID: "CVE-2021-41773",
		Risk:            &domain.Risk{Severity: "CRITICAL"},
	}
	got := CorrelateAll([]domain.Vulnerability{v}, []domain.Enrichment{e})
	if len(got) != 1 {
		t.Fatalf("expected 1 group, got %d", len(got))
	}
	var found bool
	for _, ev := range got[0].Evidence {
		if ev.Kind == domain.EvidenceKindSeverity && ev.Source == "example-enricher" && ev.Value == "CRITICAL" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected severity evidence from example-enricher")
	}
}

func TestCorrelateAllEnrichmentWithoutIDIsSkipped(t *testing.T) {
	v := domain.Vulnerability{ID: "CVE-2021-41773", Source: "nvd"}
	e := domain.Enrichment{
		Source: "example-enricher",
		Risk:   &domain.Risk{Severity: "CRITICAL"},
	}
	got := CorrelateAll([]domain.Vulnerability{v}, []domain.Enrichment{e})
	if len(got) != 1 {
		t.Fatalf("expected 1 group, got %d", len(got))
	}
	for _, ev := range got[0].Evidence {
		if ev.Source == "example-enricher" {
			t.Fatalf("enrichment without VulnerabilityID must be skipped")
		}
	}
}

func TestCorrelateAllEmptyIDStillGrouped(t *testing.T) {
	v := domain.Vulnerability{Source: "nvd"}
	got := CorrelateAll([]domain.Vulnerability{v}, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 group, got %d", len(got))
	}
	if len(got[0].Identifiers) != 0 {
		t.Fatalf("expected no identifiers, got %v", got[0].Identifiers)
	}
}
