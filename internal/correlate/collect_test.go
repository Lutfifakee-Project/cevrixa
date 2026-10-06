package correlate

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func TestCollectVulnEvidenceSkipsEmptyStatus(t *testing.T) {
	v := domain.Vulnerability{ID: "CVE-1", Source: "nvd"}
	ev := vulnEvidence(v)
	for _, e := range ev {
		if e.Kind == domain.EvidenceKindStatus {
			t.Fatalf("status evidence should not be emitted for empty status")
		}
	}
}

func TestCollectVulnEvidenceSkipsEmptyAliases(t *testing.T) {
	v := domain.Vulnerability{ID: "CVE-1", Source: "nvd", Aliases: []string{"", "CVE-1"}}
	ev := vulnEvidence(v)
	count := 0
	for _, e := range ev {
		if e.Kind == domain.EvidenceKindAlias {
			count++
			if e.Value == "" {
				t.Fatalf("empty alias must not be emitted")
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 alias evidence, got %d", count)
	}
}

func TestVulnEvidenceCarriesProvenance(t *testing.T) {
	v := domain.Vulnerability{ID: "CVE-1", Source: "nvd", SourceIdentifier: "NVD-REC-9", Status: "Analyzed"}
	ev := vulnEvidence(v)
	if len(ev) == 0 {
		t.Fatal("expected evidence")
	}
	for _, e := range ev {
		if e.Provenance == nil {
			t.Fatalf("evidence %s missing provenance", e.Kind)
		}
		if e.Provenance.SourceRecordID != "NVD-REC-9" {
			t.Fatalf("source record = %q", e.Provenance.SourceRecordID)
		}
	}
}

func TestCollectEnrichmentNoZeroValue(t *testing.T) {
	e := domain.Enrichment{
		Source: "example-enricher",
		Risk: &domain.Risk{
			Severity: "",
			CVSS:     0,
			KEV:      false,
			EPSS:     0,
		},
	}
	ev := enrichmentEvidence(e)
	for _, x := range ev {
		switch x.Kind {
		case domain.EvidenceKindSeverity,
			domain.EvidenceKindCVSS,
			domain.EvidenceKindKEV,
			domain.EvidenceKindEPSS:
			t.Fatalf("zero-value must not produce evidence: %+v", x)
		}
	}
}

func TestCollectEnrichmentKEVTrueOnly(t *testing.T) {
	yes := domain.Enrichment{
		Source: "example-enricher",
		Risk:   &domain.Risk{KEV: true},
	}
	ev := enrichmentEvidence(yes)
	var found bool
	for _, x := range ev {
		if x.Kind == domain.EvidenceKindKEV && x.Value == "true" {
			found = true
		}
	}
	if !found {
		t.Fatalf("KEV=true should emit evidence")
	}
}

func TestCollectEnrichmentKEVFalseNoEvidence(t *testing.T) {
	no := domain.Enrichment{
		Source: "example-enricher",
		Risk:   &domain.Risk{KEV: false},
	}
	ev := enrichmentEvidence(no)
	for _, x := range ev {
		if x.Kind == domain.EvidenceKindKEV {
			t.Fatalf("KEV=false must not emit evidence, got %+v", x)
		}
	}
}

func TestCollectSkipsAttributionAndSummary(t *testing.T) {
	e := domain.Enrichment{
		Source:      "example-enricher",
		Summary:     "some summary",
		Confidence:  "high",
		Attribution: &domain.Attribution{Source: "example-enricher"},
	}
	ev := enrichmentEvidence(e)
	for _, x := range ev {
		if x.Value == "some summary" || x.Value == "high" {
			t.Fatalf("summary/confidence must not be evidence: %+v", x)
		}
	}
}

func TestCollectRiskCVSSUsesCanonicalString(t *testing.T) {
	e := domain.Enrichment{
		Source: "example-enricher",
		Risk:   &domain.Risk{CVSS: 9.8, CVSSVersion: "3.1"},
	}
	ev := enrichmentEvidence(e)
	var cvss, version string
	for _, x := range ev {
		switch x.Kind {
		case domain.EvidenceKindCVSS:
			cvss = x.Value
		case domain.EvidenceKindCVSSVersion:
			version = x.Value
		}
	}
	if cvss != "9.8" {
		t.Fatalf("CVSS canonical string = %q, want %q", cvss, "9.8")
	}
	if version != "3.1" {
		t.Fatalf("CVSS version = %q, want %q", version, "3.1")
	}
}
