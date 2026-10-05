package engine

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func TestExplainEvidenceReturnsStatusAndRisk(t *testing.T) {
	vuln := domain.Vulnerability{
		ID:     "CVE-2021-41773",
		Source: "nvd",
		Status: "Analyzed",
		Risk: &domain.Risk{
			Severity:    "HIGH",
			CVSS:        7.5,
			CVSSVersion: "3.1",
		},
		References: []domain.Reference{
			{URL: "https://example.test/advisory", Source: "nvd"},
		},
	}

	evidence, conflicts := ExplainEvidence(vuln, Options{})
	if len(conflicts) != 0 {
		t.Fatalf("expected no conflicts, got %d", len(conflicts))
	}

	kinds := make(map[domain.EvidenceKind]bool)
	for _, e := range evidence {
		kinds[e.Kind] = true
	}
	for _, want := range []domain.EvidenceKind{
		domain.EvidenceKindStatus,
		domain.EvidenceKindSeverity,
		domain.EvidenceKindCVSS,
		domain.EvidenceKindCVSSVersion,
		domain.EvidenceKindReference,
	} {
		if !kinds[want] {
			t.Fatalf("evidence missing kind %q: %+v", want, evidence)
		}
	}
}

func TestExplainEvidenceNilStoreIsFine(t *testing.T) {
	vuln := domain.Vulnerability{ID: "CVE-X", Source: "nvd", Status: "Analyzed"}
	// A nil store must not panic and must still return the vulnerability's own
	// evidence.
	evidence, _ := ExplainEvidence(vuln, Options{})
	if len(evidence) == 0 {
		t.Fatal("expected at least the status evidence")
	}
}
