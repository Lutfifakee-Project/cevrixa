package engine

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
)

func TestBuildFindingBasic(t *testing.T) {
	targetCPE, err := domain.ParseCPE("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("ParseCPE: %v", err)
	}

	vuln := domain.Vulnerability{
		ID:     "CVE-2021-41773",
		Source: "nvd",
		References: []domain.Reference{
			{URL: "https://example.test/a", Source: "nvd"},
		},
	}

	mr := matcher.Result{
		Matched:  true,
		Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
		Range:    ">=2.4.0 <2.4.51",
		Fixed:    "2.4.51",
		Mode:     "range",
	}

	f := buildFinding(targetCPE, vuln, mr, nil)

	if f.VulnerabilityID != "CVE-2021-41773" {
		t.Fatalf("VulnerabilityID = %q", f.VulnerabilityID)
	}
	if f.Status != domain.FindingStatusAffected {
		t.Fatalf("Status = %q", f.Status)
	}
	if f.Confidence != domain.ConfidenceStrong {
		t.Fatalf("Confidence = %q", f.Confidence)
	}
	if !f.Applicability.Matched {
		t.Fatalf("Applicability.Matched = false")
	}
	if f.Applicability.Range != ">=2.4.0 <2.4.51" {
		t.Fatalf("Range = %q", f.Applicability.Range)
	}
	if len(f.FixedVersions) != 1 || f.FixedVersions[0] != "2.4.51" {
		t.Fatalf("FixedVersions = %v", f.FixedVersions)
	}
	if f.Why.VersionMatch == "" {
		t.Fatalf("Why.VersionMatch empty")
	}
	if len(f.Evidence) == 0 {
		t.Fatalf("Evidence empty")
	}
}

func TestBuildFindingNoFixed(t *testing.T) {
	targetCPE, _ := domain.ParseCPE("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
	vuln := domain.Vulnerability{ID: "CVE-X", Source: "nvd"}
	mr := matcher.Result{Matched: true, Range: ">=2.4.0"}

	f := buildFinding(targetCPE, vuln, mr, nil)

	if len(f.FixedVersions) != 0 {
		t.Fatalf("FixedVersions should be empty, got %v", f.FixedVersions)
	}
}

func TestStatusForResult(t *testing.T) {
	cases := []struct {
		name string
		mr   matcher.Result
		want domain.FindingStatus
	}{
		{"matched", matcher.Result{Matched: true}, domain.FindingStatusAffected},
		{"decided non-match", matcher.Result{Matched: false}, domain.FindingStatusNotAffected},
		{"undecided is never affected", matcher.Result{Undecided: true}, domain.FindingStatusInconclusive},
		{"undecided wins over matched", matcher.Result{Matched: true, Undecided: true}, domain.FindingStatusInconclusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := statusForResult(tc.mr); got != tc.want {
				t.Fatalf("statusForResult = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAttachCorrelationSurfacesCrossSourceConflict(t *testing.T) {
	vuln := domain.Vulnerability{
		ID:     "CVE-2021-41773",
		Source: "nvd",
		Risk:   &domain.Risk{Severity: "MODERATE"},
	}
	enrichments := []domain.Enrichment{
		{Source: "other-db", VulnerabilityID: "CVE-2021-41773", Risk: &domain.Risk{Severity: "CRITICAL"}},
	}

	f := attachCorrelation(domain.Finding{VulnerabilityID: vuln.ID}, vuln, enrichments)

	if len(f.Conflicts) != 1 {
		t.Fatalf("expected 1 cross-source conflict, got %+v", f.Conflicts)
	}
	if len(f.Evidence) == 0 {
		t.Fatal("expected correlated evidence")
	}
}

func TestAttachCorrelationVocabularyDifferenceIsNotConflict(t *testing.T) {
	vuln := domain.Vulnerability{
		ID:     "CVE-2021-41773",
		Source: "nvd",
		Risk:   &domain.Risk{Severity: "MODERATE"},
	}
	enrichments := []domain.Enrichment{
		{Source: "other-db", VulnerabilityID: "CVE-2021-41773", Risk: &domain.Risk{Severity: "medium"}},
	}

	f := attachCorrelation(domain.Finding{VulnerabilityID: vuln.ID}, vuln, enrichments)

	if len(f.Conflicts) != 0 {
		t.Fatalf("MODERATE vs medium is wording, not a conflict: %+v", f.Conflicts)
	}
}
