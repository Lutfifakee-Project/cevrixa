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

	f := buildFinding(targetCPE, vuln, mr)

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

	f := buildFinding(targetCPE, vuln, mr)

	if len(f.FixedVersions) != 0 {
		t.Fatalf("FixedVersions should be empty, got %v", f.FixedVersions)
	}
}
