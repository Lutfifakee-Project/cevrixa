package cli

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/output"
)

// djangoVuln mirrors the embedded GHSA-django-1 fixture: django before 4.2.10.
func djangoVuln() domain.Vulnerability {
	return domain.Vulnerability{
		ID:     "GHSA-django-1",
		Source: "osv",
		Aliases: []string{
			"CVE-2024-27351",
		},
		PackageApplicability: []domain.PackageApplicability{
			{
				Name:      "django",
				Ecosystem: "PyPI",
				Ranges: []domain.PackageRange{
					{
						Type: "ECOSYSTEM",
						Events: []domain.PackageRangeEvent{
							{Introduced: "0"},
							{Fixed: "4.2.10"},
						},
					},
				},
			},
		},
	}
}

func TestEvaluatePURLVulnerableVersion(t *testing.T) {
	report := output.ExplainReport{
		Target:        domain.Target{PURL: "pkg:pypi/django@4.2.0"},
		Vulnerability: djangoVuln(),
	}
	evaluatePURL(&report, report.Target, report.Vulnerability)

	if report.NotEvaluated {
		t.Fatalf("PURL 4.2.0 must be evaluated, got NotEvaluated: %s", report.NotEvaluatedReason)
	}
	if !report.Applicable {
		t.Fatal("django 4.2.0 is below the fix 4.2.10 and must be affected")
	}
	if report.Package == nil {
		t.Fatal("package detail must be set")
	}
	if report.Fixed != "4.2.10" {
		t.Fatalf("Fixed = %q, want 4.2.10", report.Fixed)
	}
}

func TestEvaluatePURLFixedVersion(t *testing.T) {
	report := output.ExplainReport{
		Target:        domain.Target{PURL: "pkg:pypi/django@4.2.10"},
		Vulnerability: djangoVuln(),
	}
	evaluatePURL(&report, report.Target, report.Vulnerability)

	if report.NotEvaluated {
		t.Fatalf("PURL 4.2.10 must be evaluated, got NotEvaluated: %s", report.NotEvaluatedReason)
	}
	if report.Applicable {
		t.Fatal("django 4.2.10 is the fix and must not be affected")
	}
}

func TestEvaluatePURLNoApplicabilityIsInconclusive(t *testing.T) {
	// A vulnerability with no package applicability naming this package must be
	// reported as inconclusive, never as not affected.
	report := output.ExplainReport{
		Target: domain.Target{PURL: "pkg:pypi/django@4.2.0"},
		Vulnerability: domain.Vulnerability{
			ID:     "CVE-0000-0001",
			Source: "nvd",
		},
	}
	evaluatePURL(&report, report.Target, report.Vulnerability)

	if !report.NotEvaluated {
		t.Fatal("a package with no matching applicability must be inconclusive")
	}
	if report.Decision() != output.ExplainDecisionInconclusive {
		t.Fatalf("decision = %q, want inconclusive", report.Decision())
	}
}

func TestEvaluatePURLBadPURL(t *testing.T) {
	report := output.ExplainReport{
		Target:        domain.Target{PURL: "not-a-purl"},
		Vulnerability: djangoVuln(),
	}
	evaluatePURL(&report, report.Target, report.Vulnerability)

	if !report.NotEvaluated {
		t.Fatal("an unparseable PURL must be inconclusive")
	}
}
