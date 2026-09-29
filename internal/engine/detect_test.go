package engine

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func TestDetectApacheInRange(t *testing.T) {
	target := domain.Target{Product: "Apache HTTP Server", Version: "2.4.49"}
	report, err := Detect(target, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if report.Target.ResolvedCPE == "" {
		t.Fatalf("ResolvedCPE empty")
	}
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(report.Findings), report.Findings)
	}
	for _, f := range report.Findings {
		if f.Status != domain.FindingStatusAffected {
			t.Fatalf("finding %s status = %q", f.VulnerabilityID, f.Status)
		}
		if f.VulnerabilityID == "CVE-2099-0001" {
			t.Fatalf("CVE-2099-0001 should not match 2.4.49")
		}
	}
}

func TestDetectApacheFixedVersion(t *testing.T) {
	target := domain.Target{Product: "Apache HTTP Server", Version: "2.4.51"}
	report, err := Detect(target, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected 0 findings for fixed version, got %d", len(report.Findings))
	}
}

func TestDetectExplicitCPE(t *testing.T) {
	target := domain.Target{CPE: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
	report, err := Detect(target, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(report.Findings))
	}
}

func TestDetectUnknownProduct(t *testing.T) {
	target := domain.Target{Product: "Nonexistent Software", Version: "1.0"}
	report, err := Detect(target, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected 0 findings for unknown product, got %d", len(report.Findings))
	}
}

func TestDetectNoTarget(t *testing.T) {
	target := domain.Target{}
	report, err := Detect(target, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected 0 findings for empty target, got %d", len(report.Findings))
	}
}

func TestEmbeddedFixturesLoadable(t *testing.T) {
	vulns, err := loadFixturesFromEmbed()
	if err != nil {
		t.Fatalf("loadFixturesFromEmbed: %v", err)
	}
	if len(vulns) < 3 {
		t.Fatalf("expected at least 3 embedded fixtures, got %d", len(vulns))
	}
	for _, v := range vulns {
		if v.ID == "" {
			t.Fatalf("fixture with empty ID: %+v", v)
		}
		if v.Source == "" {
			t.Fatalf("fixture %s has empty source", v.ID)
		}
	}
}
