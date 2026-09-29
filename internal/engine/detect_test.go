package engine

import (
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func fixturesDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "cve"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return dir
}

func TestDetectApacheInRange(t *testing.T) {
	target := domain.Target{Product: "Apache HTTP Server", Version: "2.4.49"}
	report, err := Detect(target, Options{FixturesDir: fixturesDir(t)})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if report.Target.ResolvedCPE == "" {
		t.Fatalf("ResolvedCPE empty")
	}
	// CVE-2021-41773, CVE-2021-42013 should match; CVE-2099-0001 should not
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
	report, err := Detect(target, Options{FixturesDir: fixturesDir(t)})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected 0 findings for fixed version, got %d", len(report.Findings))
	}
}

func TestDetectExplicitCPE(t *testing.T) {
	target := domain.Target{CPE: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
	report, err := Detect(target, Options{FixturesDir: fixturesDir(t)})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(report.Findings))
	}
}

func TestDetectUnknownProduct(t *testing.T) {
	target := domain.Target{Product: "Nonexistent Software", Version: "1.0"}
	report, err := Detect(target, Options{FixturesDir: fixturesDir(t)})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected 0 findings for unknown product, got %d", len(report.Findings))
	}
	if report.Target.ResolvedCPE != "" {
		t.Fatalf("ResolvedCPE should be empty for unknown product, got %q", report.Target.ResolvedCPE)
	}
}

func TestDetectNoTarget(t *testing.T) {
	target := domain.Target{}
	report, err := Detect(target, Options{FixturesDir: fixturesDir(t)})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected 0 findings for empty target, got %d", len(report.Findings))
	}
}

func TestDetectFixtureIntegrity(t *testing.T) {
	vulns, err := loadFixtures(fixturesDir(t))
	if err != nil {
		t.Fatalf("loadFixtures: %v", err)
	}
	if len(vulns) != 3 {
		t.Fatalf("expected 3 fixtures, got %d", len(vulns))
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

func TestDetectEmptyFixturesDir(t *testing.T) {
	dir := t.TempDir()
	report, err := Detect(domain.Target{Product: "Apache HTTP Server", Version: "2.4.49"}, Options{FixturesDir: dir})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected 0 findings from empty dir, got %d", len(report.Findings))
	}
}
