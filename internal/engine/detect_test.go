package engine

import (
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
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

func TestDetectConfidenceIsStrongForRangeMatch(t *testing.T) {
	target := domain.Target{Product: "Apache HTTP Server", Version: "2.4.49"}
	report, err := Detect(target, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("expected at least 1 finding")
	}
	for _, f := range report.Findings {
		if f.Confidence != domain.ConfidenceStrong {
			t.Fatalf("finding %s confidence = %q, want STRONG (range match)",
				f.VulnerabilityID, f.Confidence)
		}
	}
}

func TestDetectWithoutKEV(t *testing.T) {
	target := domain.Target{Product: "Apache HTTP Server", Version: "2.4.49"}
	report, err := Detect(target, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	for _, f := range report.Findings {
		if f.KnownExploited != nil {
			t.Fatalf("KnownExploited should be nil without KEV, got %+v", f.KnownExploited)
		}
	}
}

func TestDetectWithKEV(t *testing.T) {
	target := domain.Target{Product: "Apache HTTP Server", Version: "2.4.49"}
	kevData := map[string]domain.KEVInfo{
		"CVE-2021-41773": {
			CVEID:         "CVE-2021-41773",
			VendorProject: "Apache",
			Product:       "HTTP Server",
			DateAdded:     "2021-11-03",
		},
	}
	report, err := Detect(target, Options{KEV: kevData})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	var found bool
	for _, f := range report.Findings {
		if f.VulnerabilityID == "CVE-2021-41773" {
			if f.KnownExploited == nil {
				t.Fatal("KnownExploited should be set")
			}
			found = true
		}
		if f.VulnerabilityID == "CVE-2021-42013" && f.KnownExploited != nil {
			t.Fatalf("CVE-2021-42013 should not be in KEV")
		}
	}
	if !found {
		t.Fatal("CVE-2021-41773 not found")
	}
}

func TestDetectFromStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.SaveVulnerability(domain.Vulnerability{
		ID:     "CVE-STORE-001",
		Source: "nvd",
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "OR",
				Matches: []domain.CPEMatch{
					{
						Vulnerable:       true,
						Criteria:         "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
						VersionStart:     "2.4.0",
						VersionStartMode: domain.BoundModeIncluding,
						VersionEnd:       "2.4.51",
						VersionEndMode:   domain.BoundModeExcluding,
					},
				},
			},
		},
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	target := domain.Target{Product: "Apache HTTP Server", Version: "2.4.49"}
	report, err := Detect(target, Options{Store: s})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	var foundStore bool
	for _, f := range report.Findings {
		if f.VulnerabilityID == "CVE-STORE-001" {
			foundStore = true
		}
	}
	if !foundStore {
		t.Fatalf("expected CVE-STORE-001 in findings, got %+v", report.Findings)
	}
}

func TestDetectFallbackToEmbeddedWhenStoreEmpty(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "empty.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	target := domain.Target{Product: "Apache HTTP Server", Version: "2.4.49"}
	report, err := Detect(target, Options{Store: s})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Findings) < 2 {
		t.Fatalf("expected embedded fallback findings, got %d", len(report.Findings))
	}
}

func TestDetectAndRequirementDoesNotProduceFinding(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "and.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// NVD shape: tomcat is affected only when an Oracle component is present.
	// Reporting a finding for tomcat alone is the classic CPE false positive.
	if err := s.SaveVulnerability(domain.Vulnerability{
		ID:     "CVE-AND-001",
		Source: "nvd",
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "OR",
				Children: []domain.ApplicabilityNode{
					{
						Operator: "AND",
						Matches: []domain.CPEMatch{
							{Vulnerable: true, Criteria: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"},
							{Vulnerable: false, Criteria: "cpe:2.3:a:oracle:instantis_enterprisetrack:17.1:*:*:*:*:*:*:*"},
						},
					},
				},
			},
		},
	}); err != nil {
		t.Fatalf("SaveVulnerability: %v", err)
	}

	report, err := Detect(domain.Target{CPE: "cpe:2.3:a:apache:tomcat:8.5.87:*:*:*:*:*:*:*"}, Options{Store: s})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	var found *domain.Finding
	for i := range report.Findings {
		if report.Findings[i].VulnerabilityID == "CVE-AND-001" {
			found = &report.Findings[i]
		}
	}
	if found == nil {
		t.Fatal("AND requirement must still be reported as inconclusive, not dropped")
	}
	if found.Status != domain.FindingStatusInconclusive {
		t.Fatalf("AND requirement status = %q, want inconclusive", found.Status)
	}
}

func TestDetectReportsDatasetCoverage(t *testing.T) {
	report, err := Detect(domain.Target{Product: "Apache HTTP Server", Version: "2.4.49"}, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if report.Dataset.FixtureRecords == 0 {
		t.Fatal("embedded fixtures must be reported in dataset coverage")
	}
	if len(report.Dataset.Sources) == 0 {
		t.Fatal("dataset sources must be reported")
	}
	if report.Dataset.Empty() {
		t.Fatal("dataset with records must not report Empty")
	}
}

func TestDetectReportsEmptyDatasetForUnresolvedIdentity(t *testing.T) {
	report, err := Detect(domain.Target{Product: "Nonexistent Software", Version: "1.0"}, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(report.Findings))
	}
	if report.Dataset.Empty() {
		t.Fatal("dataset coverage must still be reported when the identity is unresolved")
	}
}

func TestStatusForResultUndecidedNeverAffected(t *testing.T) {
	targetCPE, err := domain.ParseCPE("cpe:2.3:a:apache:tomcat:8.5.87:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("ParseCPE: %v", err)
	}
	f := buildFinding(targetCPE, domain.Vulnerability{ID: "CVE-AND-001", Source: "nvd"}, matcher.Result{
		Undecided: true,
		Reason:    "AND configuration requires an additional component",
	}, nil)

	if f.Status != domain.FindingStatusInconclusive {
		t.Fatalf("Status = %q, want inconclusive", f.Status)
	}
}

func TestDetectDebianLetterSuffixVersionIsAffected(t *testing.T) {
	// Regression: this target returned zero findings with exit code 0, because
	// openssl 1.1.1c could not be parsed and the package was skipped without a
	// word.
	report, err := Detect(domain.Target{PURL: "pkg:deb/debian/openssl@1.1.1c-1ubuntu1"}, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	var found bool
	for _, f := range report.Findings {
		if f.VulnerabilityID != "GHSA-deb-1" {
			continue
		}
		found = true
		if f.Status != domain.FindingStatusAffected {
			t.Fatalf("status = %q, want affected", f.Status)
		}
		if len(f.FixedVersions) != 1 || f.FixedVersions[0] != "1.1.2" {
			t.Fatalf("FixedVersions = %v, want [1.1.2]", f.FixedVersions)
		}
	}
	if !found {
		t.Fatalf("expected GHSA-deb-1 for openssl 1.1.1c-1ubuntu1, got %+v", report.Findings)
	}
}

func TestDetectUncomparablePackageVersionIsInconclusive(t *testing.T) {
	report, err := Detect(domain.Target{PURL: "pkg:deb/debian/openssl@not-a-version"}, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	var found bool
	for _, f := range report.Findings {
		if f.VulnerabilityID != "GHSA-deb-1" {
			continue
		}
		found = true
		if f.Status != domain.FindingStatusInconclusive {
			t.Fatalf("status = %q, want inconclusive", f.Status)
		}
	}
	if !found {
		t.Fatalf("an uncomparable version must surface as inconclusive, got %+v", report.Findings)
	}
}

func TestDetectAttachesEnrichment(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.SaveVulnerability(domain.Vulnerability{
		ID:     "CVE-ENRICH-001",
		Source: "nvd",
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "OR",
				Matches: []domain.CPEMatch{
					{
						Vulnerable:       true,
						Criteria:         "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
						VersionStart:     "2.4.0",
						VersionStartMode: domain.BoundModeIncluding,
						VersionEnd:       "2.4.51",
						VersionEndMode:   domain.BoundModeExcluding,
					},
				},
			},
		},
	}); err != nil {
		t.Fatalf("SaveVulnerability: %v", err)
	}

	if err := s.SaveEnrichment(domain.Enrichment{
		Source:          "test",
		VulnerabilityID: "CVE-ENRICH-001",
		Mitigation:      "upgrade now",
	}); err != nil {
		t.Fatalf("SaveEnrichment: %v", err)
	}

	target := domain.Target{Product: "Apache HTTP Server", Version: "2.4.49"}
	report, err := Detect(target, Options{Store: s})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	var found bool
	for _, f := range report.Findings {
		if f.VulnerabilityID == "CVE-ENRICH-001" {
			if f.Enrichment == nil {
				t.Fatal("Enrichment should be attached to CVE-ENRICH-001")
			}
			if f.Enrichment.Mitigation != "upgrade now" {
				t.Fatalf("Mitigation = %q", f.Enrichment.Mitigation)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected CVE-ENRICH-001 in findings, got %+v", report.Findings)
	}
}

func TestDetectRiskCopied(t *testing.T) {
	target := domain.Target{Product: "Apache HTTP Server", Version: "2.4.49"}
	report, err := Detect(target, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(report.Findings) < 1 {
		t.Fatal("expected at least 1 finding")
	}
	f := report.Findings[0]
	if f.Risk == nil {
		t.Fatal("Risk should be copied from vulnerability")
	}
	if f.Risk.Severity == "" || f.Risk.CVSS == 0 {
		t.Fatalf("Risk incomplete: %+v", f.Risk)
	}
}
