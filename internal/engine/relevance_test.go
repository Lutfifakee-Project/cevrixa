package engine

import (
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

// Regression for the observed Nginx false positive: an AND configuration that
// never names nginx as a vulnerable component must not become an INCONCLUSIVE
// finding for an nginx target merely because the required component cannot be
// evaluated. Before the candidate relevance guard, records like this produced
// the bulk of the 380 all-INCONCLUSIVE findings for detect nginx 1.24.0.
func TestDetectUnrelatedAndIsNotAnNginxFinding(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nginx.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// NVD shape: the vulnerable product is an unrelated vendor's component that
	// merely requires nginx to be present. Nginx is the environment, not the
	// affected component, so this record is irrelevant to the nginx target.
	if err := s.SaveVulnerability(domain.Vulnerability{
		ID:     "CVE-NGINX-UNRELATED-001",
		Source: "nvd",
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "AND",
				Matches: []domain.CPEMatch{
					{Vulnerable: true, Criteria: "cpe:2.3:a:somevendor:someproduct:*:*:*:*:*:*:*:*"},
					{Vulnerable: false, Criteria: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"},
				},
			},
		},
	}); err != nil {
		t.Fatalf("SaveVulnerability: %v", err)
	}

	report, err := Detect(domain.Target{CPE: "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"}, Options{Store: s})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	for _, f := range report.Findings {
		if f.VulnerabilityID == "CVE-NGINX-UNRELATED-001" {
			t.Fatalf("unrelated AND must not be a finding for nginx, got %+v", f)
		}
	}
}

// A relevant AND that names nginx as the vulnerable component, with an unknown
// additional prerequisite, must remain an INCONCLUSIVE finding. This is the
// mirror of the exclusion above and prevents the guard from being a blunt
// "drop every AND" rule.
func TestDetectRelevantAndStaysInconclusiveForNginx(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nginx-and.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.SaveVulnerability(domain.Vulnerability{
		ID:     "CVE-NGINX-AND-001",
		Source: "nvd",
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "AND",
				Matches: []domain.CPEMatch{
					{Vulnerable: true, Criteria: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"},
					{Vulnerable: false, Criteria: "cpe:2.3:o:somevendor:someos:*:*:*:*:*:*:*:*"},
				},
			},
		},
	}); err != nil {
		t.Fatalf("SaveVulnerability: %v", err)
	}

	report, err := Detect(domain.Target{CPE: "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"}, Options{Store: s})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	var found *domain.Finding
	for i := range report.Findings {
		if report.Findings[i].VulnerabilityID == "CVE-NGINX-AND-001" {
			found = &report.Findings[i]
		}
	}
	if found == nil {
		t.Fatal("a relevant AND must still surface as inconclusive, not be dropped")
	}
	if found.Status != domain.FindingStatusInconclusive {
		t.Fatalf("status = %q, want inconclusive", found.Status)
	}
	if len(found.Why.Questions) == 0 && len(found.Why.Steps) == 0 {
		t.Fatal("a retained inconclusive finding must carry its reason/questions")
	}
}
