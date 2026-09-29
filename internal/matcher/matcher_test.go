package matcher

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func mustCPE(t *testing.T, s string) domain.CPE {
	t.Helper()
	c, err := domain.ParseCPE(s)
	if err != nil {
		t.Fatalf("ParseCPE(%q): %v", s, err)
	}
	return c
}

func TestMatchCPEInRange(t *testing.T) {
	vuln := domain.Vulnerability{
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
	}
	target := mustCPE(t, "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if !got.Matched {
		t.Fatalf("expected match, got %+v", got)
	}
	if got.Fixed != "2.4.51" {
		t.Fatalf("Fixed = %q, want 2.4.51", got.Fixed)
	}
}

func TestMatchCPEOutOfRange(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
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
	}
	target := mustCPE(t, "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")
	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if got.Matched {
		t.Fatalf("expected no match at boundary, got %+v", got)
	}
}

func TestMatchCPEDifferentVendor(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Matches: []domain.CPEMatch{
					{
						Vulnerable: true,
						Criteria:   "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
					},
				},
			},
		},
	}
	target := mustCPE(t, "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if got.Matched {
		t.Fatalf("expected no match for different vendor")
	}
}

func TestMatchCPEWildcardVersion(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Matches: []domain.CPEMatch{
					{
						Vulnerable: true,
						Criteria:   "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
					},
				},
			},
		},
	}
	target := mustCPE(t, "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if !got.Matched {
		t.Fatalf("expected match for wildcard version")
	}
}

func TestMatchCPEEmptyApplicability(t *testing.T) {
	vuln := domain.Vulnerability{}
	target := mustCPE(t, "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if got.Matched {
		t.Fatalf("expected no match for empty applicability")
	}
}

func TestMatchCPENegateSkipped(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Matches: []domain.CPEMatch{
					{Vulnerable: false, Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
				},
			},
		},
	}
	target := mustCPE(t, "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if got.Matched {
		t.Fatalf("expected no match when Vulnerable=false")
	}
}

func TestMatchCPEBoundaryInclusive(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Matches: []domain.CPEMatch{
					{
						Vulnerable:       true,
						Criteria:         "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
						VersionStart:     "3.0.0",
						VersionStartMode: domain.BoundModeIncluding,
					},
				},
			},
		},
	}
	target := mustCPE(t, "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*")
	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if !got.Matched {
		t.Fatalf("inclusive lower boundary should match")
	}
}

func TestMatchCPEBoundaryExclusive(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Matches: []domain.CPEMatch{
					{
						Vulnerable:       true,
						Criteria:         "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
						VersionStart:     "3.0.0",
						VersionStartMode: domain.BoundModeExcluding,
					},
				},
			},
		},
	}
	target := mustCPE(t, "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*")
	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if got.Matched {
		t.Fatalf("exclusive lower boundary should not match")
	}
}
