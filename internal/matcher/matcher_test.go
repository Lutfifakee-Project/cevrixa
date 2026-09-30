package matcher

import (
	"strings"
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

func TestMatchCPEAndRequirementIsUndecided(t *testing.T) {
	// NVD expresses "affected only when another component is also present" as
	// an AND node. Treating it as OR is the well known CPE false positive that
	// this test locks out.
	vuln := domain.Vulnerability{
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
	}
	target := mustCPE(t, "cpe:2.3:a:apache:tomcat:8.5.87:*:*:*:*:*:*:*")

	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if got.Matched {
		t.Fatalf("AND requirement must never be reported as affected: %+v", got)
	}
	if !got.Undecided {
		t.Fatalf("AND requirement must be undecided, got %+v", got)
	}
	if got.Reason == "" {
		t.Fatal("an undecided result must carry a reason")
	}
}

func TestMatchCPEAndWithForeignVulnerableComponentIsUndecided(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "AND",
				Matches: []domain.CPEMatch{
					{Vulnerable: true, Criteria: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"},
					{Vulnerable: true, Criteria: "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
				},
			},
		},
	}
	target := mustCPE(t, "cpe:2.3:a:apache:tomcat:8.5.87:*:*:*:*:*:*:*")

	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if got.Matched || !got.Undecided {
		t.Fatalf("AND over another component must be undecided, got %+v", got)
	}
}

func TestMatchCPEAndSameProductOutOfRangeIsNotAffected(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "AND",
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
	fixed := mustCPE(t, "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")

	got, err := MatchCPE(fixed, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if got.Matched {
		t.Fatalf("version at the fixed boundary must not match: %+v", got)
	}
	if got.Undecided {
		t.Fatalf("same-product range miss is decidable, got %+v", got)
	}
	if got.Fixed != "2.4.51" {
		t.Fatalf("Fixed = %q, want 2.4.51 for a why-not explanation", got.Fixed)
	}
}

func TestMatchCPENegateIsUndecided(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Negate: true,
				Matches: []domain.CPEMatch{
					{Vulnerable: true, Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
				},
			},
		},
	}
	target := mustCPE(t, "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")

	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if got.Matched || !got.Undecided {
		t.Fatalf("a negated configuration must be undecided, never silently matched: %+v", got)
	}
}

func TestMatchCPEPinnedCriteriaVersionIsHonoured(t *testing.T) {
	// CVE-2008-3909 pins django 0.91/0.95/0.96 inside the criteria string with
	// no version bounds. Ignoring that field reported every django version as
	// affected.
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Matches: []domain.CPEMatch{
					{Vulnerable: true, Criteria: "cpe:2.3:a:django_project:django:0.91:*:*:*:*:*:*:*"},
				},
			},
		},
	}

	wrong := mustCPE(t, "cpe:2.3:a:django_project:django:4.2.0:*:*:*:*:*:*:*")
	gotWrong, err := MatchCPE(wrong, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if gotWrong.Matched {
		t.Fatalf("django 4.2.0 must not match a 0.91 criterion: %+v", gotWrong)
	}

	right := mustCPE(t, "cpe:2.3:a:django_project:django:0.91:*:*:*:*:*:*:*")
	gotRight, err := MatchCPE(right, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if !gotRight.Matched {
		t.Fatalf("django 0.91 must match its own criterion: %+v", gotRight)
	}
	if gotRight.Mode != "exact" {
		t.Fatalf("pinned criteria must be exact confidence, got mode %q", gotRight.Mode)
	}
}

func TestMatchCPEOutOfRangeKeepsRangeForExplanation(t *testing.T) {
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
	target := mustCPE(t, "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")

	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if got.Matched {
		t.Fatalf("expected no match: %+v", got)
	}
	if got.Range != ">=2.4.0 <2.4.51" || got.Fixed != "2.4.51" {
		t.Fatalf("a decided non-match must still carry range and fixed version: %+v", got)
	}
}

func TestMatchCPEOutOfRangeWhyIsNotMisleading(t *testing.T) {
	target := mustCPE(t, "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")
	why := BuildWhy(target, Result{Matched: false, Range: ">=2.4.0 <2.4.51", Fixed: "2.4.51"})

	if !strings.Contains(why.VersionMatch, "outside") {
		t.Fatalf("why-not must say the version is outside the range, got %q", why.VersionMatch)
	}
	if strings.Contains(why.VersionMatch, " in ") {
		t.Fatalf("why-not must not claim the version is inside the range: %q", why.VersionMatch)
	}
}

func TestBuildWhyUndecidedStatesQuestion(t *testing.T) {
	target := mustCPE(t, "cpe:2.3:a:apache:tomcat:8.5.87:*:*:*:*:*:*:*")
	why := BuildWhy(target, Result{Undecided: true, Reason: "AND configuration requires an additional component"})

	if len(why.Questions) == 0 {
		t.Fatal("an undecided why must state what would resolve the question")
	}
	if len(why.Steps) == 0 || why.Steps[0] != "AND configuration requires an additional component" {
		t.Fatalf("undecided why must carry the reason, got %+v", why.Steps)
	}
}

func TestMatchCPEAndChildRequirementNamesTheMissingComponent(t *testing.T) {
	// Real shape from CVE-2008-4128: cisco ios AND the 871 hardware platform.
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "AND",
				Children: []domain.ApplicabilityNode{
					{
						Operator: "OR",
						Matches: []domain.CPEMatch{
							{Vulnerable: true, Criteria: "cpe:2.3:o:cisco:ios:12.4:*:*:*:*:*:*:*"},
						},
					},
					{
						Operator: "OR",
						Matches: []domain.CPEMatch{
							{Vulnerable: false, Criteria: "cpe:2.3:h:cisco:871_integrated_services_router:-:*:*:*:*:*:*:*"},
						},
					},
				},
			},
		},
	}
	target := mustCPE(t, "cpe:2.3:o:cisco:ios:12.4:*:*:*:*:*:*:*")

	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if got.Matched || !got.Undecided {
		t.Fatalf("an AND group with an unmet requirement must be undecided: %+v", got)
	}
	if !strings.Contains(got.Reason, "additional component") {
		t.Fatalf("reason must name the missing requirement, got %q", got.Reason)
	}
	if strings.Contains(got.Reason, "no part") {
		t.Fatalf("reason must not claim that nothing matched when a part did: %q", got.Reason)
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
func TestMatchCPEClassifiesMode(t *testing.T) {
	cases := []struct {
		name string
		m    domain.CPEMatch
		want string
	}{
		{
			name: "wildcard",
			m:    domain.CPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
			want: "wildcard",
		},
		{
			name: "range both bounds",
			m: domain.CPEMatch{
				Vulnerable:       true,
				Criteria:         "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
				VersionStart:     "2.4.0",
				VersionStartMode: domain.BoundModeIncluding,
				VersionEnd:       "2.4.51",
				VersionEndMode:   domain.BoundModeExcluding,
			},
			want: "range",
		},
		{
			name: "partial lower only",
			m: domain.CPEMatch{
				Vulnerable:       true,
				Criteria:         "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
				VersionStart:     "2.4.0",
				VersionStartMode: domain.BoundModeIncluding,
			},
			want: "partial",
		},
		{
			name: "exact",
			m: domain.CPEMatch{
				Vulnerable:       true,
				Criteria:         "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
				VersionStart:     "2.4.49",
				VersionStartMode: domain.BoundModeIncluding,
				VersionEnd:       "2.4.49",
				VersionEndMode:   domain.BoundModeIncluding,
			},
			want: "exact",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyMode(tc.m)
			if got != tc.want {
				t.Fatalf("classifyMode = %q, want %q", got, tc.want)
			}
		})
	}
}
