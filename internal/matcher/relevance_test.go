package matcher

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

// Case 1: an unrelated target and an AND configuration that contains no
// matching vulnerable component must be excluded (decided non-match), never
// reported as an inconclusive finding.
func TestRelevanceUnrelatedAndIsDecidedNonMatch(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "AND",
				Matches: []domain.CPEMatch{
					{Vulnerable: true, Criteria: "cpe:2.3:a:somevendor:someproduct:*:*:*:*:*:*:*:*"},
					{Vulnerable: false, Criteria: "cpe:2.3:o:othervendor:otheros:-:*:*:*:*:*:*:*"},
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
		t.Fatalf("unrelated AND must not match: %+v", got)
	}
	if got.Undecided {
		t.Fatalf("unrelated AND must be a decided non-match, got undecided: %+v", got)
	}
}

// Case 2: a target that matches a vulnerable component of an AND group, where
// an additional prerequisite is unknown, must remain a candidate and be
// INCONCLUSIVE (undecided), never dropped and never affected.
func TestRelevanceTargetInAndWithUnknownPrerequisiteIsUndecided(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "AND",
				Matches: []domain.CPEMatch{
					{Vulnerable: true, Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
					{Vulnerable: true, Criteria: "cpe:2.3:a:oracle:somecomponent:*:*:*:*:*:*:*:*"},
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
		t.Fatalf("AND with an unmet prerequisite must not be affected: %+v", got)
	}
	if !got.Undecided {
		t.Fatalf("AND with an unknown prerequisite for a matching target must be undecided: %+v", got)
	}
	if got.Reason == "" {
		t.Fatal("an undecided retained candidate must carry a reason")
	}
}

// Case 3: an OR branch must still be evaluated and a matching branch must win.
func TestRelevanceOrBranchStillEvaluated(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "OR",
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
	if !got.Matched {
		t.Fatalf("OR branch naming the target must match: %+v", got)
	}
}

// Case 4: nested AND/OR configurations must preserve their Boolean meaning.
func TestRelevanceNestedAndOrSemantics(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "AND",
				Children: []domain.ApplicabilityNode{
					{
						Operator: "OR",
						Matches: []domain.CPEMatch{
							{Vulnerable: true, Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
						},
					},
					{
						Operator: "OR",
						Matches: []domain.CPEMatch{
							{Vulnerable: false, Criteria: "cpe:2.3:h:vendor:extra_hardware:-:*:*:*:*:*:*:*"},
						},
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
		t.Fatalf("an unmet AND branch must not be affected: %+v", got)
	}
	if !got.Undecided {
		t.Fatalf("a target in a nested AND with an unmet branch stays undecided: %+v", got)
	}
	if !strings.Contains(got.Reason, "additional component") {
		t.Fatalf("reason must name the missing component, got %q", got.Reason)
	}
}

// Case 5: matching only a non-vulnerable environmental criterion must not make
// the target a vulnerable candidate on that basis alone.
func TestRelevanceEnvironmentalOnlyIsNotCandidate(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "AND",
				Matches: []domain.CPEMatch{
					{Vulnerable: false, Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
					{Vulnerable: true, Criteria: "cpe:2.3:a:othervendor:otherproduct:*:*:*:*:*:*:*:*"},
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
		t.Fatalf("environmental-only match must not be affected: %+v", got)
	}
	if got.Undecided {
		t.Fatalf("environmental-only match is a decided non-match, got undecided: %+v", got)
	}
}

// Case 6: CPE wildcards still apply to the relevance guard; a wildcard product
// naming the target vendor must keep the candidate eligible.
func TestRelevanceWildcardProduct(t *testing.T) {
	vuln := domain.Vulnerability{
		Applicability: []domain.ApplicabilityNode{
			{
				Operator: "AND",
				Matches: []domain.CPEMatch{
					{Vulnerable: true, Criteria: "cpe:2.3:a:apache:*:*:*:*:*:*:*:*:*"},
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
		t.Fatalf("wildcard product naming the target vendor must match: %+v", got)
	}
}

// Case 7: version boundaries are evaluated at the applicability stage. A
// relevant candidate whose version is out of range must be a decided
// non-match (not dropped by the relevance guard) and must keep its fixed
// version for why-not.
func TestRelevanceKeepsOutOfRangeCandidateForExplanation(t *testing.T) {
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
	target := mustCPE(t, "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")

	got, err := MatchCPE(target, vuln)
	if err != nil {
		t.Fatalf("MatchCPE: %v", err)
	}
	if got.Matched {
		t.Fatalf("out-of-range version must not match: %+v", got)
	}
	if got.Undecided {
		t.Fatalf("an out-of-range relevant candidate is decidable: %+v", got)
	}
	if got.Fixed != "2.4.51" {
		t.Fatalf("relevant candidate must keep fixed version for why-not, got %q", got.Fixed)
	}
}
