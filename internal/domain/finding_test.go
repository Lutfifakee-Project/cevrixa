package domain

import "testing"

func TestFindingStatusValues(t *testing.T) {
	want := []FindingStatus{
		FindingStatusAffected,
		FindingStatusNotAffected,
		FindingStatusUnknown,
		FindingStatusConflict,
	}
	for _, s := range want {
		if s == "" {
			t.Fatalf("empty FindingStatus value in contract")
		}
	}
}

func TestFindingConfidenceValues(t *testing.T) {
	want := []FindingConfidence{
		ConfidenceExact,
		ConfidenceStrong,
		ConfidenceModerate,
		ConfidenceWeak,
		ConfidenceUnknown,
	}
	for _, c := range want {
		if c == "" {
			t.Fatalf("empty FindingConfidence value in contract")
		}
	}
}

func TestReportZeroValue(t *testing.T) {
	var r Report
	if r.Target.CPE != "" {
		t.Fatalf("zero Report should have empty target CPE")
	}
	if len(r.Findings) != 0 {
		t.Fatalf("zero Report should have no findings")
	}
}
func TestIsSeverityAtLeast(t *testing.T) {
	aff := Finding{Status: FindingStatusAffected}
	na := Finding{Status: FindingStatusNotAffected}
	unk := Finding{Status: FindingStatusUnknown}
	affKEV := Finding{Status: FindingStatusAffected, KnownExploited: &KEVInfo{CVEID: "CVE-X"}}

	cases := []struct {
		name      string
		f         Finding
		threshold string
		want      bool
	}{
		{"empty threshold", aff, "", false},
		{"none", aff, "none", false},
		{"any with affected", aff, "any", true},
		{"any with not_affected", na, "any", true},
		{"affected with affected", aff, "affected", true},
		{"affected with not_affected", na, "affected", false},
		{"affected with unknown", unk, "affected", false},
		{"kev with kev", affKEV, "kev", true},
		{"kev without kev", aff, "kev", false},
		{"unknown threshold", aff, "bogus", false},
		{"uppercase AFFECTED", aff, "AFFECTED", true},
		{"mixed case Affected", aff, "Affected", true},
		{"uppercase KEV", affKEV, "KEV", true},
		{"uppercase ANY", na, "ANY", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.f.IsSeverityAtLeast(tc.threshold)
			if got != tc.want {
				t.Fatalf("IsSeverityAtLeast(%q) = %v, want %v", tc.threshold, got, tc.want)
			}
		})
	}
}
