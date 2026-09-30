package domain

import "testing"

func TestFindingStatusValues(t *testing.T) {
	want := []FindingStatus{
		FindingStatusAffected,
		FindingStatusNotAffected,
		FindingStatusInconclusive,
		FindingStatusUnknown,
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
		{"affected with empty threshold is inert", aff, "none", false},
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

func TestIsSeverityAtLeastSeverityGates(t *testing.T) {
	critical := Finding{Status: FindingStatusAffected, Risk: &Risk{Severity: "CRITICAL"}}
	high := Finding{Status: FindingStatusAffected, Risk: &Risk{Severity: "HIGH"}}
	moderate := Finding{Status: FindingStatusAffected, Risk: &Risk{Severity: "MODERATE"}}
	noRisk := Finding{Status: FindingStatusAffected}

	cases := []struct {
		name      string
		f         Finding
		threshold string
		want      bool
	}{
		{"critical meets critical", critical, "critical", true},
		{"critical meets high", critical, "high", true},
		{"critical meets medium", critical, "medium", true},
		{"high does not meet critical", high, "critical", false},
		{"high meets high", high, "high", true},
		{"NVD MODERATE meets OSV medium", moderate, "medium", true},
		{"NVD MODERATE meets moderate wording", moderate, "moderate", true},
		{"NVD MODERATE does not meet high", moderate, "high", false},
		{"missing risk never meets a severity gate", noRisk, "low", false},
		{"inconclusive status gate", Finding{Status: FindingStatusInconclusive}, "inconclusive", true},
		{"inconclusive status gate rejects affected", Finding{Status: FindingStatusAffected}, "inconclusive", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.f.IsSeverityAtLeast(tc.threshold); got != tc.want {
				t.Fatalf("IsSeverityAtLeast(%q) = %v, want %v", tc.threshold, got, tc.want)
			}
		})
	}
}

func TestValidGate(t *testing.T) {
	valid := []string{"none", "any", "affected", "inconclusive", "kev", "low", "medium", "moderate", "HIGH", "Critical"}
	for _, g := range valid {
		if !ValidGate(g) {
			t.Fatalf("ValidGate(%q) = false, want true", g)
		}
	}
	invalid := []string{"bogus", "critcal", "severity", "affectedd"}
	for _, g := range invalid {
		if ValidGate(g) {
			t.Fatalf("ValidGate(%q) = true, want false", g)
		}
	}
}

func TestReportCarriesDatasetInfo(t *testing.T) {
	r := Report{Dataset: DatasetInfo{StoreRecords: 10, FixtureRecords: 2, Sources: []string{"nvd", "osv"}}}
	if r.Dataset.Total() != 12 {
		t.Fatalf("Total = %d, want 12", r.Dataset.Total())
	}
	if r.Dataset.Empty() {
		t.Fatal("dataset with records must not report Empty")
	}
	if !r.Dataset.TestData() {
		t.Fatal("dataset with fixture records must report TestData")
	}
	if (DatasetInfo{}).Empty() != true {
		t.Fatal("zero dataset must report Empty")
	}
}
