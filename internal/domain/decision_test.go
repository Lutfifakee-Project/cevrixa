package domain

import "testing"

func TestDecisionForIdentityUnresolved(t *testing.T) {
	got := DecisionFor(false, nil)
	if got != DecisionIdentityUnresolved {
		t.Fatalf("decision = %q, want identity_unresolved", got)
	}
}

func TestDecisionForAffected(t *testing.T) {
	findings := []Finding{{Status: FindingStatusAffected}}
	if got := DecisionFor(true, findings); got != DecisionAffected {
		t.Fatalf("decision = %q, want affected", got)
	}
}

func TestDecisionForInconclusive(t *testing.T) {
	findings := []Finding{{Status: FindingStatusInconclusive}}
	if got := DecisionFor(true, findings); got != DecisionInconclusive {
		t.Fatalf("decision = %q, want inconclusive", got)
	}
}

func TestDecisionForNoData(t *testing.T) {
	if got := DecisionFor(true, nil); got != DecisionNoData {
		t.Fatalf("decision = %q, want no_data", got)
	}
}

// A resolved identity that only produced not_affected findings must not be
// reported as affected or inconclusive.
func TestDecisionForResolvedNotAffectedIsNoData(t *testing.T) {
	findings := []Finding{{Status: FindingStatusNotAffected}}
	if got := DecisionFor(true, findings); got != DecisionNoData {
		t.Fatalf("decision = %q, want no_data", got)
	}
}

func TestReportSatisfiesGate(t *testing.T) {
	cases := []struct {
		gate     string
		decision ReportDecision
		want     bool
	}{
		{"no_data", DecisionNoData, true},
		{"no_data", DecisionAffected, false},
		{"identity_unresolved", DecisionIdentityUnresolved, true},
		{"identity_unresolved", DecisionNoData, false},
		{"affected", DecisionAffected, false},
	}
	for _, c := range cases {
		if got := ReportSatisfiesGate(c.gate, c.decision); got != c.want {
			t.Fatalf("ReportSatisfiesGate(%q, %q) = %v, want %v", c.gate, c.decision, got, c.want)
		}
	}
}
