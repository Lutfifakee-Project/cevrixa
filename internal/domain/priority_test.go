package domain

import "testing"

func TestPriorityOnlyForAffected(t *testing.T) {
	na := Finding{Status: FindingStatusNotAffected, Risk: &Risk{Severity: "CRITICAL"}}
	if got := ComputePriority(na); got.Level != PriorityNone {
		t.Fatalf("not_affected priority = %q, want none", got.Level)
	}
	inc := Finding{Status: FindingStatusInconclusive, Risk: &Risk{Severity: "HIGH"}}
	if got := ComputePriority(inc); got.Level != PriorityNone {
		t.Fatalf("inconclusive priority = %q, want none", got.Level)
	}
}

func TestPrioritySeverityFloor(t *testing.T) {
	f := Finding{Status: FindingStatusAffected, Risk: &Risk{Severity: "HIGH"}}
	if got := ComputePriority(f); got.Level != PriorityHigh {
		t.Fatalf("high severity priority = %q, want high", got.Level)
	}
	f.Risk.Severity = "MODERATE"
	if got := ComputePriority(f); got.Level != PriorityMedium {
		t.Fatalf("moderate severity priority = %q, want medium", got.Level)
	}
}

func TestPriorityKEVIsCritical(t *testing.T) {
	f := Finding{
		Status:         FindingStatusAffected,
		Risk:           &Risk{Severity: "LOW"},
		KnownExploited: &KEVInfo{CVEID: "CVE-X"},
	}
	got := ComputePriority(f)
	if got.Level != PriorityCritical {
		t.Fatalf("KEV priority = %q, want critical", got.Level)
	}
	if len(got.Factors) == 0 {
		t.Fatal("expected factors to be recorded")
	}
}

func TestPriorityHighEPSSRaises(t *testing.T) {
	f := Finding{Status: FindingStatusAffected, Risk: &Risk{Severity: "LOW", EPSS: 0.9}}
	if got := ComputePriority(f); got.Level != PriorityHigh {
		t.Fatalf("high EPSS priority = %q, want high", got.Level)
	}
}

func TestPriorityLowEPSSDoesNotRaise(t *testing.T) {
	f := Finding{Status: FindingStatusAffected, Risk: &Risk{Severity: "LOW", EPSS: 0.01}}
	if got := ComputePriority(f); got.Level != PriorityLow {
		t.Fatalf("low EPSS priority = %q, want low", got.Level)
	}
}
