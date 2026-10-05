package domain

import "testing"

func TestRemediationUpgradeWhenFixedKnown(t *testing.T) {
	f := Finding{
		Status:        FindingStatusAffected,
		FixedVersions: []string{"2.4.51"},
	}
	got := BuildRemediation(f)
	if got.Action != "upgrade" || got.FixedVersion != "2.4.51" {
		t.Fatalf("got %+v", got)
	}
}

func TestRemediationMonitorWhenNoFixed(t *testing.T) {
	f := Finding{Status: FindingStatusAffected}
	got := BuildRemediation(f)
	if got.Action != "monitor" {
		t.Fatalf("action = %q, want monitor", got.Action)
	}
	if got.FixedVersion != "" {
		t.Fatalf("fixed must be empty, got %q", got.FixedVersion)
	}
}

func TestRemediationUsesMitigationNote(t *testing.T) {
	f := Finding{
		Status:     FindingStatusAffected,
		Enrichment: &Enrichment{Mitigation: "apply vendor patch"},
	}
	got := BuildRemediation(f)
	if got.Note != "apply vendor patch" {
		t.Fatalf("note = %q", got.Note)
	}
}

func TestRemediationEmptyForNonAffected(t *testing.T) {
	for _, status := range []FindingStatus{FindingStatusNotAffected, FindingStatusInconclusive} {
		got := BuildRemediation(Finding{Status: status, FixedVersions: []string{"1.0"}})
		if got.Action != "" {
			t.Fatalf("status %q: remediation must be empty, got %+v", status, got)
		}
	}
}
