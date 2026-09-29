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
