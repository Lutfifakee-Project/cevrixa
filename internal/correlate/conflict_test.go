package correlate

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func TestDetectConflictsSeverityConflict(t *testing.T) {
	ev := []domain.Evidence{
		{Kind: domain.EvidenceKindSeverity, Source: "a", Value: "HIGH"},
		{Kind: domain.EvidenceKindSeverity, Source: "b", Value: "CRITICAL"},
	}
	got := detectConflicts(ev)
	if len(got) != 1 || got[0].Kind != domain.EvidenceKindSeverity {
		t.Fatalf("expected severity conflict, got %+v", got)
	}
	if len(got[0].Values) != 2 {
		t.Fatalf("expected 2 conflict values, got %d", len(got[0].Values))
	}
}

func TestDetectConflictsSeverityAgreement(t *testing.T) {
	ev := []domain.Evidence{
		{Kind: domain.EvidenceKindSeverity, Source: "a", Value: "HIGH"},
		{Kind: domain.EvidenceKindSeverity, Source: "b", Value: "HIGH"},
	}
	got := detectConflicts(ev)
	if len(got) != 0 {
		t.Fatalf("agreement is not conflict, got %+v", got)
	}
}

func TestDetectConflictsCVSSSameVersion(t *testing.T) {
	ev := []domain.Evidence{
		{Kind: domain.EvidenceKindCVSS, Source: "a", Value: "7.5"},
		{Kind: domain.EvidenceKindCVSSVersion, Source: "a", Value: "3.1"},
		{Kind: domain.EvidenceKindCVSS, Source: "b", Value: "9.8"},
		{Kind: domain.EvidenceKindCVSSVersion, Source: "b", Value: "3.1"},
	}
	got := detectConflicts(ev)
	if len(got) != 1 || got[0].Kind != domain.EvidenceKindCVSS {
		t.Fatalf("expected cvss conflict, got %+v", got)
	}
}

func TestDetectConflictsCVSSDifferentVersion(t *testing.T) {
	ev := []domain.Evidence{
		{Kind: domain.EvidenceKindCVSS, Source: "a", Value: "7.5"},
		{Kind: domain.EvidenceKindCVSSVersion, Source: "a", Value: "3.0"},
		{Kind: domain.EvidenceKindCVSS, Source: "b", Value: "9.8"},
		{Kind: domain.EvidenceKindCVSSVersion, Source: "b", Value: "3.1"},
	}
	got := detectConflicts(ev)

	for _, c := range got {
		switch c.Kind {
		case domain.EvidenceKindCVSS:
			t.Fatalf("CVSS with different CVSSVersion must not conflict: %+v", c)
		case domain.EvidenceKindCVSSVersion:
			t.Fatalf("CVSSVersion must never be reported as scalar conflict: %+v", c)
		}
	}

	if len(got) != 0 {
		t.Fatalf("expected no conflicts, got %+v", got)
	}
}

func TestDetectConflictsIgnoresNonScalarKinds(t *testing.T) {
	ref1 := &domain.Reference{URL: "https://example/a"}
	ref2 := &domain.Reference{URL: "https://example/b"}
	ev := []domain.Evidence{
		{Kind: domain.EvidenceKindReference, Source: "a", Reference: ref1},
		{Kind: domain.EvidenceKindReference, Source: "b", Reference: ref2},
		{Kind: domain.EvidenceKindMitigation, Source: "a", Value: "upgrade"},
		{Kind: domain.EvidenceKindMitigation, Source: "b", Value: "patch"},
		{Kind: domain.EvidenceKindEPSS, Source: "a", Value: "0.5"},
		{Kind: domain.EvidenceKindEPSS, Source: "b", Value: "0.9"},
		{Kind: domain.EvidenceKindEPSSPercentile, Source: "a", Value: "0.6"},
		{Kind: domain.EvidenceKindEPSSPercentile, Source: "b", Value: "0.95"},
	}
	got := detectConflicts(ev)
	if len(got) != 0 {
		t.Fatalf("non-scalar kinds must not conflict, got %+v", got)
	}
}

func TestDetectConflictsDuplicateValuesNotConflict(t *testing.T) {
	ev := []domain.Evidence{
		{Kind: domain.EvidenceKindKEV, Source: "a", Value: "true"},
		{Kind: domain.EvidenceKindKEV, Source: "b", Value: "true"},
	}
	got := detectConflicts(ev)
	if len(got) != 0 {
		t.Fatalf("same value is not conflict, got %+v", got)
	}
}

func TestDetectConflictsMissingValueIgnored(t *testing.T) {
	ev := []domain.Evidence{
		{Kind: domain.EvidenceKindSeverity, Source: "a", Value: "HIGH"},
		{Kind: domain.EvidenceKindSeverity, Source: "b", Value: ""},
	}
	got := detectConflicts(ev)
	if len(got) != 0 {
		t.Fatalf("missing value must not create conflict, got %+v", got)
	}
}

func TestDetectConflictsEvidenceOnlyKinds(t *testing.T) {
	cases := []struct {
		kind   domain.EvidenceKind
		valueA string
		valueB string
	}{
		{domain.EvidenceKindCVSSVersion, "3.0", "3.1"},
		{domain.EvidenceKindEPSS, "0.5", "0.9"},
		{domain.EvidenceKindEPSSPercentile, "0.6", "0.95"},
		{domain.EvidenceKindMitigation, "upgrade", "patch"},
		{domain.EvidenceKindPoC, "https://a/poc", "https://b/poc"},
		{domain.EvidenceKindPatch, "https://a/commit", "https://b/commit"},
	}

	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			ev := []domain.Evidence{
				{Kind: tc.kind, Source: "a", Value: tc.valueA},
				{Kind: tc.kind, Source: "b", Value: tc.valueB},
			}
			got := detectConflicts(ev)
			if len(got) != 0 {
				t.Fatalf("%s must not produce conflict, got %+v", tc.kind, got)
			}
		})
	}
}

func TestDetectConflictsScalarContract(t *testing.T) {
	scalarKinds := []domain.EvidenceKind{
		domain.EvidenceKindSeverity,
		domain.EvidenceKindStatus,
		domain.EvidenceKindCVSS,
		domain.EvidenceKindKEV,
	}
	for _, kind := range scalarKinds {
		t.Run(string(kind), func(t *testing.T) {
			ev := []domain.Evidence{
				{Kind: kind, Source: "a", Value: "value-a"},
				{Kind: kind, Source: "b", Value: "value-b"},
			}
			got := detectConflicts(ev)
			if len(got) != 1 || got[0].Kind != kind {
				t.Fatalf("%s must produce exactly one conflict, got %+v", kind, got)
			}
		})
	}
}
