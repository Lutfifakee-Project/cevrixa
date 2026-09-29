package engine

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
)

func TestComputeConfidence(t *testing.T) {
	cases := []struct {
		name string
		mr   matcher.Result
		want domain.FindingConfidence
	}{
		{
			name: "not matched",
			mr:   matcher.Result{Matched: false, Mode: "range"},
			want: domain.ConfidenceUnknown,
		},
		{
			name: "exact",
			mr:   matcher.Result{Matched: true, Mode: "exact"},
			want: domain.ConfidenceExact,
		},
		{
			name: "strong (range both bounds)",
			mr:   matcher.Result{Matched: true, Mode: "range"},
			want: domain.ConfidenceStrong,
		},
		{
			name: "moderate (partial range)",
			mr:   matcher.Result{Matched: true, Mode: "partial"},
			want: domain.ConfidenceModerate,
		},
		{
			name: "weak (wildcard)",
			mr:   matcher.Result{Matched: true, Mode: "wildcard"},
			want: domain.ConfidenceWeak,
		},
		{
			name: "unknown mode",
			mr:   matcher.Result{Matched: true, Mode: ""},
			want: domain.ConfidenceUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := computeConfidence(tc.mr)
			if got != tc.want {
				t.Fatalf("computeConfidence = %q, want %q", got, tc.want)
			}
		})
	}
}
