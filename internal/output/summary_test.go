package output

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func TestReportDecisionLabel(t *testing.T) {
	tests := []struct {
		decision domain.ReportDecision
		want     string
	}{
		{domain.DecisionAffected, "AFFECTED"},
		{domain.DecisionInconclusive, "INCONCLUSIVE"},
		{domain.DecisionNoData, "NO DATA"},
		{domain.DecisionIdentityUnresolved, "IDENTITY UNRESOLVED"},
		{"", "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(string(tt.decision), func(t *testing.T) {
			got := reportDecisionLabel(domain.Report{Decision: tt.decision})
			if got != tt.want {
				t.Fatalf("label = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindingSummaryEmpty(t *testing.T) {
	if got := findingSummary(nil); got != "" {
		t.Fatalf("empty findings should yield empty summary, got %q", got)
	}
}

func TestFindingSummaryCounts(t *testing.T) {
	findings := []domain.Finding{
		{Status: domain.FindingStatusAffected, Risk: &domain.Risk{Severity: "HIGH"}},
		{Status: domain.FindingStatusAffected, Risk: &domain.Risk{Severity: "CRITICAL"}},
		{Status: domain.FindingStatusInconclusive},
		{Status: domain.FindingStatusNotAffected},
	}
	got := findingSummary(findings)
	for _, want := range []string{"2 AFFECTED", "1 INCONCLUSIVE", "1 NOT_AFFECTED", "1 CRITICAL", "1 HIGH"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary missing %q: %q", want, got)
		}
	}
}

func TestRenderHumanHasDecisionAndSummary(t *testing.T) {
	report := sampleReport()
	report.Decision = domain.DecisionAffected
	var buf strings.Builder
	if err := RenderHuman(&buf, report); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Decision") || !strings.Contains(out, "AFFECTED") {
		t.Fatalf("human output should show the report decision: %s", out)
	}
	if !strings.Contains(out, "Summary") {
		t.Fatalf("human output should show a summary: %s", out)
	}
}

func TestRenderHumanDefaultHidesEvidenceCount(t *testing.T) {
	report := sampleReport()
	report.Findings[0].Evidence = []domain.Evidence{
		{Kind: domain.EvidenceKindStatus, Source: "nvd", Value: "Analyzed"},
	}
	var buf strings.Builder
	if err := RenderHuman(&buf, report); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	if strings.Contains(buf.String(), "Evidence") {
		t.Fatalf("evidence count should be hidden without --verbose: %s", buf.String())
	}
}

func TestRenderHumanVerboseShowsEvidenceCount(t *testing.T) {
	report := sampleReport()
	report.Findings[0].Evidence = []domain.Evidence{
		{Kind: domain.EvidenceKindStatus, Source: "nvd", Value: "Analyzed"},
	}
	var buf strings.Builder
	if err := RenderHumanWithOptions(&buf, report, RenderOptions{Verbose: true}); err != nil {
		t.Fatalf("RenderHumanWithOptions: %v", err)
	}
	if !strings.Contains(buf.String(), "Evidence") {
		t.Fatalf("evidence count should appear with --verbose: %s", buf.String())
	}
}

func TestRenderHumanEmptyHidesDecisionHeader(t *testing.T) {
	report := domain.Report{
		Target:   domain.Target{Product: "no-such", Version: "1.0"},
		Decision: domain.DecisionIdentityUnresolved,
	}
	var buf strings.Builder
	if err := RenderHuman(&buf, report); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "Decision") {
		t.Fatalf("empty report should not print a Decision header line: %s", out)
	}
	if !strings.Contains(out, "IDENTITY UNRESOLVED") {
		t.Fatalf("empty report should still state its decision in the block: %s", out)
	}
}
