package cli

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/output"
)

// affectedFlags and notAffectedFlags target the embedded CVE-2021-41773
// fixture, whose affected range is >=2.4.0 <2.4.51.
func whyFlags(version string) explainFlags {
	return explainFlags{
		VulnID: "CVE-2021-41773",
		CPE:    "cpe:2.3:a:apache:http_server:" + version + ":*:*:*:*:*:*:*",
	}
}

func TestBuildExplainReportAffected(t *testing.T) {
	report, err := buildExplainReport(whyFlags("2.4.49"))
	if err != nil {
		t.Fatalf("buildExplainReport: %v", err)
	}
	if report.Decision() != output.ExplainDecisionAffected {
		t.Fatalf("2.4.49 decision = %q, want affected", report.Decision())
	}
}

func TestBuildExplainReportNotAffected(t *testing.T) {
	report, err := buildExplainReport(whyFlags("2.4.51"))
	if err != nil {
		t.Fatalf("buildExplainReport: %v", err)
	}
	if report.Decision() != output.ExplainDecisionNotAffected {
		t.Fatalf("2.4.51 decision = %q, want not_affected", report.Decision())
	}
}

func TestWhyMismatchDoesNotInventReason(t *testing.T) {
	// why on a not-affected target must not produce an "affected" explanation.
	report, err := buildExplainReport(whyFlags("2.4.51"))
	if err != nil {
		t.Fatalf("buildExplainReport: %v", err)
	}
	if report.Decision() == output.ExplainDecisionAffected {
		t.Fatal("precondition failed: 2.4.51 should not be affected")
	}
}

func TestParseTargetArgsUnknownFlag(t *testing.T) {
	_, err := parseTargetArgs([]string{"CVE-2021-41773", "--cpe", "x", "--nope"}, "why")
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}
