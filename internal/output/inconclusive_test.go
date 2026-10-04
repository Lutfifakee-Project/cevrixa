package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

// inconclusiveReport builds a report whose only finding is inconclusive, as
// produced when CPE applicability cannot be decided (AND requires another
// component, negated node, or an uncomparable version range).
func inconclusiveReport() domain.Report {
	return domain.Report{
		Target: domain.Target{
			Product:     "Apache Tomcat",
			Version:     "8.5.87",
			ResolvedCPE: "cpe:2.3:a:apache:tomcat:8.5.87:*:*:*:*:*:*:*",
		},
		Findings: []domain.Finding{
			{
				VulnerabilityID: "CVE-AND-001",
				Status:          domain.FindingStatusInconclusive,
				Confidence:      domain.ConfidenceWeak,
				Applicability: domain.Applicability{
					Matched: false,
					Source:  "nvd",
				},
			},
		},
	}
}

// TestScanJSONKeepsInconclusive guards the promise that an unanswerable
// question surfaces as inconclusive rather than being dropped from a scan.
func TestScanJSONKeepsInconclusive(t *testing.T) {
	reports := []domain.Report{inconclusiveReport()}

	var buf bytes.Buffer
	if err := RenderScanJSON(&buf, reports); err != nil {
		t.Fatalf("RenderScanJSON: %v", err)
	}

	var parsed struct {
		Reports []domain.Report `json:"reports"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v in %s", err, buf.String())
	}
	if len(parsed.Reports) != 1 || len(parsed.Reports[0].Findings) != 1 {
		t.Fatalf("expected 1 report with 1 finding, got %+v", parsed.Reports)
	}
	if parsed.Reports[0].Findings[0].Status != domain.FindingStatusInconclusive {
		t.Fatalf("status = %q, want inconclusive", parsed.Reports[0].Findings[0].Status)
	}
}

// TestScanHumanKeepsInconclusive checks the human renderer shows the
// inconclusive verdict instead of hiding it.
func TestScanHumanKeepsInconclusive(t *testing.T) {
	reports := []domain.Report{inconclusiveReport()}

	var buf bytes.Buffer
	if err := RenderScanHuman(&buf, reports); err != nil {
		t.Fatalf("RenderScanHuman: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "CVE-AND-001") {
		t.Fatalf("inconclusive finding ID missing from output: %s", out)
	}
	if !strings.Contains(strings.ToUpper(out), "INCONCLUSIVE") {
		t.Fatalf("expected INCONCLUSIVE in output: %s", out)
	}
}

// TestScanSARIFKeepsInconclusive checks the SARIF output carries the finding
// as a result rather than omitting it.
func TestScanSARIFKeepsInconclusive(t *testing.T) {
	reports := []domain.Report{inconclusiveReport()}

	var buf bytes.Buffer
	if err := RenderScanSARIF(&buf, reports, "test"); err != nil {
		t.Fatalf("RenderScanSARIF: %v", err)
	}

	var parsed struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid SARIF JSON: %v in %s", err, buf.String())
	}
	if len(parsed.Runs) != 1 || len(parsed.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 SARIF result, got %+v", parsed.Runs)
	}
	if parsed.Runs[0].Results[0].RuleID != "CVE-AND-001" {
		t.Fatalf("ruleId = %q", parsed.Runs[0].Results[0].RuleID)
	}
}
