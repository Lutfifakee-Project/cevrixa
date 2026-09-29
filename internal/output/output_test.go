package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func sampleReport() domain.Report {
	return domain.Report{
		Target: domain.Target{
			Product:     "Apache HTTP Server",
			Version:     "2.4.49",
			ResolvedCPE: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
		},
		Findings: []domain.Finding{
			{
				VulnerabilityID: "CVE-2021-41773",
				Status:          domain.FindingStatusAffected,
				Confidence:      domain.ConfidenceStrong,
				Applicability: domain.Applicability{
					Matched: true,
					Range:   ">=2.4.0 <2.4.51",
					Source:  "nvd",
				},
				Why: domain.Why{
					VersionMatch: "2.4.49 in >=2.4.0 <2.4.51",
				},
				FixedVersions: []string{"2.4.51"},
			},
		},
	}
}

func TestRenderHumanBasic(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHuman(&buf, sampleReport()); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Cevrixa", "Apache HTTP Server", "2.4.49", "CVE-2021-41773", "AFFECTED", "STRONG", "2.4.51"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q\n%s", want, out)
		}
	}
}

func TestRenderHumanEmptyReport(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderHuman(&buf, domain.Report{}); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	if !strings.Contains(buf.String(), "Findings: 0") {
		t.Fatalf("expected Findings: 0, got: %s", buf.String())
	}
}

func TestRenderJSONValid(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, sampleReport()); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var parsed domain.Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(parsed.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(parsed.Findings))
	}
	if parsed.Findings[0].VulnerabilityID != "CVE-2021-41773" {
		t.Fatalf("VulnerabilityID = %q", parsed.Findings[0].VulnerabilityID)
	}
}

func TestRenderJSONHasRequiredFields(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, sampleReport()); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`"vulnerability_id"`, `"status"`, `"confidence"`, `"applicability"`, `"why"`, `"fixed_versions"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("JSON missing field %q\n%s", want, out)
		}
	}
}
func TestRenderJSONEvidenceSnakeCase(t *testing.T) {
	report := sampleReport()
	report.Findings[0].Evidence = []domain.Evidence{
		{
			Kind:   domain.EvidenceKindStatus,
			Source: "nvd",
			Value:  "Analyzed",
		},
		{
			Kind:   domain.EvidenceKindReference,
			Source: "nvd",
			Reference: &domain.Reference{
				URL:    "https://example.test/a",
				Source: "nvd",
			},
		},
	}

	var buf bytes.Buffer
	if err := RenderJSON(&buf, report); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	out := buf.String()

	for _, want := range []string{`"kind"`, `"source"`, `"value"`, `"reference"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("JSON missing snake_case key %q\n%s", want, out)
		}
	}
	for _, forbidden := range []string{`"Kind"`, `"Source"`, `"Value"`, `"Reference"`, `"Range"`, `"Applicability"`} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("JSON contains PascalCase key %q\n%s", forbidden, out)
		}
	}
}

func TestRenderJSONNoHTMLEscape(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, sampleReport()); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, `\u003e`) || strings.Contains(out, `\u003c`) {
		t.Fatalf("JSON contains HTML-escaped < or >\n%s", out)
	}
	if !strings.Contains(out, ">=") {
		t.Fatalf("expected literal >= in JSON output\n%s", out)
	}
}
func TestRenderHumanWithKEV(t *testing.T) {
	report := sampleReport()
	report.Findings[0].KnownExploited = &domain.KEVInfo{
		CVEID:     "CVE-2021-41773",
		DateAdded: "2021-11-03",
	}

	var buf bytes.Buffer
	if err := RenderHuman(&buf, report); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "KEV") {
		t.Fatalf("expected KEV line in output:\n%s", out)
	}
	if !strings.Contains(out, "2021-11-03") {
		t.Fatalf("expected date in output:\n%s", out)
	}
}

func TestRenderHumanWithoutKEV(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	if err := RenderHuman(&buf, report); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	if strings.Contains(buf.String(), "KEV") {
		t.Fatalf("KEV line should not appear without KnownExploited:\n%s", buf.String())
	}
}
func TestRenderJSONLBasic(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSONL(&buf, sampleReport()); err != nil {
		t.Fatalf("RenderJSONL: %v", err)
	}
	raw := strings.TrimSpace(buf.String())
	if raw == "" {
		t.Fatal("expected at least one line")
	}
	lines := strings.Split(raw, "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	var parsed struct {
		Target  domain.Target  `json:"target"`
		Finding domain.Finding `json:"finding"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &parsed); err != nil {
		t.Fatalf("invalid JSON line: %v\n%s", err, lines[0])
	}
	if parsed.Finding.VulnerabilityID != "CVE-2021-41773" {
		t.Fatalf("VulnerabilityID = %q", parsed.Finding.VulnerabilityID)
	}
}

func TestRenderJSONLMultipleFindings(t *testing.T) {
	report := sampleReport()
	report.Findings = append(report.Findings, domain.Finding{
		VulnerabilityID: "CVE-2021-42013",
		Status:          domain.FindingStatusAffected,
		Confidence:      domain.ConfidenceStrong,
	})

	var buf bytes.Buffer
	if err := RenderJSONL(&buf, report); err != nil {
		t.Fatalf("RenderJSONL: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	for _, line := range lines {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			t.Fatalf("invalid JSON line: %v", err)
		}
	}
}

func TestRenderJSONLEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSONL(&buf, domain.Report{}); err != nil {
		t.Fatalf("RenderJSONL: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected empty output, got: %q", buf.String())
	}
}
func TestRenderSARIFValid(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, sampleReport(), "test-version"); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}

	var parsed struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, buf.String())
	}
	if parsed.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", parsed.Version)
	}
	if parsed.Schema == "" {
		t.Fatal("$schema missing")
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(parsed.Runs))
	}
	if parsed.Runs[0].Tool.Driver.Name != "Cevrixa" {
		t.Fatalf("driver name = %q", parsed.Runs[0].Tool.Driver.Name)
	}
	if parsed.Runs[0].Tool.Driver.Version != "test-version" {
		t.Fatalf("driver version = %q", parsed.Runs[0].Tool.Driver.Version)
	}
	if len(parsed.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(parsed.Runs[0].Results))
	}
	if parsed.Runs[0].Results[0].RuleID != "CVE-2021-41773" {
		t.Fatalf("ruleId = %q", parsed.Runs[0].Results[0].RuleID)
	}
	if parsed.Runs[0].Results[0].Level != "warning" {
		t.Fatalf("level = %q, want warning", parsed.Runs[0].Results[0].Level)
	}
}

func TestRenderSARIFKEVEscalatesLevel(t *testing.T) {
	report := sampleReport()
	report.Findings[0].KnownExploited = &domain.KEVInfo{
		CVEID:     "CVE-2021-41773",
		DateAdded: "2021-11-03",
	}

	var buf bytes.Buffer
	if err := RenderSARIF(&buf, report, "test"); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}

	var parsed struct {
		Runs []struct {
			Results []struct {
				Level string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Runs[0].Results[0].Level != "error" {
		t.Fatalf("KEV finding should escalate to error, got %q", parsed.Runs[0].Results[0].Level)
	}
}

func TestRenderSARIFEmptyReport(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, domain.Report{}, "test"); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var parsed struct {
		Version string `json:"version"`
		Runs    []any  `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Version != "2.1.0" {
		t.Fatalf("version = %q", parsed.Version)
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("expected 1 run even if empty, got %d", len(parsed.Runs))
	}
}
func TestRenderHumanWithEnrichment(t *testing.T) {
	report := sampleReport()
	report.Findings[0].Enrichment = &domain.Enrichment{
		Source:         "dbcve",
		Mitigation:     "Upgrade to 2.4.51",
		PoCURL:         "https://example.test/poc",
		PatchCommitURL: "https://example.test/commit",
	}

	var buf bytes.Buffer
	if err := RenderHuman(&buf, report); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Mitigation", "Upgrade to 2.4.51", "PoC", "Patch"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q\n%s", want, out)
		}
	}
}
