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
