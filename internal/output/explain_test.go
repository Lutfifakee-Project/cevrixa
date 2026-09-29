package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
)

func sampleExplain() ExplainReport {
	cpe, _ := domain.ParseCPE("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
	return ExplainReport{
		Vulnerability: domain.Vulnerability{
			ID:      "CVE-2021-41773",
			Source:  "nvd",
			Summary: "Path traversal",
			References: []domain.Reference{
				{URL: "https://example.test/advisory", Source: "nvd"},
			},
		},
		Target: domain.Target{
			Product:     "Apache HTTP Server",
			Version:     "2.4.49",
			ResolvedCPE: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
		},
		TargetCPE:  cpe,
		Match:      matcher.Result{Matched: true, Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", Range: ">=2.4.0 <2.4.51", Fixed: "2.4.51", Mode: "range"},
		Applicable: true,
		Fixed:      "2.4.51",
		Confidence: "strong",
	}
}

func TestRenderExplainHumanBasic(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderExplainHuman(&buf, sampleExplain()); err != nil {
		t.Fatalf("RenderExplainHuman: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"CVE-2021-41773", "AFFECTED", "Apache HTTP Server", "2.4.49", ">=2.4.0 <2.4.51", "2.4.51", "STRONG"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q\n%s", want, out)
		}
	}
}

func TestRenderExplainHumanNotAffected(t *testing.T) {
	rep := sampleExplain()
	rep.Applicable = false
	rep.Match.Matched = false

	var buf bytes.Buffer
	if err := RenderExplainHuman(&buf, rep); err != nil {
		t.Fatalf("RenderExplainHuman: %v", err)
	}
	if !strings.Contains(buf.String(), "NOT AFFECTED") {
		t.Fatalf("expected NOT AFFECTED:\n%s", buf.String())
	}
}

func TestRenderExplainJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderExplainJSON(&buf, sampleExplain()); err != nil {
		t.Fatalf("RenderExplainJSON: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if parsed["vulnerability_id"] != "CVE-2021-41773" {
		t.Fatalf("vulnerability_id = %v", parsed["vulnerability_id"])
	}
	if parsed["decision"] != "affected" {
		t.Fatalf("decision = %v", parsed["decision"])
	}
}
