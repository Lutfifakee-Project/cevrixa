package dbcve

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func TestMapEnrichmentPreservesRiskMetadata(t *testing.T) {
	payload := apiResponse{
		Data: apiData{
			CVEID:          "CVE-2021-41773",
			Severity:       "CRITICAL",
			CVSS:           9.8,
			CVSSVersion:    "3.1",
			KEV:            true,
			EPSS:           0.99992,
			EPSSPercentile: 0.99986,
			Enrichment: apiEnrichment{
				Status:     "complete",
				Summary:    "test summary",
				Mitigation: "upgrade",
				Confidence: "high",
			},
			CWEs: []apiCWE{
				{
					ID:   "CWE-22",
					Name: "Path Traversal",
				},
			},
		},
	}

	got := mapEnrichment(payload)

	if got.Source != "dbcve" {
		t.Fatalf("Source = %q, want %q", got.Source, "dbcve")
	}

	if got.Risk == nil {
		t.Fatal("Risk is nil")
	}

	wantRisk := &domain.Risk{
		Severity:       "CRITICAL",
		CVSS:           9.8,
		CVSSVersion:    "3.1",
		KEV:            true,
		EPSS:           0.99992,
		EPSSPercentile: 0.99986,
	}

	if got.Risk.Severity != wantRisk.Severity {
		t.Fatalf("Severity = %q, want %q", got.Risk.Severity, wantRisk.Severity)
	}

	if got.Risk.CVSS != wantRisk.CVSS {
		t.Fatalf("CVSS = %v, want %v", got.Risk.CVSS, wantRisk.CVSS)
	}

	if got.Risk.CVSSVersion != wantRisk.CVSSVersion {
		t.Fatalf("CVSSVersion = %q, want %q", got.Risk.CVSSVersion, wantRisk.CVSSVersion)
	}

	if got.Risk.KEV != wantRisk.KEV {
		t.Fatalf("KEV = %v, want %v", got.Risk.KEV, wantRisk.KEV)
	}

	if got.Risk.EPSS != wantRisk.EPSS {
		t.Fatalf("EPSS = %v, want %v", got.Risk.EPSS, wantRisk.EPSS)
	}

	if got.Risk.EPSSPercentile != wantRisk.EPSSPercentile {
		t.Fatalf(
			"EPSSPercentile = %v, want %v",
			got.Risk.EPSSPercentile,
			wantRisk.EPSSPercentile,
		)
	}
}

// TestMapEnrichmentNoRiskWhenNoRiskData guards the anti-fabrication rule:
// when the upstream response carries no risk metadata, Risk must stay nil.
func TestMapEnrichmentNoRiskWhenNoRiskData(t *testing.T) {
	payload := apiResponse{
		Data: apiData{
			CVEID:      "CVE-2099-0001",
			Enrichment: apiEnrichment{Status: "complete"},
		},
	}

	got := mapEnrichment(payload)

	if got.Risk != nil {
		t.Fatalf("Risk should be nil when upstream has no risk data, got: %+v", got.Risk)
	}
}
