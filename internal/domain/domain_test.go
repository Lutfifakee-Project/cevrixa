package domain

import "testing"

func TestTargetEmpty(t *testing.T) {
	var tgt Target
	if tgt.Product != "" || tgt.Version != "" || tgt.CPE != "" || tgt.PURL != "" || tgt.ResolvedCPE != "" {
		t.Fatalf("zero Target should have all empty fields, got %+v", tgt)
	}
}

func TestTargetCPEOnly(t *testing.T) {
	tgt := Target{CPE: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
	if tgt.CPE == "" {
		t.Fatalf("expected CPE to be set")
	}
}
