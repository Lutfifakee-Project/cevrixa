package dbcve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientMapsEnrichment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/cve/CVE-2026-48908/" {
			t.Fatalf("path = %s, want /api/v1/cve/CVE-2026-48908/", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": {
				"cve_id": "CVE-2026-48908",
				"severity": "CRITICAL",
				"cvss": 9.8,
				"cvss_version": "3.1",
				"kev": true,
				"published": "2026-06-20",
				"vendor": "ollyo",
				"product": "SP Page Builder",
				"description": "Example description",
				"url": "https://dbcve.org/cve/CVE-2026-48908",
				"enrichment": {
					"status": "complete",
					"summary": "Unauthenticated file upload leading to PHP execution",
					"mitigation": "Update to a patched release",
					"confidence": "high",
					"poc_url": "https://example.test/poc",
					"patch_commit_url": "https://example.test/commit"
				},
				"cwes": [{"id":"CWE-434","name":"Unrestricted Upload of File with Dangerous Type"}],
				"references": [{"url":"https://example.test/advisory","tags":["Vendor Advisory"]}]
			},
			"attribution": {
				"source":"dbcve.org",
				"license":"CC-BY-4.0",
				"terms":"Attribution required",
				"docs":"https://dbcve.org/api"
			}
		}`))
	}))
	defer server.Close()

	client := NewClient(server.Client())
	client.BaseURL = server.URL + "/api/v1"

	got, err := client.Enrich(context.Background(), "CVE-2026-48908")
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if got.Source != "dbcve" {
		t.Fatalf("Source = %q, want dbcve", got.Source)
	}
	if got.Status != "complete" || got.Confidence != "high" {
		t.Fatalf("unexpected enrichment state: %+v", got)
	}
	if got.Summary == "" || got.Mitigation == "" || got.PoCURL == "" || got.PatchCommitURL == "" {
		t.Fatalf("missing enrichment fields: %+v", got)
	}
	if len(got.Weaknesses) != 1 || got.Weaknesses[0].ID != "CWE-434" {
		t.Fatalf("unexpected weaknesses: %+v", got.Weaknesses)
	}
	if len(got.References) != 1 || got.References[0].URL == "" {
		t.Fatalf("unexpected references: %+v", got.References)
	}
	if got.Attribution == nil || got.Attribution.License != "CC-BY-4.0" {
		t.Fatalf("missing attribution: %+v", got.Attribution)
	}
}

func TestClientReturnsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"CVE not found"}`))
	}))
	defer server.Close()

	client := NewClient(server.Client())
	client.BaseURL = strings.TrimRight(server.URL, "/")

	_, err := client.Enrich(context.Background(), "CVE-DOES-NOT-EXIST")
	if err == nil || !strings.Contains(err.Error(), "CVE not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientRejectsEmptyID(t *testing.T) {
	client := NewClient(nil)
	_, err := client.Enrich(context.Background(), "   ")
	if err == nil {
		t.Fatal("expected error for empty vulnerability ID")
	}
}
