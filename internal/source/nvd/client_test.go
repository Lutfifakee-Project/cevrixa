package nvd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/source"
)

func TestClientMapsResponse(t *testing.T) {
	fixture := `{
      "resultsPerPage": 1,
      "startIndex": 0,
      "totalResults": 1,
      "vulnerabilities": [{
        "cve": {
          "id": "CVE-2099-1234",
          "sourceIdentifier": "security@example.org",
          "published": "2026-01-02T03:04:05.000Z",
          "lastModified": "2026-01-03T03:04:05.000Z",
          "vulnStatus": "Analyzed",
          "descriptions": [{"lang":"en","value":"Example vulnerability"}],
          "configurations": [{
            "operator": "AND",
            "nodes": [{
              "operator": "OR",
              "negate": false,
              "cpeMatch": [{
                "vulnerable": true,
                "criteria": "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
                "matchCriteriaId": "11111111-1111-1111-1111-111111111111",
                "versionStartIncluding": "2.0.0",
                "versionEndExcluding": "3.0.0"
              }]
            }]
          }],
          "references": [{"url":"https://example.org/advisory","tags":["vendor-advisory"]}]
        }
      }]
    }`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cveId"); got != "CVE-2099-1234" {
			t.Fatalf("cveId=%q", got)
		}
		if got := r.Header.Get("apiKey"); got != "test-key" {
			t.Fatalf("apiKey header=%q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixture))
	}))
	defer server.Close()

	client := NewClient(server.Client())
	client.BaseURL = server.URL
	client.APIKey = "test-key"

	result, err := client.List(context.Background(), source.Query{ID: "CVE-2099-1234"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if result.TotalResults != 1 || len(result.Vulnerabilities) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}

	vuln := result.Vulnerabilities[0]
	if vuln.ID != "CVE-2099-1234" || vuln.Source != "nvd" {
		t.Fatalf("unexpected vulnerability: %+v", vuln)
	}
	// The API nests cpeMatch inside "nodes"; the wrapper node itself carries no
	// matches. Asserting on the nested level is what catches a mapper that only
	// reads "children".
	if len(vuln.Applicability) != 1 {
		t.Fatalf("unexpected applicability: %+v", vuln.Applicability)
	}
	if len(vuln.Applicability[0].Children) != 1 {
		t.Fatalf("nested configuration nodes were not mapped: %+v", vuln.Applicability)
	}
	if len(vuln.Applicability[0].Children[0].Matches) != 1 {
		t.Fatalf("cpeMatch inside nodes was not mapped: %+v", vuln.Applicability)
	}
	match := vuln.Applicability[0].Children[0].Matches[0]
	if match.VersionStart != "2.0.0" || match.VersionStartMode != "including" || match.VersionEnd != "3.0.0" || match.VersionEndMode != "excluding" {
		t.Fatalf("unexpected range: %+v", match)
	}
	if match.Criteria != "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*" {
		t.Fatalf("criteria was not mapped: %+v", match)
	}
}
func TestClientWithDateRange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("lastModStartDate"); got != "2024-01-01T00:00:00.000" {
			t.Fatalf("lastModStartDate = %q", got)
		}
		if got := r.URL.Query().Get("lastModEndDate"); got != "2024-01-02T00:00:00.000" {
			t.Fatalf("lastModEndDate = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer server.Close()

	client := NewClient(server.Client())
	client.BaseURL = server.URL

	_, err := client.List(context.Background(), source.Query{
		LastModStart: "2024-01-01T00:00:00.000",
		LastModEnd:   "2024-01-02T00:00:00.000",
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
}

func TestClientRejectsDateRangeWithCVEID(t *testing.T) {
	client := NewClient(nil)
	_, err := client.List(context.Background(), source.Query{
		ID:           "CVE-2024-1234",
		LastModStart: "2024-01-01T00:00:00.000",
		LastModEnd:   "2024-01-02T00:00:00.000",
	})
	if err == nil {
		t.Fatal("expected error for cveId + date range")
	}
}

func TestClientRejectsPartialDateRange(t *testing.T) {
	client := NewClient(nil)
	_, err := client.List(context.Background(), source.Query{
		LastModStart: "2024-01-01T00:00:00.000",
	})
	if err == nil {
		t.Fatal("expected error for partial date range")
	}
}
