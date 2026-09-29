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
            "operator": "OR",
            "negate": false,
            "cpeMatch": [{
              "vulnerable": true,
              "criteria": "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
              "matchCriteriaId": "11111111-1111-1111-1111-111111111111",
              "versionStartIncluding": "2.0.0",
              "versionEndExcluding": "3.0.0"
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
	if len(vuln.Applicability) != 1 || len(vuln.Applicability[0].Matches) != 1 {
		t.Fatalf("unexpected applicability: %+v", vuln.Applicability)
	}
	match := vuln.Applicability[0].Matches[0]
	if match.VersionStart != "2.0.0" || match.VersionStartMode != "including" || match.VersionEnd != "3.0.0" || match.VersionEndMode != "excluding" {
		t.Fatalf("unexpected range: %+v", match)
	}
}
