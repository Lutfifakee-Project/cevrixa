package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/source"
)

func TestClientMapsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("content-type = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
          "vulns": [{
            "id": "GHSA-test-1234-abcd",
            "summary": "test vulnerability",
            "details": "details",
            "aliases": ["CVE-2099-0001"],
            "published": "2026-01-01T00:00:00Z",
            "modified": "2026-01-02T00:00:00Z",
            "references": [{"type":"ADVISORY","url":"https://example.test/advisory"}],
            "affected": [{
              "package": {"name":"django","ecosystem":"PyPI","purl":"pkg:pypi/django"},
              "ranges": [{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.2.10"}]}],
              "versions": ["4.2.0"],
              "ecosystem_specific": {"severity":"HIGH"}
            }]
          }],
          "next_page_token":"next123"
        }`))
	}))
	defer server.Close()

	client := NewClient(server.Client())
	client.BaseURL = server.URL

	result, err := client.List(context.Background(), source.Query{
		PURL:    "pkg:pypi/django",
		Version: "4.2.0",
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if result.NextPageToken != "next123" {
		t.Fatalf("next token = %q", result.NextPageToken)
	}
	if len(result.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want 1", len(result.Vulnerabilities))
	}
	v := result.Vulnerabilities[0]
	if v.ID != "GHSA-test-1234-abcd" || v.Source != "osv" {
		t.Fatalf("unexpected vulnerability: %+v", v)
	}
	if len(v.Aliases) != 1 || v.Aliases[0] != "CVE-2099-0001" {
		t.Fatalf("aliases = %#v", v.Aliases)
	}
	if len(v.PackageApplicability) != 1 {
		t.Fatalf("package applicability = %d", len(v.PackageApplicability))
	}
	pkg := v.PackageApplicability[0]
	if pkg.Name != "django" || pkg.Ecosystem != "PyPI" || pkg.PURL != "pkg:pypi/django" {
		t.Fatalf("package = %+v", pkg)
	}
	if len(pkg.Ranges) != 1 || len(pkg.Ranges[0].Events) != 2 {
		t.Fatalf("ranges = %+v", pkg.Ranges)
	}
	if got := pkg.Ranges[0].Events[1].Fixed; got != "4.2.10" {
		t.Fatalf("fixed = %q", got)
	}
}

func TestClientValidatesQuery(t *testing.T) {
	client := NewClient(nil)
	client.BaseURL = "http://127.0.0.1:1"

	cases := []struct {
		name  string
		query source.Query
		want  string
	}{
		{"missing target", source.Query{}, "package/PURL or commit is required"},
		{"partial package", source.Query{PackageName: "django"}, "package name and ecosystem must be provided together"},
		{"versioned purl plus version", source.Query{PURL: "pkg:pypi/django@4.2.0", Version: "4.2.0"}, "version must not be supplied with a versioned PURL"},
		{"commit plus version", source.Query{Commit: "abc", Version: "1.0.0"}, "version and commit are mutually exclusive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.List(context.Background(), tc.query)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestClientReturnsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()

	client := NewClient(server.Client())
	client.BaseURL = server.URL

	_, err := client.List(context.Background(), source.Query{PURL: "pkg:pypi/django", Version: "4.2.0"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("error = %v, want HTTP 400", err)
	}
}
