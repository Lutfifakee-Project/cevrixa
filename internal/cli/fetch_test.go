package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withMockNVD(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	old := nvdBaseURL
	nvdBaseURL = srv.URL
	t.Cleanup(func() {
		nvdBaseURL = old
		srv.Close()
	})
}

func nvdSingleCVE(id string) string {
	return `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"` + id + `","sourceIdentifier":"test","published":"2024-01-01T00:00:00.000Z","lastModified":"2024-01-02T00:00:00.000Z","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"test"}],"configurations":[{"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*","matchCriteriaId":"x"}]}],"references":[]}}]}`
}

const emptyNVD = `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`

func TestFetchVulnByIDSuccess(t *testing.T) {
	withMockNVD(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cveId"); got != "CVE-2099-7777" {
			t.Errorf("cveId = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nvdSingleCVE("CVE-2099-7777")))
	})

	v, err := fetchVulnByID(context.Background(), "CVE-2099-7777")
	if err != nil {
		t.Fatalf("fetchVulnByID: %v", err)
	}
	if v.ID != "CVE-2099-7777" {
		t.Fatalf("ID = %q", v.ID)
	}
	if v.Source != "nvd" {
		t.Fatalf("Source = %q", v.Source)
	}
}

func TestFetchVulnByIDNotFound(t *testing.T) {
	withMockNVD(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(emptyNVD))
	})
	_, err := fetchVulnByID(context.Background(), "CVE-2099-0000")
	if !errors.Is(err, errCVENotInNVD) {
		t.Fatalf("err = %v, want errCVENotInNVD", err)
	}
}

func TestFetchVulnByIDMismatch(t *testing.T) {
	withMockNVD(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(nvdSingleCVE("CVE-0000-0000")))
	})
	_, err := fetchVulnByID(context.Background(), "CVE-2099-7777")
	if err == nil {
		t.Fatal("expected error for mismatched CVE ID")
	}
	if errors.Is(err, errCVENotInNVD) {
		t.Fatal("a mismatched ID must not be reported as not-found")
	}
}

func TestFetchVulnByIDHTTPError(t *testing.T) {
	withMockNVD(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	_, err := fetchVulnByID(context.Background(), "CVE-2099-7777")
	if err == nil {
		t.Fatal("expected error for HTTP 503")
	}
	if errors.Is(err, errCVENotInNVD) {
		t.Fatal("an HTTP error must not be reported as not-found")
	}
}

func TestFetchVulnByIDBadJSON(t *testing.T) {
	withMockNVD(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json at all"))
	})
	_, err := fetchVulnByID(context.Background(), "CVE-2099-7777")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if errors.Is(err, errCVENotInNVD) {
		t.Fatal("a parse failure must not be reported as not-found")
	}
}

func TestFetchVulnByIDTimeout(t *testing.T) {
	withMockNVD(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(emptyNVD))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := fetchVulnByID(ctx, "CVE-2099-7777")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if errors.Is(err, errCVENotInNVD) {
		t.Fatal("a timeout must not be reported as not-found")
	}
}

func TestExplainLocalHitDoesNotFetch(t *testing.T) {
	withMockNVD(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("unexpected NVD fetch for a locally known CVE")
		w.WriteHeader(http.StatusInternalServerError)
	})
	flags := explainFlags{
		VulnID:  "CVE-2021-41773",
		Product: "Apache HTTP Server",
		Version: "2.4.49",
		DB:      filepath.Join(t.TempDir(), "none.db"),
		DBSet:   true,
	}
	report, err := buildExplainReport(flags)
	if err != nil {
		t.Fatalf("buildExplainReport: %v", err)
	}
	if report.Vulnerability.ID != "CVE-2021-41773" {
		t.Fatalf("ID = %q", report.Vulnerability.ID)
	}
}

func TestBuildExplainReportFetchesOnMiss(t *testing.T) {
	withMockNVD(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(nvdSingleCVE("CVE-2099-7777")))
	})
	flags := explainFlags{
		VulnID:  "CVE-2099-7777",
		Product: "nginx",
		Version: "1.24.0",
		DB:      filepath.Join(t.TempDir(), "none.db"),
		DBSet:   true,
	}
	report, err := buildExplainReport(flags)
	if err != nil {
		t.Fatalf("buildExplainReport: %v", err)
	}
	if report.Vulnerability.ID != "CVE-2099-7777" {
		t.Fatalf("ID = %q", report.Vulnerability.ID)
	}
	if report.IdentityUnresolved {
		t.Fatal("nginx should resolve to a CPE")
	}
	if report.NotEvaluated {
		t.Fatalf("fetched record should be evaluated: %s", report.NotEvaluatedReason)
	}
	if !report.Applicable {
		t.Fatal("nginx 1.24.0 against a wildcard nginx CPE should be affected")
	}
}

func TestBuildExplainReportFetchNotInNVD(t *testing.T) {
	withMockNVD(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(emptyNVD))
	})
	flags := explainFlags{
		VulnID:  "CVE-2099-0000",
		Product: "nginx",
		Version: "1.24.0",
		DB:      filepath.Join(t.TempDir(), "none.db"),
		DBSet:   true,
	}
	_, err := buildExplainReport(flags)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "NVD has no record") {
		t.Fatalf("err = %v", err)
	}
}

func TestBuildExplainReportFetchFailureDistinct(t *testing.T) {
	withMockNVD(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	flags := explainFlags{
		VulnID:  "CVE-2099-0002",
		Product: "nginx",
		Version: "1.24.0",
		DB:      filepath.Join(t.TempDir(), "none.db"),
		DBSet:   true,
	}
	_, err := buildExplainReport(flags)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "NVD has no record") {
		t.Fatal("a network failure must not be reported as not-found")
	}
	if !strings.Contains(err.Error(), "not in the local dataset") {
		t.Fatalf("err = %v", err)
	}
}
