package sync

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/source/nvd"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func nvdFixture(ids ...string) string {
	var sb strings.Builder
	sb.WriteString(`{"resultsPerPage":`)
	sb.WriteString(fmt.Sprintf("%d", len(ids)))
	sb.WriteString(`,"startIndex":0,"totalResults":`)
	sb.WriteString(fmt.Sprintf("%d", len(ids)))
	sb.WriteString(`,"vulnerabilities":[`)
	for i, id := range ids {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf(`{"cve":{"id":"%s","vulnStatus":"Analyzed"}}`, id))
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func TestSyncNVDSinglePage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nvdFixture("CVE-2024-0001", "CVE-2024-0002")))
	}))
	defer server.Close()

	client := nvd.NewClient(server.Client())
	client.BaseURL = server.URL

	s := openTestStore(t)

	n, err := SyncNVD(context.Background(), NVDOptions{
		Source:       client,
		Store:        s,
		LastModStart: "2024-01-01T00:00:00.000",
		LastModEnd:   "2024-01-02T00:00:00.000",
	})
	if err != nil {
		t.Fatalf("SyncNVD: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 records, got %d", n)
	}

	count, _ := s.CountVulnerabilities()
	if count != 2 {
		t.Fatalf("store count = %d, want 2", count)
	}
}

func TestSyncNVDMetadataWritten(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nvdFixture("CVE-2024-0001")))
	}))
	defer server.Close()

	client := nvd.NewClient(server.Client())
	client.BaseURL = server.URL

	s := openTestStore(t)

	_, err := SyncNVD(context.Background(), NVDOptions{
		Source:       client,
		Store:        s,
		LastModStart: "2024-01-01T00:00:00.000",
		LastModEnd:   "2024-01-02T00:00:00.000",
	})
	if err != nil {
		t.Fatalf("SyncNVD: %v", err)
	}

	meta, err := s.GetSyncMetadata("nvd")
	if err != nil {
		t.Fatalf("GetSyncMetadata: %v", err)
	}
	if meta.RecordsSynced != 1 {
		t.Fatalf("RecordsSynced = %d, want 1", meta.RecordsSynced)
	}
	if meta.LastSyncISO != "2024-01-02T00:00:00.000" {
		t.Fatalf("LastSyncISO = %q", meta.LastSyncISO)
	}
}

func TestSyncNVDMultiPage(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		page++
		switch page {
		case 1:
			// First page: 2 results, total 4.
			_, _ = w.Write([]byte(`{"resultsPerPage":2,"startIndex":0,"totalResults":4,"vulnerabilities":[{"cve":{"id":"CVE-A"}},{"cve":{"id":"CVE-B"}}]}`))
		case 2:
			// Second page: 2 results at startIndex=2.
			_, _ = w.Write([]byte(`{"resultsPerPage":2,"startIndex":2,"totalResults":4,"vulnerabilities":[{"cve":{"id":"CVE-C"}},{"cve":{"id":"CVE-D"}}]}`))
		default:
			t.Fatalf("unexpected page %d", page)
		}
	}))
	defer server.Close()

	client := nvd.NewClient(server.Client())
	client.BaseURL = server.URL

	s := openTestStore(t)

	n, err := SyncNVD(context.Background(), NVDOptions{
		Source:       client,
		Store:        s,
		PageLimit:    2,
		LastModStart: "2024-01-01T00:00:00.000",
		LastModEnd:   "2024-01-02T00:00:00.000",
	})
	if err != nil {
		t.Fatalf("SyncNVD: %v", err)
	}
	if n != 4 {
		t.Fatalf("expected 4 records, got %d", n)
	}
	if page != 2 {
		t.Fatalf("expected 2 pages, got %d", page)
	}
}

func TestSyncNVDMaxPagesGuard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always returns 1 result, but claims total 1000 → infinite loop without guard.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resultsPerPage":1,"startIndex":0,"totalResults":1000,"vulnerabilities":[{"cve":{"id":"CVE-A"}}]}`))
	}))
	defer server.Close()

	client := nvd.NewClient(server.Client())
	client.BaseURL = server.URL

	s := openTestStore(t)

	_, err := SyncNVD(context.Background(), NVDOptions{
		Source:       client,
		Store:        s,
		MaxPages:     3,
		LastModStart: "2024-01-01T00:00:00.000",
		LastModEnd:   "2024-01-02T00:00:00.000",
	})
	if err == nil {
		t.Fatal("expected MaxPages error")
	}
	if !strings.Contains(err.Error(), "MaxPages") {
		t.Fatalf("error = %v", err)
	}
}

func TestSyncNVDRequiresSourceAndStore(t *testing.T) {
	if _, err := SyncNVD(context.Background(), NVDOptions{}); err == nil {
		t.Fatal("expected error for missing options")
	}
}
