package sync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/source/osv"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

func TestSyncOSVPersists(t *testing.T) {
	fixture := `{"vulns":[{"id":"GHSA-test-1","summary":"t","aliases":["CVE-2024-9999"],"affected":[{"package":{"name":"django","ecosystem":"PyPI","purl":"pkg:pypi/django"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.2.10"}]}]}]}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixture))
	}))
	defer server.Close()

	client := osv.NewClient(server.Client())
	client.BaseURL = server.URL

	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	n, err := SyncOSV(context.Background(), OSVOptions{
		Source: client,
		Store:  s,
		PURL:   "pkg:pypi/django",
	})
	if err != nil {
		t.Fatalf("SyncOSV: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}
	if _, err := s.GetVulnerability("GHSA-test-1", "osv"); err != nil {
		t.Fatalf("Get: %v", err)
	}
}

func TestSyncOSVRequiresArgs(t *testing.T) {
	if _, err := SyncOSV(context.Background(), OSVOptions{}); err == nil {
		t.Fatal("expected error")
	}
}
