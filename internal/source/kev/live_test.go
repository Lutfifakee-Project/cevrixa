package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchLiveFromMock(t *testing.T) {
	fixture := `{"title":"Test","vulnerabilities":[{"cveID":"CVE-2024-0001","vendorProject":"V","product":"P"},{"cveID":"CVE-2024-0002","vendorProject":"V","product":"P"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixture))
	}))
	defer server.Close()

	cat, err := FetchLiveFrom(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("FetchLiveFrom: %v", err)
	}
	if len(cat.Entries) != 2 {
		t.Fatalf("expected 2, got %d", len(cat.Entries))
	}
}

func TestFetchLiveFromHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()
	if _, err := FetchLiveFrom(context.Background(), server.URL); err == nil {
		t.Fatal("expected error")
	}
}
