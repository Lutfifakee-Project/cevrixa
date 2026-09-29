package nvd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/source"
)

func TestClientReturnsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream failure", http.StatusBadGateway)
	}))
	defer server.Close()

	client := NewClient(server.Client())
	client.BaseURL = server.URL

	_, err := client.List(context.Background(), source.Query{ID: "CVE-2099-1234"})
	if err == nil {
		t.Fatal("expected HTTP error")
	}
}
