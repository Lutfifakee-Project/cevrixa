package resolver

import (
	"errors"
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func TestResolveExplicitCPE(t *testing.T) {
	r := New()
	input := "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
	got, err := r.Resolve(domain.Target{CPE: input, Product: "ignored", Version: "ignored"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.CPE != input {
		t.Fatalf("CPE = %q, want %q", got.CPE, input)
	}
	if got.Source != "explicit" {
		t.Fatalf("Source = %q, want explicit", got.Source)
	}
}

func TestResolveEmptyProduct(t *testing.T) {
	r := New()
	got, err := r.Resolve(domain.Target{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.CPE != "" {
		t.Fatalf("CPE = %q, want empty", got.CPE)
	}
	if got.Source != "" {
		t.Fatalf("Source = %q, want empty", got.Source)
	}
}

func TestResolveExactMatch(t *testing.T) {
	r := New()
	got, err := r.Resolve(domain.Target{Product: "Apache HTTP Server", Version: "2.4.49"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
	if got.CPE != want {
		t.Fatalf("CPE = %q, want %q", got.CPE, want)
	}
	if got.Source != "catalog" {
		t.Fatalf("Source = %q, want catalog", got.Source)
	}
}

func TestResolveCaseInsensitive(t *testing.T) {
	r := New()
	for _, input := range []string{"apache http server", "APACHE HTTP SERVER", "Apache HTTP Server"} {
		got, err := r.Resolve(domain.Target{Product: input, Version: "2.4.49"})
		if err != nil {
			t.Fatalf("Resolve(%q): %v", input, err)
		}
		if got.CPE == "" {
			t.Fatalf("Resolve(%q) returned empty CPE", input)
		}
	}
}

func TestResolveAlias(t *testing.T) {
	r := New()
	for _, input := range []string{"httpd", "apache2", "apache_httpd", "apache_http_server"} {
		got, err := r.Resolve(domain.Target{Product: input, Version: "2.4.49"})
		if err != nil {
			t.Fatalf("Resolve(%q): %v", input, err)
		}
		if got.CPE == "" {
			t.Fatalf("Resolve(%q) returned empty CPE", input)
		}
	}
}

func TestResolveNoMatch(t *testing.T) {
	r := New()
	got, err := r.Resolve(domain.Target{Product: "Nonexistent Product", Version: "1.0"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.CPE != "" {
		t.Fatalf("CPE = %q, want empty", got.CPE)
	}
	if got.Source != "" {
		t.Fatalf("Source = %q, want empty", got.Source)
	}
}

func TestResolveWithoutVersionUsesWildcard(t *testing.T) {
	r := New()
	got, err := r.Resolve(domain.Target{Product: "OpenSSL"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
	if got.CPE != want {
		t.Fatalf("CPE = %q, want %q", got.CPE, want)
	}
}

func TestResolveAmbiguous(t *testing.T) {
	r := &Resolver{
		catalog: []catalogEntry{
			{Name: "Foo A", Aliases: []string{"foo"}, CPEBase: "cpe:2.3:a:foo:a"},
			{Name: "Foo B", Aliases: []string{"foo"}, CPEBase: "cpe:2.3:a:foo:b"},
		},
	}
	_, err := r.Resolve(domain.Target{Product: "Foo", Version: "1.0"})
	if err == nil {
		t.Fatal("expected ErrAmbiguous")
	}
	var ae *ErrAmbiguous
	if !errors.As(err, &ae) {
		t.Fatalf("error type = %T, want *ErrAmbiguous", err)
	}
	if len(ae.Candidates) != 2 {
		t.Fatalf("Candidates = %v, want 2 entries", ae.Candidates)
	}
	if len(ae.Names) != 2 {
		t.Fatalf("Names = %v, want 2 entries", ae.Names)
	}
}

func TestResolveWhitespaceProduct(t *testing.T) {
	r := New()
	got, err := r.Resolve(domain.Target{Product: "   "})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.CPE != "" {
		t.Fatalf("CPE = %q, want empty", got.CPE)
	}
}

func TestResolveAllCatalogEntries(t *testing.T) {
	r := New()
	for _, e := range defaultCatalog {
		got, err := r.Resolve(domain.Target{Product: e.Name, Version: "1.0.0"})
		if err != nil {
			t.Fatalf("Resolve(%q): %v", e.Name, err)
		}
		if got.CPE == "" {
			t.Fatalf("Resolve(%q) returned empty CPE", e.Name)
		}
		if _, err := domain.ParseCPE(got.CPE); err != nil {
			t.Fatalf("Resolve(%q) produced invalid CPE %q: %v", e.Name, got.CPE, err)
		}
	}
}
