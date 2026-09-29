package resolver

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func TestDefaultCatalogSanity(t *testing.T) {
	if len(defaultCatalog) == 0 {
		t.Fatal("defaultCatalog is empty")
	}
	for _, e := range defaultCatalog {
		if e.Name == "" {
			t.Fatalf("catalog entry with empty name")
		}
		if len(e.Aliases) == 0 {
			t.Fatalf("entry %q has no aliases", e.Name)
		}
		if e.CPEBase == "" {
			t.Fatalf("entry %q has no CPE base", e.Name)
		}
	}
}

func TestDefaultCatalogCPEsAreValid(t *testing.T) {
	for _, e := range defaultCatalog {
		cpe := BuildCPE(e.CPEBase, "1.0.0")
		if _, err := domain.ParseCPE(cpe); err != nil {
			t.Errorf("entry %q produces invalid CPE %q: %v", e.Name, cpe, err)
		}
	}
}

func TestDefaultCatalogNoDuplicateAliases(t *testing.T) {
	seen := map[string]string{}
	for _, e := range defaultCatalog {
		for _, a := range e.Aliases {
			if prev, ok := seen[a]; ok {
				t.Errorf("alias %q appears in both %q and %q", a, prev, e.Name)
			}
			seen[a] = e.Name
		}
	}
}
