package kev

import (
	"strings"
	"testing"
)

func TestLoadEmbedded(t *testing.T) {
	cat, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if len(cat.Entries) < 3 {
		t.Fatalf("expected at least 3 entries, got %d", len(cat.Entries))
	}
}

func TestLookupFound(t *testing.T) {
	cat, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	info, ok := cat.Lookup("CVE-2021-41773")
	if !ok {
		t.Fatal("CVE-2021-41773 not found")
	}
	if info.VendorProject != "Apache" {
		t.Fatalf("VendorProject = %q, want Apache", info.VendorProject)
	}
	if info.DateAdded != "2021-11-03" {
		t.Fatalf("DateAdded = %q", info.DateAdded)
	}
}

func TestLookupNotFound(t *testing.T) {
	cat, _ := LoadEmbedded()
	_, ok := cat.Lookup("CVE-9999-9999")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestNilCatalogLookup(t *testing.T) {
	var cat *Catalog
	_, ok := cat.Lookup("CVE-2021-41773")
	if ok {
		t.Fatal("nil catalog should return not found")
	}
}

func TestLoadFromReaderInvalid(t *testing.T) {
	_, err := LoadFromReader(strings.NewReader("not json"))
	if err == nil {
		t.Fatal("expected error")
	}
}
