package engine

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func djangoVuln() domain.Vulnerability {
	return domain.Vulnerability{
		ID:     "GHSA-django-1",
		Source: "osv",
		PackageApplicability: []domain.PackageApplicability{
			{
				Name:      "django",
				Ecosystem: "PyPI",
				PURL:      "pkg:pypi/django",
				Ranges: []domain.PackageRange{
					{
						Type: "ECOSYSTEM",
						Events: []domain.PackageRangeEvent{
							{Introduced: "0"},
							{Fixed: "4.2.10"},
						},
					},
				},
			},
		},
	}
}

func TestMatchPackageInRange(t *testing.T) {
	purl, _ := domain.ParsePURL("pkg:pypi/django@4.2.0")
	got, ok := matchPackage(purl, djangoVuln())
	if !ok {
		t.Fatal("expected match attempt")
	}
	if !got.Matched {
		t.Fatalf("expected matched, got %+v", got)
	}
	if got.Fixed != "4.2.10" {
		t.Fatalf("Fixed = %q", got.Fixed)
	}
}

func TestMatchPackageFixed(t *testing.T) {
	purl, _ := domain.ParsePURL("pkg:pypi/django@4.2.10")
	got, ok := matchPackage(purl, djangoVuln())
	if !ok {
		t.Fatal("expected match attempt")
	}
	if got.Matched {
		t.Fatalf("expected not matched at fixed version, got %+v", got)
	}
}

func TestMatchPackageWrongEcosystem(t *testing.T) {
	purl, _ := domain.ParsePURL("pkg:npm/django@4.2.0")
	_, ok := matchPackage(purl, djangoVuln())
	if ok {
		t.Fatal("expected no match for wrong ecosystem")
	}
}

func TestMatchPackageWrongName(t *testing.T) {
	purl, _ := domain.ParsePURL("pkg:pypi/flask@2.0.0")
	_, ok := matchPackage(purl, djangoVuln())
	if ok {
		t.Fatal("expected no match for wrong name")
	}
}

func TestMatchPackageUnsupportedEcosystem(t *testing.T) {
	purl, _ := domain.ParsePURL("pkg:unknown/foo@1.0")
	_, ok := matchPackage(purl, djangoVuln())
	if ok {
		t.Fatal("expected no match for unsupported ecosystem")
	}
}

func TestMatchPackageNoApplicability(t *testing.T) {
	purl, _ := domain.ParsePURL("pkg:pypi/django@4.2.0")
	_, ok := matchPackage(purl, domain.Vulnerability{})
	if ok {
		t.Fatal("expected no match for empty vuln")
	}
}
