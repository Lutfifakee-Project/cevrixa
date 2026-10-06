package engine

import (
	"testing"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

// TestMatchPackageMultiEntry verifies that a vulnerability listing the same
// package several times (each with its own ranges) is affected if ANY entry
// matches. This mirrors GHSA-5hgc-2vfp-mqvc, which lists django 5.1.x, 5.0.x,
// and 4.2.x in one advisory.
func TestMatchPackageMultiEntry(t *testing.T) {
	vuln := domain.Vulnerability{
		ID:     "GHSA-test-multi",
		Source: "osv",
		PackageApplicability: []domain.PackageApplicability{
			{
				Name:      "django",
				Ecosystem: "PyPI",
				Ranges: []domain.PackageRange{{Type: "ECOSYSTEM", Events: []domain.PackageRangeEvent{
					{Introduced: "5.1"}, {Fixed: "5.1.1"},
				}}},
			},
			{
				Name:      "django",
				Ecosystem: "PyPI",
				Ranges: []domain.PackageRange{{Type: "ECOSYSTEM", Events: []domain.PackageRangeEvent{
					{Introduced: "5.0"}, {Fixed: "5.0.9"},
				}}},
			},
			{
				Name:      "django",
				Ecosystem: "PyPI",
				Ranges: []domain.PackageRange{{Type: "ECOSYSTEM", Events: []domain.PackageRangeEvent{
					{Introduced: "4.2"}, {Fixed: "4.2.16"},
				}}},
			},
		},
	}

	purl, err := domain.ParsePURL("pkg:pypi/django@4.2.0")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}

	res, ok := matchPackage(purl, vuln)
	if !ok {
		t.Fatal("expected the package to match by name")
	}
	if !res.Matched {
		t.Fatalf("4.2.0 is in [4.2, 4.2.16) and must be affected, got %+v", res)
	}
}

// TestMatchPackageSkipsGITRange verifies that a GIT range does not make an
// otherwise evaluable advisory inconclusive.
func TestMatchPackageSkipsGITRange(t *testing.T) {
	vuln := domain.Vulnerability{
		ID:     "GHSA-test-git",
		Source: "osv",
		PackageApplicability: []domain.PackageApplicability{
			{
				Name:      "django",
				Ecosystem: "PyPI",
				Ranges: []domain.PackageRange{
					{Type: "GIT", Events: []domain.PackageRangeEvent{{Introduced: "0"}, {Fixed: "abc123def456"}}},
					{Type: "ECOSYSTEM", Events: []domain.PackageRangeEvent{{Introduced: "4.2"}, {Fixed: "4.2.16"}}},
				},
			},
		},
	}

	purl, err := domain.ParsePURL("pkg:pypi/django@4.2.0")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}

	res, ok := matchPackage(purl, vuln)
	if !ok {
		t.Fatal("expected the package to match by name")
	}
	if !res.Matched {
		t.Fatalf("GIT range must be skipped, not poison the match; got %+v", res)
	}
}
