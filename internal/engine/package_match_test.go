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

func expressLastAffectedVuln() domain.Vulnerability {
	return domain.Vulnerability{
		ID:     "GHSA-express-1",
		Source: "osv",
		PackageApplicability: []domain.PackageApplicability{
			{
				Name:      "express",
				Ecosystem: "npm",
				PURL:      "pkg:npm/express",
				Ranges: []domain.PackageRange{
					{
						Type: "ECOSYSTEM",
						Events: []domain.PackageRangeEvent{
							{Introduced: "4.0.0"},
							{LastAffected: "4.19.1"},
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
	if got.Mode != "range" {
		t.Fatalf("Mode = %q, want range (introduced=0 + fixed)", got.Mode)
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

func TestMatchPackagePyPICaseInsensitive(t *testing.T) {
	purl, err := domain.ParsePURL("pkg:pypi/Django@4.2.0")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	got, ok := matchPackage(purl, djangoVuln())
	if !ok || !got.Matched {
		t.Fatalf("PyPI should match case-insensitively, got ok=%v res=%+v", ok, got)
	}
}

func TestMatchPackageLastAffectedInclusive(t *testing.T) {
	purl, _ := domain.ParsePURL("pkg:npm/express@4.19.1")
	got, ok := matchPackage(purl, expressLastAffectedVuln())
	if !ok || !got.Matched {
		t.Fatalf("4.19.1 should match (last_affected inclusive), got ok=%v res=%+v", ok, got)
	}
	if got.Fixed != "" {
		t.Fatalf("Fixed should be empty for last_affected, got %q", got.Fixed)
	}
}

func TestMatchPackageLastAffectedAboveBoundary(t *testing.T) {
	purl, _ := domain.ParsePURL("pkg:npm/express@4.19.2")
	got, ok := matchPackage(purl, expressLastAffectedVuln())
	if !ok {
		t.Fatal("expected match attempt")
	}
	if got.Matched {
		t.Fatalf("4.19.2 should not match, got %+v", got)
	}
}

func TestMatchPackageLastAffectedBelowIntroduced(t *testing.T) {
	purl, _ := domain.ParsePURL("pkg:npm/express@3.0.0")
	got, ok := matchPackage(purl, expressLastAffectedVuln())
	if !ok {
		t.Fatal("expected match attempt")
	}
	if got.Matched {
		t.Fatalf("3.0.0 should not match (introduced=4.0.0), got %+v", got)
	}
}

func TestMatchPackageGo(t *testing.T) {
	purl, _ := domain.ParsePURL("pkg:golang/github.com/gin-gonic/gin@v1.9.0")
	vuln := domain.Vulnerability{
		ID:     "GHSA-go-1",
		Source: "osv",
		PackageApplicability: []domain.PackageApplicability{
			{
				Name:      "github.com/gin-gonic/gin",
				Ecosystem: "Go",
				PURL:      "pkg:golang/github.com/gin-gonic/gin",
				Ranges: []domain.PackageRange{
					{
						Type: "ECOSYSTEM",
						Events: []domain.PackageRangeEvent{
							{Introduced: "0"},
							{Fixed: "v1.10.0"},
						},
					},
				},
			},
		},
	}
	got, ok := matchPackage(purl, vuln)
	if !ok || !got.Matched {
		t.Fatalf("Go match failed, ok=%v res=%+v", ok, got)
	}
}

func TestMatchPackageMaven(t *testing.T) {
	purl, _ := domain.ParsePURL("pkg:maven/org.apache.commons/commons-lang3@3.12.0")
	vuln := domain.Vulnerability{
		ID:     "GHSA-maven-1",
		Source: "osv",
		PackageApplicability: []domain.PackageApplicability{
			{
				Name:      "org.apache.commons:commons-lang3",
				Ecosystem: "Maven",
				PURL:      "pkg:maven/org.apache.commons/commons-lang3",
				Ranges: []domain.PackageRange{
					{
						Type: "ECOSYSTEM",
						Events: []domain.PackageRangeEvent{
							{Introduced: "0"},
							{Fixed: "3.13.0"},
						},
					},
				},
			},
		},
	}
	got, ok := matchPackage(purl, vuln)
	if !ok || !got.Matched {
		t.Fatalf("Maven match failed, ok=%v res=%+v", ok, got)
	}
}

func TestMatchPackageVersionsListExact(t *testing.T) {
	purl, _ := domain.ParsePURL("pkg:pypi/django@4.2.0")
	vuln := domain.Vulnerability{
		ID:     "GHSA-exact",
		Source: "osv",
		PackageApplicability: []domain.PackageApplicability{
			{
				Name:      "django",
				Ecosystem: "PyPI",
				PURL:      "pkg:pypi/django",
				Versions:  []string{"4.2.0", "4.2.1"},
			},
		},
	}
	got, ok := matchPackage(purl, vuln)
	if !ok || !got.Matched {
		t.Fatalf("exact version list match failed: ok=%v res=%+v", ok, got)
	}
	if got.Mode != "exact" {
		t.Fatalf("Mode = %q, want exact", got.Mode)
	}
}
func opensslDebianVuln() domain.Vulnerability {
	return domain.Vulnerability{
		ID:     "GHSA-deb-1",
		Source: "osv",
		PackageApplicability: []domain.PackageApplicability{
			{
				Name:      "openssl",
				Ecosystem: "Debian",
				PURL:      "pkg:deb/debian/openssl",
				Ranges: []domain.PackageRange{
					{
						Type: "ECOSYSTEM",
						Events: []domain.PackageRangeEvent{
							{Introduced: "0"},
							{Fixed: "1.1.2"},
						},
					},
				},
			},
		},
	}
}

func TestMatchPackageDebianLetterSuffix(t *testing.T) {
	// Regression: openssl 1.1.1c-1ubuntu1 used to be silently skipped because
	// the version could not be parsed, so an affected package produced zero
	// findings and exit code 0.
	purl, err := domain.ParsePURL("pkg:deb/debian/openssl@1.1.1c-1ubuntu1")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	got, ok := matchPackage(purl, opensslDebianVuln())
	if !ok {
		t.Fatal("expected a match attempt")
	}
	if !got.Matched {
		t.Fatalf("1.1.1c-1ubuntu1 must be affected (< 1.1.2), got %+v", got)
	}
	if got.Fixed != "1.1.2" {
		t.Fatalf("Fixed = %q, want 1.1.2", got.Fixed)
	}
}

func TestMatchPackageUncomparableVersionIsUndecided(t *testing.T) {
	purl, err := domain.ParsePURL("pkg:deb/debian/openssl@not-a-version")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	got, ok := matchPackage(purl, opensslDebianVuln())
	if !ok {
		t.Fatal("an uncomparable version must be reported, not silently skipped")
	}
	if got.Matched {
		t.Fatalf("uncomparable version must not be reported as affected: %+v", got)
	}
	if !got.Undecided {
		t.Fatalf("expected Undecided, got %+v", got)
	}
	if got.Reason == "" {
		t.Fatal("an undecided package result must carry a reason")
	}
}

func TestMatchPackageDebianEpoch(t *testing.T) {
	purl, err := domain.ParsePURL("pkg:deb/debian/openssl@1.1.1")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	vuln := domain.Vulnerability{
		ID:     "GHSA-deb-1",
		Source: "osv",
		PackageApplicability: []domain.PackageApplicability{
			{
				Name:      "openssl",
				Ecosystem: "Debian",
				PURL:      "pkg:deb/debian/openssl",
				Ranges: []domain.PackageRange{
					{
						Type: "ECOSYSTEM",
						Events: []domain.PackageRangeEvent{
							{Introduced: "0"},
							{Fixed: "1.1.2"},
						},
					},
				},
			},
		},
	}
	got, ok := matchPackage(purl, vuln)
	if !ok || !got.Matched {
		t.Fatalf("Debian match failed: ok=%v res=%+v", ok, got)
	}
	if got.Fixed != "1.1.2" {
		t.Fatalf("Fixed = %q", got.Fixed)
	}
}
