package version

import (
	"testing"
)

// A Debian revision sorts after the plain version: 2.4.7 < 2.4.7-1. The generic
// parser reads the hyphen as a pre-release, which would invert this. The scheme
// dispatch must select the Debian parser so the order is correct.
func TestParseForSchemeDebianRevisionOrdering(t *testing.T) {
	plain, err := ParseForScheme("2.4.7", SchemeDebian)
	if err != nil {
		t.Fatalf("plain: %v", err)
	}
	rev, err := ParseForScheme("2.4.7-1", SchemeDebian)
	if err != nil {
		t.Fatalf("revision: %v", err)
	}
	if plain.Compare(rev) >= 0 {
		t.Fatalf("expected 2.4.7 < 2.4.7-1, got comparison %d", plain.Compare(rev))
	}
}

// The generic parser intentionally reads 2.4.7-1 as a pre-release, which is why
// the ecosystem must not fall back to it for a Debian target.
func TestParseForSchemeGenericVsDebianDiffer(t *testing.T) {
	generic, err := ParseForScheme("2.4.7-1", SchemeGeneric)
	if err != nil {
		t.Fatalf("generic: %v", err)
	}
	debian, err := ParseForScheme("2.4.7-1", SchemeDebian)
	if err != nil {
		t.Fatalf("debian: %v", err)
	}
	plainGeneric := MustParse("2.4.7")
	plainDebian := MustParse("2.4.7")
	if generic.Compare(plainGeneric) >= 0 {
		t.Fatal("precondition: generic 2.4.7-1 should sort below 2.4.7")
	}
	if debian.Compare(plainDebian) <= 0 {
		t.Fatal("debian 2.4.7-1 must sort above 2.4.7")
	}
}

func TestParseForSchemeRPMRelease(t *testing.T) {
	base, err := ParseForScheme("1.2.3", SchemeRPM)
	if err != nil {
		t.Fatalf("base: %v", err)
	}
	release, err := ParseForScheme("1.2.3-4.el8", SchemeRPM)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if base.Compare(release) >= 0 {
		t.Fatalf("expected 1.2.3 < 1.2.3-4.el8, got comparison %d", base.Compare(release))
	}
}
