package version

import "testing"

func TestParseAndCompare(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{"numeric ordering", "2.10", "2.9", 1},
		{"patch ordering", "2.4.51", "2.4.49", 1},
		{"equal trailing zero", "2.4", "2.4.0", 0},
		{"v prefix", "v1.2.3", "1.2.3", 0},
		{"prerelease before release", "1.0.0-rc.1", "1.0.0", -1},
		{"prerelease numeric ordering", "1.0.0-alpha.2", "1.0.0-alpha.10", -1},
		{"numeric prerelease before text", "1.0.0-1", "1.0.0-alpha", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := Parse(tt.a)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.a, err)
			}
			b, err := Parse(tt.b)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.b, err)
			}
			got := a.Compare(b)
			if got != tt.want {
				t.Fatalf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestParseRejectsInvalidVersions(t *testing.T) {
	invalid := []string{
		"",
		"v",
		"1..2",
		"1.2.beta",
		"1.2-",
		"1.2.3-alpha..1",
		"1.02.3",
		"1.2.3-01",
	}

	for _, input := range invalid {
		t.Run(input, func(t *testing.T) {
			if _, err := Parse(input); err == nil {
				t.Fatalf("Parse(%q) unexpectedly succeeded", input)
			}
		})
	}
}

func TestRangeBoundaries(t *testing.T) {
	r, err := ParseRange(">=2.4.0,<2.4.51")
	if err != nil {
		t.Fatalf("ParseRange: %v", err)
	}

	cases := []struct {
		version string
		want    bool
	}{
		{"2.3.99", false},
		{"2.4.0", true},
		{"2.4.49", true},
		{"2.4.50", true},
		{"2.4.51", false},
		{"2.5.0", false},
	}

	for _, tt := range cases {
		v := MustParse(tt.version)
		if got := r.Contains(v); got != tt.want {
			t.Errorf("range Contains(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

func TestExclusiveRange(t *testing.T) {
	r, err := ParseRange(">2.4.49,<=2.4.51")
	if err != nil {
		t.Fatalf("ParseRange: %v", err)
	}

	if r.Contains(MustParse("2.4.49")) {
		t.Fatal("lower exclusive boundary should not match")
	}
	if !r.Contains(MustParse("2.4.50")) {
		t.Fatal("middle version should match")
	}
	if !r.Contains(MustParse("2.4.51")) {
		t.Fatal("upper inclusive boundary should match")
	}
}

func TestExactRange(t *testing.T) {
	r, err := ParseRange("2.4.49")
	if err != nil {
		t.Fatalf("ParseRange: %v", err)
	}

	if !r.Contains(MustParse("2.4.49")) {
		t.Fatal("exact version should match")
	}
	if r.Contains(MustParse("2.4.50")) {
		t.Fatal("different version should not match")
	}
}

func TestInvalidRange(t *testing.T) {
	invalid := []string{
		"",
		",",
		">=2.4.0,<2.4.0",
		">2.4.0,<2.4.0",
		"2.4.51,2.4.49",
	}

	for _, expr := range invalid {
		t.Run(expr, func(t *testing.T) {
			if _, err := ParseRange(expr); err == nil {
				t.Fatalf("ParseRange(%q) unexpectedly succeeded", expr)
			}
		})
	}
}

func TestExactConstraintIntersectsBounds(t *testing.T) {
	r, err := ParseRange(">=2.4.0,2.4.49,<2.5.0")
	if err != nil {
		t.Fatalf("ParseRange: %v", err)
	}
	if !r.Contains(MustParse("2.4.49")) {
		t.Fatal("exact version inside range should match")
	}
}

func TestConflictingExactConstraints(t *testing.T) {
	for _, expr := range []string{
		">=2.5.0,2.4.49",
		"<=2.4.48,2.4.49",
		"2.4.49,2.4.50",
	} {
		t.Run(expr, func(t *testing.T) {
			if _, err := ParseRange(expr); err == nil {
				t.Fatalf("ParseRange(%q) unexpectedly succeeded", expr)
			}
		})
	}
}
func TestParseLenientStrict(t *testing.T) {
	v, err := ParseLenient("2.4.49")
	if err != nil {
		t.Fatalf("ParseLenient: %v", err)
	}
	if v.Raw() != "2.4.49" {
		t.Fatalf("Raw = %q, want 2.4.49", v.Raw())
	}
}

func TestParseLenientStripsEpoch(t *testing.T) {
	v, err := ParseLenient("1:2.4.7")
	if err != nil {
		t.Fatalf("ParseLenient: %v", err)
	}
	want := MustParse("2.4.7")
	if !v.Equal(want) {
		t.Fatalf("ParseLenient(1:2.4.7) should equal 2.4.7")
	}
}

func TestParseLenientStripsTilde(t *testing.T) {
	v, err := ParseLenient("~1.2.3")
	if err != nil {
		t.Fatalf("ParseLenient: %v", err)
	}
	want := MustParse("1.2.3")
	if !v.Equal(want) {
		t.Fatalf("ParseLenient(~1.2.3) should equal 1.2.3")
	}
}

func TestParseLenientStripsTrailing(t *testing.T) {
	v, err := ParseLenient("1.2.3 extra")
	if err != nil {
		t.Fatalf("ParseLenient: %v", err)
	}
	want := MustParse("1.2.3")
	if !v.Equal(want) {
		t.Fatalf("ParseLenient(1.2.3 extra) should equal 1.2.3")
	}
}

func TestParseLenientRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "v", "abc", "..."} {
		if _, err := ParseLenient(s); err == nil {
			t.Fatalf("ParseLenient(%q) unexpectedly succeeded", s)
		}
	}
}

func TestParseLetterSuffixOrdering(t *testing.T) {
	plain := MustParse("1.1.1")
	a := MustParse("1.1.1a")
	c := MustParse("1.1.1c")
	next := MustParse("1.1.2")

	if plain.Compare(c) >= 0 {
		t.Fatal("1.1.1 must sort before 1.1.1c")
	}
	if c.Compare(plain) <= 0 {
		t.Fatal("1.1.1c must sort after 1.1.1")
	}
	if a.Compare(c) >= 0 {
		t.Fatal("1.1.1a must sort before 1.1.1c")
	}
	if c.Compare(next) >= 0 {
		t.Fatal("1.1.1c must sort before 1.1.2")
	}
}

func TestParseLenientDebianLetterSuffix(t *testing.T) {
	// openssl 1.1.1c shipped in Ubuntu 19.10; rejecting this string silently
	// dropped the target from package matching.
	v, err := ParseLenient("1.1.1c-1ubuntu1")
	if err != nil {
		t.Fatalf("ParseLenient: %v", err)
	}
	if v.Raw() != "1.1.1c-1ubuntu1" {
		t.Fatalf("Raw = %q", v.Raw())
	}
	if v.Compare(MustParse("1.1.2")) >= 0 {
		t.Fatal("1.1.1c-1ubuntu1 must sort before 1.1.2")
	}
}

func TestParseLenientDebianEpochWithLetterSuffix(t *testing.T) {
	v, err := ParseLenient("1:1.1.1c-1ubuntu1")
	if err != nil {
		t.Fatalf("ParseLenient: %v", err)
	}
	if v.Compare(MustParse("1.1.2")) >= 0 {
		t.Fatal("epoch must be stripped and 1.1.1c must sort before 1.1.2")
	}
}

func TestParseRejectsInvalidComponents(t *testing.T) {
	for _, s := range []string{"1a2", "1.2.x", "x1.2", "1.2.-1"} {
		if _, err := Parse(s); err == nil {
			t.Fatalf("Parse(%q) unexpectedly succeeded", s)
		}
	}
}

func TestParseDebianRevisionSortsAfterVersion(t *testing.T) {
	base := MustParse("2.4.7")
	rev1, err := ParseDebian("2.4.7-1")
	if err != nil {
		t.Fatalf("ParseDebian: %v", err)
	}
	rev2, err := ParseDebian("2.4.7-2")
	if err != nil {
		t.Fatalf("ParseDebian: %v", err)
	}

	if base.Compare(rev1) >= 0 {
		t.Fatal("a Debian revision must sort after the plain version: 2.4.7 < 2.4.7-1")
	}
	if rev1.Compare(rev2) >= 0 {
		t.Fatal("2.4.7-1 must sort before 2.4.7-2")
	}
}

func TestParseRPMReleaseSortsAfterVersion(t *testing.T) {
	base := MustParse("1.2.3")
	rel, err := ParseRPM("1.2.3-4.el8")
	if err != nil {
		t.Fatalf("ParseRPM: %v", err)
	}
	if base.Compare(rel) >= 0 {
		t.Fatal("an RPM release must sort after the plain version: 1.2.3 < 1.2.3-4.el8")
	}
}

func TestParsePinnedVersionSuffixStillCompares(t *testing.T) {
	// A criteria version such as 1.1.1c must be comparable, not rejected.
	v, err := ParseLenient("1.1.1c")
	if err != nil {
		t.Fatalf("ParseLenient: %v", err)
	}
	if v.Compare(MustParse("1.1.1")) <= 0 {
		t.Fatal("1.1.1c must be greater than 1.1.1")
	}
}

func TestParseLenientToleratesLeadingZeroPrerelease(t *testing.T) {
	// sonicwall firmware 12.4.3-02854 was rejected outright, which made the
	// whole version range uncomparable.
	v, err := ParseLenient("12.4.3-02854")
	if err != nil {
		t.Fatalf("ParseLenient: %v", err)
	}
	if v.Raw() != "12.4.3-02854" {
		t.Fatalf("Raw = %q, want the original input", v.Raw())
	}
	if v.Compare(MustParse("12.4.4")) >= 0 {
		t.Fatal("12.4.3-02854 must sort before 12.4.4")
	}
	// The hyphenated part is still read as a pre-release, so it sorts before the
	// plain release. Treating it as a build number needs per-ecosystem version
	// semantics, which is a known gap.
	if v.Compare(MustParse("12.4.3")) >= 0 {
		t.Fatal("this parser treats -02854 as a pre-release, not a build number")
	}
}

func TestParseDebianBasic(t *testing.T) {
	v, err := ParseDebian("2.4.7-1")
	if err != nil {
		t.Fatalf("ParseDebian: %v", err)
	}
	if v.Raw() != "2.4.7-1" {
		t.Fatalf("Raw = %q", v.Raw())
	}
	// Upstream should match strict parse of just "2.4.7".
	upstream, _ := Parse("2.4.7")
	if v.components[0] != upstream.components[0] {
		t.Fatalf("upstream mismatch")
	}
}

func TestParseDebianEpoch(t *testing.T) {
	v, err := ParseDebian("1:2.4.7-1ubuntu4.20")
	if err != nil {
		t.Fatalf("ParseDebian: %v", err)
	}
	if v.Raw() != "1:2.4.7-1ubuntu4.20" {
		t.Fatalf("Raw = %q", v.Raw())
	}
}

func TestParseDebianRevisionOrdering(t *testing.T) {
	v1, err := ParseDebian("2.4.7-1")
	if err != nil {
		t.Fatalf("ParseDebian v1: %v", err)
	}
	v2, err := ParseDebian("2.4.7-2")
	if err != nil {
		t.Fatalf("ParseDebian v2: %v", err)
	}
	if v1.Compare(v2) >= 0 {
		t.Fatalf("2.4.7-1 should be < 2.4.7-2")
	}
}

func TestParseRPMBasic(t *testing.T) {
	v, err := ParseRPM("1.2.3-4.el8")
	if err != nil {
		t.Fatalf("ParseRPM: %v", err)
	}
	if v.Raw() != "1.2.3-4.el8" {
		t.Fatalf("Raw = %q", v.Raw())
	}
	// The upstream "1.2.3" should compare equal ignoring the release.
	upstream, err := Parse("1.2.3")
	if err != nil {
		t.Fatalf("Parse upstream: %v", err)
	}
	if v.components[0] != upstream.components[0] ||
		v.components[1] != upstream.components[1] ||
		v.components[2] != upstream.components[2] {
		t.Fatalf("upstream numeric components mismatch")
	}
}

func TestParseDebianRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "v", "...", ":"} {
		if _, err := ParseDebian(s); err == nil {
			t.Fatalf("ParseDebian(%q) unexpectedly succeeded", s)
		}
	}
}
