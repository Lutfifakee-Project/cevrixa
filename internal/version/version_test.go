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
