package version

import "testing"

func TestParsePEP440PreRelease(t *testing.T) {
	// 3.2a1 etc. must parse and sort before their plain release.
	cases := []struct {
		in    string
		preOf string
	}{
		{"3.2a1", "3.2"},
		{"4.1a1", "4.1"},
		{"1.10rc1", "1.10"},
		{"1.7b4", "1.7"},
		{"1.8c1", "1.8"},
	}
	for _, tc := range cases {
		v, err := Parse(tc.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.in, err)
		}
		rel, err := Parse(tc.preOf)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.preOf, err)
		}
		if v.Compare(rel) >= 0 {
			t.Fatalf("%q must sort before %q", tc.in, tc.preOf)
		}
	}
}

func TestParsePEP440Loose(t *testing.T) {
	// These forms must be parseable rather than rejected.
	for _, in := range []string{"2.0a1", "5.0a1", "6.1a1", "1.9rc2", "1.8b2"} {
		if _, err := Parse(in); err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
	}
}

func TestParseDebianSuffixStillPostRelease(t *testing.T) {
	// A trailing letter with no following digit stays a post-release suffix:
	// 1.1.1 < 1.1.1c.
	a, _ := Parse("1.1.1")
	b, err := Parse("1.1.1c")
	if err != nil {
		t.Fatalf("Parse(1.1.1c): %v", err)
	}
	if a.Compare(b) >= 0 {
		t.Fatal("1.1.1 must sort before 1.1.1c")
	}
}
