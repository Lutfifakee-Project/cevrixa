package engine

import "testing"

func TestNormalizeEcosystem(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"pypi", "PyPI"},
		{"PyPI", "PyPI"},
		{"npm", "npm"},
		{"NPM", "npm"},
		{"golang", "Go"},
		{"maven", "Maven"},
		{"cargo", "crates.io"},
		{"unknown", ""},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := normalizeEcosystem(tc.in)
			if got != tc.want {
				t.Fatalf("normalizeEcosystem(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
