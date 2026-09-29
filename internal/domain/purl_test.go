package domain

import "testing"

func TestParsePURLSimple(t *testing.T) {
	p, err := ParsePURL("pkg:npm/lodash@4.17.20")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	if p.Type != "npm" || p.Name != "lodash" || p.Version != "4.17.20" {
		t.Fatalf("unexpected: %+v", p)
	}
	if p.Namespace != "" {
		t.Fatalf("Namespace = %q, want empty", p.Namespace)
	}
}

func TestParsePURLNoVersion(t *testing.T) {
	p, err := ParsePURL("pkg:pypi/django")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	if p.Version != "" {
		t.Fatalf("Version = %q, want empty", p.Version)
	}
}

func TestParsePURLWithNamespace(t *testing.T) {
	p, err := ParsePURL("pkg:golang/github.com/gin-gonic/gin@v1.9.0")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	if p.Namespace != "github.com/gin-gonic" {
		t.Fatalf("Namespace = %q", p.Namespace)
	}
	if p.Name != "gin" {
		t.Fatalf("Name = %q", p.Name)
	}
	if p.Version != "v1.9.0" {
		t.Fatalf("Version = %q", p.Version)
	}
}

func TestParsePURLWithQualifiers(t *testing.T) {
	p, err := ParsePURL("pkg:npm/lodash@4.17.20?arch=x86&os=linux")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	if p.Qualifiers["arch"] != "x86" || p.Qualifiers["os"] != "linux" {
		t.Fatalf("Qualifiers = %v", p.Qualifiers)
	}
}

func TestParsePURLWithSubpath(t *testing.T) {
	p, err := ParsePURL("pkg:golang/github.com/foo/bar@v1#cmd/server")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	if p.Subpath != "cmd/server" {
		t.Fatalf("Subpath = %q", p.Subpath)
	}
}

func TestParsePURLTypeCaseInsensitive(t *testing.T) {
	p, err := ParsePURL("pkg:NPM/lodash")
	if err != nil {
		t.Fatalf("ParsePURL: %v", err)
	}
	if p.Type != "npm" {
		t.Fatalf("Type = %q, want npm", p.Type)
	}
}

func TestParsePURLInvalid(t *testing.T) {
	invalid := []string{
		"",
		"lodash",
		"npm/lodash",
		"pkg:",
		"pkg:npm",
		"pkg:/lodash",
		"pkg:npm/",
	}
	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			if _, err := ParsePURL(s); err == nil {
				t.Fatalf("ParsePURL(%q) unexpectedly succeeded", s)
			}
		})
	}
}

func TestPURLRoundTrip(t *testing.T) {
	cases := []string{
		"pkg:npm/lodash",
		"pkg:npm/lodash@4.17.20",
		"pkg:pypi/django@4.2.0",
		"pkg:golang/github.com/gin-gonic/gin@v1.9.0",
		"pkg:maven/org.apache.commons/commons-lang3@3.12.0",
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			p, err := ParsePURL(s)
			if err != nil {
				t.Fatalf("ParsePURL: %v", err)
			}
			if got := p.String(); got != s {
				t.Fatalf("round-trip mismatch:\n  got:  %q\n  want: %q", got, s)
			}
		})
	}
}
