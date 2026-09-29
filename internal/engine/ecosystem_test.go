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

func TestMatchNamePyPICaseInsensitive(t *testing.T) {
	if !matchName("PyPI", "", "Django", "django") {
		t.Fatal("PyPI should match case-insensitively")
	}
	if !matchName("PyPI", "", "django", "Django") {
		t.Fatal("PyPI should match case-insensitively (reverse)")
	}
}

func TestMatchNameNPMCaseSensitive(t *testing.T) {
	if matchName("npm", "", "Lodash", "lodash") {
		t.Fatal("npm should be case-sensitive")
	}
	if !matchName("npm", "", "lodash", "lodash") {
		t.Fatal("npm exact match should succeed")
	}
}

func TestMatchNameGo(t *testing.T) {
	if !matchName("Go", "github.com/gin-gonic", "gin", "github.com/gin-gonic/gin") {
		t.Fatal("Go namespace+name should join with slash")
	}
	if matchName("Go", "github.com/gin-gonic", "gin", "gin") {
		t.Fatal("Go should require full path, not just name")
	}
}

func TestMatchNameMaven(t *testing.T) {
	if !matchName("Maven", "org.apache.commons", "commons-lang3", "org.apache.commons:commons-lang3") {
		t.Fatal("Maven namespace:name should use colon")
	}
	if matchName("Maven", "org.apache.commons", "commons-lang3", "commons-lang3") {
		t.Fatal("Maven should require group:artifact")
	}
}

func TestNormalizeEcosystemDebianFamily(t *testing.T) {
	cases := map[string]string{
		"deb":    "Debian",
		"debian": "Debian",
		"apk":    "Alpine",
		"alpine": "Alpine",
		"rpm":    "Red Hat",
		"redhat": "Red Hat",
		"fedora": "Red Hat",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			got := normalizeEcosystem(in)
			if got != want {
				t.Fatalf("normalizeEcosystem(%q) = %q, want %q", in, got, want)
			}
		})
	}
}
