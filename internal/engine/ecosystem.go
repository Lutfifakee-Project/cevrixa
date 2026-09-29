package engine

import "strings"

// normalizeEcosystem maps a PURL type to the OSV ecosystem name.
// Returns empty string if the ecosystem is not supported.
func normalizeEcosystem(purlType string) string {
	switch strings.ToLower(purlType) {
	case "pypi":
		return "PyPI"
	case "npm":
		return "npm"
	case "golang":
		return "Go"
	case "maven":
		return "Maven"
	case "cargo":
		return "crates.io"
	case "gem":
		return "RubyGems"
	case "composer":
		return "Packagist"
	case "nuget":
		return "NuGet"
	default:
		return ""
	}
}
