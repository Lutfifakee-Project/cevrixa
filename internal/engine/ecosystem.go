package engine

import "strings"

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

func matchName(ecosystem, purlNamespace, purlName, osvName string) bool {
	switch ecosystem {
	case "PyPI":
		return strings.EqualFold(purlName, osvName)
	case "Go":
		full := purlName
		if purlNamespace != "" {
			full = purlNamespace + "/" + purlName
		}
		return full == osvName
	case "Maven":
		if purlNamespace != "" {
			return purlNamespace+":"+purlName == osvName
		}
		return purlName == osvName
	default:
		return purlName == osvName
	}
}
