package matcher

import (
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/version"
)

func matchNode(node domain.ApplicabilityNode, target domain.CPE, v version.Version) (Result, bool) {
	for _, child := range node.Children {
		if r, ok := matchNode(child, target, v); ok {
			return r, true
		}
	}

	for _, m := range node.Matches {
		if !m.Vulnerable {
			continue
		}
		if r, ok := matchSingle(m, target, v); ok {
			return r, true
		}
	}

	return Result{}, false
}

func matchSingle(m domain.CPEMatch, target domain.CPE, v version.Version) (Result, bool) {
	criteriaCPE, err := domain.ParseCPE(m.Criteria)
	if err != nil {
		return Result{}, false
	}

	if !cpeFieldMatches(criteriaCPE.Part, target.Part) {
		return Result{}, false
	}
	if !cpeFieldMatches(criteriaCPE.Vendor, target.Vendor) {
		return Result{}, false
	}
	if !cpeFieldMatches(criteriaCPE.Product, target.Product) {
		return Result{}, false
	}

	rng, err := buildRange(m)
	if err != nil {
		return Result{}, false
	}

	matched := rng.Contains(v)

	return Result{
		Matched:  matched,
		Criteria: m.Criteria,
		Range:    formatRange(m),
		Fixed:    fixedVersion(m),
		Mode:     classifyMode(m),
	}, true
}

func cpeFieldMatches(criteria, target string) bool {
	if criteria == "" || criteria == "*" || criteria == "-" {
		return true
	}
	return strings.EqualFold(criteria, target)
}
