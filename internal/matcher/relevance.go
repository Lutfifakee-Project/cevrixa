package matcher

import "github.com/Lutfifakee-Project/cevrixa/internal/domain"

// cpeIdentityMatches reports whether a criteria CPE identifies the same part,
// vendor and product as the target, treating wildcards as matching. Version is
// deliberately excluded: version evaluation belongs to the applicability stage
// and must not influence whether a candidate is relevant to the target.
func cpeIdentityMatches(criteriaCPE, target domain.CPE) bool {
	if !cpeFieldMatches(criteriaCPE.Part, target.Part) {
		return false
	}
	if !cpeFieldMatches(criteriaCPE.Vendor, target.Vendor) {
		return false
	}
	return cpeFieldMatches(criteriaCPE.Product, target.Product)
}

// criteriaIdentityMatches parses a criteria string and reports whether it
// identifies the target product. Criteria that cannot be parsed are never
// treated as a relevant identity.
func criteriaIdentityMatches(criteria string, target domain.CPE) bool {
	criteriaCPE, err := domain.ParseCPE(criteria)
	if err != nil {
		return false
	}
	return cpeIdentityMatches(criteriaCPE, target)
}

// nodeNamesVulnerableTarget reports whether an applicability subtree contains at
// least one vulnerable component whose part, vendor and product identify the
// target. An AND group that does not name the target as a vulnerable component
// cannot make the target affected, so it is a decided non-match. A group that
// names the target only through a non-vulnerable (environmental) requirement is
// likewise not a vulnerable candidate for the target.
//
// A negated node, and a vulnerable match whose criteria cannot be parsed, are
// treated as relevant so that genuine uncertainty is never hidden by the
// relevance guard.
func nodeNamesVulnerableTarget(node domain.ApplicabilityNode, target domain.CPE) bool {
	if node.Negate {
		return true
	}
	for _, m := range node.Matches {
		if !m.Vulnerable {
			continue
		}
		criteriaCPE, err := domain.ParseCPE(m.Criteria)
		if err != nil {
			return true
		}
		if cpeIdentityMatches(criteriaCPE, target) {
			return true
		}
	}
	for _, child := range node.Children {
		if nodeNamesVulnerableTarget(child, target) {
			return true
		}
	}
	return false
}
