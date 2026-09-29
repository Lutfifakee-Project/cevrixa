package nvd

import "github.com/Lutfifakee-Project/cevrixa/internal/domain"

func mapVulnerability(cve apiCVE) domain.Vulnerability {
	result := domain.Vulnerability{
		ID:               cve.ID,
		Source:           "nvd",
		SourceIdentifier: cve.SourceIdentifier,
		Status:           cve.VulnStatus,
		Published:        cve.Published,
		Modified:         cve.LastModified,
	}

	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			result.Summary = d.Value
			break
		}
	}
	if result.Summary == "" && len(cve.Descriptions) > 0 {
		result.Summary = cve.Descriptions[0].Value
	}

	result.References = make([]domain.Reference, 0, len(cve.References))
	for _, ref := range cve.References {
		result.References = append(result.References, domain.Reference{
			URL:    ref.URL,
			Source: "nvd",
			Tags:   append([]string(nil), ref.Tags...),
		})
	}

	result.Applicability = make([]domain.ApplicabilityNode, 0, len(cve.Configurations))
	for _, node := range cve.Configurations {
		result.Applicability = append(result.Applicability, mapNode(node))
	}

	return result
}

func mapNode(node apiConfigNode) domain.ApplicabilityNode {
	out := domain.ApplicabilityNode{
		Operator: node.Operator,
		Negate:   node.Negate,
		Matches:  make([]domain.CPEMatch, 0, len(node.CPEMatch)),
		Children: make([]domain.ApplicabilityNode, 0, len(node.Children)),
	}

	for _, child := range node.Children {
		out.Children = append(out.Children, mapNode(child))
	}

	for _, m := range node.CPEMatch {
		cm := domain.CPEMatch{
			Vulnerable:      m.Vulnerable,
			Criteria:        m.Criteria,
			MatchCriteriaID: m.MatchCriteriaID,
		}
		if m.VersionStartIncluding != "" {
			cm.VersionStart = m.VersionStartIncluding
			cm.VersionStartMode = "including"
		} else if m.VersionStartExcluding != "" {
			cm.VersionStart = m.VersionStartExcluding
			cm.VersionStartMode = "excluding"
		}
		if m.VersionEndIncluding != "" {
			cm.VersionEnd = m.VersionEndIncluding
			cm.VersionEndMode = "including"
		} else if m.VersionEndExcluding != "" {
			cm.VersionEnd = m.VersionEndExcluding
			cm.VersionEndMode = "excluding"
		}
		out.Matches = append(out.Matches, cm)
	}

	return out
}
