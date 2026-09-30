package nvd

import (
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func mapVulnerability(cve apiCVE) domain.Vulnerability {
	result := domain.Vulnerability{
		ID:               cve.ID,
		Source:           "nvd",
		SourceIdentifier: cve.SourceIdentifier,
		Status:           cve.VulnStatus,
		Published:        cve.Published.Time,
		Modified:         cve.LastModified.Time,
		Risk:             mapRisk(cve.Metrics),
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

	result.References = dedupeReferences(cve.References)

	result.Applicability = make([]domain.ApplicabilityNode, 0, len(cve.Configurations))
	for _, node := range cve.Configurations {
		result.Applicability = append(result.Applicability, mapNode(node))
	}

	return result
}

// dedupeReferences collapses repeated URLs. NVD lists the same advisory once per
// contributing source, which duplicated evidence and inflated evidence counts.
func dedupeReferences(refs []apiReference) []domain.Reference {
	index := make(map[string]int)
	out := make([]domain.Reference, 0, len(refs))
	for _, ref := range refs {
		if ref.URL == "" {
			continue
		}
		if i, ok := index[ref.URL]; ok {
			out[i].Tags = mergeTags(out[i].Tags, ref.Tags)
			continue
		}
		index[ref.URL] = len(out)
		out = append(out, domain.Reference{
			URL:    ref.URL,
			Source: "nvd",
			Tags:   append([]string(nil), ref.Tags...),
		})
	}
	return out
}

func mergeTags(existing, extra []string) []string {
	for _, tag := range extra {
		if tag == "" {
			continue
		}
		found := false
		for _, have := range existing {
			if strings.EqualFold(have, tag) {
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, tag)
		}
	}
	return existing
}

func mapRisk(metrics apiMetrics) *domain.Risk {
	var chosen *apiCVSSMetric
	switch {
	case len(metrics.CVSSMetricV31) > 0:
		chosen = &metrics.CVSSMetricV31[0]
	case len(metrics.CVSSMetricV30) > 0:
		chosen = &metrics.CVSSMetricV30[0]
	case len(metrics.CVSSMetricV2) > 0:
		chosen = &metrics.CVSSMetricV2[0]
	default:
		return nil
	}

	severity := chosen.CVSSData.BaseSeverity
	if severity == "" {
		severity = chosen.BaseSeverity
	}

	if severity == "" && chosen.CVSSData.BaseScore == 0 && chosen.CVSSData.Version == "" {
		return nil
	}

	return &domain.Risk{
		Severity:    severity,
		CVSS:        chosen.CVSSData.BaseScore,
		CVSSVersion: chosen.CVSSData.Version,
	}
}

func mapNode(node apiConfigNode) domain.ApplicabilityNode {
	out := domain.ApplicabilityNode{
		Operator: node.Operator,
		Negate:   node.Negate,
		Matches:  make([]domain.CPEMatch, 0, len(node.CPEMatch)),
		Children: make([]domain.ApplicabilityNode, 0, len(node.Children)),
	}

	for _, child := range node.childNodes() {
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
			cm.VersionStartMode = domain.BoundModeIncluding
		} else if m.VersionStartExcluding != "" {
			cm.VersionStart = m.VersionStartExcluding
			cm.VersionStartMode = domain.BoundModeExcluding
		}
		if m.VersionEndIncluding != "" {
			cm.VersionEnd = m.VersionEndIncluding
			cm.VersionEndMode = domain.BoundModeIncluding
		} else if m.VersionEndExcluding != "" {
			cm.VersionEnd = m.VersionEndExcluding
			cm.VersionEndMode = domain.BoundModeExcluding
		}
		out.Matches = append(out.Matches, cm)
	}

	return out
}
