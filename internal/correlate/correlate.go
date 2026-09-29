package correlate

import "github.com/Lutfifakee-Project/cevrixa/internal/domain"

func CorrelateAll(
	vulns []domain.Vulnerability,
	enrichments []domain.Enrichment,
) []domain.CorrelatedVulnerability {
	groups := groupByIdentity(vulns)

	byID := make(map[string][]domain.Enrichment)
	for _, e := range enrichments {
		if e.VulnerabilityID == "" {
			continue
		}
		byID[e.VulnerabilityID] = append(byID[e.VulnerabilityID], e)
	}

	results := make([]domain.CorrelatedVulnerability, 0, len(groups))
	for _, g := range groups {
		ev := collectVulnEvidence(g.vulns)
		for _, id := range g.identifiers {
			ev = append(ev, collectEnrichmentEvidence(byID[id])...)
		}

		identifiers := append([]string(nil), g.identifiers...)
		sortStrings(identifiers)

		results = append(results, domain.CorrelatedVulnerability{
			Identifiers: identifiers,
			Evidence:    ev,
			Conflicts:   detectConflicts(ev),
		})
	}
	return results
}
