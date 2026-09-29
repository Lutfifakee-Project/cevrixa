package osv

import "github.com/Lutfifakee-Project/cevrixa/internal/domain"

func mapVulnerability(v apiVulnerability) domain.Vulnerability {
	result := domain.Vulnerability{
		ID:        v.ID,
		Source:    "osv",
		Aliases:   append([]string(nil), v.Aliases...),
		Summary:   v.Summary,
		Details:   v.Details,
		Published: v.Published,
		Modified:  v.Modified,
	}

	result.References = make([]domain.Reference, 0, len(v.References))
	for _, ref := range v.References {
		result.References = append(result.References, domain.Reference{
			URL:    ref.URL,
			Source: "osv",
			Tags:   nonEmptyTag(ref.Type),
		})
	}

	result.PackageApplicability = make([]domain.PackageApplicability, 0, len(v.Affected))
	for _, affected := range v.Affected {
		pkg := domain.PackageApplicability{
			Name:              affected.Package.Name,
			Ecosystem:         affected.Package.Ecosystem,
			PURL:              affected.Package.PURL,
			Versions:          append([]string(nil), affected.Versions...),
			EcosystemSpecific: cloneMap(affected.EcosystemSpecific),
		}
		pkg.Ranges = make([]domain.PackageRange, 0, len(affected.Ranges))
		for _, r := range affected.Ranges {
			pr := domain.PackageRange{
				Type:   r.Type,
				Repo:   r.Repo,
				Events: make([]domain.PackageRangeEvent, 0, len(r.Events)),
			}
			for _, event := range r.Events {
				pr.Events = append(pr.Events, domain.PackageRangeEvent{
					Introduced:   event.Introduced,
					Fixed:        event.Fixed,
					LastAffected: event.LastAffected,
				})
			}
			pkg.Ranges = append(pkg.Ranges, pr)
		}
		result.PackageApplicability = append(result.PackageApplicability, pkg)
	}

	return result
}

func nonEmptyTag(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
