package dbcve

import "github.com/Lutfifakee-Project/cevrixa/internal/domain"

func mapEnrichment(payload apiResponse) domain.Enrichment {
	out := domain.Enrichment{
		Source:          "dbcve",
		VulnerabilityID: payload.Data.CVEID,
		Status:          payload.Data.Enrichment.Status,
		Summary:         payload.Data.Enrichment.Summary,
		Mitigation:      payload.Data.Enrichment.Mitigation,
		Confidence:      payload.Data.Enrichment.Confidence,
		PoCURL:          payload.Data.Enrichment.PoCURL,
		PatchCommitURL:  payload.Data.Enrichment.PatchCommitURL,
		Weaknesses:      make([]domain.Weakness, 0, len(payload.Data.CWEs)),
		References:      make([]domain.Reference, 0, len(payload.Data.References)),
	}

	if risk := mapRisk(payload.Data); risk != nil {
		out.Risk = risk
	}

	for _, cwe := range payload.Data.CWEs {
		out.Weaknesses = append(out.Weaknesses, domain.Weakness{
			ID:   cwe.ID,
			Name: cwe.Name,
		})
	}

	for _, ref := range payload.Data.References {
		out.References = append(out.References, domain.Reference{
			URL:    ref.URL,
			Source: "dbcve",
			Tags:   append([]string(nil), ref.Tags...),
		})
	}

	if payload.Attribution != nil {
		out.Attribution = &domain.Attribution{
			Source:  payload.Attribution.Source,
			License: payload.Attribution.License,
			Terms:   payload.Attribution.Terms,
			Docs:    payload.Attribution.Docs,
		}
	}

	return out
}

func mapRisk(data apiData) *domain.Risk {
	hasSignal := data.Severity != "" ||
		data.CVSS != 0 ||
		data.CVSSVersion != "" ||
		data.KEV ||
		data.EPSS != 0 ||
		data.EPSSPercentile != 0
	if !hasSignal {
		return nil
	}
	return &domain.Risk{
		Severity:       data.Severity,
		CVSS:           data.CVSS,
		CVSSVersion:    data.CVSSVersion,
		KEV:            data.KEV,
		EPSS:           data.EPSS,
		EPSSPercentile: data.EPSSPercentile,
	}
}
