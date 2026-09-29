package dbcve

import "github.com/Lutfifakee-Project/cevrixa/internal/domain"

func mapEnrichment(payload apiResponse) domain.Enrichment {
	out := domain.Enrichment{
		Source:         "dbcve",
		Status:         payload.Data.Enrichment.Status,
		Summary:        payload.Data.Enrichment.Summary,
		Mitigation:     payload.Data.Enrichment.Mitigation,
		Confidence:     payload.Data.Enrichment.Confidence,
		PoCURL:         payload.Data.Enrichment.PoCURL,
		PatchCommitURL: payload.Data.Enrichment.PatchCommitURL,
		Weaknesses:     make([]domain.Weakness, 0, len(payload.Data.CWEs)),
		References:     make([]domain.Reference, 0, len(payload.Data.References)),
	}

	// Map risk metadata when at least one risk signal is present.
	// We intentionally do not fabricate a Risk struct for responses that
	// carry no risk information at all.
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

// mapRisk returns a non-nil Risk only when the upstream response actually
// carried risk metadata. Returning nil otherwise keeps "no data" distinct
// from "zero values", which matters for later evidence and confidence logic.
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
