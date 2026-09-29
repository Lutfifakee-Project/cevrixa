package correlate

import (
	"strconv"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func collectVulnEvidence(vulns []domain.Vulnerability) []domain.Evidence {
	var out []domain.Evidence
	for _, v := range vulns {
		out = append(out, vulnEvidence(v)...)
	}
	return out
}

func vulnEvidence(v domain.Vulnerability) []domain.Evidence {
	var ev []domain.Evidence

	if v.Status != "" {
		ev = append(ev, domain.Evidence{
			Kind:   domain.EvidenceKindStatus,
			Source: v.Source,
			Value:  v.Status,
		})
	}

	for _, a := range v.Aliases {
		if a == "" {
			continue
		}
		ev = append(ev, domain.Evidence{
			Kind:   domain.EvidenceKindAlias,
			Source: v.Source,
			Value:  a,
		})
	}

	for i := range v.References {
		ref := v.References[i]
		ev = append(ev, domain.Evidence{
			Kind:      domain.EvidenceKindReference,
			Source:    v.Source,
			Reference: &ref,
		})
	}

	for i := range v.Applicability {
		node := v.Applicability[i]
		ev = append(ev, domain.Evidence{
			Kind:          domain.EvidenceKindApplicability,
			Source:        v.Source,
			Applicability: &node,
		})
	}

	for _, pkg := range v.PackageApplicability {
		for i := range pkg.Ranges {
			r := pkg.Ranges[i]
			ev = append(ev, domain.Evidence{
				Kind:   domain.EvidenceKindPackageRange,
				Source: v.Source,
				Range:  &r,
			})
		}
	}

	return ev
}

func collectEnrichmentEvidence(enrichments []domain.Enrichment) []domain.Evidence {
	var out []domain.Evidence
	for _, e := range enrichments {
		out = append(out, enrichmentEvidence(e)...)
	}
	return out
}

func enrichmentEvidence(e domain.Enrichment) []domain.Evidence {
	var ev []domain.Evidence

	if e.Mitigation != "" {
		ev = append(ev, domain.Evidence{
			Kind:   domain.EvidenceKindMitigation,
			Source: e.Source,
			Value:  e.Mitigation,
		})
	}
	if e.PoCURL != "" {
		ev = append(ev, domain.Evidence{
			Kind:   domain.EvidenceKindPoC,
			Source: e.Source,
			Value:  e.PoCURL,
		})
	}
	if e.PatchCommitURL != "" {
		ev = append(ev, domain.Evidence{
			Kind:   domain.EvidenceKindPatch,
			Source: e.Source,
			Value:  e.PatchCommitURL,
		})
	}

	for _, w := range e.Weaknesses {
		if w.ID == "" {
			continue
		}
		ev = append(ev, domain.Evidence{
			Kind:   domain.EvidenceKindWeakness,
			Source: e.Source,
			Value:  w.ID,
		})
	}

	for i := range e.References {
		ref := e.References[i]
		ev = append(ev, domain.Evidence{
			Kind:      domain.EvidenceKindReference,
			Source:    e.Source,
			Reference: &ref,
		})
	}

	if e.Risk != nil {
		ev = append(ev, riskEvidence(e.Source, *e.Risk)...)
	}

	return ev
}

func riskEvidence(source string, r domain.Risk) []domain.Evidence {
	var ev []domain.Evidence

	if r.Severity != "" {
		ev = append(ev, domain.Evidence{
			Kind:   domain.EvidenceKindSeverity,
			Source: source,
			Value:  r.Severity,
		})
	}
	if r.CVSS != 0 {
		ev = append(ev, domain.Evidence{
			Kind:   domain.EvidenceKindCVSS,
			Source: source,
			Value:  strconv.FormatFloat(r.CVSS, 'f', -1, 64),
		})
	}
	if r.CVSSVersion != "" {
		ev = append(ev, domain.Evidence{
			Kind:   domain.EvidenceKindCVSSVersion,
			Source: source,
			Value:  r.CVSSVersion,
		})
	}
	if r.KEV {
		ev = append(ev, domain.Evidence{
			Kind:   domain.EvidenceKindKEV,
			Source: source,
			Value:  "true",
		})
	}
	if r.EPSS != 0 {
		ev = append(ev, domain.Evidence{
			Kind:   domain.EvidenceKindEPSS,
			Source: source,
			Value:  strconv.FormatFloat(r.EPSS, 'f', -1, 64),
		})
	}
	if r.EPSSPercentile != 0 {
		ev = append(ev, domain.Evidence{
			Kind:   domain.EvidenceKindEPSSPercentile,
			Source: source,
			Value:  strconv.FormatFloat(r.EPSSPercentile, 'f', -1, 64),
		})
	}

	return ev
}
