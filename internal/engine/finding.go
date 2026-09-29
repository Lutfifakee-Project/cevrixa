package engine

import (
	"github.com/Lutfifakee-Project/cevrixa/internal/correlate"
	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
)

func buildFinding(targetCPE domain.CPE, v domain.Vulnerability, mr matcher.Result) domain.Finding {
	f := domain.Finding{
		VulnerabilityID: v.ID,
		Status:          domain.FindingStatusAffected,
		Confidence:      computeConfidence(mr),
		Applicability: domain.Applicability{
			Matched:   mr.Matched,
			Range:     mr.Range,
			MatchedBy: mr.Criteria,
			Source:    v.Source,
		},
		Why: matcher.BuildWhy(targetCPE, mr),
	}

	if mr.Fixed != "" {
		f.FixedVersions = []string{mr.Fixed}
	}

	correlated := correlate.CorrelateAll([]domain.Vulnerability{v}, nil)
	if len(correlated) > 0 {
		f.Evidence = correlated[0].Evidence
		f.Conflicts = correlated[0].Conflicts
	}

	return f
}
