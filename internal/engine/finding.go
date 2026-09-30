package engine

import (
	"github.com/Lutfifakee-Project/cevrixa/internal/correlate"
	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
)

func buildFinding(targetCPE domain.CPE, v domain.Vulnerability, mr matcher.Result, enrichments []domain.Enrichment) domain.Finding {
	f := domain.Finding{
		VulnerabilityID: v.ID,
		Status:          statusForResult(mr),
		Confidence:      computeConfidence(mr),
		Risk:            v.Risk,
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

	return attachCorrelation(f, v, enrichments)
}

// statusForResult maps a matcher outcome onto the finding status. An undecided
// outcome must never be reported as affected.
func statusForResult(mr matcher.Result) domain.FindingStatus {
	switch {
	case mr.Undecided:
		return domain.FindingStatusInconclusive
	case mr.Matched:
		return domain.FindingStatusAffected
	default:
		return domain.FindingStatusNotAffected
	}
}

// attachCorrelation adds correlated evidence and cross-source conflicts to a
// finding. Enrichments are included so that disagreements between sources are
// visible instead of being silently dropped.
func attachCorrelation(f domain.Finding, v domain.Vulnerability, enrichments []domain.Enrichment) domain.Finding {
	correlated := correlate.CorrelateAll([]domain.Vulnerability{v}, enrichments)
	if len(correlated) > 0 {
		f.Evidence = correlated[0].Evidence
		f.Conflicts = correlated[0].Conflicts
	}
	return f
}

func buildPackageFinding(purl domain.PURL, v domain.Vulnerability, pr PackageMatchResult, enrichments []domain.Enrichment) domain.Finding {
	f := domain.Finding{
		VulnerabilityID: v.ID,
		Status:          domain.FindingStatusAffected,
		Confidence:      ConfidenceFromMode(pr.Mode),
		Risk:            v.Risk,
		Applicability: domain.Applicability{
			Matched:   pr.Matched,
			Range:     pr.Range,
			MatchedBy: pr.Criteria,
			Source:    v.Source,
		},
		Why: domain.Why{
			IdentityMatch: "package name+ecosystem matched target PURL",
			VersionMatch:  purl.Name + "@" + purl.Version + " in " + pr.Range,
			Steps: []string{
				"parsed target PURL",
				"matched ecosystem=" + v.Source + " name=" + purl.Name,
				"built version range " + pr.Range,
				"checked target version " + purl.Version,
			},
		},
	}

	if pr.Fixed != "" {
		f.FixedVersions = []string{pr.Fixed}
		f.Why.FixedReason = "fixed in " + pr.Fixed
		f.Why.Steps = append(f.Why.Steps, "fixed version is "+pr.Fixed)
	}

	return attachCorrelation(f, v, enrichments)
}
