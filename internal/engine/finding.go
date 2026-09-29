package engine

import (
	"github.com/Lutfifakee-Project/cevrixa/internal/correlate"
	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
)

func buildPackageFinding(purl domain.PURL, v domain.Vulnerability, pr PackageMatchResult) domain.Finding {
	f := domain.Finding{
		VulnerabilityID: v.ID,
		Status:          domain.FindingStatusAffected,
		Confidence:      confidenceFromMode(pr.Mode),
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

	correlated := correlate.CorrelateAll([]domain.Vulnerability{v}, nil)
	if len(correlated) > 0 {
		f.Evidence = correlated[0].Evidence
		f.Conflicts = correlated[0].Conflicts
	}

	return f
}

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
