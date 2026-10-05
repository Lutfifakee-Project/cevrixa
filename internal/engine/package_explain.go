package engine

import (
	"fmt"

	"github.com/Lutfifakee-Project/cevrixa/internal/correlate"
	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

// EvaluatePURL reports whether a package target is affected by a vulnerability,
// using the same package matcher as detection. The second result is false when
// the vulnerability carries no package applicability that names this package,
// which means the question cannot be answered from the record rather than that
// the answer is no.
func EvaluatePURL(target domain.Target, vuln domain.Vulnerability) (PackageMatchResult, bool, error) {
	purl, err := domain.ParsePURL(target.PURL)
	if err != nil {
		return PackageMatchResult{}, false, fmt.Errorf("engine: parse PURL: %w", err)
	}
	if purl.Version == "" {
		return PackageMatchResult{}, false, fmt.Errorf("engine: PURL must include a version")
	}
	pr, ok := matchPackage(purl, vuln)
	return pr, ok, nil
}

// BuildPackageWhy explains a package applicability result with the same
// verdict-aware wording used for CPE results, so that explain never states a
// reason that contradicts its own decision.
func BuildPackageWhy(purl domain.PURL, pr PackageMatchResult) domain.Why {
	if pr.Undecided {
		return domain.Why{
			IdentityMatch: "package name and ecosystem matched the target PURL",
			VersionMatch:  "applicability could not be decided",
			Steps:         []string{pr.Reason},
			Questions:     []string{"is the installed version comparable with " + purl.Type + " ranges?"},
		}
	}

	why := domain.Why{
		IdentityMatch: "package name and ecosystem matched the target PURL",
		VersionMatch:  purl.Name + "@" + purl.Version + " in " + pr.Range,
		Steps: []string{
			"parsed target PURL",
			"matched package name " + purl.Name,
			"built version range " + pr.Range,
			"checked target version " + purl.Version,
		},
	}
	if pr.Fixed != "" {
		why.FixedReason = "fixed in " + pr.Fixed
		why.Steps = append(why.Steps, "fixed version is "+pr.Fixed)
	}
	return why
}

// ExplainEvidence returns the correlated evidence and cross-source conflicts
// for a vulnerability, using the same correlation that detection uses, so an
// explanation and a finding cannot disagree about the evidence. Enrichments are
// included when a store is available; a nil store yields an empty enrichment
// set, not an error.
func ExplainEvidence(vuln domain.Vulnerability, opts Options) ([]domain.Evidence, []domain.Conflict) {
	var enrichments []domain.Enrichment
	if opts.Store != nil {
		if list, err := opts.Store.ListEnrichments(vuln.ID); err == nil {
			enrichments = list
		}
	}
	correlated := correlate.CorrelateAll([]domain.Vulnerability{vuln}, enrichments)
	if len(correlated) == 0 {
		return nil, nil
	}
	return correlated[0].Evidence, correlated[0].Conflicts
}
