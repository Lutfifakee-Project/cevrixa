package engine

import (
	"fmt"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
	"github.com/Lutfifakee-Project/cevrixa/internal/resolver"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

type Options struct {
	KEV   map[string]domain.KEVInfo
	Store *store.Store
}

func Detect(target domain.Target, opts Options) (domain.Report, error) {
	if target.PURL != "" {
		return detectByPURL(target, opts)
	}
	return detectByCPE(target, opts)
}

func detectByCPE(target domain.Target, opts Options) (domain.Report, error) {
	r := resolver.New()
	res, err := r.Resolve(target)
	if err != nil {
		return domain.Report{}, err
	}
	target.ResolvedCPE = res.CPE

	vulns, dataset, err := loadVulnerabilities(opts)
	if err != nil {
		return domain.Report{}, err
	}

	report := domain.Report{Target: target, Findings: []domain.Finding{}, Dataset: dataset}
	if target.ResolvedCPE == "" {
		// The identity could not be resolved, so nothing was searched. This is
		// a different answer from "searched and found nothing", and the dataset
		// is still reported so the caller can tell the two apart.
		return report, nil
	}

	targetCPE, err := domain.ParseCPE(target.ResolvedCPE)
	if err != nil {
		return domain.Report{}, fmt.Errorf("engine: parse resolved CPE: %w", err)
	}

	findings := []domain.Finding{}
	for _, v := range vulns {
		mr, err := matcher.MatchCPE(targetCPE, v)
		if err != nil {
			continue
		}
		if !mr.Matched && !mr.Undecided {
			continue
		}
		f := buildFinding(targetCPE, v, mr, enrichmentsFor(opts, v.ID))
		attachKEV(&f, v.ID, opts)
		attachEnrichment(&f, v.ID, opts)
		findings = append(findings, f)
	}
	report.Findings = findings

	return report, nil
}

func detectByPURL(target domain.Target, opts Options) (domain.Report, error) {
	purl, err := domain.ParsePURL(target.PURL)
	if err != nil {
		return domain.Report{}, fmt.Errorf("engine: parse PURL: %w", err)
	}
	if purl.Version == "" {
		return domain.Report{}, fmt.Errorf("engine: PURL must include a version")
	}

	vulns, dataset, err := loadVulnerabilities(opts)
	if err != nil {
		return domain.Report{}, err
	}

	findings := []domain.Finding{}
	for _, v := range vulns {
		if len(v.PackageApplicability) == 0 {
			continue
		}
		pr, ok := matchPackage(purl, v)
		if !ok {
			continue
		}
		if !pr.Matched && !pr.Undecided {
			continue
		}
		f := buildPackageFinding(purl, v, pr, enrichmentsFor(opts, v.ID))
		attachKEV(&f, v.ID, opts)
		attachEnrichment(&f, v.ID, opts)
		findings = append(findings, f)
	}

	return domain.Report{Target: target, Findings: findings, Dataset: dataset}, nil
}

// enrichmentsFor returns every stored enrichment for a vulnerability, from all
// sources. Passing them into correlation is what makes cross-source conflicts
// reachable; without them the conflict machinery never has two sources to
// compare.
func enrichmentsFor(opts Options, vulnID string) []domain.Enrichment {
	if opts.Store == nil || vulnID == "" {
		return nil
	}
	list, err := opts.Store.ListEnrichments(vulnID)
	if err != nil {
		return nil
	}
	return list
}

func attachKEV(f *domain.Finding, cveID string, opts Options) {
	if opts.KEV == nil {
		return
	}
	if info, ok := opts.KEV[cveID]; ok {
		infoCopy := info
		f.KnownExploited = &infoCopy
	}
}

func attachEnrichment(f *domain.Finding, cveID string, opts Options) {
	if opts.Store == nil {
		return
	}
	e, err := opts.Store.GetEnrichmentAny(cveID, "")
	if err != nil {
		return
	}
	f.Enrichment = &e
}
