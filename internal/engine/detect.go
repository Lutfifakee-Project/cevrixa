package engine

import (
	"fmt"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
	"github.com/Lutfifakee-Project/cevrixa/internal/resolver"
)

type Options struct {
	KEV    map[string]domain.KEVInfo
	Source string
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

	if target.ResolvedCPE == "" {
		return domain.Report{Target: target}, nil
	}

	targetCPE, err := domain.ParseCPE(target.ResolvedCPE)
	if err != nil {
		return domain.Report{}, fmt.Errorf("engine: parse resolved CPE: %w", err)
	}

	vulns, err := loadFixturesFromEmbed()
	if err != nil {
		return domain.Report{}, err
	}

	findings := []domain.Finding{}
	for _, v := range vulns {
		mr, err := matcher.MatchCPE(targetCPE, v)
		if err != nil {
			continue
		}
		if !mr.Matched {
			continue
		}
		f := buildFinding(targetCPE, v, mr)
		attachKEV(&f, v.ID, opts)
		findings = append(findings, f)
	}

	return domain.Report{Target: target, Findings: findings}, nil
}

func detectByPURL(target domain.Target, opts Options) (domain.Report, error) {
	purl, err := domain.ParsePURL(target.PURL)
	if err != nil {
		return domain.Report{}, fmt.Errorf("engine: parse PURL: %w", err)
	}
	if purl.Version == "" {
		return domain.Report{}, fmt.Errorf("engine: PURL must include a version")
	}

	vulns, err := loadFixturesFromEmbed()
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
		if !pr.Matched {
			continue
		}
		f := buildPackageFinding(purl, v, pr)
		attachKEV(&f, v.ID, opts)
		findings = append(findings, f)
	}

	return domain.Report{Target: target, Findings: findings}, nil
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
