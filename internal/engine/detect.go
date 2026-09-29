package engine

import (
	"fmt"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
	"github.com/Lutfifakee-Project/cevrixa/internal/resolver"
)

type Options struct {
	KEV map[string]domain.KEVInfo
}

func Detect(target domain.Target, opts Options) (domain.Report, error) {
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
		if opts.KEV != nil {
			if info, ok := opts.KEV[v.ID]; ok {
				infoCopy := info
				f.KnownExploited = &infoCopy
			}
		}
		findings = append(findings, f)
	}

	return domain.Report{Target: target, Findings: findings}, nil
}
