package engine

import (
	"fmt"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
	"github.com/Lutfifakee-Project/cevrixa/internal/resolver"
)

type Options struct{}

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
		findings = append(findings, buildFinding(targetCPE, v, mr))
	}

	return domain.Report{Target: target, Findings: findings}, nil
}
