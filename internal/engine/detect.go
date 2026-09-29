package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
	"github.com/Lutfifakee-Project/cevrixa/internal/resolver"
)

type Options struct {
	FixturesDir string
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

	vulns, err := loadFixtures(opts.FixturesDir)
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

func loadFixtures(dir string) ([]domain.Vulnerability, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("engine: read fixtures dir %q: %w", dir, err)
	}

	var out []domain.Vulnerability
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("engine: read %s: %w", path, err)
		}
		var v domain.Vulnerability
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("engine: parse %s: %w", path, err)
		}
		out = append(out, v)
	}
	return out, nil
}
