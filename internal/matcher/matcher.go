package matcher

import "github.com/Lutfifakee-Project/cevrixa/internal/domain"

type Result struct {
	Matched  bool
	Criteria string
	Range    string
	Fixed    string
	Mode     string
}

func MatchCPE(target domain.CPE, vuln domain.Vulnerability) (Result, error) {
	version, err := parseVersion(target.Version)
	if err != nil {
		return Result{}, err
	}

	for _, node := range vuln.Applicability {
		if r, ok := matchNode(node, target, version); ok {
			return r, nil
		}
	}
	return Result{}, nil
}
