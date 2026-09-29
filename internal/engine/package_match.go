package engine

import (
	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/version"
)

type PackageMatchResult struct {
	Matched  bool
	Range    string
	Fixed    string
	Mode     string
	Criteria string
}

func matchPackage(purl domain.PURL, vuln domain.Vulnerability) (PackageMatchResult, bool) {
	ecosystem := normalizeEcosystem(purl.Type)
	if ecosystem == "" {
		return PackageMatchResult{}, false
	}

	for _, pkg := range vuln.PackageApplicability {
		if pkg.Ecosystem != ecosystem {
			continue
		}
		if pkg.Name != purl.Name {
			continue
		}

		for _, r := range pkg.Ranges {
			res, ok := matchPackageRange(purl, r)
			if ok {
				return res, true
			}
		}
	}
	return PackageMatchResult{}, false
}

func matchPackageRange(purl domain.PURL, r domain.PackageRange) (PackageMatchResult, bool) {
	targetVersion, err := version.ParseLenient(purl.Version)
	if err != nil {
		return PackageMatchResult{}, false
	}

	var introduced, fixed string
	for _, ev := range r.Events {
		if ev.Introduced != "" {
			introduced = ev.Introduced
		}
		if ev.Fixed != "" {
			fixed = ev.Fixed
		}
	}

	if introduced == "" && fixed == "" {
		return PackageMatchResult{}, false
	}

	// Introduced = 0 means "all versions up to fixed".
	var lower *version.Bound
	if introduced != "" && introduced != "0" {
		v, err := version.ParseLenient(introduced)
		if err != nil {
			return PackageMatchResult{}, false
		}
		lower = &version.Bound{Version: v, Inclusive: true}
	}

	var upper *version.Bound
	if fixed != "" {
		v, err := version.ParseLenient(fixed)
		if err != nil {
			return PackageMatchResult{}, false
		}
		upper = &version.Bound{Version: v, Inclusive: false}
	}

	rng, err := version.NewRange(lower, upper)
	if err != nil {
		return PackageMatchResult{}, false
	}

	matched := rng.Contains(targetVersion)

	mode := "range"
	if lower == nil && upper != nil {
		mode = "partial"
	} else if lower != nil && upper == nil {
		mode = "partial"
	}

	return PackageMatchResult{
		Matched:  matched,
		Range:    formatPackageRange(introduced, fixed),
		Fixed:    fixed,
		Mode:     mode,
		Criteria: "pkg:" + purl.Type + "/" + purl.Name,
	}, true
}

func formatPackageRange(introduced, fixed string) string {
	if introduced == "" && fixed == "" {
		return "any"
	}
	out := ""
	if introduced != "" && introduced != "0" {
		out = ">=" + introduced
	}
	if fixed != "" {
		if out != "" {
			out += " "
		}
		out += "<" + fixed
	}
	if out == "" {
		return "any"
	}
	return out
}
