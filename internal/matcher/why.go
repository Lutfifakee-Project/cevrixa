package matcher

import "github.com/Lutfifakee-Project/cevrixa/internal/domain"

func BuildWhy(target domain.CPE, r Result) domain.Why {
	why := domain.Why{
		IdentityMatch: "CPE vendor+product matched target",
		VersionMatch:  target.Version + " in " + r.Range,
		Steps: []string{
			"parsed target CPE",
			"matched vendor=" + target.Vendor + " product=" + target.Product,
			"built version range " + r.Range,
			"checked target version " + target.Version,
		},
	}
	if r.Fixed != "" {
		why.FixedReason = "fixed in " + r.Fixed
		why.Steps = append(why.Steps, "version_end_excluding "+r.Fixed+" is the fixed version")
	}
	return why
}
