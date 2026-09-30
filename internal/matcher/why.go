package matcher

import "github.com/Lutfifakee-Project/cevrixa/internal/domain"

// BuildWhy explains either why a target matched, why it did not, or why the
// question could not be answered. The wording follows the verdict so that
// `explain` never states a reason that contradicts its own decision.
func BuildWhy(target domain.CPE, r Result) domain.Why {
	if r.Undecided {
		why := domain.Why{
			IdentityMatch: "CPE vendor=" + target.Vendor + " product=" + target.Product + " matched a configuration",
			VersionMatch:  "applicability could not be decided",
			Questions:     []string{"which other components apply to this target?"},
		}
		if r.Reason != "" {
			why.Steps = append(why.Steps, r.Reason)
		} else {
			why.Steps = append(why.Steps, "the applicable configuration is undecidable from a single target")
		}
		return why
	}

	if !r.Matched {
		why := domain.Why{
			IdentityMatch: "no vulnerable CPE configuration matched vendor=" + target.Vendor + " product=" + target.Product,
		}
		if r.Range != "" {
			why.VersionMatch = target.Version + " is outside " + r.Range
			if r.Fixed != "" {
				why.FixedReason = "fixed in " + r.Fixed
				why.Steps = append(why.Steps, "target "+target.Version+" is at or above the fixed version "+r.Fixed)
			}
		} else {
			why.VersionMatch = "no version boundary applies to " + target.Version
		}
		if r.Criteria != "" {
			why.Steps = append(why.Steps, "closest configuration: "+r.Criteria)
		}
		return why
	}

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
