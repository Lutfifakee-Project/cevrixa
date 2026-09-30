package matcher

import "github.com/Lutfifakee-Project/cevrixa/internal/domain"

// Result is the outcome of matching a single target against a vulnerability's
// applicability statements.
type Result struct {
	Matched  bool
	Criteria string
	Range    string
	Fixed    string
	Mode     string

	// Undecided reports that applicability could not be determined from the
	// information available: an AND configuration that requires another
	// component, a negated configuration, or a version range that cannot be
	// compared. When Undecided is true the caller must not report the target
	// as affected or as not affected; the honest status is inconclusive.
	Undecided bool
	// Reason explains an Undecided outcome, or why a decided non-match did not
	// apply, so that `explain` can state the cause instead of only the verdict.
	Reason string
}

// MatchCPE evaluates a target CPE against every applicability statement of a
// vulnerability. A match wins over an undecided outcome, and an undecided
// outcome wins over a decided non-match.
func MatchCPE(target domain.CPE, vuln domain.Vulnerability) (Result, error) {
	targetVersion, err := parseVersion(target.Version)
	if err != nil {
		return Result{}, err
	}

	var undecided, nonMatch *Result
	for _, node := range vuln.Applicability {
		out := matchNode(node, target, targetVersion)

		switch {
		case out.decided && out.matched:
			return out.result, nil
		case !out.decided:
			if undecided == nil {
				r := out.result
				r.Undecided = true
				r.Reason = out.reason
				undecided = &r
			}
		default:
			if nonMatch == nil {
				r := out.result
				r.Reason = out.reason
				nonMatch = &r
			}
		}
	}

	if undecided != nil {
		return *undecided, nil
	}
	if nonMatch != nil {
		return *nonMatch, nil
	}
	return Result{}, nil
}
