package matcher

import (
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/version"
)

// nodeOutcome is the result of evaluating one NVD configuration node against a
// single target CPE. decided=false means Cevrixa cannot answer for this node
// and must say so instead of guessing.
type nodeOutcome struct {
	matched bool
	decided bool
	reason  string
	result  Result
}

func matchNode(node domain.ApplicabilityNode, target domain.CPE, v version.Version) nodeOutcome {
	if node.Negate {
		// A negated node asserts that the target matches when the underlying
		// configuration does not. Without a full asset model that cannot be
		// turned into an affected/not-affected verdict, so it is reported as
		// undecided rather than silently ignored.
		return nodeOutcome{reason: "negated NVD configuration is not evaluated by Cevrixa"}
	}
	if strings.EqualFold(strings.TrimSpace(node.Operator), "AND") {
		return matchAndNode(node, target, v)
	}
	return matchOrNode(node, target, v)
}

func matchOrNode(node domain.ApplicabilityNode, target domain.CPE, v version.Version) nodeOutcome {
	var undecided, nonMatch *Result

	for _, child := range node.Children {
		out := matchNode(child, target, v)
		switch {
		case out.decided && out.matched:
			return out
		case !out.decided:
			if undecided == nil {
				r := out.result
				r.Reason = out.reason
				undecided = &r
			}
		default:
			if nonMatch == nil {
				r := out.result
				nonMatch = &r
			}
		}
	}

	for _, m := range node.Matches {
		if !m.Vulnerable {
			// In an OR node a vulnerable:false entry states that this CPE on
			// its own does not imply vulnerability, so it can never make the
			// target affected.
			continue
		}

		r, identityMatched := matchSingle(m, target, v)
		if !identityMatched {
			continue
		}
		if r.Undecided {
			if undecided == nil {
				u := r
				undecided = &u
			}
			continue
		}
		if r.Matched {
			return nodeOutcome{matched: true, decided: true, result: r}
		}
		if nonMatch == nil {
			nm := r
			nonMatch = &nm
		}
	}

	if undecided != nil {
		return nodeOutcome{reason: undecided.Reason, result: *undecided}
	}
	if nonMatch != nil {
		return nodeOutcome{decided: true, result: *nonMatch}
	}
	return nodeOutcome{decided: true}
}

// matchAndNode evaluates an AND configuration the way NVD intends: every part
// must hold. Cevrixa evaluates a single target, so an AND group whose parts
// refer to components other than the target cannot be decided on that evidence
// alone. Treating those groups as OR is what produces the well known CPE false
// positives, so they are reported as undecided instead.
func matchAndNode(node domain.ApplicabilityNode, target domain.CPE, v version.Version) nodeOutcome {
	var (
		vulnerableMatch  *Result
		vulnerableFailed *Result
		identitySeen     bool
		requirements     []string
	)

	for _, child := range node.Children {
		out := matchNode(child, target, v)
		if !out.decided {
			return nodeOutcome{reason: out.reason}
		}
		if !out.matched {
			return nodeOutcome{reason: "no part of the AND configuration matched the target"}
		}
		if vulnerableMatch == nil && out.result.Matched {
			r := out.result
			vulnerableMatch = &r
		}
	}

	for _, m := range node.Matches {
		r, identityMatched := matchSingle(m, target, v)

		if !m.Vulnerable {
			// A vulnerable:false entry is a requirement: the configuration
			// only applies when that CPE is present as well. An unmet
			// requirement means the answer needs information Cevrixa does not
			// have about the surrounding asset.
			if !identityMatched {
				requirements = append(requirements, m.Criteria)
			}
			continue
		}

		if !identityMatched {
			return nodeOutcome{
				reason: "AND configuration requires a component that is not the target: " + m.Criteria,
			}
		}
		identitySeen = true
		if r.Undecided {
			return nodeOutcome{reason: r.Reason}
		}
		if r.Matched {
			if vulnerableMatch == nil {
				res := r
				vulnerableMatch = &res
			}
			continue
		}
		if vulnerableFailed == nil {
			res := r
			vulnerableFailed = &res
		}
	}

	if len(requirements) > 0 {
		return nodeOutcome{
			reason: "AND configuration requires an additional component: " + strings.Join(requirements, ", "),
		}
	}
	if vulnerableMatch != nil {
		return nodeOutcome{matched: true, decided: true, result: *vulnerableMatch}
	}
	if identitySeen && vulnerableFailed != nil {
		// The vulnerable component is the target and the target version is
		// outside every vulnerable range: genuinely not affected.
		return nodeOutcome{decided: true, result: *vulnerableFailed}
	}
	return nodeOutcome{decided: true}
}

func matchSingle(m domain.CPEMatch, target domain.CPE, v version.Version) (Result, bool) {
	criteriaCPE, err := domain.ParseCPE(m.Criteria)
	if err != nil {
		return Result{}, false
	}

	if !cpeFieldMatches(criteriaCPE.Part, target.Part) {
		return Result{}, false
	}
	if !cpeFieldMatches(criteriaCPE.Vendor, target.Vendor) {
		return Result{}, false
	}
	if !cpeFieldMatches(criteriaCPE.Product, target.Product) {
		return Result{}, false
	}

	// NVD frequently pins the affected version inside the criteria string
	// itself (for example cpe:2.3:a:django_project:django:0.91:*:*:*:*:*:*:*)
	// with no versionStart/versionEnd bounds. The pinned version is part of the
	// criterion and must be honoured; ignoring it reports every version of the
	// product as affected.
	if !criteriaCPE.IsWildcard("version") && m.VersionStart == "" && m.VersionEnd == "" {
		pinned := strings.TrimSpace(criteriaCPE.Version)
		pv, err := version.ParseLenient(pinned)
		if err != nil {
			return Result{
				Criteria:  m.Criteria,
				Range:     "= " + pinned,
				Undecided: true,
				Reason:    "criteria pins version " + pinned + " which cannot be compared",
			}, true
		}
		return Result{
			Matched:  v.Compare(pv) == 0,
			Criteria: m.Criteria,
			Range:    "= " + pinned,
			Mode:     "exact",
		}, true
	}

	rng, err := buildRange(m)
	if err != nil {
		return Result{
			Criteria:  m.Criteria,
			Range:     formatRange(m),
			Undecided: true,
			Reason:    "version range could not be compared: " + err.Error(),
		}, true
	}

	matched := rng.Contains(v)

	return Result{
		Matched:  matched,
		Criteria: m.Criteria,
		Range:    formatRange(m),
		Fixed:    fixedVersion(m),
		Mode:     classifyMode(m),
	}, true
}

func cpeFieldMatches(criteria, target string) bool {
	if criteria == "" || criteria == "*" || criteria == "-" {
		return true
	}
	return strings.EqualFold(criteria, target)
}
