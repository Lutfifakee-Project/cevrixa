package domain

// ReportDecision is the overall verdict of a detection report.
//
// It exists so that "no findings" can never be confused with "not affected".
// A report that searched a dataset and found no candidate is NO_DATA, not
// NOT_AFFECTED: the absence of evidence is not evidence of absence. A report
// whose target identity could not be resolved is IDENTITY_UNRESOLVED, so a
// failed resolution is never read as a clean result.
type ReportDecision string

const (
	// DecisionAffected means at least one finding proved the target is affected.
	DecisionAffected ReportDecision = "affected"
	// DecisionInconclusive means candidates exist but applicability could not be
	// decided reliably (for example an AND configuration needing another
	// component, or an uncomparable version range).
	DecisionInconclusive ReportDecision = "inconclusive"
	// DecisionNoData means the target was evaluated but the available
	// intelligence did not contain a matching candidate. It does not prove the
	// target is safe.
	DecisionNoData ReportDecision = "no_data"
	// DecisionIdentityUnresolved means the target could not be mapped to a
	// sufficiently reliable identity, so no applicability was evaluated.
	DecisionIdentityUnresolved ReportDecision = "identity_unresolved"
)

// DecisionFor derives the report decision from its findings and the state of
// identity resolution. The order matters: a proven affected finding wins over
// everything; an undecided finding is still a reason the report is not clean;
// an unresolved identity is reported as such rather than as "no data"; and a
// report with no candidates at all is NO_DATA.
func DecisionFor(identityResolved bool, findings []Finding) ReportDecision {
	if !identityResolved {
		return DecisionIdentityUnresolved
	}
	inconclusive := false
	for _, f := range findings {
		switch f.Status {
		case FindingStatusAffected:
			return DecisionAffected
		case FindingStatusInconclusive:
			inconclusive = true
		}
	}
	if inconclusive {
		return DecisionInconclusive
	}
	return DecisionNoData
}
