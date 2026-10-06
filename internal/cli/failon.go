package cli

import (
	"fmt"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

// validateFailOn rejects an unrecognised --fail-on gate. Ignoring one would
// silently disable the check and exit successfully on a vulnerable target, so
// every command that accepts the flag validates it.
func validateFailOn(command, gate string) error {
	if gate == "" || domain.ValidGate(gate) {
		return nil
	}
	return fmt.Errorf(
		"%s: unsupported --fail-on %q (supported: none, any, affected, inconclusive, kev, no_data, identity_unresolved, low, medium, high, critical)",
		command, gate,
	)
}

// reportGateFails reports whether a report-level gate (no_data or
// identity_unresolved) is triggered by the report decision. These gates live on
// the report, not on a finding, so they are evaluated once per report.
func reportGateFails(command, gate string, decision domain.ReportDecision) error {
	if !domain.ReportSatisfiesGate(gate, decision) {
		return nil
	}
	return fmt.Errorf("%s: fail-on %q triggered: decision is %s", command, gate, decision)
}
