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
		"%s: unsupported --fail-on %q (supported: none, any, affected, inconclusive, kev, low, medium, high, critical)",
		command, gate,
	)
}
