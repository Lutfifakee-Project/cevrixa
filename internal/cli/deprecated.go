package cli

import (
	"fmt"
	"os"
)

// warnDeprecated prints a one-line deprecation notice to stderr. The old
// command keeps working so existing scripts do not break, but the user is
// pointed at the replacement.
func warnDeprecated(old string) {
	switch old {
	case "why":
		fmt.Fprintln(os.Stderr, "Warning: 'why' is deprecated.")
		fmt.Fprintln(os.Stderr, "Use 'cevrixa explain' instead.")
	case "why-not":
		fmt.Fprintln(os.Stderr, "Warning: 'why-not' is deprecated.")
		fmt.Fprintln(os.Stderr, "Use 'cevrixa explain' instead.")
	case "sbom":
		fmt.Fprintln(os.Stderr, "Warning: 'sbom' is deprecated as a top-level command.")
		fmt.Fprintln(os.Stderr, "Use 'cevrixa detect --sbom <file>' instead.")
	default:
		fmt.Fprintln(os.Stderr, "Warning: '"+old+"' is deprecated.")
	}
}
