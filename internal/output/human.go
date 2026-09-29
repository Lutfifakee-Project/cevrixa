package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func RenderHuman(w io.Writer, r domain.Report) error {
	if _, err := fmt.Fprintln(w, "Cevrixa"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, "Target"); err != nil {
		return err
	}
	if r.Target.Product != "" {
		fmt.Fprintf(w, "  Product : %s\n", r.Target.Product)
	}
	if r.Target.Version != "" {
		fmt.Fprintf(w, "  Version : %s\n", r.Target.Version)
	}
	if r.Target.CPE != "" {
		fmt.Fprintf(w, "  CPE     : %s\n", r.Target.CPE)
	}
	if r.Target.ResolvedCPE != "" && r.Target.ResolvedCPE != r.Target.CPE {
		fmt.Fprintf(w, "  Resolved: %s\n", r.Target.ResolvedCPE)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Findings: %d\n", len(r.Findings))

	for _, f := range r.Findings {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n", f.VulnerabilityID)
		fmt.Fprintf(w, "  Status     : %s\n", strings.ToUpper(string(f.Status)))
		fmt.Fprintf(w, "  Confidence : %s\n", strings.ToUpper(string(f.Confidence)))
		if f.Applicability.Range != "" {
			fmt.Fprintf(w, "  Matched    : %s\n", f.Applicability.Range)
		}
		if len(f.FixedVersions) > 0 {
			fmt.Fprintf(w, "  Fixed      : %s\n", f.FixedVersions[0])
		}
		if f.Why.VersionMatch != "" {
			fmt.Fprintf(w, "  Why        : %s\n", f.Why.VersionMatch)
		}
		fmt.Fprintf(w, "  Evidence   : %d\n", len(f.Evidence))
	}

	return nil
}
