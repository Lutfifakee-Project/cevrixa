package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

type RenderOptions struct {
	Verbose bool
	Quiet   bool
}

func RenderHuman(w io.Writer, r domain.Report) error {
	return RenderHumanWithOptions(w, r, RenderOptions{})
}

func RenderHumanWithOptions(w io.Writer, r domain.Report, opts RenderOptions) error {
	if opts.Quiet {
		return renderHumanQuiet(w, r)
	}

	fmt.Fprintln(w, "Cevrixa")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Target")
	if r.Target.Product != "" {
		fmt.Fprintf(w, "  Product : %s\n", r.Target.Product)
	}
	if r.Target.Version != "" {
		fmt.Fprintf(w, "  Version : %s\n", r.Target.Version)
	}
	if r.Target.CPE != "" {
		fmt.Fprintf(w, "  CPE     : %s\n", r.Target.CPE)
	}
	if r.Target.PURL != "" {
		fmt.Fprintf(w, "  PURL    : %s\n", r.Target.PURL)
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
		if f.KnownExploited != nil {
			line := "  KEV        : YES"
			if f.KnownExploited.DateAdded != "" {
				line += " (added " + f.KnownExploited.DateAdded + ")"
			}
			fmt.Fprintln(w, line)
		}
		if f.Enrichment != nil {
			if f.Enrichment.Mitigation != "" {
				fmt.Fprintf(w, "  Mitigation : %s\n", f.Enrichment.Mitigation)
			}
			if f.Enrichment.PoCURL != "" {
				fmt.Fprintf(w, "  PoC        : %s\n", f.Enrichment.PoCURL)
			}
			if f.Enrichment.PatchCommitURL != "" {
				fmt.Fprintf(w, "  Patch      : %s\n", f.Enrichment.PatchCommitURL)
			}
		}
		if opts.Verbose && len(f.Why.Steps) > 0 {
			fmt.Fprintln(w, "  Steps:")
			for _, s := range f.Why.Steps {
				fmt.Fprintf(w, "    - %s\n", s)
			}
		}
		fmt.Fprintf(w, "  Evidence   : %d\n", len(f.Evidence))
	}
	printAttributionFooter(w, r.Findings)
	return nil
}

func renderHumanQuiet(w io.Writer, r domain.Report) error {
	for _, f := range r.Findings {
		if _, err := fmt.Fprintf(w, "%s %s\n", f.VulnerabilityID, strings.ToUpper(string(f.Status))); err != nil {
			return err
		}
	}
	return nil
}
func printAttributionFooter(w io.Writer, findings []domain.Finding) {
	attr := ""
	for _, f := range findings {
		if a := enrichmentAttribution(f.Enrichment); a != "" {
			attr = a
			break
		}
	}
	if attr == "" {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Enrichment data: %s\n", attr)
}

func enrichmentAttribution(e *domain.Enrichment) string {
	if e == nil {
		return ""
	}
	if e.Attribution != nil && e.Attribution.Source != "" {
		s := e.Attribution.Source
		if e.Attribution.License != "" {
			s += " (" + e.Attribution.License + ")"
		}
		return s
	}
	return ""
}
