package output

import (
	"fmt"
	"io"
	"strconv"
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

	renderTarget(w, r.Target)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "[*] Findings: %d\n", len(r.Findings))
	renderDataset(w, r.Dataset)

	if len(r.Findings) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "    [!] No matching vulnerabilities found in the current local dataset.")
		fmt.Fprintln(w, "        This does NOT prove the target is not affected.")
		renderTrace(w, r.Trace)
		return nil
	}

	for _, f := range r.Findings {
		fmt.Fprintln(w)
		renderFinding(w, f, opts)
	}

	renderTrace(w, r.Trace)
	printAttributionFooter(w, r.Findings)
	return nil
}

// renderTrace prints the reasoning path behind a decision, so a reader can see
// how the verdict was reached and not only its result.
func renderTrace(w io.Writer, t domain.Trace) {
	if len(t.Steps) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[+] Decision Trace")
	for i, s := range t.Steps {
		mark := traceMark(s.Status)
		fmt.Fprintf(w, "    %s %d. %s", mark, i+1, s.Name)
		if s.Detail != "" {
			fmt.Fprintf(w, " — %s", s.Detail)
		}
		fmt.Fprintln(w)
	}
}

func traceMark(status string) string {
	switch status {
	case domain.TraceOK:
		return "[+]"
	case domain.TraceSkipped:
		return "[-]"
	case domain.TraceWarn:
		return "[!]"
	case domain.TraceFail:
		return "[x]"
	default:
		return "[*]"
	}
}

// renderDataset states which records a report was computed from, so that a
// zero-finding result can be told apart from a run against no data, and so that
// embedded test fixtures are never mistaken for vulnerability intelligence.
func renderDataset(w io.Writer, d domain.DatasetInfo) {
	if d.Empty() && len(d.Sources) == 0 {
		fmt.Fprintln(w, "    [*] Dataset      none (no local store and no embedded fixtures)")
		return
	}
	desc := fmt.Sprintf("local store %d record(s)", d.StoreRecords)
	if d.FixtureRecords > 0 {
		desc += fmt.Sprintf(" + embedded fixtures %d record(s), TEST DATA", d.FixtureRecords)
	}
	if len(d.Sources) > 0 {
		desc += " [" + strings.Join(d.Sources, ", ") + "]"
	}
	fmt.Fprintf(w, "    [*] Dataset      %s\n", desc)
}

func renderTarget(w io.Writer, t domain.Target) {
	fmt.Fprintln(w, "[+] Target")
	if t.Product != "" {
		fmt.Fprintf(w, "    Product      %s\n", t.Product)
	}
	if t.Version != "" {
		fmt.Fprintf(w, "    Version      %s\n", t.Version)
	}
	if t.CPE != "" {
		fmt.Fprintf(w, "    CPE          %s\n", t.CPE)
	}
	if t.PURL != "" {
		fmt.Fprintf(w, "    PURL         %s\n", t.PURL)
	}
	if t.ResolvedCPE != "" && t.ResolvedCPE != t.CPE {
		fmt.Fprintf(w, "    Resolved     %s\n", t.ResolvedCPE)
	}
}

func renderFinding(w io.Writer, f domain.Finding, opts RenderOptions) {
	fmt.Fprintf(w, "    [+] %s\n", f.VulnerabilityID)
	fmt.Fprintf(w, "        [*] Status       %s\n", strings.ToUpper(string(f.Status)))
	if f.Risk != nil {
		if f.Risk.Severity != "" {
			fmt.Fprintf(w, "        [*] Severity     %s\n", f.Risk.Severity)
		}
		if f.Risk.CVSS != 0 {
			v := ""
			if f.Risk.CVSSVersion != "" {
				v = " (v" + f.Risk.CVSSVersion + ")"
			}
			fmt.Fprintf(w, "        [*] CVSS         %s%s\n", formatFloat(f.Risk.CVSS), v)
		}
	}
	fmt.Fprintf(w, "        [*] Confidence   %s\n", strings.ToUpper(string(f.Confidence)))
	if f.Applicability.Range != "" {
		fmt.Fprintf(w, "        [*] Matched      %s\n", f.Applicability.Range)
	}
	if len(f.FixedVersions) > 0 {
		fmt.Fprintf(w, "        [*] Fixed        %s\n", f.FixedVersions[0])
	}
	if f.KnownExploited != nil {
		line := "        [*] KEV          YES"
		if f.KnownExploited.DateAdded != "" {
			line += " (added " + f.KnownExploited.DateAdded + ")"
		}
		fmt.Fprintln(w, line)
	}
	if f.Enrichment != nil {
		if f.Enrichment.Mitigation != "" {
			fmt.Fprintf(w, "        [*] Mitigation   %s\n", f.Enrichment.Mitigation)
		}
		if f.Enrichment.PoCURL != "" {
			fmt.Fprintf(w, "        [*] PoC          %s\n", f.Enrichment.PoCURL)
		}
		if f.Enrichment.PatchCommitURL != "" {
			fmt.Fprintf(w, "        [*] Patch        %s\n", f.Enrichment.PatchCommitURL)
		}
	}
	if opts.Verbose && len(f.Why.Steps) > 0 {
		fmt.Fprintln(w, "        [-] Why")
		for _, s := range f.Why.Steps {
			fmt.Fprintf(w, "            • %s\n", s)
		}
	}
	if f.Status == domain.FindingStatusInconclusive {
		if f.Why.VersionMatch != "" {
			fmt.Fprintf(w, "        [!] Undecided    %s\n", f.Why.VersionMatch)
		}
		for _, step := range f.Why.Steps {
			fmt.Fprintf(w, "            • %s\n", step)
		}
		for _, q := range f.Why.Questions {
			fmt.Fprintf(w, "            ? %s\n", q)
		}
	}
	if len(f.Conflicts) > 0 {
		fmt.Fprintf(w, "        [!] Conflicts    sources disagree (%d kind(s))\n", len(f.Conflicts))
		for _, c := range f.Conflicts {
			for _, v := range c.Values {
				fmt.Fprintf(w, "            %s %s = %s\n", strings.ToUpper(string(c.Kind)), v.Source, v.Value)
			}
		}
	}
	fmt.Fprintf(w, "        [*] Evidence     %d\n", len(f.Evidence))
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
	fmt.Fprintf(w, "[!] Enrichment data: %s\n", attr)
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

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}
