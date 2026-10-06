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

// line prints one formatted line, then a newline. Using this instead of an
// explicit newline escape in every format string keeps the renderers readable
// and keeps the text identical across platforms.
func line(w io.Writer, format string, a ...any) {
	fmt.Fprintf(w, format, a...)
	fmt.Fprintln(w)
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
	line(w, "[*] Findings: %d", len(r.Findings))
	renderDataset(w, r.Dataset)

	if len(r.Findings) == 0 {
		renderEmptyDecision(w, r)
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

// renderEmptyDecision states the report decision when there are no findings.
// An unresolved identity and a searched-but-empty dataset are different
// answers, and neither is "not affected", so they must never look the same.
func renderEmptyDecision(w io.Writer, r domain.Report) {
	fmt.Fprintln(w)
	switch r.Decision {
	case domain.DecisionIdentityUnresolved:
		fmt.Fprintln(w, "    [!] IDENTITY UNRESOLVED")
		fmt.Fprintln(w, "        The target identity could not be resolved, so no")
		fmt.Fprintln(w, "        applicability was evaluated. This is not a clean result.")
		fmt.Fprintln(w, "        Provide --cpe, or a product present in the resolver catalog.")
	default:
		fmt.Fprintln(w, "    [!] NO DATA")
		fmt.Fprintln(w, "        No matching vulnerabilities found in the current dataset.")
		fmt.Fprintln(w, "        This does NOT prove the target is not affected.")
	}
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
		if s.Detail != "" {
			line(w, "    %s %d. %s - %s", mark, i+1, s.Name, s.Detail)
		} else {
			line(w, "    %s %d. %s", mark, i+1, s.Name)
		}
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
	if d.Empty() && len(d.Sources) == 0 && d.Snapshot == "" {
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
	if d.Snapshot != "" {
		desc += " snapshot=" + d.Snapshot
	}
	line(w, "    [*] Dataset      %s", desc)
	if d.Digest != "" {
		line(w, "    [*] Digest       %s", d.Digest)
	}
}

func renderTarget(w io.Writer, t domain.Target) {
	fmt.Fprintln(w, "[+] Target")
	if t.Product != "" {
		line(w, "    Product      %s", t.Product)
	}
	if t.Version != "" {
		line(w, "    Version      %s", t.Version)
	}
	if t.CPE != "" {
		line(w, "    CPE          %s", t.CPE)
	}
	if t.PURL != "" {
		line(w, "    PURL         %s", t.PURL)
	}
	if t.ResolvedCPE != "" && t.ResolvedCPE != t.CPE {
		line(w, "    Resolved     %s", t.ResolvedCPE)
	}
}

func renderFinding(w io.Writer, f domain.Finding, opts RenderOptions) {
	line(w, "    [+] %s", f.VulnerabilityID)
	line(w, "        [*] Status       %s", strings.ToUpper(string(f.Status)))
	if f.Risk != nil {
		if f.Risk.Severity != "" {
			line(w, "        [*] Severity     %s", f.Risk.Severity)
		}
		if f.Risk.CVSS != 0 {
			v := ""
			if f.Risk.CVSSVersion != "" {
				v = " (v" + f.Risk.CVSSVersion + ")"
			}
			line(w, "        [*] CVSS         %s%s", formatFloat(f.Risk.CVSS), v)
		}
	}
	line(w, "        [*] Confidence   %s", strings.ToUpper(string(f.Confidence)))
	if f.Priority.Level != "" && f.Priority.Level != domain.PriorityNone {
		text := "        [*] Priority     " + strings.ToUpper(f.Priority.Level)
		if len(f.Priority.Factors) > 0 {
			text += " (" + strings.Join(f.Priority.Factors, ", ") + ")"
		}
		fmt.Fprintln(w, text)
	}
	if f.Applicability.Range != "" {
		line(w, "        [*] Matched      %s", f.Applicability.Range)
	}
	if len(f.FixedVersions) > 0 {
		line(w, "        [*] Fixed        %s", f.FixedVersions[0])
	}
	if f.Remediation.Action != "" {
		// The note already reads as an action, so show it alone rather than
		// repeating the action and version.
		text := f.Remediation.Note
		if text == "" {
			text = f.Remediation.Action
			if f.Remediation.FixedVersion != "" {
				text += " to " + f.Remediation.FixedVersion
			}
		}
		line(w, "        [*] Fix          %s", text)
	}
	if f.KnownExploited != nil {
		text := "        [*] KEV          YES"
		if f.KnownExploited.DateAdded != "" {
			text += " (added " + f.KnownExploited.DateAdded + ")"
		}
		fmt.Fprintln(w, text)
	}
	if f.Enrichment != nil {
		if f.Enrichment.Mitigation != "" {
			line(w, "        [*] Mitigation   %s", f.Enrichment.Mitigation)
		}
		if f.Enrichment.PoCURL != "" {
			line(w, "        [*] PoC          %s", f.Enrichment.PoCURL)
		}
		if f.Enrichment.PatchCommitURL != "" {
			line(w, "        [*] Patch        %s", f.Enrichment.PatchCommitURL)
		}
	}
	if opts.Verbose && len(f.Why.Steps) > 0 {
		fmt.Fprintln(w, "        [-] Why")
		for _, s := range f.Why.Steps {
			line(w, "            - %s", s)
		}
	}
	if f.Status == domain.FindingStatusInconclusive {
		if f.Why.VersionMatch != "" {
			line(w, "        [!] Undecided    %s", f.Why.VersionMatch)
		}
		for _, step := range f.Why.Steps {
			line(w, "            - %s", step)
		}
		for _, q := range f.Why.Questions {
			line(w, "            ? %s", q)
		}
	}
	if len(f.Conflicts) > 0 {
		line(w, "        [!] Conflicts    sources disagree (%d kind(s))", len(f.Conflicts))
		for _, c := range f.Conflicts {
			for _, v := range c.Values {
				line(w, "            %s %s = %s", strings.ToUpper(string(c.Kind)), v.Source, v.Value)
			}
		}
	}
	line(w, "        [*] Evidence     %d", len(f.Evidence))
}

func renderHumanQuiet(w io.Writer, r domain.Report) error {
	if len(r.Findings) == 0 {
		line(w, "%s", strings.ToUpper(string(r.Decision)))
		return nil
	}
	for _, f := range r.Findings {
		line(w, "%s %s", f.VulnerabilityID, strings.ToUpper(string(f.Status)))
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
	line(w, "[!] Enrichment data: %s", attr)
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
