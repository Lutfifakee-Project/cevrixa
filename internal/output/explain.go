package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
)

// PackageExplain describes a package (PURL) applicability result in the
// renderer's own terms, so the output package does not need to depend on the
// engine.
type PackageExplain struct {
	Range     string
	Fixed     string
	Mode      string
	Undecided bool
	Reason    string
}

type ExplainReport struct {
	Vulnerability domain.Vulnerability
	Target        domain.Target
	TargetCPE     domain.CPE
	Match         matcher.Result
	Applicable    bool
	Fixed         string
	Confidence    string

	// Package is set when the target was a PURL and package applicability was
	// evaluated. Nil means the report is not a package evaluation.
	Package *PackageExplain

	// Why carries the reasoning built by the caller. When empty the renderer
	// falls back to matcher.BuildWhy for CPE reports.
	Why domain.Why

	// Evidence is the correlated evidence set for this vulnerability, including
	// evidence from other sources. Conflicts lists cross-source disagreements
	// found while correlating them. Both are optional.
	Evidence  []domain.Evidence
	Conflicts []domain.Conflict

	// NotEvaluated reports that applicability was never evaluated for this
	// target (for example an unresolved identity, or an unusable version). The
	// zero value means "was evaluated", so a report that simply carries a verdict
	// cannot silently become inconclusive.
	NotEvaluated bool
	// NotEvaluatedReason explains why no verdict could be produced.
	NotEvaluatedReason string
}

type ExplainDecision string

const (
	ExplainDecisionAffected     ExplainDecision = "affected"
	ExplainDecisionNotAffected  ExplainDecision = "not_affected"
	ExplainDecisionInconclusive ExplainDecision = "inconclusive"
)

// Decision derives the verdict. Inconclusive is returned whenever Cevrixa did
// not actually evaluate applicability, so that explain can never print
// NOT AFFECTED for a question it did not answer.
func (r ExplainReport) Decision() ExplainDecision {
	if r.NotEvaluated {
		return ExplainDecisionInconclusive
	}
	if r.Applicable {
		return ExplainDecisionAffected
	}
	return ExplainDecisionNotAffected
}

// DecisionLabel renders a decision for human output.
func (d ExplainDecision) Label() string {
	switch d {
	case ExplainDecisionAffected:
		return "AFFECTED"
	case ExplainDecisionNotAffected:
		return "NOT AFFECTED"
	default:
		return "INCONCLUSIVE"
	}
}

func RenderExplainHuman(w io.Writer, r ExplainReport) error {
	return RenderExplainHumanWithOptions(w, r, RenderOptions{})
}

func RenderExplainHumanWithOptions(w io.Writer, r ExplainReport, opts RenderOptions) error {
	if opts.Quiet {
		_, err := fmt.Fprintf(w, "%s %s\n",
			r.Vulnerability.ID,
			strings.ToUpper(string(r.Decision())),
		)
		return err
	}

	fmt.Fprintf(w, "[+] %s\n", r.Vulnerability.ID)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "    [+] Decision")
	fmt.Fprintf(w, "        [*] Status       %s\n", r.Decision().Label())
	if r.NotEvaluated {
		fmt.Fprintf(w, "        [!] No verdict was produced: %s\n", r.NotEvaluatedReason)
	} else if r.Confidence != "" {
		fmt.Fprintf(w, "        [*] Confidence   %s\n", strings.ToUpper(r.Confidence))
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "    [+] Identity")
	if r.Target.Product != "" {
		fmt.Fprintf(w, "        [*] Product      %s\n", r.Target.Product)
	}
	if r.Target.Version != "" {
		fmt.Fprintf(w, "        [*] Version      %s\n", r.Target.Version)
	}
	if r.Target.PURL != "" {
		fmt.Fprintf(w, "        [*] PURL         %s\n", r.Target.PURL)
	}
	if r.Target.ResolvedCPE != "" {
		fmt.Fprintf(w, "        [*] CPE          %s\n", r.Target.ResolvedCPE)
	}
	fmt.Fprintln(w)

	if r.Match.Criteria != "" {
		fmt.Fprintln(w, "    [+] Applicability")
		fmt.Fprintf(w, "        [*] Source       %s\n", r.Vulnerability.Source)
		if r.Match.Range != "" {
			fmt.Fprintf(w, "        [*] Range        %s\n", r.Match.Range)
		}
		fmt.Fprintf(w, "        [*] Criteria     %s\n", r.Match.Criteria)
		result := "NO MATCH"
		switch {
		case r.Match.Undecided:
			result = "UNDECIDED"
		case r.Applicable:
			result = "MATCH"
		}
		fmt.Fprintf(w, "        [*] Result       %s\n", result)
		if r.Match.Undecided && r.Match.Reason != "" {
			fmt.Fprintf(w, "        [!] Reason       %s\n", r.Match.Reason)
		}
		fmt.Fprintln(w)
	}

	if r.Package != nil {
		fmt.Fprintln(w, "    [+] Applicability")
		fmt.Fprintf(w, "        [*] Source       %s\n", r.Vulnerability.Source)
		if r.Package.Range != "" {
			fmt.Fprintf(w, "        [*] Range        %s\n", r.Package.Range)
		}
		result := "NO MATCH"
		switch {
		case r.Package.Undecided:
			result = "UNDECIDED"
		case r.Applicable:
			result = "MATCH"
		}
		fmt.Fprintf(w, "        [*] Result       %s\n", result)
		if r.Package.Undecided && r.Package.Reason != "" {
			fmt.Fprintf(w, "        [!] Reason       %s\n", r.Package.Reason)
		}
		fmt.Fprintln(w)
	}

	if r.Fixed != "" {
		fmt.Fprintln(w, "    [+] Fixed")
		fmt.Fprintf(w, "        [*] Version      %s\n", r.Fixed)
		fmt.Fprintln(w)
	}

	why := r.Why
	if len(why.Steps) == 0 && r.Package == nil {
		why = matcher.BuildWhy(r.TargetCPE, r.Match)
	}
	if len(why.Steps) > 0 {
		fmt.Fprintln(w, "    [+] Why")
		for _, step := range why.Steps {
			fmt.Fprintf(w, "        • %s\n", step)
		}
		fmt.Fprintln(w)
	}

	renderExplainEvidence(w, r)

	return nil
}

// renderExplainEvidence prints the evidence tree and any cross-source
// conflicts. Evidence is the first-class reasoning record, so it is shown
// alongside the references rather than replaced by them.
func renderExplainEvidence(w io.Writer, r ExplainReport) {
	if len(r.Evidence) > 0 {
		fmt.Fprintln(w, "    [+] Evidence")
		for _, e := range r.Evidence {
			line := "        [*] " + string(e.Kind)
			if e.Source != "" {
				line += " [" + e.Source + "]"
			}
			if v := evidenceValue(e); v != "" {
				line += " " + v
			}
			fmt.Fprintln(w, line)
		}
		fmt.Fprintln(w)
	}

	if len(r.Vulnerability.References) > 0 {
		fmt.Fprintln(w, "    [+] References")
		for _, ref := range r.Vulnerability.References {
			fmt.Fprintf(w, "        [*] [%s] %s\n", ref.Source, ref.URL)
		}
		fmt.Fprintln(w)
	}

	if len(r.Conflicts) > 0 {
		fmt.Fprintln(w, "    [+] Conflicts")
		for _, c := range r.Conflicts {
			fmt.Fprintf(w, "        [!] %s\n", c.Kind)
			for _, v := range c.Values {
				fmt.Fprintf(w, "            [%s] %s\n", v.Source, v.Value)
			}
		}
		fmt.Fprintln(w)
	}
}

// evidenceValue renders the human-readable value of an evidence item.
func evidenceValue(e domain.Evidence) string {
	if e.Value != "" {
		return e.Value
	}
	if e.Reference != nil {
		return e.Reference.URL
	}
	if e.Range != nil {
		return formatEvidenceRange(e.Range)
	}
	return ""
}

func formatEvidenceRange(r *domain.PackageRange) string {
	if len(r.Events) == 0 {
		return ""
	}
	parts := make([]string, 0, len(r.Events))
	for _, ev := range r.Events {
		switch {
		case ev.Introduced != "":
			parts = append(parts, ">="+ev.Introduced)
		case ev.Fixed != "":
			parts = append(parts, "<"+ev.Fixed)
		case ev.LastAffected != "":
			parts = append(parts, "<="+ev.LastAffected)
		}
	}
	return strings.Join(parts, " ")
}

func RenderExplainJSON(w io.Writer, r ExplainReport) error {
	type jsonOut struct {
		VulnerabilityID string             `json:"vulnerability_id"`
		Source          string             `json:"source"`
		Summary         string             `json:"summary,omitempty"`
		Decision        string             `json:"decision"`
		Undecided       bool               `json:"undecided,omitempty"`
		Reason          string             `json:"reason,omitempty"`
		Confidence      string             `json:"confidence"`
		Target          domain.Target      `json:"target"`
		Applicability   map[string]any     `json:"applicability,omitempty"`
		Fixed           string             `json:"fixed,omitempty"`
		References      []domain.Reference `json:"references,omitempty"`
		Why             domain.Why         `json:"why,omitempty"`
		Evidence        []domain.Evidence  `json:"evidence,omitempty"`
		Conflicts       []domain.Conflict  `json:"conflicts,omitempty"`
	}
	out := jsonOut{
		VulnerabilityID: r.Vulnerability.ID,
		Source:          r.Vulnerability.Source,
		Summary:         r.Vulnerability.Summary,
		Decision:        string(r.Decision()),
		Undecided:       r.Match.Undecided || r.NotEvaluated || r.undecidedPackage(),
		Reason:          r.reason(),
		Confidence:      r.Confidence,
		Target:          r.Target,
		Fixed:           r.Fixed,
		References:      r.Vulnerability.References,
		Why:             r.why(),
		Evidence:        r.Evidence,
		Conflicts:       r.Conflicts,
	}
	if r.Match.Criteria != "" {
		out.Applicability = map[string]any{
			"matched":  r.Applicable,
			"range":    r.Match.Range,
			"criteria": r.Match.Criteria,
			"source":   r.Vulnerability.Source,
		}
	} else if r.Package != nil {
		out.Applicability = map[string]any{
			"matched": r.Applicable,
			"range":   r.Package.Range,
			"mode":    r.Package.Mode,
			"source":  r.Vulnerability.Source,
		}
	}
	enc := newJSONEncoder(w)
	return enc.Encode(out)
}

func (r ExplainReport) why() domain.Why {
	if len(r.Why.Steps) != 0 {
		return r.Why
	}
	if r.Package != nil {
		return domain.Why{}
	}
	return matcher.BuildWhy(r.TargetCPE, r.Match)
}

func (r ExplainReport) undecidedPackage() bool {
	return r.Package != nil && r.Package.Undecided
}

// reason returns the single explanation for a report that could not be decided.
func (r ExplainReport) reason() string {
	if r.NotEvaluated {
		return r.NotEvaluatedReason
	}
	if r.Match.Undecided {
		return r.Match.Reason
	}
	if r.Package != nil && r.Package.Undecided {
		return r.Package.Reason
	}
	return ""
}
