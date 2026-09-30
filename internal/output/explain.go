package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
)

type ExplainReport struct {
	Vulnerability domain.Vulnerability
	Target        domain.Target
	TargetCPE     domain.CPE
	Match         matcher.Result
	Applicable    bool
	Fixed         string
	Confidence    string

	// NotEvaluated reports that applicability was never evaluated for this
	// target (for example a package target, an unresolved identity, or an
	// unusable version). The zero value means "was evaluated", so a report that
	// simply carries a verdict cannot silently become inconclusive.
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

	if r.Fixed != "" {
		fmt.Fprintln(w, "    [+] Fixed")
		fmt.Fprintf(w, "        [*] Version      %s\n", r.Fixed)
		fmt.Fprintln(w)
	}

	why := matcher.BuildWhy(r.TargetCPE, r.Match)
	if len(why.Steps) > 0 {
		fmt.Fprintln(w, "    [+] Why")
		for _, step := range why.Steps {
			fmt.Fprintf(w, "        • %s\n", step)
		}
		fmt.Fprintln(w)
	}

	if len(r.Vulnerability.References) > 0 {
		fmt.Fprintln(w, "    [+] Evidence")
		for _, ref := range r.Vulnerability.References {
			fmt.Fprintf(w, "        [*] [%s] %s\n", ref.Source, ref.URL)
		}
		fmt.Fprintln(w)
	}

	return nil
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
	}
	out := jsonOut{
		VulnerabilityID: r.Vulnerability.ID,
		Source:          r.Vulnerability.Source,
		Summary:         r.Vulnerability.Summary,
		Decision:        string(r.Decision()),
		Undecided:       r.Match.Undecided || r.NotEvaluated,
		Reason:          r.reason(),
		Confidence:      r.Confidence,
		Target:          r.Target,
		Fixed:           r.Fixed,
		References:      r.Vulnerability.References,
	}
	if r.Match.Criteria != "" {
		out.Applicability = map[string]any{
			"matched":  r.Applicable,
			"range":    r.Match.Range,
			"criteria": r.Match.Criteria,
			"source":   r.Vulnerability.Source,
		}
	}
	enc := newJSONEncoder(w)
	return enc.Encode(out)
}

// reason returns the single explanation for a report that could not be decided.
func (r ExplainReport) reason() string {
	if r.NotEvaluated {
		return r.NotEvaluatedReason
	}
	if r.Match.Undecided {
		return r.Match.Reason
	}
	return ""
}
