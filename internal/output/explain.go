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
}

func RenderExplainHuman(w io.Writer, r ExplainReport) error {
	return RenderExplainHumanWithOptions(w, r, RenderOptions{})
}

func RenderExplainHumanWithOptions(w io.Writer, r ExplainReport, opts RenderOptions) error {
	if opts.Quiet {
		decision := "NOT_AFFECTED"
		if r.Applicable {
			decision = "AFFECTED"
		}
		_, err := fmt.Fprintf(w, "%s %s\n", r.Vulnerability.ID, decision)
		return err
	}

	fmt.Fprintln(w, r.Vulnerability.ID)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Decision")
	decision := "NOT AFFECTED"
	if r.Applicable {
		decision = "AFFECTED"
	}
	fmt.Fprintf(w, "  %s\n", decision)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Identity")
	if r.Target.Product != "" {
		fmt.Fprintf(w, "  Product  : %s\n", r.Target.Product)
	}
	if r.Target.Version != "" {
		fmt.Fprintf(w, "  Version  : %s\n", r.Target.Version)
	}
	if r.Target.PURL != "" {
		fmt.Fprintf(w, "  PURL     : %s\n", r.Target.PURL)
	}
	if r.Target.ResolvedCPE != "" {
		fmt.Fprintf(w, "  CPE      : %s\n", r.Target.ResolvedCPE)
	}
	fmt.Fprintln(w)

	if r.Match.Criteria != "" {
		fmt.Fprintln(w, "Applicability")
		fmt.Fprintf(w, "  Source   : %s\n", r.Vulnerability.Source)
		if r.Match.Range != "" {
			fmt.Fprintf(w, "  Range    : %s\n", r.Match.Range)
		}
		fmt.Fprintf(w, "  Criteria : %s\n", r.Match.Criteria)
		result := "NO MATCH"
		if r.Applicable {
			result = "MATCH"
		}
		fmt.Fprintf(w, "  Result   : %s\n", result)
		fmt.Fprintln(w)
	}

	if r.Fixed != "" {
		fmt.Fprintln(w, "Fixed")
		fmt.Fprintf(w, "  %s\n", r.Fixed)
		fmt.Fprintln(w)
	}

	why := matcher.BuildWhy(r.TargetCPE, r.Match)
	if len(why.Steps) > 0 {
		fmt.Fprintln(w, "Why")
		for _, step := range why.Steps {
			fmt.Fprintf(w, "  - %s\n", step)
		}
		fmt.Fprintln(w)
	}

	if len(r.Vulnerability.References) > 0 {
		fmt.Fprintln(w, "Evidence")
		for _, ref := range r.Vulnerability.References {
			fmt.Fprintf(w, "  [%s] reference: %s\n", ref.Source, ref.URL)
		}
		fmt.Fprintln(w)
	}

	if r.Confidence != "" {
		fmt.Fprintln(w, "Confidence")
		fmt.Fprintf(w, "  %s\n", strings.ToUpper(r.Confidence))
	}
	return nil
}

func RenderExplainJSON(w io.Writer, r ExplainReport) error {
	type jsonOut struct {
		VulnerabilityID string             `json:"vulnerability_id"`
		Source          string             `json:"source"`
		Summary         string             `json:"summary,omitempty"`
		Decision        string             `json:"decision"`
		Confidence      string             `json:"confidence"`
		Target          domain.Target      `json:"target"`
		Applicability   map[string]any     `json:"applicability,omitempty"`
		Fixed           string             `json:"fixed,omitempty"`
		References      []domain.Reference `json:"references,omitempty"`
	}
	decision := "not_affected"
	if r.Applicable {
		decision = "affected"
	}
	out := jsonOut{
		VulnerabilityID: r.Vulnerability.ID,
		Source:          r.Vulnerability.Source,
		Summary:         r.Vulnerability.Summary,
		Decision:        decision,
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
