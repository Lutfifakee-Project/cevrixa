package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
)

// ExplainReport bundles everything the explain formatter needs.
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
	if _, err := fmt.Fprintln(w, r.Vulnerability.ID); err != nil {
		return err
	}
	fmt.Fprintln(w)

	if _, err := fmt.Fprintln(w, "Decision"); err != nil {
		return err
	}
	decision := "NOT AFFECTED"
	if r.Applicable {
		decision = "AFFECTED"
	}
	fmt.Fprintf(w, "  %s\n", decision)
	fmt.Fprintln(w)

	if _, err := fmt.Fprintln(w, "Identity"); err != nil {
		return err
	}
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
		if _, err := fmt.Fprintln(w, "Applicability"); err != nil {
			return err
		}
		fmt.Fprintf(w, "  Source   : %s\n", r.Vulnerability.Source)
		if r.Match.Range != "" {
			fmt.Fprintf(w, "  Range    : %s\n", r.Match.Range)
		}
		if r.Match.Criteria != "" {
			fmt.Fprintf(w, "  Criteria : %s\n", r.Match.Criteria)
		}
		result := "NO MATCH"
		if r.Applicable {
			result = "MATCH"
		}
		fmt.Fprintf(w, "  Result   : %s\n", result)
		fmt.Fprintln(w)
	}

	if r.Fixed != "" {
		if _, err := fmt.Fprintln(w, "Fixed"); err != nil {
			return err
		}
		fmt.Fprintf(w, "  %s\n", r.Fixed)
		fmt.Fprintln(w)
	}

	why := matcher.BuildWhy(r.TargetCPE, r.Match)
	if len(why.Steps) > 0 {
		if _, err := fmt.Fprintln(w, "Why"); err != nil {
			return err
		}
		for _, step := range why.Steps {
			fmt.Fprintf(w, "  - %s\n", step)
		}
		fmt.Fprintln(w)
	}

	if len(r.Vulnerability.References) > 0 {
		if _, err := fmt.Fprintln(w, "Evidence"); err != nil {
			return err
		}
		for _, ref := range r.Vulnerability.References {
			fmt.Fprintf(w, "  [%s] reference: %s\n", ref.Source, ref.URL)
		}
		fmt.Fprintln(w)
	}

	if r.Confidence != "" {
		if _, err := fmt.Fprintln(w, "Confidence"); err != nil {
			return err
		}
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
