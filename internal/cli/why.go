package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/Lutfifakee-Project/cevrixa/internal/output"
)

// runWhy answers "why is this target affected". It uses the same reasoning
// path as explain; when the target is not affected it says so rather than
// inventing a reason. The exit status stays zero: an unfulfilled question is an
// answer, not an error.
func runWhy(args []string) error {
	flags, err := parseTargetArgs(args, "why")
	if errors.Is(err, errHelpRequested) {
		return nil
	}
	if err != nil {
		return err
	}

	report, err := buildExplainReport(flags)
	if err != nil {
		return err
	}

	if report.Decision() != output.ExplainDecisionAffected {
		return renderWhyMismatch(os.Stdout, report, true)
	}
	return renderWhyReport(os.Stdout, report, flags)
}

// runWhyNot answers "why is this target not affected". It uses the same
// reasoning path as explain; when the target is affected it says so rather
// than inventing a reason.
func runWhyNot(args []string) error {
	flags, err := parseTargetArgs(args, "why-not")
	if errors.Is(err, errHelpRequested) {
		return nil
	}
	if err != nil {
		return err
	}

	report, err := buildExplainReport(flags)
	if err != nil {
		return err
	}

	if report.Decision() != output.ExplainDecisionNotAffected {
		return renderWhyMismatch(os.Stdout, report, false)
	}
	return renderWhyReport(os.Stdout, report, flags)
}

func renderWhyReport(w *os.File, report output.ExplainReport, flags explainFlags) error {
	return output.RenderExplainHumanWithOptions(w, report, output.RenderOptions{
		Verbose: flags.Verbose,
		Quiet:   flags.Quiet,
	})
}

// renderWhyMismatch states that the question asked does not match the verdict,
// so that why and why-not never manufacture a reason that contradicts the
// decision. It still prints the real decision and its explanation.
func renderWhyMismatch(w *os.File, report output.ExplainReport, wantAffected bool) error {
	real := string(report.Decision())
	if wantAffected {
		fmt.Fprintf(w, "this target is %s, not affected; there is no 'why it is affected' to give.\n", real)
	} else {
		fmt.Fprintf(w, "this target is %s, not 'not affected'; there is no 'why it is not affected' to give.\n", real)
	}
	fmt.Fprintln(w)
	return output.RenderExplainHumanWithOptions(w, report, output.RenderOptions{})
}
