package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/engine"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
	"github.com/Lutfifakee-Project/cevrixa/internal/output"
	"github.com/Lutfifakee-Project/cevrixa/internal/resolver"
)

type explainFlags struct {
	VulnID  string
	Product string
	Version string
	CPE     string
	PURL    string
	Output  string
	DB      string
	DBSet   bool
	Verbose bool
	Quiet   bool
	Trace   bool
}

func runExplain(args []string) error {
	flags, err := parseExplainArgs(args)
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

	switch flags.Output {
	case "", "human":
		return output.RenderExplainHumanWithOptions(os.Stdout, report, output.RenderOptions{
			Verbose: flags.Verbose,
			Quiet:   flags.Quiet,
		})
	case "json":
		return output.RenderExplainJSON(os.Stdout, report)
	default:
		return fmt.Errorf("explain: unsupported --output %q", flags.Output)
	}
}

// buildExplainReport resolves the target, finds the vulnerability, evaluates
// applicability, and collects the evidence. It is the single reasoning path
// shared by explain, why, and why-not, so the three cannot disagree.
func buildExplainReport(flags explainFlags) (output.ExplainReport, error) {
	trace := domain.Trace{}

	target := domain.Target{
		Product: flags.Product,
		Version: flags.Version,
		CPE:     flags.CPE,
		PURL:    flags.PURL,
	}

	r := resolver.New()
	res, err := r.Resolve(target)
	if err != nil {
		return output.ExplainReport{}, fmt.Errorf("explain: %w", err)
	}
	target.ResolvedCPE = res.CPE
	trace.Add("resolve identity", explainTraceStatus(res.CPE != "" || flags.PURL != ""), explainResolveDetail(target))

	dbPath := resolveDBPath(flags.DB, flags.DBSet)

	opts := engine.Options{}
	if s, err := openStoreIfDB(dbPath); err != nil {
		return output.ExplainReport{}, fmt.Errorf("explain: %w", err)
	} else if s != nil {
		defer s.Close()
		opts.Store = s
	}

	vuln, err := engine.FindByID(flags.VulnID, opts)
	if err != nil {
		return output.ExplainReport{}, fmt.Errorf("explain: %w (hint: run 'cevrixa sync nvd --days 30' or pass --db path)", err)
	}
	trace.Add("load vulnerability", domain.TraceOK, vuln.ID+" from "+vuln.Source)

	report := output.ExplainReport{
		Vulnerability: vuln,
		Target:        target,
	}

	switch {
	case flags.PURL != "":
		evaluatePURL(&report, target, vuln)
		trace.Add("evaluate package applicability", explainTraceStatus(!report.NotEvaluated), packageTraceDetail(report))
	case target.ResolvedCPE == "":
		report.NotEvaluated = true
		report.NotEvaluatedReason = "target identity could not be resolved to a CPE; pass --cpe or use a product present in the resolver catalog"
		trace.Add("evaluate applicability", domain.TraceSkipped, report.NotEvaluatedReason)
	default:
		targetCPE, err := domain.ParseCPE(target.ResolvedCPE)
		if err != nil {
			return output.ExplainReport{}, fmt.Errorf("explain: %w", err)
		}
		report.TargetCPE = targetCPE

		mr, matchErr := matcher.MatchCPE(targetCPE, vuln)
		report.Match = mr
		if matchErr != nil {
			report.NotEvaluated = true
			report.NotEvaluatedReason = matchErr.Error()
			trace.Add("evaluate applicability", domain.TraceWarn, matchErr.Error())
			break
		}
		report.Applicable = mr.Matched
		report.Fixed = mr.Fixed
		report.Confidence = string(engine.ConfidenceFromMode(mr.Mode))
		trace.Add("evaluate applicability", explainTraceStatus(mr.Matched), cpeTraceDetail(mr))

		if mr.Undecided {
			report.NotEvaluated = true
			report.NotEvaluatedReason = mr.Reason
		}
	}

	report.Evidence, report.Conflicts = engine.ExplainEvidence(vuln, opts)
	trace.Add("collect evidence", domain.TraceOK, fmt.Sprintf("%d item(s), %d conflict(s)", len(report.Evidence), len(report.Conflicts)))

	report.Trace = explainTraceIf(flags.Trace, trace)
	return report, nil
}

func explainTraceIf(enabled bool, t domain.Trace) domain.Trace {
	if !enabled {
		return domain.Trace{}
	}
	return t
}

func explainTraceStatus(ok bool) string {
	if ok {
		return domain.TraceOK
	}
	return domain.TraceWarn
}

func explainResolveDetail(target domain.Target) string {
	if target.ResolvedCPE != "" {
		return "resolved to " + target.ResolvedCPE
	}
	if target.PURL != "" {
		return "package " + target.PURL
	}
	return "target identity could not be resolved"
}

func cpeTraceDetail(mr matcher.Result) string {
	switch {
	case mr.Undecided:
		return "undecided"
	case mr.Matched:
		return "matched " + mr.Range
	default:
		return "no match"
	}
}

func packageTraceDetail(r output.ExplainReport) string {
	if r.Package == nil {
		return r.NotEvaluatedReason
	}
	if r.Package.Undecided {
		return "undecided"
	}
	if r.Applicable {
		return "matched " + r.Package.Range
	}
	return "no match"
}

// evaluatePURL fills the report from the package matcher. The package matcher
// is shared with detection, so explain and detect cannot disagree about a
// package target.
func evaluatePURL(report *output.ExplainReport, target domain.Target, vuln domain.Vulnerability) {
	pr, ok, err := engine.EvaluatePURL(target, vuln)
	if err != nil {
		report.NotEvaluated = true
		report.NotEvaluatedReason = err.Error()
		return
	}
	if !ok {
		report.NotEvaluated = true
		report.NotEvaluatedReason = "the vulnerability carries no package applicability for this target"
		return
	}

	report.Applicable = pr.Matched
	report.Fixed = pr.Fixed
	report.Confidence = string(engine.ConfidenceFromMode(pr.Mode))
	report.Package = &output.PackageExplain{
		Range:     pr.Range,
		Fixed:     pr.Fixed,
		Mode:      pr.Mode,
		Undecided: pr.Undecided,
		Reason:    pr.Reason,
	}
	if purl, perr := domain.ParsePURL(target.PURL); perr == nil {
		report.Why = engine.BuildPackageWhy(purl, pr)
	}
	if pr.Undecided {
		report.NotEvaluated = true
		report.NotEvaluatedReason = pr.Reason
	}
}

func parseExplainArgs(args []string) (explainFlags, error) {
	return parseTargetArgs(args, "explain")
}

// parseTargetArgs parses the flags shared by explain, why, and why-not. The
// command name is used in error messages so the user sees which command
// rejected the input.
func parseTargetArgs(args []string, command string) (explainFlags, error) {
	var f explainFlags

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "-h" || arg == "--help" {
			printTargetUsage(command)
			return explainFlags{}, errHelpRequested
		}
		if arg == "--verbose" {
			f.Verbose = true
			continue
		}
		if arg == "--quiet" {
			f.Quiet = true
			continue
		}
		if arg == "--trace" {
			f.Trace = true
			continue
		}

		if len(arg) > 0 && arg[0] != '-' {
			if f.VulnID == "" {
				f.VulnID = arg
				continue
			}
			return f, fmt.Errorf("%s: unexpected positional argument %q", command, arg)
		}

		key, value, hasInlineValue := splitFlag(arg)
		if !hasInlineValue {
			if i+1 >= len(args) {
				return f, fmt.Errorf("%s: flag %q requires a value", command, arg)
			}
			value = args[i+1]
			i++
		}

		switch key {
		case "--product":
			f.Product = value
		case "--version":
			f.Version = value
		case "--cpe":
			f.CPE = value
		case "--purl":
			f.PURL = value
		case "--output":
			f.Output = value
		case "--db":
			f.DB = value
			f.DBSet = true
		default:
			return f, fmt.Errorf("%s: unknown flag %q", command, key)
		}
	}

	if f.VulnID == "" {
		return f, fmt.Errorf("%s: vulnerability ID is required (e.g. CVE-2021-41773)", command)
	}
	identityCount := 0
	if f.Product != "" {
		identityCount++
	}
	if f.CPE != "" {
		identityCount++
	}
	if f.PURL != "" {
		identityCount++
	}
	if identityCount == 0 {
		return f, fmt.Errorf("%s: one of --product, --cpe, or --purl is required", command)
	}
	if identityCount > 1 {
		return f, fmt.Errorf("%s: use only one of --product, --cpe, or --purl", command)
	}
	if f.Product != "" && f.Version == "" {
		return f, fmt.Errorf("%s: --product requires --version", command)
	}
	switch f.Output {
	case "", "human", "json":
	default:
		return f, fmt.Errorf("%s: unsupported --output %q (supported: human, json)", command, f.Output)
	}
	return f, nil
}

func printTargetUsage(command string) {
	switch command {
	case "why":
		fmt.Println("Usage: cevrixa why " + vulnArg + " [flags]")
		fmt.Println()
		fmt.Println("Answer why a target is affected by a vulnerability.")
		fmt.Println("Takes the same flags as 'cevrixa explain'. If the target is not")
		fmt.Println("affected, why says so instead of inventing a reason.")
	case "why-not":
		fmt.Println("Usage: cevrixa why-not " + vulnArg + " [flags]")
		fmt.Println()
		fmt.Println("Answer why a target is not affected by a vulnerability.")
		fmt.Println("Takes the same flags as 'cevrixa explain'. If the target is affected,")
		fmt.Println("why-not says so instead of inventing a reason.")
	default:
		fmt.Println("Usage: cevrixa explain " + vulnArg + " [flags]")
		fmt.Println()
		fmt.Println("Explain why a vulnerability does or does not apply to a target.")
		fmt.Println()
		fmt.Println("Flags: --product NAME --version VER | --cpe CPE | --purl PURL")
		fmt.Println("       --db PATH --output human|json --verbose --quiet --trace -h")
	}
}

const vulnArg = "vuln-id"
