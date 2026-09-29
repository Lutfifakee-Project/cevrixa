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
	Verbose bool
	Quiet   bool
}

func runExplain(args []string) error {
	flags, err := parseExplainArgs(args)
	if errors.Is(err, errHelpRequested) {
		return nil
	}
	if err != nil {
		return err
	}

	target := domain.Target{
		Product: flags.Product,
		Version: flags.Version,
		CPE:     flags.CPE,
		PURL:    flags.PURL,
	}

	r := resolver.New()
	res, err := r.Resolve(target)
	if err != nil {
		return fmt.Errorf("explain: %w", err)
	}
	target.ResolvedCPE = res.CPE

	dbPath := resolveDBPath(flags.DB)

	opts := engine.Options{}
	if s, err := openStoreIfDB(dbPath); err != nil {
		return fmt.Errorf("explain: %w", err)
	} else if s != nil {
		defer s.Close()
		opts.Store = s
	}

	vuln, err := engine.FindByID(flags.VulnID, opts)
	if err != nil {
		return fmt.Errorf("explain: %w", err)
	}

	report := output.ExplainReport{
		Vulnerability: vuln,
		Target:        target,
	}

	if target.ResolvedCPE != "" {
		targetCPE, err := domain.ParseCPE(target.ResolvedCPE)
		if err != nil {
			return fmt.Errorf("explain: %w", err)
		}
		report.TargetCPE = targetCPE

		mr, _ := matcher.MatchCPE(targetCPE, vuln)
		report.Match = mr
		report.Applicable = mr.Matched
		report.Fixed = mr.Fixed
		report.Confidence = string(engine.ConfidenceFromMode(mr.Mode))
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

func parseExplainArgs(args []string) (explainFlags, error) {
	var f explainFlags

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "-h" || arg == "--help" {
			printExplainUsage()
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

		if len(arg) > 0 && arg[0] != '-' {
			if f.VulnID == "" {
				f.VulnID = arg
				continue
			}
			return f, fmt.Errorf("explain: unexpected positional argument %q", arg)
		}

		key, value, hasInlineValue := splitFlag(arg)
		if !hasInlineValue {
			if i+1 >= len(args) {
				return f, fmt.Errorf("explain: flag %q requires a value", arg)
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
		default:
			return f, fmt.Errorf("explain: unknown flag %q", key)
		}
	}

	if f.VulnID == "" {
		return f, errors.New("explain: vulnerability ID is required (e.g. CVE-2021-41773)")
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
		return f, errors.New("explain: one of --product, --cpe, or --purl is required")
	}
	if identityCount > 1 {
		return f, errors.New("explain: use only one of --product, --cpe, or --purl")
	}
	if f.Product != "" && f.Version == "" {
		return f, errors.New("explain: --product requires --version")
	}
	switch f.Output {
	case "", "human", "json":
	default:
		return f, fmt.Errorf("explain: unsupported --output %q (supported: human, json)", f.Output)
	}
	return f, nil
}

func printExplainUsage() {
	fmt.Println(`Usage: cevrixa explain <vulnerability-id> [flags]

Explain why a vulnerability does or does not apply to a specific target.

Arguments:
  vulnerability-id     CVE, GHSA, or alias (e.g. CVE-2021-41773)

Flags:
  --product <name>     Product name (requires --version)
  --version <ver>      Product version
  --cpe <cpe>          CPE 2.3 identifier
  --purl <purl>        Package URL
  --db <path>          Read from SQLite database (default: embedded)
  --verbose            Show full reasoning steps
  --quiet              Print only ID + decision
  --output <fmt>       Output format: human (default) or json
  -h, --help           Show this help

Examples:
  cevrixa explain CVE-2021-41773 --product "Apache HTTP Server" --version "2.4.49"
  cevrixa explain CVE-2021-41773 --cpe "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
  cevrixa explain CVE-2021-41773 --product "Apache HTTP Server" --version "2.4.49" --quiet`)
}
