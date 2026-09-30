package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/engine"
	"github.com/Lutfifakee-Project/cevrixa/internal/output"
)

var errHelpRequested = errors.New("help requested")

type detectFlags struct {
	Product string
	Version string
	CPE     string
	PURL    string
	Output  string
	WithKEV bool
	FailOn  string
	DB      string
	DBSet   bool
	Verbose bool
	Quiet   bool
}

func runDetect(args []string) error {
	flags, err := parseDetectArgs(args)
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

	dbPath := resolveDBPath(flags.DB, flags.DBSet)

	opts := engine.Options{}
	if flags.WithKEV {
		entries, src, err := loadKEV(true, dbPath)
		if err != nil {
			return fmt.Errorf("detect: %w", err)
		}
		opts.KEV = entries
		opts.Source = src
	}

	if s, err := openStoreIfDB(dbPath); err != nil {
		return fmt.Errorf("detect: %w", err)
	} else if s != nil {
		defer s.Close()
		opts.Store = s
	}

	report, err := engine.Detect(target, opts)
	if err != nil {
		return fmt.Errorf("detect: %w", err)
	}

	var renderErr error
	switch flags.Output {
	case "", "human":
		renderErr = output.RenderHumanWithOptions(os.Stdout, report, output.RenderOptions{
			Verbose: flags.Verbose,
			Quiet:   flags.Quiet,
		})
	case "json":
		renderErr = output.RenderJSON(os.Stdout, report)
	case "jsonl":
		renderErr = output.RenderJSONL(os.Stdout, report)
	case "sarif":
		renderErr = output.RenderSARIF(os.Stdout, report, Version)
	default:
		return fmt.Errorf("detect: unsupported --output %q", flags.Output)
	}
	if renderErr != nil {
		return renderErr
	}

	if flags.FailOn != "" {
		for _, f := range report.Findings {
			if f.IsSeverityAtLeast(flags.FailOn) {
				return fmt.Errorf("detect: fail-on %q triggered by %s", flags.FailOn, f.VulnerabilityID)
			}
		}
	}
	return nil
}

func parseDetectArgs(args []string) (detectFlags, error) {
	var f detectFlags

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "-h" || arg == "--help" {
			printDetectUsage()
			return detectFlags{}, errHelpRequested
		}
		if arg == "--with-kev" {
			f.WithKEV = true
			continue
		}
		if arg == "--verbose" {
			f.Verbose = true
			continue
		}
		if arg == "--quiet" {
			f.Quiet = true
			continue
		}

		key, value, hasInlineValue := splitFlag(arg)
		if !hasInlineValue {
			if i+1 >= len(args) {
				return f, fmt.Errorf("detect: flag %q requires a value", arg)
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
		case "--fail-on":
			f.FailOn = value
		case "--db":
			f.DB = value
			f.DBSet = true
		default:
			return f, fmt.Errorf("detect: unknown flag %q", key)
		}
	}

	if err := validateDetectFlags(f); err != nil {
		return f, err
	}
	return f, nil
}

func splitFlag(arg string) (key, value string, hasValue bool) {
	for i := 0; i < len(arg); i++ {
		if arg[i] == '=' {
			return arg[:i], arg[i+1:], true
		}
	}
	return arg, "", false
}

func validateDetectFlags(f detectFlags) error {
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
		return errors.New("detect: one of --product, --cpe, or --purl is required")
	}
	if identityCount > 1 {
		return errors.New("detect: use only one of --product, --cpe, or --purl")
	}
	if f.Product != "" && f.Version == "" {
		return errors.New("detect: --product requires --version")
	}
	if f.Product == "" && f.Version != "" {
		return errors.New("detect: --version requires --product")
	}
	switch f.Output {
	case "", "human", "json", "jsonl", "sarif":
	default:
		return fmt.Errorf("detect: unsupported --output %q (supported: human, json, jsonl, sarif)", f.Output)
	}
	if f.FailOn != "" && !domain.ValidGate(f.FailOn) {
		// A typo here used to disable the CI gate silently, exiting 0 on a
		// vulnerable target. Validate instead of ignoring.
		return fmt.Errorf(
			"detect: unsupported --fail-on %q (supported: none, any, affected, inconclusive, kev, low, medium, high, critical)",
			f.FailOn,
		)
	}
	return nil
}

func printDetectUsage() {
	fmt.Println(`Usage: cevrixa detect [flags]

Determine whether a target is affected by known vulnerabilities.

Flags:
  --product <name>     Product name (requires --version)
  --version <ver>      Product version
  --cpe <cpe>          CPE 2.3 identifier
  --purl <purl>        Package URL (e.g. pkg:pypi/django@4.2.0)
  --with-kev           Enrich findings with CISA KEV data
  --db <path>          SQLite database (default: ~/.cevrixa/cevrixa.db if exists)
  --fail-on <level>    Exit non-zero if any finding matches: none, any, affected, inconclusive, kev, or a severity (low, medium, high, critical)
  --verbose            Show full reasoning steps
  --quiet              Print only CVE-ID + status per finding
  --output <fmt>       Output format: human (default), json, jsonl, or sarif
  -h, --help           Show this help

Examples:
  cevrixa detect --product "Apache HTTP Server" --version "2.4.49"
  cevrixa detect --purl "pkg:pypi/django@4.2.0"
  cevrixa detect --product "Apache HTTP Server" --version "2.4.49" --verbose`)
}
