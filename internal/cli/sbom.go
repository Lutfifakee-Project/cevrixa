package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/engine"
	"github.com/Lutfifakee-Project/cevrixa/internal/output"
	"github.com/Lutfifakee-Project/cevrixa/internal/sbom"
)

type sbomFlags struct {
	Input   string
	Output  string
	WithKEV bool
	FailOn  string
	DB      string
}

func runSBOM(args []string) error {
	flags, err := parseSBOMArgs(args)
	if errors.Is(err, errHelpRequested) {
		return nil
	}
	if err != nil {
		return err
	}

	targets, err := sbom.ReadCycloneDXFile(flags.Input)
	if err != nil {
		return fmt.Errorf("sbom: %w", err)
	}

	dbPath := resolveDBPath(flags.DB)

	opts := engine.Options{}
	if flags.WithKEV {
		entries, src, err := loadKEV(true, dbPath)
		if err != nil {
			return fmt.Errorf("sbom: %w", err)
		}
		opts.KEV = entries
		opts.Source = src
	}

	if s, err := openStoreIfDB(dbPath); err != nil {
		return fmt.Errorf("sbom: %w", err)
	} else if s != nil {
		defer s.Close()
		opts.Store = s
	}
	if s, err := openStoreIfDB(flags.DB); err != nil {
		return fmt.Errorf("sbom: %w", err)
	} else if s != nil {
		defer s.Close()
		opts.Store = s
	}

	reports := make([]domain.Report, 0, len(targets))
	for _, t := range targets {
		r, err := engine.Detect(t, opts)
		if err != nil {
			return fmt.Errorf("sbom: detect %v: %w", t, err)
		}
		reports = append(reports, r)
	}

	switch flags.Output {
	case "", "human":
		if err := output.RenderScanHuman(os.Stdout, reports); err != nil {
			return err
		}
	case "json":
		if err := output.RenderScanJSON(os.Stdout, reports); err != nil {
			return err
		}
	case "jsonl":
		if err := output.RenderScanJSONL(os.Stdout, reports); err != nil {
			return err
		}
	case "sarif":
		if err := output.RenderScanSARIF(os.Stdout, reports, Version); err != nil {
			return err
		}
	default:
		return fmt.Errorf("sbom: unsupported --output %q", flags.Output)
	}

	if flags.FailOn != "" {
		for _, r := range reports {
			for _, f := range r.Findings {
				if f.IsSeverityAtLeast(flags.FailOn) {
					return fmt.Errorf("sbom: fail-on %q triggered by %s", flags.FailOn, f.VulnerabilityID)
				}
			}
		}
	}
	return nil
}

func parseSBOMArgs(args []string) (sbomFlags, error) {
	f := sbomFlags{Input: "-", Output: "human"}

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "-" || (len(arg) > 0 && arg[0] != '-') {
			f.Input = arg
			continue
		}
		if arg == "-h" || arg == "--help" {
			printSBOMUsage()
			return sbomFlags{}, errHelpRequested
		}
		if arg == "--with-kev" {
			f.WithKEV = true
			continue
		}

		key, value, hasInlineValue := splitFlag(arg)
		if !hasInlineValue {
			if i+1 >= len(args) {
				return f, fmt.Errorf("sbom: flag %q requires a value", arg)
			}
			value = args[i+1]
			i++
		}

		switch key {
		case "--output":
			f.Output = value
		case "--fail-on":
			f.FailOn = value
		case "--db":
			f.DB = value
		default:
			return f, fmt.Errorf("sbom: unknown flag %q", key)
		}
	}

	switch f.Output {
	case "human", "json", "jsonl", "sarif":
	default:
		return f, fmt.Errorf("sbom: unsupported --output %q (supported: human, json, jsonl, sarif)", f.Output)
	}
	return f, nil
}

func printSBOMUsage() {
	fmt.Println(`Usage: cevrixa sbom [input] [flags]

Read a CycloneDX SBOM and detect vulnerabilities for every component
that carries a PURL.

Arguments:
  input                Path to CycloneDX JSON (default: "-" for stdin)

Flags:
  --with-kev           Enrich findings with CISA KEV data
  --db <path>          Read KEV from SQLite database (default: embedded)
  --fail-on <level>    Exit non-zero if any finding matches: any, affected, kev
  --output <fmt>       Output format: human (default), json, jsonl, or sarif
  -h, --help           Show this help

Examples:
  cevrixa sbom app.cdx.json
  cevrixa sbom - < app.cdx.json --output sarif
  cevrixa sbom app.cdx.json --fail-on affected --with-kev`)
}
