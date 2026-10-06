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
	Input    string
	Output   string
	WithKEV  bool
	FailOn   string
	DB       string
	DBSet    bool
	Snapshot string
}

// runSBOM is kept for compatibility. The canonical way to feed an SBOM into
// Cevrixa is 'cevrixa detect --sbom <file>'.
//
// Deprecated: use 'cevrixa detect --sbom <file>' instead.
func runSBOM(args []string) error {
	flags, err := parseSBOMArgs(args)
	if errors.Is(err, errHelpRequested) {
		return nil
	}
	if err != nil {
		return err
	}

	warnDeprecated("sbom")

	targets, err := sbom.ReadAnyFile(flags.Input)
	if err != nil {
		return fmt.Errorf("sbom: %w", err)
	}

	dbPath, err := resolveStorePath(flags.DB, flags.DBSet, flags.Snapshot)
	if err != nil {
		return fmt.Errorf("sbom: %w", err)
	}

	opts := engine.Options{}
	if flags.WithKEV {
		entries, _, err := loadKEV(true, dbPath)
		if err != nil {
			return fmt.Errorf("sbom: %w", err)
		}
		opts.KEV = entries
	}

	s, err := openStoreIfDB(dbPath)
	if err != nil {
		return fmt.Errorf("sbom: %w", err)
	}
	if s != nil {
		defer s.Close()
		opts.Store = s
	}

	reports := make([]domain.Report, 0, len(targets))
	for _, t := range targets {
		r, err := engine.Detect(t, opts)
		if err != nil {
			return fmt.Errorf("sbom: detect %v: %w", t, err)
		}
		r.Dataset.Snapshot = flags.Snapshot
		if s != nil {
			if d, derr := s.Digest(); derr == nil {
				r.Dataset.Digest = d
			}
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
			f.DBSet = true
		case "--snapshot":
			f.Snapshot = value
		default:
			return f, fmt.Errorf("sbom: unknown flag %q", key)
		}
	}

	if f.DBSet && f.Snapshot != "" {
		return f, errors.New("sbom: use only one of --db or --snapshot")
	}
	switch f.Output {
	case "human", "json", "jsonl", "sarif":
	default:
		return f, fmt.Errorf("sbom: unsupported --output %q (supported: human, json, jsonl, sarif)", f.Output)
	}
	if err := validateFailOn("sbom", f.FailOn); err != nil {
		return f, err
	}
	return f, nil
}

func printSBOMUsage() {
	fmt.Println("Usage: cevrixa sbom [input] [flags]")
	fmt.Println()
	fmt.Println("Deprecated: prefer 'cevrixa detect --sbom <file>'.")
	fmt.Println()
	fmt.Println("Read an SBOM (CycloneDX or SPDX JSON) and detect vulnerabilities for")
	fmt.Println("every component that carries a PURL. The format is detected automatically.")
	fmt.Println()
	fmt.Println("Arguments:")
	fmt.Println("  input                Path to an SBOM JSON file (default: - for stdin)")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  --with-kev           Enrich findings with CISA KEV data")
	fmt.Println("  --db <path>          SQLite database (default: ~/.cevrixa/cevrixa.db if exists)")
	fmt.Println("  --snapshot <name>    Read from a named snapshot instead of the live store")
	fmt.Println("  --fail-on <level>    Exit non-zero on a matching finding")
	fmt.Println("  --output <fmt>       Output format: human (default), json, jsonl, or sarif")
	fmt.Println("  -h, --help           Show this help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  cevrixa detect --sbom app.cdx.json")
	fmt.Println("  cevrixa sbom app.cdx.json            (deprecated)")
}
