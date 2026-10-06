package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/engine"
	"github.com/Lutfifakee-Project/cevrixa/internal/output"
	"github.com/Lutfifakee-Project/cevrixa/internal/sbom"
)

var errHelpRequested = errors.New("help requested")

type detectFlags struct {
	Product  string
	Version  string
	CPE      string
	PURL     string
	SBOM     string
	Output   string
	WithKEV  bool
	FailOn   string
	DB       string
	DBSet    bool
	Snapshot string
	Stdin    bool
	NoSync   bool
	Verbose  bool
	Quiet    bool
	Trace    bool
}

func runDetect(args []string) error {
	flags, err := parseDetectArgs(args)
	if errors.Is(err, errHelpRequested) {
		return nil
	}
	if err != nil {
		return err
	}

	dbPath, err := resolveStorePath(flags.DB, flags.DBSet, flags.Snapshot)
	if err != nil {
		return fmt.Errorf("detect: %w", err)
	}

	// A snapshot is a frozen, self-contained dataset; never auto-sync into it.
	if flags.Snapshot == "" {
		if err := ensureDataset(dbPath, !flags.NoSync); err != nil {
			return fmt.Errorf("detect: %w", err)
		}
	}

	if flags.SBOM != "" {
		return detectSBOM(flags, dbPath)
	}

	target := domain.Target{
		Product: flags.Product,
		Version: flags.Version,
		CPE:     flags.CPE,
		PURL:    flags.PURL,
	}
	if flags.Stdin {
		t, err := readOneTarget(os.Stdin)
		if err != nil {
			return fmt.Errorf("detect: %w", err)
		}
		target = t
	}

	opts := engine.Options{Trace: flags.Trace}
	if flags.WithKEV {
		entries, _, err := loadKEV(true, dbPath)
		if err != nil {
			return fmt.Errorf("detect: %w", err)
		}
		opts.KEV = entries
	}

	s, err := openStoreIfDB(dbPath)
	if err != nil {
		return fmt.Errorf("detect: %w", err)
	}
	if s != nil {
		defer s.Close()
		opts.Store = s
	}

	report, err := engine.Detect(target, opts)
	if err != nil {
		return fmt.Errorf("detect: %w", err)
	}

	report.Dataset.Snapshot = flags.Snapshot
	if s != nil {
		if d, derr := s.Digest(); derr == nil {
			report.Dataset.Digest = d
		}
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

// detectSBOM runs detection for every component in an SBOM. It is the
// canonical way to feed an SBOM into Cevrixa: an SBOM is one input shape,
// alongside product, CPE, and PURL.
func detectSBOM(flags detectFlags, dbPath string) error {
	targets, err := sbom.ReadAnyFile(flags.SBOM)
	if err != nil {
		return fmt.Errorf("detect: %w", err)
	}

	opts := engine.Options{Trace: flags.Trace}
	if flags.WithKEV {
		entries, _, err := loadKEV(true, dbPath)
		if err != nil {
			return fmt.Errorf("detect: %w", err)
		}
		opts.KEV = entries
	}

	s, err := openStoreIfDB(dbPath)
	if err != nil {
		return fmt.Errorf("detect: %w", err)
	}
	if s != nil {
		defer s.Close()
		opts.Store = s
	}

	reports := make([]domain.Report, 0, len(targets))
	for _, t := range targets {
		r, err := engine.Detect(t, opts)
		if err != nil {
			return fmt.Errorf("detect: %v: %w", t, err)
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
		if err := output.RenderScanHumanWithOptions(os.Stdout, reports, output.RenderOptions{
			Verbose: flags.Verbose,
			Quiet:   flags.Quiet,
		}); err != nil {
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
		return fmt.Errorf("detect: unsupported --output %q", flags.Output)
	}

	if flags.FailOn != "" {
		for _, r := range reports {
			for _, f := range r.Findings {
				if f.IsSeverityAtLeast(flags.FailOn) {
					return fmt.Errorf("detect: fail-on %q triggered by %s", flags.FailOn, f.VulnerabilityID)
				}
			}
		}
	}
	return nil
}

// readOneTarget reads a single target JSON object, for "detect -". A JSON
// object is expected; an array is rejected so that the caller uses scan for
// multiple targets.
func readOneTarget(r io.Reader) (domain.Target, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return domain.Target{}, fmt.Errorf("read stdin: %w", err)
	}
	if len(raw) == 0 {
		return domain.Target{}, errors.New("empty input")
	}
	var t domain.Target
	if err := json.Unmarshal(raw, &t); err != nil {
		return domain.Target{}, fmt.Errorf("parse target: %w", err)
	}
	if t.Product == "" && t.CPE == "" && t.PURL == "" {
		return domain.Target{}, errors.New("target has no product, cpe, or purl")
	}
	return t, nil
}

func parseDetectArgs(args []string) (detectFlags, error) {
	var f detectFlags

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "-" {
			f.Stdin = true
			continue
		}
		if arg == "-h" || arg == "--help" {
			printDetectUsage()
			return detectFlags{}, errHelpRequested
		}
		if arg == "--with-kev" {
			f.WithKEV = true
			continue
		}
		if arg == "--no-sync" {
			f.NoSync = true
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
		if arg == "--trace" {
			f.Trace = true
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
		case "--sbom":
			f.SBOM = value
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
	if f.SBOM != "" {
		identityCount++
	}

	if f.Stdin {
		if identityCount != 0 {
			return errors.New("detect: use either - or an identity flag, not both")
		}
	} else {
		if identityCount == 0 {
			return errors.New("detect: one of --product, --cpe, --purl, --sbom, or - is required")
		}
	}
	if identityCount > 1 {
		return errors.New("detect: use only one of --product, --cpe, --purl, or --sbom")
	}
	if f.Product != "" && f.Version == "" {
		return errors.New("detect: --product requires --version")
	}
	if f.Product == "" && f.Version != "" {
		return errors.New("detect: --version requires --product")
	}
	if f.DBSet && f.Snapshot != "" {
		return errors.New("detect: use only one of --db or --snapshot")
	}
	switch f.Output {
	case "", "human", "json", "jsonl", "sarif":
	default:
		return fmt.Errorf("detect: unsupported --output %q (supported: human, json, jsonl, sarif)", f.Output)
	}
	if err := validateFailOn("detect", f.FailOn); err != nil {
		return err
	}
	return nil
}

func printDetectUsage() {
	fmt.Println("Usage: cevrixa detect [flags]")
	fmt.Println("       cevrixa detect -          (read one target JSON object from stdin)")
	fmt.Println()
	fmt.Println("Determine whether a target is affected by known vulnerabilities.")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  --product <name>     Product name (requires --version)")
	fmt.Println("  --version <ver>      Product version")
	fmt.Println("  --cpe <cpe>          CPE 2.3 identifier")
	fmt.Println("  --purl <purl>        Package URL (e.g. pkg:pypi/django@4.2.0)")
	fmt.Println("  --sbom <file>        Detect every component in a CycloneDX or SPDX SBOM")
	fmt.Println("  --with-kev           Enrich findings with CISA KEV data")
	fmt.Println("  --no-sync            Never prompt to sync; fail if the dataset is missing")
	fmt.Println("  --db <path>          SQLite database (default: ~/.cevrixa/cevrixa.db if exists)")
	fmt.Println("  --snapshot <name>    Read from a named snapshot instead of the live store")
	fmt.Println("  --fail-on <level>    Exit non-zero on a matching finding")
	fmt.Println("  --verbose            Show full reasoning steps")
	fmt.Println("  --quiet              Print only CVE-ID + status per finding")
	fmt.Println("  --trace              Show the decision trace behind the result")
	fmt.Println("  --output <fmt>       Output format: human (default), json, jsonl, or sarif")
	fmt.Println("  -h, --help           Show this help")
}
