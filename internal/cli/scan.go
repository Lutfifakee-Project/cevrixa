package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/engine"
	"github.com/Lutfifakee-Project/cevrixa/internal/output"
)

type scanFlags struct {
	Input    string
	Output   string
	WithKEV  bool
	FailOn   string
	DB       string
	DBSet    bool
	Snapshot string
	Verbose  bool
	Quiet    bool
}

func runScan(args []string) error {
	flags, err := parseScanArgs(args)
	if errors.Is(err, errHelpRequested) {
		return nil
	}
	if err != nil {
		return err
	}

	targets, err := readTargets(flags.Input)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	dbPath, err := resolveStorePath(flags.DB, flags.DBSet, flags.Snapshot)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	opts := engine.Options{}
	if flags.WithKEV {
		entries, _, err := loadKEV(true, dbPath)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		opts.KEV = entries
	}

	s, err := openStoreIfDB(dbPath)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	if s != nil {
		defer s.Close()
		opts.Store = s
	}

	reports := make([]domain.Report, 0, len(targets))
	for _, t := range targets {
		r, err := engine.Detect(t, opts)
		if err != nil {
			return fmt.Errorf("scan: detect %v: %w", t, err)
		}
		r.Dataset.Snapshot = flags.Snapshot
		r.Dataset.EngineVersion = Version
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
		return fmt.Errorf("scan: unsupported --output %q", flags.Output)
	}

	if flags.FailOn != "" {
		for _, r := range reports {
			for _, f := range r.Findings {
				if f.IsSeverityAtLeast(flags.FailOn) {
					return fmt.Errorf("scan: fail-on %q triggered by %s", flags.FailOn, f.VulnerabilityID)
				}
			}
		}
	}
	return nil
}

func parseScanArgs(args []string) (scanFlags, error) {
	f := scanFlags{Input: "-", Output: "human"}

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "-" || (len(arg) > 0 && arg[0] != '-') {
			f.Input = arg
			continue
		}
		if arg == "-h" || arg == "--help" {
			printScanUsage()
			return scanFlags{}, errHelpRequested
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
				return f, fmt.Errorf("scan: flag %q requires a value", arg)
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
			return f, fmt.Errorf("scan: unknown flag %q", key)
		}
	}

	if f.DBSet && f.Snapshot != "" {
		return f, errors.New("scan: use only one of --db or --snapshot")
	}
	switch f.Output {
	case "human", "json", "jsonl", "sarif":
	default:
		return f, fmt.Errorf("scan: unsupported --output %q (supported: human, json, jsonl, sarif)", f.Output)
	}
	if err := validateFailOn("scan", f.FailOn); err != nil {
		return f, err
	}
	return f, nil
}

func readTargets(input string) ([]domain.Target, error) {
	var reader io.Reader
	if input == "-" || input == "" {
		reader = os.Stdin
	} else {
		f, err := os.Open(input)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", input, err)
		}
		defer f.Close()
		reader = f
	}

	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("empty input")
	}

	var arr []domain.Target
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}

	var targets []domain.Target
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var t domain.Target
		if err := json.Unmarshal(line, &t); err != nil {
			return nil, fmt.Errorf("parse line: %w", err)
		}
		targets = append(targets, t)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan input: %w", err)
	}
	if len(targets) == 0 {
		return nil, errors.New("no targets parsed")
	}
	return targets, nil
}

func printScanUsage() {
	fmt.Println("Usage: cevrixa scan [input] [flags]")
	fmt.Println()
	fmt.Println("Read multiple targets from a file or stdin and detect affected")
	fmt.Println("vulnerabilities.")
	fmt.Println()
	fmt.Println("Arguments:")
	fmt.Println("  input                Path to JSON or JSONL file (default: - for stdin)")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  --with-kev           Enrich findings with CISA KEV data")
	fmt.Println("  --db <path>          SQLite database (default: ~/.cevrixa/cevrixa.db if exists)")
	fmt.Println("  --snapshot <name>    Read from a named snapshot instead of the live store")
	fmt.Println("  --fail-on <level>    Exit non-zero on a matching finding")
	fmt.Println("  --verbose            Show full reasoning steps")
	fmt.Println("  --quiet              Print only CVE-ID + status per finding")
	fmt.Println("  --output <fmt>       Output format: human (default), json, jsonl, or sarif")
	fmt.Println("  -h, --help           Show this help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  cevrixa scan targets.json")
	fmt.Println("  cevrixa scan targets.json --with-kev")
	fmt.Println("  cevrixa scan targets.json --snapshot 2026-09-30")
}
