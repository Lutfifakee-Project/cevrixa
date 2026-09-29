package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/engine"
	"github.com/Lutfifakee-Project/cevrixa/internal/output"
	"github.com/Lutfifakee-Project/cevrixa/internal/source/kev"
)

type scanFlags struct {
	Input   string
	Output  string
	WithKEV bool
	FailOn  string
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

	opts := engine.Options{}
	if flags.WithKEV {
		cat, err := kev.LoadEmbedded()
		if err != nil {
			return fmt.Errorf("scan: load KEV catalog: %w", err)
		}
		opts.KEV = cat.Entries
	}

	reports := make([]domain.Report, 0, len(targets))
	for _, t := range targets {
		r, err := engine.Detect(t, opts)
		if err != nil {
			return fmt.Errorf("scan: detect %v: %w", t, err)
		}
		reports = append(reports, r)
	}

	switch flags.Output {
	case "", "human":
		return output.RenderScanHuman(os.Stdout, reports)
	case "json":
		return output.RenderScanJSON(os.Stdout, reports)
	case "jsonl":
		return output.RenderScanJSONL(os.Stdout, reports)
	case "sarif":
		return output.RenderScanSARIF(os.Stdout, reports, Version)
	default:
		return fmt.Errorf("scan: unsupported --output %q", flags.Output)
	}
}

func parseScanArgs(args []string) (scanFlags, error) {
	f := scanFlags{Input: "-", Output: "human"}

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Positional argument: input path or "-" for stdin.
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

		default:
			return f, fmt.Errorf("scan: unknown flag %q", key)
		}
	}

	switch f.Output {
	case "human", "json", "jsonl", "sarif":
	default:
		return f, fmt.Errorf("scan: unsupported --output %q (supported: human, json, jsonl, sarif)", f.Output)
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

	// Try JSON array first.
	var arr []domain.Target
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}

	// Fall back to JSONL (one object per line).
	var targets []domain.Target
	scanner := bufio.NewScanner(bytesReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		trimmed := trimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		var t domain.Target
		if err := json.Unmarshal(trimmed, &t); err != nil {
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

func bytesReader(b []byte) io.Reader {
	return &sliceReader{data: b}
}

type sliceReader struct {
	data []byte
	pos  int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\t' || b[start] == '\r' || b[start] == '\n') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\r' || b[end-1] == '\n') {
		end--
	}
	return b[start:end]
}

func printScanUsage() {
	fmt.Println(`Usage: cevrixa scan [input] [flags]

Read multiple targets from a file or stdin and detect affected vulnerabilities.

Arguments:
  input                Path to JSON or JSONL file (default: "-" for stdin)

Flags:
  --with-kev           Enrich findings with CISA KEV data
  --output <fmt>       Output format: human (default), json, jsonl, or sarif
  -h, --help           Show this help

Input formats:
  JSON array:          [{"product": "Apache HTTP Server", "version": "2.4.49"}]
  JSONL:               {"product": "Apache HTTP Server", "version": "2.4.49"}
                       {"purl": "pkg:pypi/django@4.2.0"}

Examples:
  echo '[{"product": "Apache HTTP Server", "version": "2.4.49"}]' | cevrixa scan -
  cevrixa scan targets.json
  cevrixa scan targets.json --output jsonl`)
}
