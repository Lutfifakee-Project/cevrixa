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
}

func runDetect(args []string) error {
	flags, err := parseDetectArgs(args)
	if errors.Is(err, errHelpRequested) {
		return nil
	}
	if err != nil {
		return err
	}

	if flags.PURL != "" {
		return fmt.Errorf("detect: %w (PURL support is planned for a later milestone)", errNotImplemented)
	}

	target := domain.Target{
		Product: flags.Product,
		Version: flags.Version,
		CPE:     flags.CPE,
	}

	report, err := engine.Detect(target, engine.Options{})
	if err != nil {
		return fmt.Errorf("detect: %w", err)
	}

	switch flags.Output {
	case "", "human":
		return output.RenderHuman(os.Stdout, report)
	case "json":
		return output.RenderJSON(os.Stdout, report)
	default:
		return fmt.Errorf("detect: unsupported --output %q", flags.Output)
	}
}

func parseDetectArgs(args []string) (detectFlags, error) {
	var f detectFlags

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "-h" || arg == "--help" {
			printDetectUsage()
			return detectFlags{}, errHelpRequested
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
	case "", "human", "json":
	default:
		return fmt.Errorf("detect: unsupported --output %q (supported: human, json)", f.Output)
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
  --purl <purl>        Package URL (not yet implemented)
  --output <fmt>       Output format: human (default) or json
  -h, --help           Show this help

Examples:
  cevrixa detect --product "Apache HTTP Server" --version "2.4.49"
  cevrixa detect --cpe "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
  cevrixa detect --product "Apache HTTP Server" --version "2.4.49" --output json

Note: detection currently uses embedded sample fixtures, not live upstream
sources. Live NVD/OSV integration is planned for a later milestone.`)
}
