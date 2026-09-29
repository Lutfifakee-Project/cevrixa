package cli

import (
	"errors"
	"fmt"
)

// errHelpRequested signals that --help was handled and Run should exit cleanly.
var errHelpRequested = errors.New("help requested")

type detectFlags struct {
	Product string
	Version string
	CPE     string
	PURL    string
}

func runDetect(args []string) error {
	flags, err := parseDetectArgs(args)
	if errors.Is(err, errHelpRequested) {
		return nil
	}
	if err != nil {
		return err
	}

	_ = flags
	return fmt.Errorf("detect: %w (detection engine is planned for a later milestone)", errNotImplemented)
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
	return nil
}

func printDetectUsage() {
	fmt.Println(`Usage: cevrixa detect [flags]

Identify a target for future vulnerability applicability analysis.

Flags:
  --product <name>     Product name (requires --version)
  --version <ver>      Product version
  --cpe <cpe>          CPE 2.3 identifier
  --purl <purl>        Package URL
  -h, --help           Show this help

Note: detection is intentionally not implemented yet. This command validates
input only and does not fabricate vulnerability results.`)
}
