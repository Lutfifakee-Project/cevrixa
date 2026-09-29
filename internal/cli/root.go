package cli

import (
	"errors"
	"fmt"
)

// Run dispatches a command-line invocation to the appropriate command.
func Run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "version":
		return runVersion(args[1:])
	case "detect":
		return runDetect(args[1:])
	case "scan":
		return runScan(args[1:])
	case "sync":
		return runSync(args[1:])
	case "sbom":
		return runSBOM(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage() {
	fmt.Println(`cevrixa — evidence-first vulnerability applicability engine

Usage:
  cevrixa <command> [flags]

Commands:
  detect     Detect whether a single target is affected
  scan       Read multiple targets from a file or stdin
  version    Print version information
  help       Show this help message

Run 'cevrixa <command> --help' for more information on a command.`)
}

var errNotImplemented = errors.New("not implemented in this milestone")
