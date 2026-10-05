package cli

import (
	"fmt"
	"os"
)

func Run(args []string) error {
	if len(args) == 0 {
		writeBanner(os.Stdout)
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
	case "sbom":
		return runSBOM(args[1:])
	case "sync":
		return runSync(args[1:])
	case "explain":
		return runExplain(args[1:])
	case "why":
		return runWhy(args[1:])
	case "why-not":
		return runWhyNot(args[1:])
	case "snapshot":
		return runSnapshot(args[1:])
	case "info":
		return runInfo(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "help", "-h", "--help":
		writeBanner(os.Stdout)
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage() {
	fmt.Println(`Usage:
  cevrixa <command> [flags]

Commands:
  detect     Detect whether a single target is affected
  scan       Read multiple targets from a file or stdin
  sbom       Read a CycloneDX SBOM and detect affected components
  sync       Download and persist vulnerability data to local store
  explain    Explain why a vulnerability applies or not
  why        Answer why a target is affected
  why-not    Answer why a target is not affected
  snapshot   Create and list frozen intelligence snapshots
  info       Show environment and data status
  doctor     Run environment and data health checks
  version    Print version information
  help       Show this help message

Run 'cevrixa <command> --help' for more information on a command.`)
}
