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
	fmt.Println("Usage:")
	fmt.Println("  cevrixa <command> [flags]")
	fmt.Println()
	fmt.Println("Primary:")
	fmt.Println("  detect     Detect whether a target is affected (product, CPE, PURL, or SBOM)")
	fmt.Println("  explain    Explain why a vulnerability does or does not apply")
	fmt.Println()
	fmt.Println("Bulk and data:")
	fmt.Println("  scan       Read multiple targets from a file or stdin")
	fmt.Println("  sync       Sync vulnerability data (default: all sources)")
	fmt.Println()
	fmt.Println("Diagnostics:")
	fmt.Println("  doctor     Run environment and data health checks")
	fmt.Println("  info       Show environment and data status")
	fmt.Println("  version    Print version information")
	fmt.Println()
	fmt.Println("Advanced:")
	fmt.Println("  snapshot   Create and list frozen intelligence snapshots")
	fmt.Println("  sbom       Deprecated: use 'cevrixa detect --sbom <file>'")
	fmt.Println()
	fmt.Println("Run 'cevrixa <command> --help' for more information on a command.")
}
