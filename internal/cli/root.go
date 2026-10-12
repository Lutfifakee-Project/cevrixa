package cli

import (
	"fmt"
	"os"
)

func Run(args []string) error {
	if len(args) == 0 {
		writeBanner(os.Stdout)
		printQuickHelp()
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
		return runHelp(args[1:])
	default:
		printUsage()
		return fmt.Errorf("unknown command %q (run 'cevrixa help' for the command list)", args[0])
	}
}

// runHelp prints general help, or the help of a named command. Routing the
// command's own --help through the same parser keeps a single source of truth
// for every usage text.
func runHelp(args []string) error {
	if len(args) == 0 {
		writeBanner(os.Stdout)
		printUsage()
		return nil
	}

	topic := args[0]
	switch topic {
	case "detect", "scan", "sbom", "sync", "explain", "why", "why-not", "snapshot", "info", "doctor", "version":
		return Run([]string{topic, "--help"})
	default:
		printUsage()
		return fmt.Errorf("help: unknown topic %q", topic)
	}
}

// printQuickHelp is shown when Cevrixa is run with no arguments. It leads with
// copy-pasteable examples so a new user can act without reading the full usage.
func printQuickHelp() {
	fmt.Println("Know why a vulnerability applies.")
	fmt.Println()
	fmt.Println("Quick start:")
	fmt.Println("  cevrixa detect nginx 1.24.0")
	fmt.Println("  cevrixa detect pkg:pypi/django@4.2.0")
	fmt.Println("  cevrixa detect --sbom app.cdx.json")
	fmt.Println("  cevrixa explain CVE-2021-41773 --product nginx --version 1.24.0")
	fmt.Println("  cevrixa sync")
	fmt.Println()
	fmt.Println("Run 'cevrixa help' for all commands, or 'cevrixa help <command>' for one.")
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
	fmt.Println("Run 'cevrixa help <command>' or 'cevrixa <command> --help' for details.")
}
