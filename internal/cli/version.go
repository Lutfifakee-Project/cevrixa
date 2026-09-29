package cli

import (
	"fmt"
	"runtime"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func runVersion(args []string) error {
	for _, arg := range args {
		switch arg {
		case "-h", "--help":
			fmt.Println("Usage: cevrixa version\n\nPrint Cevrixa version and build information.")
			return nil
		default:
			return fmt.Errorf("version: unknown argument %q", arg)
		}
	}

	fmt.Printf("cevrixa %s\n", Version)
	fmt.Printf("  commit:  %s\n", Commit)
	fmt.Printf("  built:   %s\n", Date)
	fmt.Printf("  go:      %s\n", runtime.Version())
	fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	return nil
}
