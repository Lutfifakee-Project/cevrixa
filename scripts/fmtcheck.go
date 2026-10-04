//go:build ignore

// Command fmtcheck fails when any Go file in the tree is not gofmt-clean.
// It is implemented in Go so it runs identically on every platform, without
// relying on a Unix shell or external tools.
package main

import (
	"fmt"
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var unformatted []string

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		formatted, err := format.Source(src)
		if err != nil {
			unformatted = append(unformatted, path+" parse error: "+err.Error())
			return nil
		}
		if string(formatted) != string(src) {
			unformatted = append(unformatted, path)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fmtcheck:", err)
		os.Exit(2)
	}

	if len(unformatted) > 0 {
		fmt.Fprintln(os.Stderr, "not gofmt-clean:")
		for _, p := range unformatted {
			fmt.Fprintln(os.Stderr, "  "+p)
		}
		os.Exit(1)
	}
	fmt.Println("gofmt clean")
}
