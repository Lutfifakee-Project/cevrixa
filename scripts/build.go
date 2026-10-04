//go:build ignore

// Command build cross-compiles cevrixa for the supported platforms.
//
// Usage:
//
//	go run scripts/build.go                 # build for the host platform
//	go run scripts/build.go --all           # build every supported target
//	go run scripts/build.go --os linux --arch arm64
//
// Version metadata can be supplied through the VERSION, COMMIT and DATE
// environment variables; sensible defaults are used when they are absent.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type target struct {
	goos   string
	goarch string
}

// supported lists the platforms Cevrixa ships for. It covers the common
// server, desktop and CI environments; 32-bit and niche Unix targets are
// intentionally omitted.
var supported = []target{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
	{"windows", "arm64"},
}

const pkg = "./cmd/cevrixa"

func main() {
	all := flag.Bool("all", false, "build every supported target")
	goos := flag.String("os", runtime.GOOS, "target GOOS")
	goarch := flag.String("arch", runtime.GOARCH, "target GOARCH")
	out := flag.String("out", "bin", "output directory")
	flag.Parse()

	version := envOr("VERSION", "dev")
	commit := envOr("COMMIT", "none")
	date := envOr("DATE", time.Now().UTC().Format(time.RFC3339))

	targets := []target{{*goos, *goarch}}
	if *all {
		targets = supported
	}

	for _, t := range targets {
		if err := build(t, *out, version, commit, date); err != nil {
			fmt.Fprintln(os.Stderr, "build", t.goos, t.goarch, "failed:", err)
			os.Exit(1)
		}
	}
}

func build(t target, outDir, version, commit, date string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	outPath := filepath.Join(outDir, "cevrixa_"+t.goos+"_"+t.goarch+ext(t.goos))

	ldflags := "-s -w " +
		"-X github.com/Lutfifakee-Project/cevrixa/internal/cli.Version=" + version + " " +
		"-X github.com/Lutfifakee-Project/cevrixa/internal/cli.Commit=" + commit + " " +
		"-X github.com/Lutfifakee-Project/cevrixa/internal/cli.Date=" + date

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", outPath, pkg)
	cmd.Env = append(os.Environ(), "GOOS="+t.goos, "GOARCH="+t.goarch, "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Fprintln(os.Stdout, "building", t.goos+"/"+t.goarch, "->", outPath)
	return cmd.Run()
}

func ext(goos string) string {
	if goos == "windows" {
		return ".exe"
	}
	return ""
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
