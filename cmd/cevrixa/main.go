package main

import (
	"fmt"
	"os"

	"github.com/Lutfifakee-Project/cevrixa/internal/cli"
	"github.com/Lutfifakee-Project/cevrixa/internal/config"
	"github.com/Lutfifakee-Project/cevrixa/internal/logging"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		// Config errors are non-fatal; fall back to defaults.
		fmt.Fprintf(os.Stderr, "cevrixa: warning: %v\n", err)
		cfg = config.Default()
	}
	logger := logging.New(cfg.LogLevel, false)
	logger.Debug("cevrixa starting", "log_level", cfg.LogLevel)

	if err := cli.Run(os.Args[1:]); err != nil {
		// A downstream consumer that stops reading (for example a command
		// piped into head) closes the pipe; that is a clean stop, not a
		// failure, so it stays quiet and exits zero.
		if isBrokenPipe(err) {
			return
		}
		fmt.Fprintf(os.Stderr, "cevrixa: %v\n", err)
		os.Exit(1)
	}
}
