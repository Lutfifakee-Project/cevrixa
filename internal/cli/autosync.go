package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

// isInteractive reports whether stdin is attached to a terminal. Auto-sync
// prompts only when a human can answer; piped or CI input never blocks on a
// question.
func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// datasetHasData reports whether the local store exists and holds at least one
// vulnerability record. An empty or missing store means the user has not synced
// yet.
func datasetHasData(dbPath string) bool {
	if dbPath == "" {
		return false
	}
	if _, err := os.Stat(dbPath); err != nil {
		return false
	}
	s, err := store.Open(dbPath)
	if err != nil {
		return false
	}
	defer s.Close()
	n, err := s.CountVulnerabilities()
	if err != nil {
		return false
	}
	return n > 0
}

// ensureDataset gives the user a working dataset before a detection runs.
//
//   - If data already exists, it does nothing.
//   - If --no-sync was passed and there is no data, it fails with a clear,
//     scriptable error instead of prompting.
//   - Otherwise, when stdin is a terminal, it offers to run an initial sync.
//     Non-interactive callers that did not pass --no-sync continue with the
//     embedded fixtures, matching the previous behavior.
func ensureDataset(dbPath string, allowSync bool) error {
	if datasetHasData(dbPath) {
		return nil
	}

	if !allowSync {
		return fmt.Errorf("local vulnerability dataset is unavailable; " +
			"automatic synchronization is disabled by --no-sync; run 'cevrixa sync'")
	}

	if !isInteractive() {
		return nil
	}

	fmt.Fprintln(os.Stderr, "Cevrixa")
	fmt.Fprintln(os.Stderr, "No local vulnerability dataset was found.")
	fmt.Fprintln(os.Stderr, "Initial synchronization is required.")
	if !promptYes("Sync vulnerability data now? [Y/n] ") {
		fmt.Fprintln(os.Stderr, "Skipping sync; continuing with embedded fixtures.")
		return nil
	}

	flags := syncFlags{Target: "all", DBPath: dbPath, Days: 7}
	if err := syncAll(flags); err != nil {
		return fmt.Errorf("initial sync: %w", err)
	}
	return nil
}

// promptYes asks a yes/no question on stderr and reads the answer from stdin.
// An empty answer means yes, matching the [Y/n] default.
func promptYes(question string) bool {
	fmt.Fprint(os.Stderr, question)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString(byte(10))
	if err != nil && line == "" {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "" || answer == "y" || answer == "yes"
}
