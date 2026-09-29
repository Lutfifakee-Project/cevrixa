package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Lutfifakee-Project/cevrixa/internal/source/kev"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

type syncFlags struct {
	Target string // "kev" (extensible for "nvd", "osv", "all")
	DBPath string
}

func runSync(args []string) error {
	if len(args) == 0 {
		printSyncUsage()
		return errors.New("sync: target required (try: kev)")
	}

	// First positional arg is the target; remaining args are flags.
	target := ""
	rest := args
	if len(args) > 0 && args[0] != "-" && args[0][0] != '-' {
		target = args[0]
		rest = args[1:]
	}

	flags, err := parseSyncArgs(rest)
	if errors.Is(err, errHelpRequested) {
		return nil
	}
	if err != nil {
		return err
	}
	flags.Target = target

	if flags.DBPath == "" {
		p, err := defaultDBPath()
		if err != nil {
			return fmt.Errorf("sync: locate default db: %w", err)
		}
		flags.DBPath = p
	}

	switch flags.Target {
	case "kev":
		return syncKEV(flags.DBPath)
	case "all":
		if err := syncKEV(flags.DBPath); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("sync: unknown target %q (supported: kev, all)", flags.Target)
	}
}

func syncKEV(dbPath string) error {
	cat, err := kev.LoadEmbedded()
	if err != nil {
		return fmt.Errorf("sync kev: load embedded catalog: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return fmt.Errorf("sync kev: mkdir %s: %w", filepath.Dir(dbPath), err)
	}

	s, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("sync kev: open store: %w", err)
	}
	defer s.Close()

	if err := s.DeleteAllKEV(); err != nil {
		return fmt.Errorf("sync kev: clear existing: %w", err)
	}

	for _, info := range cat.Entries {
		if err := s.SaveKEV(info); err != nil {
			return fmt.Errorf("sync kev: save %s: %w", info.CVEID, err)
		}
	}

	n, err := s.CountKEV()
	if err != nil {
		return fmt.Errorf("sync kev: count: %w", err)
	}
	fmt.Fprintf(os.Stderr, "sync kev: %d entries written to %s\n", n, dbPath)
	return nil
}

func parseSyncArgs(args []string) (syncFlags, error) {
	var f syncFlags

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "-h" || arg == "--help" {
			printSyncUsage()
			return syncFlags{}, errHelpRequested
		}

		key, value, hasInlineValue := splitFlag(arg)
		if !hasInlineValue {
			if i+1 >= len(args) {
				return f, fmt.Errorf("sync: flag %q requires a value", arg)
			}
			value = args[i+1]
			i++
		}

		switch key {
		case "--db":
			f.DBPath = value
		default:
			return f, fmt.Errorf("sync: unknown flag %q", key)
		}
	}
	return f, nil
}

func defaultDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cevrixa", "cevrixa.db"), nil
}

func printSyncUsage() {
	fmt.Println(`Usage: cevrixa sync <target> [flags]

Download and persist vulnerability data to the local SQLite store.

Targets:
  kev                  Sync the CISA Known Exploited Vulnerabilities catalog
  all                  Sync all available targets

Flags:
  --db <path>          Path to SQLite database (default: ~/.cevrixa/cevrixa.db)
  -h, --help           Show this help

Examples:
  cevrixa sync kev
  cevrixa sync kev --db ./test.db

Note: currently reads from embedded fixtures. Live source fetching is
planned for a later milestone.`)
}
