package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Lutfifakee-Project/cevrixa/internal/source/kev"
	"github.com/Lutfifakee-Project/cevrixa/internal/source/nvd"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
	syncpkg "github.com/Lutfifakee-Project/cevrixa/internal/sync"
)

type syncFlags struct {
	Target string
	DBPath string
	Days   int
}

func runSync(args []string) error {
	if len(args) == 0 {
		printSyncUsage()
		return errors.New("sync: target required (try: kev, nvd, or all)")
	}

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
	if flags.Days == 0 {
		flags.Days = 7
	}

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
	case "nvd":
		return syncNVDRemote(flags.DBPath, flags.Days)
	case "all":
		if err := syncKEV(flags.DBPath); err != nil {
			return err
		}
		if err := syncNVDRemote(flags.DBPath, flags.Days); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("sync: unknown target %q (supported: kev, nvd, all)", flags.Target)
	}
}

func syncKEV(dbPath string) error {
	cat, err := kev.LoadEmbedded()
	if err != nil {
		return fmt.Errorf("sync kev: load embedded catalog: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return fmt.Errorf("sync kev: mkdir: %w", err)
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

func syncNVDRemote(dbPath string, days int) error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return fmt.Errorf("sync nvd: mkdir: %w", err)
	}

	s, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("sync nvd: open store: %w", err)
	}
	defer s.Close()

	client := nvd.NewClient(nil)

	end := time.Now().UTC().Format("2006-01-02T15:04:05.000")
	start := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02T15:04:05.000")

	n, err := syncpkg.SyncNVD(context.Background(), syncpkg.NVDOptions{
		Source:       client,
		Store:        s,
		LastModStart: start,
		LastModEnd:   end,
		ProgressFreq: 500,
	})
	if err != nil {
		return fmt.Errorf("sync nvd: %w", err)
	}

	fmt.Fprintf(os.Stderr, "sync nvd: %d records written to %s\n", n, dbPath)
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
		case "--days":
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return f, fmt.Errorf("sync: --days requires a positive integer")
			}
			f.Days = n
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
  nvd                  Sync recent CVE records from the NVD API 2.0
  all                  Sync all available targets

Flags:
  --db <path>          Path to SQLite database (default: ~/.cevrixa/cevrixa.db)
  --days <n>           For NVD: how many days back to fetch (default: 7)
  -h, --help           Show this help

Examples:
  cevrixa sync kev
  cevrixa sync nvd --days 30
  cevrixa sync all --db ./test.db

Note: kev reads from embedded fixtures. nvd fetches from the live NVD API
and requires network access.`)
}
