package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Lutfifakee-Project/cevrixa/internal/config"
	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/source/kev"
	"github.com/Lutfifakee-Project/cevrixa/internal/source/nvd"
	"github.com/Lutfifakee-Project/cevrixa/internal/source/osv"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
	syncpkg "github.com/Lutfifakee-Project/cevrixa/internal/sync"
)

type syncFlags struct {
	Target      string
	DBPath      string
	Days        int
	Full        bool
	Live        bool
	PURL        string
	PackageName string
	Ecosystem   string
	Version     string
}

func runSync(args []string) error {
	if len(args) == 0 {
		printSyncUsage()
		return errors.New("sync: target required (kev, nvd, osv, or all)")
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
		return syncKEV(flags.DBPath, flags.Live)
	case "nvd":
		if flags.Full {
			return syncNVDFull(flags.DBPath)
		}
		return syncNVDRemote(flags.DBPath, flags.Days)
	case "osv":
		return syncOSVRemote(flags)
	case "all":
		if err := syncKEV(flags.DBPath, flags.Live); err != nil {
			return err
		}
		if err := syncNVDRemote(flags.DBPath, flags.Days); err != nil {
			return err
		}
		if flags.PURL != "" || flags.PackageName != "" {
			if err := syncOSVRemote(flags); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("sync: unknown target %q (supported: kev, nvd, osv, all)", flags.Target)
	}
}

func syncKEV(dbPath string, live bool) error {
	var (
		entries map[string]domain.KEVInfo
		source  string
	)
	if live {
		cat, err := kev.FetchLive(context.Background())
		if err != nil {
			return fmt.Errorf("sync kev: fetch live: %w", err)
		}
		entries = cat.Entries
		source = "live"
	} else {
		cat, err := kev.LoadEmbedded()
		if err != nil {
			return fmt.Errorf("sync kev: load embedded: %w", err)
		}
		entries = cat.Entries
		source = "embedded"
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
		return fmt.Errorf("sync kev: clear: %w", err)
	}
	for _, info := range entries {
		if err := s.SaveKEV(info); err != nil {
			return fmt.Errorf("sync kev: save %s: %w", info.CVEID, err)
		}
	}
	n, _ := s.CountKEV()
	fmt.Fprintf(os.Stderr, "sync kev: %d entries from %s written to %s\n", n, source, dbPath)
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

	client := nvd.NewClient(&http.Client{Timeout: 180 * time.Second})

	cfg, _ := config.Load()
	if cfg.NVDAPIKey != "" {
		client.APIKey = cfg.NVDAPIKey
		fmt.Fprintln(os.Stderr, "sync nvd: using API key (fast mode)")
	} else {
		fmt.Fprintln(os.Stderr, "sync nvd: no API key — using NVD public rate limit (~6s between pages)")
	}

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

func syncNVDFull(dbPath string) error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return fmt.Errorf("sync nvd full: mkdir: %w", err)
	}
	s, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("sync nvd full: open store: %w", err)
	}
	defer s.Close()

	client := nvd.NewClient(&http.Client{Timeout: 180 * time.Second})
	cfg, _ := config.Load()
	if cfg.NVDAPIKey != "" {
		client.APIKey = cfg.NVDAPIKey
		fmt.Fprintln(os.Stderr, "sync nvd full: using API key (fast mode)")
	} else {
		fmt.Fprintln(os.Stderr, "sync nvd full: no API key — public rate limit applies")
		fmt.Fprintln(os.Stderr, "sync nvd full: this will take several hours")
	}

	fmt.Fprintln(os.Stderr, "sync nvd full: fetching full NVD history (~250k CVE)")
	n, err := syncpkg.BackfillNVD(context.Background(), syncpkg.NVDBackfillOptions{
		Source:       client,
		Store:        s,
		ProgressFreq: 1,
	})
	if err != nil {
		return fmt.Errorf("sync nvd full: %w", err)
	}
	fmt.Fprintf(os.Stderr, "sync nvd full: %d records written to %s\n", n, dbPath)
	return nil
}

func syncOSVRemote(flags syncFlags) error {
	if err := os.MkdirAll(filepath.Dir(flags.DBPath), 0o755); err != nil {
		return fmt.Errorf("sync osv: mkdir: %w", err)
	}
	s, err := store.Open(flags.DBPath)
	if err != nil {
		return fmt.Errorf("sync osv: open store: %w", err)
	}
	defer s.Close()

	client := osv.NewClient(&http.Client{Timeout: 60 * time.Second})

	n, err := syncpkg.SyncOSV(context.Background(), syncpkg.OSVOptions{
		Source:      client,
		Store:       s,
		PURL:        flags.PURL,
		PackageName: flags.PackageName,
		Ecosystem:   flags.Ecosystem,
		Version:     flags.Version,
	})
	if err != nil {
		return fmt.Errorf("sync osv: %w", err)
	}
	fmt.Fprintf(os.Stderr, "sync osv: %d records written to %s\n", n, flags.DBPath)
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
		if arg == "--full" {
			f.Full = true
			continue
		}
		if arg == "--live" {
			f.Live = true
			continue
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
		case "--purl":
			f.PURL = value
		case "--package":
			f.PackageName = value
		case "--ecosystem":
			f.Ecosystem = value
		case "--version":
			f.Version = value
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
  kev                  Sync CISA Known Exploited Vulnerabilities
  nvd                  Sync recent CVE records from NVD API 2.0
  osv                  Sync OSV vulnerabilities for a package/PURL
  all                  Sync all available targets

Flags:
  --db <path>          Path to SQLite database (default: ~/.cevrixa/cevrixa.db)
  --days <n>           For NVD: how many days back to fetch (default: 7)
  --full               For NVD: fetch full history
  --live               For KEV: fetch from CISA instead of embedded
  --purl <purl>        For OSV: package URL (e.g. pkg:pypi/django)
  --package <name>     For OSV: package name
  --ecosystem <name>   For OSV: ecosystem (PyPI, npm, Go, Maven)
  --version <ver>      For OSV: restrict to a version
  -h, --help           Show this help

Examples:
  cevrixa sync kev --live
  cevrixa sync nvd --days 30
  cevrixa sync osv --purl pkg:pypi/django
  cevrixa sync osv --package lodash --ecosystem npm

No API key required. NVD public rate limit is handled automatically.`)
}
