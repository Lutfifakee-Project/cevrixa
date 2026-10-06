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
	"github.com/Lutfifakee-Project/cevrixa/internal/source/epss"
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

// selectSyncTarget separates an optional leading source name from the rest of
// the arguments. With no source name, the target is "all": the default path for
// a new user. Advanced users can name one source (nvd, osv, kev, epss).
func selectSyncTarget(args []string) (target string, rest []string) {
	if len(args) == 0 {
		return "all", args
	}
	if args[0] != "-" && args[0][0] != '-' {
		return args[0], args[1:]
	}
	return "all", args
}

func runSync(args []string) error {
	target, rest := selectSyncTarget(args)

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
	case "epss":
		return syncEPSS(flags.DBPath)
	case "all":
		return syncAll(flags)
	default:
		return fmt.Errorf("sync: unknown target %q (supported: kev, nvd, osv, epss, all)", flags.Target)
	}
}

func syncAll(flags syncFlags) error {
	fmt.Fprintln(os.Stderr, "Cevrixa data update")

	fmt.Fprintln(os.Stderr, "[] Updating CISA KEV...")
	if err := syncKEV(flags.DBPath, flags.Live); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "[] Updating NVD...")
	if err := syncNVDRemote(flags.DBPath, flags.Days); err != nil {
		return err
	}

	if flags.PURL != "" || flags.PackageName != "" {
		fmt.Fprintln(os.Stderr, "[] Updating OSV...")
		if err := syncOSVRemote(flags); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(os.Stderr, "[] OSV skipped (pass --purl or --package to sync OSV)")
	}

	fmt.Fprintln(os.Stderr, "[] Updating EPSS...")
	if err := syncEPSS(flags.DBPath); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "[+] Dataset ready")
	return nil
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
	fmt.Fprintln(os.Stderr, "[+] KEV:", n, "entries from", source)
	return nil
}

// syncEPSS downloads the daily EPSS feed and stores each score. EPSS ranks
// findings; it never changes applicability.
func syncEPSS(dbPath string) error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return fmt.Errorf("sync epss: mkdir: %w", err)
	}
	s, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("sync epss: open store: %w", err)
	}
	defer s.Close()

	client := epss.NewClient(&http.Client{Timeout: 300 * time.Second})
	scores, err := client.Fetch(context.Background())
	if err != nil {
		return fmt.Errorf("sync epss: %w", err)
	}

	records := make([]store.EPSSRecord, 0, len(scores))
	for _, sc := range scores {
		records = append(records, store.EPSSRecord{
			CVEID:      sc.CVEID,
			Score:      sc.Score,
			Percentile: sc.Percentile,
		})
	}
	if err := s.SaveEPSS(records); err != nil {
		return fmt.Errorf("sync epss: save: %w", err)
	}
	n, _ := s.CountEPSS()
	fmt.Fprintln(os.Stderr, "[+] EPSS:", n, "scores")
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

	client := nvd.NewClient(&http.Client{Timeout: 600 * time.Second})
	cfg, _ := config.Load()
	if cfg.NVDAPIKey != "" {
		client.APIKey = cfg.NVDAPIKey
		fmt.Fprintln(os.Stderr, "[] NVD: using API key")
	} else {
		fmt.Fprintln(os.Stderr, "[] NVD: no API key, using public rate limit (~6s between pages)")
	}

	end := time.Now().UTC().Format("2006-01-02T15:04:05.000")
	start := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02T15:04:05.000")

	n, err := syncpkg.SyncNVD(context.Background(), syncpkg.NVDOptions{
		Source:       client,
		Store:        s,
		LastModStart: start,
		LastModEnd:   end,
		PageLimit:    500,
		ProgressFreq: 100,
	})
	if err != nil {
		return fmt.Errorf("sync nvd: %w", err)
	}
	fmt.Fprintln(os.Stderr, "[+] NVD:", n, "records")
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

	client := nvd.NewClient(&http.Client{Timeout: 600 * time.Second})
	cfg, _ := config.Load()
	if cfg.NVDAPIKey != "" {
		client.APIKey = cfg.NVDAPIKey
	}

	fmt.Fprintln(os.Stderr, "[] NVD full: fetching full NVD history")
	n, err := syncpkg.BackfillNVD(context.Background(), syncpkg.NVDBackfillOptions{
		Source:       client,
		Store:        s,
		ProgressFreq: 1,
	})
	if err != nil {
		return fmt.Errorf("sync nvd full: %w", err)
	}
	fmt.Fprintln(os.Stderr, "[+] NVD full:", n, "records")
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
	fmt.Fprintln(os.Stderr, "[+] OSV:", n, "records")
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
	fmt.Println("Usage: cevrixa sync [target] [flags]")
	fmt.Println()
	fmt.Println("Download and persist vulnerability data to the local SQLite store.")
	fmt.Println("With no target, sync updates every supported source. Naming a")
	fmt.Println("single source is an advanced option for automation or troubleshooting.")
	fmt.Println()
	fmt.Println("Targets (advanced):")
	fmt.Println("  nvd                  Sync recent CVE records from NVD API 2.0")
	fmt.Println("  osv                  Sync OSV vulnerabilities for a package/PURL")
	fmt.Println("  kev                  Sync CISA Known Exploited Vulnerabilities")
	fmt.Println("  epss                 Sync FIRST.org EPSS scores")
	fmt.Println("  all                  Sync all available targets (default)")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  --db <path>          SQLite database (default: ~/.cevrixa/cevrixa.db)")
	fmt.Println("  --days <n>           For NVD: how many days back (default: 7)")
	fmt.Println("  --full               For NVD: full history")
	fmt.Println("  --live               For KEV: fetch live from CISA")
	fmt.Println("  --purl <purl>        For OSV: package URL")
	fmt.Println("  --package <name>     For OSV: package name")
	fmt.Println("  --ecosystem <name>   For OSV: PyPI, npm, Go, Maven")
	fmt.Println("  --version <ver>      For OSV: restrict to a version")
	fmt.Println("  -h, --help           Show this help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  cevrixa sync")
	fmt.Println("  cevrixa sync nvd --days 30")
	fmt.Println("  cevrixa sync osv --purl pkg:pypi/django")
}
