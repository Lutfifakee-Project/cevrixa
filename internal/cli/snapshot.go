package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

func runSnapshot(args []string) error {
	if len(args) == 0 {
		printSnapshotUsage()
		return nil
	}

	switch args[0] {
	case "-h", "--help", "help":
		printSnapshotUsage()
		return nil
	case "create":
		return runSnapshotCreate(args[1:])
	case "list":
		return runSnapshotList(args[1:])
	default:
		printSnapshotUsage()
		return fmt.Errorf("snapshot: unknown subcommand %q", args[0])
	}
}

func snapshotDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cevrixa", "snapshots"), nil
}

func runSnapshotCreate(args []string) error {
	var name, db, dbFlag string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if i+1 >= len(args) {
				return errors.New("snapshot create: --db requires a value")
			}
			dbFlag = args[i+1]
			i++
		case "-h", "--help":
			printSnapshotUsage()
			return nil
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("snapshot create: unknown flag %q", args[i])
			}
			if name == "" {
				name = args[i]
			} else {
				return fmt.Errorf("snapshot create: unexpected argument %q", args[i])
			}
		}
	}
	if name == "" {
		return errors.New("snapshot create: a snapshot name is required")
	}
	if filepath.Base(name) != name {
		return fmt.Errorf("snapshot create: name %q must not contain a path separator", name)
	}

	if dbFlag == "" {
		db = resolveDBPath("", false)
		if db == "" {
			return errors.New("snapshot create: no local database found; run a sync first or pass --db")
		}
	} else {
		db = dbFlag
	}

	src, err := store.Open(db)
	if err != nil {
		return fmt.Errorf("snapshot create: %w", err)
	}
	defer src.Close()

	dir, err := snapshotDir()
	if err != nil {
		return fmt.Errorf("snapshot create: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("snapshot create: %w", err)
	}
	target := filepath.Join(dir, name+".db")
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("snapshot create: %q already exists", name)
	}

	meta, err := src.CreateSnapshot(target, name, Version)
	if err != nil {
		return fmt.Errorf("snapshot create: %w", err)
	}

	fmt.Printf("snapshot %s created\n", meta.Name)
	fmt.Printf("  path:    %s\n", target)
	fmt.Printf("  records: %d\n", meta.RecordCount)
	fmt.Printf("  sources: %s\n", strings.Join(meta.Sources, ", "))
	fmt.Printf("  digest:  %s\n", meta.Digest)
	return nil
}

func runSnapshotList(args []string) error {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			printSnapshotUsage()
			return nil
		}
		return fmt.Errorf("snapshot list: unexpected argument %q", a)
	}

	dir, err := snapshotDir()
	if err != nil {
		return fmt.Errorf("snapshot list: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("no snapshots")
			return nil
		}
		return fmt.Errorf("snapshot list: %w", err)
	}

	found := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		s, err := store.Open(path)
		if err != nil {
			fmt.Printf("%s: unreadable (%v)\n", e.Name(), err)
			continue
		}
		meta, err := s.GetSnapshotMeta()
		s.Close()
		if err != nil {
			fmt.Printf("%s: no metadata\n", e.Name())
			continue
		}
		found = true
		fmt.Printf("%s\n", meta.Name)
		fmt.Printf("  created: %s\n", meta.CreatedAt.Format(time.RFC3339))
		fmt.Printf("  records: %d  sources: %s\n", meta.RecordCount, strings.Join(meta.Sources, ", "))
		fmt.Printf("  digest:  %s\n", meta.Digest)
	}
	if !found {
		fmt.Println("no snapshots")
	}
	return nil
}

func printSnapshotUsage() {
	fmt.Println("Usage: cevrixa snapshot <subcommand>")
	fmt.Println()
	fmt.Println("Manage frozen copies of the local intelligence store.")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  create <name> [--db PATH]   Freeze the current store as a snapshot")
	fmt.Println("  list                         List snapshots")
	fmt.Println()
	fmt.Println("Snapshots are stored under ~/.cevrixa/snapshots/.")
}
