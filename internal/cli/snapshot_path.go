package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// snapshotPath returns the file path of a named snapshot.
func snapshotPath(name string) (string, error) {
	dir, err := snapshotDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".db"), nil
}

// resolveStorePath returns the database path a command should read, from an
// explicit --db, a --snapshot name, or the default database. A named snapshot
// that does not exist is an error, never a silent fallback to the live store:
// a reproducible result must come from the state the caller asked for.
func resolveStorePath(db string, dbSet bool, snapshot string) (string, error) {
	if snapshot == "" {
		return resolveDBPath(db, dbSet), nil
	}
	if dbSet {
		return "", errors.New("use only one of --db or --snapshot")
	}
	p, err := snapshotPath(snapshot)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("snapshot %q not found", snapshot)
	}
	return p, nil
}
