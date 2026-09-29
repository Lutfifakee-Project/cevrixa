package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/source/kev"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

// loadKEV resolves the KEV catalog from either a database file (if dbPath
// is non-empty) or the embedded fixture. It returns the entries and a
// short label describing the source.
//
// Precedence:
//  1. If withKEV is false → returns nil (KEV disabled).
//  2. If dbPath is set and the file exists → read from SQLite.
//  3. Otherwise → read embedded.
func loadKEV(withKEV bool, dbPath string) (map[string]domain.KEVInfo, string, error) {
	if !withKEV {
		return nil, "", nil
	}

	if dbPath != "" {
		if _, err := os.Stat(dbPath); err == nil {
			s, err := store.Open(dbPath)
			if err != nil {
				return nil, "", fmt.Errorf("open db: %w", err)
			}
			defer s.Close()

			entries, err := s.AllKEV()
			if err != nil {
				return nil, "", fmt.Errorf("read kev: %w", err)
			}
			if len(entries) == 0 {
				return nil, "", fmt.Errorf("db contains no KEV entries; run 'cevrixa sync kev --db %s' first", dbPath)
			}
			return entries, "db", nil
		}
	}

	cat, err := kev.LoadEmbedded()
	if err != nil {
		return nil, "", fmt.Errorf("load embedded kev: %w", err)
	}
	return cat.Entries, "embedded", nil
}

func defaultKEVDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cevrixa", "cevrixa.db")
}
func openStoreIfDB(dbPath string) (*store.Store, error) {
	if dbPath == "" {
		return nil, nil
	}
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat db: %w", err)
	}
	s, err := store.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	return s, nil
}
