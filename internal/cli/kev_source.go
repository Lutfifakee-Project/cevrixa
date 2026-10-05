package cli

import (
	"fmt"
	"os"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/source/kev"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

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

func resolveDBPath(requested string, wasSet bool) string {
	if wasSet {
		return requested
	}
	p, err := defaultDBPath()
	if err != nil {
		return ""
	}
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}
