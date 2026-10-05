package store

import (
	"database/sql"
	"fmt"
)

// EPSSRecord is one FIRST.org EPSS score for a CVE.
type EPSSRecord struct {
	CVEID      string
	Score      float64
	Percentile float64
	ModelDate  string
}

// SaveEPSS upserts a batch of EPSS records in a single transaction.
func (s *Store) SaveEPSS(records []EPSSRecord) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: save epss: begin: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO epss (cve_id, score, percentile, model_date)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			score = excluded.score,
			percentile = excluded.percentile,
			model_date = excluded.model_date
	`)
	if err != nil {
		return fmt.Errorf("store: save epss: prepare: %w", err)
	}
	defer stmt.Close()

	for _, r := range records {
		if r.CVEID == "" {
			continue
		}
		if _, err := stmt.Exec(r.CVEID, r.Score, r.Percentile, r.ModelDate); err != nil {
			return fmt.Errorf("store: save epss %s: %w", r.CVEID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: save epss: commit: %w", err)
	}
	return nil
}

// GetEPSS returns the EPSS record for a CVE, or false when none is stored.
func (s *Store) GetEPSS(cveID string) (EPSSRecord, bool, error) {
	var r EPSSRecord
	err := s.db.QueryRow(`
		SELECT cve_id, score, percentile, model_date FROM epss WHERE cve_id = ?
	`, cveID).Scan(&r.CVEID, &r.Score, &r.Percentile, &r.ModelDate)
	if err != nil {
		if err == sql.ErrNoRows {
			return EPSSRecord{}, false, nil
		}
		return EPSSRecord{}, false, fmt.Errorf("store: get epss %s: %w", cveID, err)
	}
	return r, true, nil
}

// CountEPSS returns how many EPSS records are stored.
func (s Store) CountEPSS() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT() FROM epss`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count epss: %w", err)
	}
	return n, nil
}
