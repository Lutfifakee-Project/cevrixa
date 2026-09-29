package store

import (
	"database/sql"
	"fmt"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func (s *Store) SaveKEV(info domain.KEVInfo) error {
	if info.CVEID == "" {
		return fmt.Errorf("store: KEV entry must have CVEID")
	}

	_, err := s.db.Exec(`
		INSERT INTO kev (
			cve_id, vendor_project, product, date_added,
			short_description, required_action, due_date, known_ransomware
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			vendor_project = excluded.vendor_project,
			product = excluded.product,
			date_added = excluded.date_added,
			short_description = excluded.short_description,
			required_action = excluded.required_action,
			due_date = excluded.due_date,
			known_ransomware = excluded.known_ransomware
	`, info.CVEID, info.VendorProject, info.Product, info.DateAdded,
		info.ShortDescription, info.RequiredAction, info.DueDate, info.KnownRansomware)
	if err != nil {
		return fmt.Errorf("store: save kev %s: %w", info.CVEID, err)
	}
	return nil
}

func (s *Store) GetKEV(cveID string) (domain.KEVInfo, error) {
	var info domain.KEVInfo
	err := s.db.QueryRow(`
		SELECT cve_id, vendor_project, product, date_added,
		       short_description, required_action, due_date, known_ransomware
		FROM kev WHERE cve_id = ?
	`, cveID).Scan(
		&info.CVEID, &info.VendorProject, &info.Product, &info.DateAdded,
		&info.ShortDescription, &info.RequiredAction, &info.DueDate, &info.KnownRansomware,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.KEVInfo{}, fmt.Errorf("store: kev %s not found", cveID)
		}
		return domain.KEVInfo{}, fmt.Errorf("store: get kev %s: %w", cveID, err)
	}
	return info, nil
}

func (s *Store) AllKEV() (map[string]domain.KEVInfo, error) {
	rows, err := s.db.Query(`
		SELECT cve_id, vendor_project, product, date_added,
		       short_description, required_action, due_date, known_ransomware
		FROM kev
	`)
	if err != nil {
		return nil, fmt.Errorf("store: list kev: %w", err)
	}
	defer rows.Close()

	out := map[string]domain.KEVInfo{}
	for rows.Next() {
		var info domain.KEVInfo
		if err := rows.Scan(
			&info.CVEID, &info.VendorProject, &info.Product, &info.DateAdded,
			&info.ShortDescription, &info.RequiredAction, &info.DueDate, &info.KnownRansomware,
		); err != nil {
			return nil, fmt.Errorf("store: scan kev: %w", err)
		}
		out[info.CVEID] = info
	}
	return out, rows.Err()
}

func (s *Store) CountKEV() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM kev`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count kev: %w", err)
	}
	return n, nil
}

func (s *Store) DeleteAllKEV() error {
	if _, err := s.db.Exec(`DELETE FROM kev`); err != nil {
		return fmt.Errorf("store: delete all kev: %w", err)
	}
	return nil
}
