package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func (s *Store) SaveEnrichment(e domain.Enrichment) error {
	if e.VulnerabilityID == "" {
		return fmt.Errorf("store: enrichment requires VulnerabilityID")
	}
	if e.Source == "" {
		return fmt.Errorf("store: enrichment requires Source")
	}

	payload, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("store: marshal enrichment: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT INTO enrichments (vulnerability_id, source, payload, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(vulnerability_id, source) DO UPDATE SET
			payload = excluded.payload,
			updated_at = excluded.updated_at
	`, e.VulnerabilityID, e.Source, payload, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("store: save enrichment %s/%s: %w", e.VulnerabilityID, e.Source, err)
	}
	return nil
}

func (s *Store) GetEnrichment(vulnID, source string) (domain.Enrichment, error) {
	var payload []byte
	err := s.db.QueryRow(`
		SELECT payload FROM enrichments
		WHERE vulnerability_id = ? AND source = ?
	`, vulnID, source).Scan(&payload)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.Enrichment{}, fmt.Errorf("store: enrichment %s/%s not found", vulnID, source)
		}
		return domain.Enrichment{}, fmt.Errorf("store: get enrichment: %w", err)
	}

	var e domain.Enrichment
	if err := json.Unmarshal(payload, &e); err != nil {
		return domain.Enrichment{}, fmt.Errorf("store: unmarshal enrichment: %w", err)
	}
	return e, nil
}

// GetEnrichmentAny returns any enrichment for a vulnerability, preferring
// the given preferredSource but falling back to any available source.
func (s *Store) GetEnrichmentAny(vulnID string, preferredSource string) (domain.Enrichment, error) {
	if preferredSource != "" {
		if e, err := s.GetEnrichment(vulnID, preferredSource); err == nil {
			return e, nil
		}
	}

	rows, err := s.db.Query(`
		SELECT payload FROM enrichments
		WHERE vulnerability_id = ?
		LIMIT 1
	`, vulnID)
	if err != nil {
		return domain.Enrichment{}, fmt.Errorf("store: query enrichments: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return domain.Enrichment{}, fmt.Errorf("store: no enrichment for %s", vulnID)
	}

	var payload []byte
	if err := rows.Scan(&payload); err != nil {
		return domain.Enrichment{}, fmt.Errorf("store: scan enrichment: %w", err)
	}

	var e domain.Enrichment
	if err := json.Unmarshal(payload, &e); err != nil {
		return domain.Enrichment{}, fmt.Errorf("store: unmarshal enrichment: %w", err)
	}
	return e, nil
}

// ListEnrichments returns every stored enrichment for a vulnerability, from
// all sources. Correlation needs all of them to be able to detect that two
// sources disagree.
func (s *Store) ListEnrichments(vulnID string) ([]domain.Enrichment, error) {
	rows, err := s.db.Query(`
		SELECT payload FROM enrichments
		WHERE vulnerability_id = ?
		ORDER BY source
	`, vulnID)
	if err != nil {
		return nil, fmt.Errorf("store: list enrichments: %w", err)
	}
	defer rows.Close()

	var out []domain.Enrichment
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("store: scan enrichment: %w", err)
		}
		var e domain.Enrichment
		if err := json.Unmarshal(payload, &e); err != nil {
			return nil, fmt.Errorf("store: unmarshal enrichment: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) CountEnrichments() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM enrichments`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count enrichments: %w", err)
	}
	return n, nil
}

func (s *Store) DeleteAllEnrichments() error {
	if _, err := s.db.Exec(`DELETE FROM enrichments`); err != nil {
		return fmt.Errorf("store: delete all enrichments: %w", err)
	}
	return nil
}

// ListCVEIDs returns all unique vulnerability IDs starting with "CVE-"
// that are already in the local store. Used by DBCVE sync --from-store.
func (s *Store) ListCVEIDs() ([]string, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT id FROM vulnerabilities
		WHERE id LIKE 'CVE-%'
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("store: list CVE IDs: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: scan ID: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
