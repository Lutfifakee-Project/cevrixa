package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// SnapshotMeta identifies the intelligence state a database holds. A snapshot
// is a frozen copy of the store: it never changes after creation, so a report
// computed from it can be reproduced.
type SnapshotMeta struct {
	Name          string
	CreatedAt     time.Time
	EngineVersion string
	Digest        string
	RecordCount   int
	Sources       []string
}

// SaveSnapshotMeta writes the single snapshot metadata row.
func (s *Store) SaveSnapshotMeta(m SnapshotMeta) error {
	_, err := s.db.Exec(`
		INSERT INTO snapshot_meta (id, name, created_at, engine_version, digest, record_count, sources)
		VALUES (1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			created_at = excluded.created_at,
			engine_version = excluded.engine_version,
			digest = excluded.digest,
			record_count = excluded.record_count,
			sources = excluded.sources
	`, m.Name, m.CreatedAt.Unix(), m.EngineVersion, m.Digest, m.RecordCount, strings.Join(m.Sources, ","))
	if err != nil {
		return fmt.Errorf("store: save snapshot meta: %w", err)
	}
	return nil
}

// GetSnapshotMeta reads the snapshot metadata row.
func (s *Store) GetSnapshotMeta() (SnapshotMeta, error) {
	var (
		m        SnapshotMeta
		unixTime int64
		sources  string
	)
	err := s.db.QueryRow(`SELECT name, created_at, engine_version, digest, record_count, sources FROM snapshot_meta WHERE id = 1`).
		Scan(&m.Name, &unixTime, &m.EngineVersion, &m.Digest, &m.RecordCount, &sources)
	if err != nil {
		if err == sql.ErrNoRows {
			return SnapshotMeta{}, fmt.Errorf("store: snapshot meta not set")
		}
		return SnapshotMeta{}, fmt.Errorf("store: get snapshot meta: %w", err)
	}
	m.CreatedAt = time.Unix(unixTime, 0).UTC()
	if sources != "" {
		m.Sources = strings.Split(sources, ",")
	}
	return m, nil
}

// Digest returns a deterministic SHA-256 over the stored vulnerability
// records, so two reports can be shown to come from the same intelligence
// state. Records are read in a stable order.
func (s *Store) Digest() (string, error) {
	rows, err := s.db.Query(`SELECT id, source, payload FROM vulnerabilities ORDER BY source, id`)
	if err != nil {
		return "", fmt.Errorf("store: digest: %w", err)
	}
	defer rows.Close()

	h := sha256.New()
	for rows.Next() {
		var (
			id, source string
			payload    []byte
		)
		if err := rows.Scan(&id, &source, &payload); err != nil {
			return "", fmt.Errorf("store: digest scan: %w", err)
		}
		h.Write([]byte(id))
		h.Write([]byte{0})
		h.Write([]byte(source))
		h.Write([]byte{0})
		h.Write(payload)
		h.Write([]byte{0})
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CreateSnapshot writes a frozen copy of this store to targetPath and stamps
// it with snapshot metadata. VACUUM INTO produces a compact, consistent copy
// without touching the source database's contents.
func (s *Store) CreateSnapshot(targetPath, name, engineVersion string) (SnapshotMeta, error) {
	if targetPath == "" {
		return SnapshotMeta{}, fmt.Errorf("store: empty snapshot path")
	}
	// A path is data, not SQL, but VACUUM INTO cannot bind a parameter, so the
	// single quote is escaped to keep the statement well formed.
	escaped := strings.ReplaceAll(targetPath, "'", "''")
	if _, err := s.db.Exec("VACUUM INTO '" + escaped + "'"); err != nil {
		return SnapshotMeta{}, fmt.Errorf("store: create snapshot: %w", err)
	}

	snap, err := Open(targetPath)
	if err != nil {
		return SnapshotMeta{}, err
	}
	defer snap.Close()

	digest, err := snap.Digest()
	if err != nil {
		return SnapshotMeta{}, err
	}
	count, err := snap.CountVulnerabilities()
	if err != nil {
		return SnapshotMeta{}, err
	}
	sources, err := snap.sources()
	if err != nil {
		return SnapshotMeta{}, err
	}

	m := SnapshotMeta{
		Name:          name,
		CreatedAt:     time.Now().UTC(),
		EngineVersion: engineVersion,
		Digest:        digest,
		RecordCount:   count,
		Sources:       sources,
	}
	if err := snap.SaveSnapshotMeta(m); err != nil {
		return SnapshotMeta{}, err
	}
	return m, nil
}

// sources lists the distinct vulnerability sources in the store.
func (s *Store) sources() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT source FROM vulnerabilities WHERE source != '' ORDER BY source`)
	if err != nil {
		return nil, fmt.Errorf("store: list sources: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var src string
		if err := rows.Scan(&src); err != nil {
			return nil, fmt.Errorf("store: scan source: %w", err)
		}
		out = append(out, src)
	}
	return out, rows.Err()
}
