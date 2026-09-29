package store

import (
	"database/sql"
	"fmt"
	"time"
)

type SyncMetadata struct {
	Source        string
	LastSyncAt    time.Time
	LastSyncISO   string
	RecordsSynced int
}

func (s *Store) SaveSyncMetadata(m SyncMetadata) error {
	if m.Source == "" {
		return fmt.Errorf("store: sync metadata requires source")
	}
	_, err := s.db.Exec(`
		INSERT INTO sync_metadata (source, last_sync_at, last_sync_iso, records_synced)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET
			last_sync_at = excluded.last_sync_at,
			last_sync_iso = excluded.last_sync_iso,
			records_synced = excluded.records_synced
	`, m.Source, m.LastSyncAt.Unix(), m.LastSyncISO, m.RecordsSynced)
	if err != nil {
		return fmt.Errorf("store: save sync metadata %s: %w", m.Source, err)
	}
	return nil
}

func (s *Store) GetSyncMetadata(source string) (SyncMetadata, error) {
	var (
		m        SyncMetadata
		unixTime int64
	)
	err := s.db.QueryRow(`
		SELECT source, last_sync_at, last_sync_iso, records_synced
		FROM sync_metadata WHERE source = ?
	`, source).Scan(&m.Source, &unixTime, &m.LastSyncISO, &m.RecordsSynced)
	if err != nil {
		if err == sql.ErrNoRows {
			return SyncMetadata{}, fmt.Errorf("store: sync metadata %s not found", source)
		}
		return SyncMetadata{}, fmt.Errorf("store: get sync metadata %s: %w", source, err)
	}
	m.LastSyncAt = time.Unix(unixTime, 0).UTC()
	return m, nil
}

func (s *Store) DeleteSyncMetadata(source string) error {
	if _, err := s.db.Exec(`DELETE FROM sync_metadata WHERE source = ?`, source); err != nil {
		return fmt.Errorf("store: delete sync metadata %s: %w", source, err)
	}
	return nil
}
