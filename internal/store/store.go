// Package store provides a local SQLite-backed persistence layer for
// Cevrixa vulnerability records and KEV enrichment data.
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

const SchemaVersion = 4

type Store struct {
	db   *sql.DB
	path string
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("store: empty path")
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Path() string { return s.path }

func (s *Store) migrate() error {
	var current int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("store: read user_version: %w", err)
	}

	for current < SchemaVersion {
		next := current + 1
		stmts, ok := migrations[next]
		if !ok {
			return fmt.Errorf("store: missing migration for version %d", next)
		}
		for _, stmt := range stmts {
			if _, err := s.db.Exec(stmt); err != nil {
				return fmt.Errorf("store: migrate to v%d: %w", next, err)
			}
		}
		if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", next)); err != nil {
			return fmt.Errorf("store: set user_version to %d: %w", next, err)
		}
		current = next
	}
	return nil
}
