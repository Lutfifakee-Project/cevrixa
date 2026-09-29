package store

// migrations maps a schema version to the DDL statements that bring the
// database from version (key-1) to (key). Migrations are applied in order.
//
// Never edit an existing migration. To change the schema, add a new
// version with new statements.
var migrations = map[int][]string{
	1: {
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
			id          TEXT NOT NULL,
			source      TEXT NOT NULL,
			aliases     TEXT NOT NULL DEFAULT '',
			payload     BLOB NOT NULL,
			updated_at  INTEGER NOT NULL,
			PRIMARY KEY (id, source)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_id ON vulnerabilities(id)`,
		`CREATE TABLE IF NOT EXISTS kev (
			cve_id              TEXT PRIMARY KEY,
			vendor_project      TEXT NOT NULL DEFAULT '',
			product             TEXT NOT NULL DEFAULT '',
			date_added          TEXT NOT NULL DEFAULT '',
			short_description   TEXT NOT NULL DEFAULT '',
			required_action     TEXT NOT NULL DEFAULT '',
			due_date            TEXT NOT NULL DEFAULT '',
			known_ransomware    TEXT NOT NULL DEFAULT ''
		)`,
	},
	2: {
		`CREATE TABLE IF NOT EXISTS sync_metadata (
			source          TEXT PRIMARY KEY,
			last_sync_at    INTEGER NOT NULL,
			last_sync_iso   TEXT NOT NULL,
			records_synced  INTEGER NOT NULL DEFAULT 0
		)`,
	},
}
