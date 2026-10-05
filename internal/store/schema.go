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
	3: {
		`CREATE TABLE IF NOT EXISTS enrichments (
			vulnerability_id TEXT NOT NULL,
			source           TEXT NOT NULL,
			payload          BLOB NOT NULL,
			updated_at       INTEGER NOT NULL,
			PRIMARY KEY (vulnerability_id, source)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_enrichments_vuln ON enrichments(vulnerability_id)`,
	},
	4: {
		`DELETE FROM enrichments WHERE source = 'dbcve'`,
	},
	5: {
		`CREATE TABLE IF NOT EXISTS snapshot_meta (
			id             INTEGER PRIMARY KEY CHECK (id = 1),
			name           TEXT NOT NULL DEFAULT '',
			created_at     INTEGER NOT NULL DEFAULT 0,
			engine_version TEXT NOT NULL DEFAULT '',
			digest         TEXT NOT NULL DEFAULT '',
			record_count   INTEGER NOT NULL DEFAULT 0,
			sources        TEXT NOT NULL DEFAULT ''
		)`,
	},
	6: {
		`CREATE TABLE IF NOT EXISTS epss (
			cve_id     TEXT PRIMARY KEY,
			score      REAL NOT NULL DEFAULT 0,
			percentile REAL NOT NULL DEFAULT 0,
			model_date TEXT NOT NULL DEFAULT ''
		)`,
	},
}
