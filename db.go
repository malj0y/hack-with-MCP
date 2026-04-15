package main

import (
	"database/sql"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

var (
	personalDB  *sql.DB
	disclosedDB *sql.DB
)

func dbDir() string {
	dir := os.Getenv("HWM_DB_DIR")
	if dir == "" {
		// Default: same directory as binary
		ex, _ := os.Executable()
		dir = filepath.Dir(ex)
	}
	return dir
}

// --- Personal DB ---

func initPersonalDB() error {
	path := filepath.Join(dbDir(), "personal.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer
	personalDB = db
	return migratePersonalDB()
}

func migratePersonalDB() error {
	_, err := personalDB.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA foreign_keys=ON;

		CREATE TABLE IF NOT EXISTS reports (
			id              TEXT PRIMARY KEY,
			title           TEXT,
			state           TEXT,
			created_at      TEXT,
			bounty_awarded_at TEXT,
			closed_at       TEXT,
			disclosed_at    TEXT,
			program_handle  TEXT,
			weakness_name   TEXT,
			weakness_cwe    TEXT,
			severity_rating TEXT,
			severity_score  REAL,
			bounty_amount   REAL DEFAULT 0,
			bounty_currency TEXT DEFAULT 'USD',
			vuln_info       TEXT,
			asset_identifier TEXT,
			asset_type      TEXT
		);

		CREATE TABLE IF NOT EXISTS programs (
			id               TEXT PRIMARY KEY,
			handle           TEXT UNIQUE,
			name             TEXT,
			submission_state TEXT,
			offers_bounties  INTEGER DEFAULT 0,
			currency         TEXT,
			response_time    TEXT,
			avg_bounty_low   REAL,
			avg_bounty_high  REAL
		);

		CREATE TABLE IF NOT EXISTS scopes (
			id                   TEXT PRIMARY KEY,
			program_handle       TEXT,
			asset_identifier     TEXT,
			asset_type           TEXT,
			eligible_for_bounty  INTEGER DEFAULT 0,
			eligible_for_submission INTEGER DEFAULT 0,
			max_severity         TEXT,
			instruction          TEXT
		);

		CREATE TABLE IF NOT EXISTS attachments (
			id           TEXT PRIMARY KEY,
			report_id    TEXT,
			file_name    TEXT,
			content_type TEXT,
			file_size    INTEGER,
			created_at   TEXT,
			FOREIGN KEY (report_id) REFERENCES reports(id)
		);

		CREATE TABLE IF NOT EXISTS sync_meta (
			key   TEXT PRIMARY KEY,
			value TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_reports_program  ON reports(program_handle);
		CREATE INDEX IF NOT EXISTS idx_reports_weakness ON reports(weakness_name);
		CREATE INDEX IF NOT EXISTS idx_reports_severity ON reports(severity_rating);
		CREATE INDEX IF NOT EXISTS idx_reports_state    ON reports(state);
		CREATE INDEX IF NOT EXISTS idx_scopes_program   ON scopes(program_handle);
	`)
	return err
}

// --- Disclosed DB ---

func initDisclosedDB() error {
	path := filepath.Join(dbDir(), "disclosed.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	disclosedDB = db
	return migrateDisclosedDB()
}

func migrateDisclosedDB() error {
	_, err := disclosedDB.Exec(`
		PRAGMA journal_mode=WAL;

		CREATE TABLE IF NOT EXISTS disclosed_reports (
			id               INTEGER PRIMARY KEY,
			title            TEXT,
			vuln_info        TEXT,
			weakness_name    TEXT,
			program_handle   TEXT,
			asset_identifier TEXT,
			asset_type       TEXT,
			cve_ids          TEXT DEFAULT '[]',
			bounty_amount    REAL,
			disclosed_at     TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_dis_program  ON disclosed_reports(program_handle);
		CREATE INDEX IF NOT EXISTS idx_dis_weakness ON disclosed_reports(weakness_name);
		CREATE INDEX IF NOT EXISTS idx_dis_bounty   ON disclosed_reports(bounty_amount);
	`)
	if err != nil {
		return err
	}

	// FTS5 virtual table — separate statement
	_, err = disclosedDB.Exec(`
		CREATE VIRTUAL TABLE IF NOT EXISTS disclosed_fts USING fts5(
			title,
			vuln_info,
			content='disclosed_reports',
			content_rowid='id'
		);
	`)
	return err
}

// --- Meta helpers ---

func getMeta(key string) string {
	var val string
	personalDB.QueryRow("SELECT value FROM sync_meta WHERE key = ?", key).Scan(&val)
	return val
}

func setMeta(key, value string) {
	personalDB.Exec(
		"INSERT OR REPLACE INTO sync_meta(key, value) VALUES (?, ?)",
		key, value,
	)
}
