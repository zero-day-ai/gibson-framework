// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package dao

import (
	"github.com/jmoiron/sqlx"
)

// Migration represents a database migration
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// ApplyMigrations applies all database migrations
func ApplyMigrations(db *sqlx.DB) error {
	// Create migration tracking table if it doesn't exist
	if err := createMigrationTable(db); err != nil {
		return err
	}

	migrations := getAllMigrations()

	for _, migration := range migrations {
		applied, err := isMigrationApplied(db, migration.Version)
		if err != nil {
			return err
		}

		if !applied {
			if err := applyMigration(db, migration); err != nil {
				return err
			}
		}
	}

	return nil
}

// createMigrationTable creates the migration tracking table
func createMigrationTable(db *sqlx.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := db.Exec(query)
	return err
}

// isMigrationApplied checks if a migration has been applied
func isMigrationApplied(db *sqlx.DB, version int) (bool, error) {
	var count int
	err := db.Get(&count, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version)
	return count > 0, err
}

// applyMigration applies a single migration
func applyMigration(db *sqlx.DB, migration Migration) error {
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Execute the migration SQL
	if _, err := tx.Exec(migration.SQL); err != nil {
		return err
	}

	// Record the migration as applied
	if _, err := tx.Exec(
		"INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
		migration.Version, migration.Name,
	); err != nil {
		return err
	}

	return tx.Commit()
}

// getAllMigrations returns all database migrations in order
func getAllMigrations() []Migration {
	return []Migration{
		{
			Version: 1,
			Name:    "create_targets_table",
			SQL: `
			CREATE TABLE IF NOT EXISTS targets (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL UNIQUE,
				type TEXT NOT NULL,
				provider TEXT NOT NULL,
				model TEXT,
				url TEXT,
				api_version TEXT,
				credential_id TEXT,
				status TEXT NOT NULL DEFAULT 'active',
				description TEXT,
				tags TEXT, -- JSON array
				headers TEXT, -- JSON object
				config TEXT, -- JSON object
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (credential_id) REFERENCES credentials(id)
			);

			CREATE INDEX IF NOT EXISTS idx_targets_name ON targets(name);
			CREATE INDEX IF NOT EXISTS idx_targets_provider ON targets(provider);
			CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status);
			CREATE INDEX IF NOT EXISTS idx_targets_type ON targets(type);
			`,
		},
		{
			Version: 2,
			Name:    "create_credentials_table",
			SQL: `
			CREATE TABLE IF NOT EXISTS credentials (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL UNIQUE,
				type TEXT NOT NULL,
				provider TEXT NOT NULL,
				status TEXT NOT NULL DEFAULT 'active',
				description TEXT,
				encrypted_value BLOB NOT NULL,
				encryption_iv BLOB NOT NULL,
				key_derivation_salt BLOB NOT NULL,
				tags TEXT, -- JSON array
				rotation_info TEXT, -- JSON object
				usage TEXT, -- JSON object
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				last_used DATETIME
			);

			CREATE INDEX IF NOT EXISTS idx_credentials_name ON credentials(name);
			CREATE INDEX IF NOT EXISTS idx_credentials_provider ON credentials(provider);
			CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status);
			CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(type);
			`,
		},
		{
			Version: 3,
			Name:    "create_scans_table",
			SQL: `
			CREATE TABLE IF NOT EXISTS scans (
				id TEXT PRIMARY KEY,
				target_id TEXT NOT NULL,
				name TEXT NOT NULL,
				type TEXT NOT NULL DEFAULT 'basic',
				status TEXT NOT NULL DEFAULT 'pending',
				progress REAL DEFAULT 0.0,
				error TEXT,
				started_by TEXT,
				started_at DATETIME,
				completed_at DATETIME,
				scheduled_for DATETIME,
				options TEXT, -- JSON object
				statistics TEXT, -- JSON object
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
			);

			CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
			CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
			CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(type);
			CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
			`,
		},
		{
			Version: 4,
			Name:    "create_findings_table",
			SQL: `
			CREATE TABLE IF NOT EXISTS findings (
				id TEXT PRIMARY KEY,
				scan_id TEXT NOT NULL,
				target_id TEXT NOT NULL,
				plugin_id TEXT,
				title TEXT NOT NULL,
				description TEXT,
				severity TEXT NOT NULL,
				confidence REAL DEFAULT 0.0,
				risk_score REAL DEFAULT 0.0,
				category TEXT,
				status TEXT NOT NULL DEFAULT 'new',
				evidence TEXT,
				remediation TEXT,
				cve TEXT,
				cwe TEXT,
				owasp TEXT,
				location TEXT,
				notes TEXT,
				accepted_by TEXT,
				resolved_by TEXT,
				accepted_at DATETIME,
				resolved_at DATETIME,
				metadata TEXT, -- JSON object
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
				FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
			);

			CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
			CREATE INDEX IF NOT EXISTS idx_findings_target_id ON findings(target_id);
			CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
			CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
			CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
			CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at);
			`,
		},
		{
			Version: 5,
			Name:    "create_reports_table",
			SQL: `
			CREATE TABLE IF NOT EXISTS reports (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				type TEXT NOT NULL,
				status TEXT NOT NULL DEFAULT 'pending',
				format TEXT NOT NULL DEFAULT 'json',
				target_id TEXT,
				scan_id TEXT,
				template_id TEXT,
				output_path TEXT,
				generated_by TEXT,
				generated_at DATETIME,
				scheduled_for DATETIME,
				config TEXT, -- JSON object
				filters TEXT, -- JSON object
				data TEXT, -- JSON object - the actual report data
				error TEXT,
				file_size INTEGER DEFAULT 0,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL,
				FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
			);

			CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(type);
			CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
			CREATE INDEX IF NOT EXISTS idx_reports_target_id ON reports(target_id);
			CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);
			CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);
			`,
		},
		{
			Version: 6,
			Name:    "create_report_schedules_table",
			SQL: `
			CREATE TABLE IF NOT EXISTS report_schedules (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				description TEXT,
				report_type TEXT NOT NULL,
				target_id TEXT,
				scan_type TEXT,
				schedule_expression TEXT NOT NULL, -- cron expression
				format TEXT NOT NULL DEFAULT 'json',
				template_id TEXT,
				enabled BOOLEAN DEFAULT 1,
				last_run DATETIME,
				next_run DATETIME,
				config TEXT, -- JSON object
				filters TEXT, -- JSON object
				output_config TEXT, -- JSON object
				notification_config TEXT, -- JSON object
				created_by TEXT,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
			);

			CREATE INDEX IF NOT EXISTS idx_report_schedules_enabled ON report_schedules(enabled);
			CREATE INDEX IF NOT EXISTS idx_report_schedules_next_run ON report_schedules(next_run);
			CREATE INDEX IF NOT EXISTS idx_report_schedules_target_id ON report_schedules(target_id);
			`,
		},
		{
			Version: 7,
			Name:    "create_payloads_table",
			SQL: `
			CREATE TABLE IF NOT EXISTS payloads (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				category TEXT NOT NULL,
				domain TEXT NOT NULL,
				type TEXT NOT NULL,
				version INTEGER DEFAULT 1,
				parent_id TEXT, -- For versioning
				content TEXT NOT NULL,
				description TEXT,
				severity TEXT NOT NULL DEFAULT 'medium',
				tags TEXT, -- JSON array
				variables TEXT, -- JSON object
				config TEXT, -- JSON object
				language TEXT,
				enabled BOOLEAN DEFAULT 1,
				validated BOOLEAN DEFAULT 0,
				validation_result TEXT, -- JSON object
				usage_count INTEGER DEFAULT 0,
				success_rate REAL DEFAULT 0.0,
				last_used DATETIME,
				created_by TEXT,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (parent_id) REFERENCES payloads(id) ON DELETE SET NULL
			);

			CREATE INDEX IF NOT EXISTS idx_payloads_name ON payloads(name);
			CREATE INDEX IF NOT EXISTS idx_payloads_category ON payloads(category);
			CREATE INDEX IF NOT EXISTS idx_payloads_domain ON payloads(domain);
			CREATE INDEX IF NOT EXISTS idx_payloads_type ON payloads(type);
			CREATE INDEX IF NOT EXISTS idx_payloads_enabled ON payloads(enabled);
			CREATE INDEX IF NOT EXISTS idx_payloads_parent_id ON payloads(parent_id);
			CREATE INDEX IF NOT EXISTS idx_payloads_version ON payloads(version);
			`,
		},
		{
			Version: 8,
			Name:    "create_plugin_stats_table",
			SQL: `
			CREATE TABLE IF NOT EXISTS plugin_stats (
				id TEXT PRIMARY KEY,
				plugin_name TEXT NOT NULL,
				plugin_version TEXT NOT NULL,
				metric_name TEXT NOT NULL,
				metric_type TEXT NOT NULL, -- counter, gauge, histogram, timer
				value REAL NOT NULL,
				unit TEXT,
				tags TEXT, -- JSON object
				target_id TEXT,
				scan_id TEXT,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL,
				FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
			);

			CREATE INDEX IF NOT EXISTS idx_plugin_stats_plugin_name ON plugin_stats(plugin_name);
			CREATE INDEX IF NOT EXISTS idx_plugin_stats_metric_name ON plugin_stats(metric_name);
			CREATE INDEX IF NOT EXISTS idx_plugin_stats_metric_type ON plugin_stats(metric_type);
			CREATE INDEX IF NOT EXISTS idx_plugin_stats_timestamp ON plugin_stats(timestamp);
			CREATE INDEX IF NOT EXISTS idx_plugin_stats_target_id ON plugin_stats(target_id);
			CREATE INDEX IF NOT EXISTS idx_plugin_stats_scan_id ON plugin_stats(scan_id);

			-- Composite index for common queries
			CREATE INDEX IF NOT EXISTS idx_plugin_stats_plugin_metric ON plugin_stats(plugin_name, metric_name);
			CREATE INDEX IF NOT EXISTS idx_plugin_stats_time_series ON plugin_stats(plugin_name, metric_name, timestamp);
			`,
		},
		{
			Version: 9,
			Name:    "create_payload_repositories_table",
			SQL: `
			CREATE TABLE IF NOT EXISTS payload_repositories (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL UNIQUE,
				url TEXT NOT NULL,
				local_path TEXT NOT NULL,

				-- Repository configuration
				clone_depth INTEGER NOT NULL DEFAULT 1,
				is_full_clone BOOLEAN DEFAULT 0,
				branch TEXT DEFAULT 'main',
				auth_type TEXT NOT NULL DEFAULT 'https',
				credential_id TEXT,
				conflict_strategy TEXT NOT NULL DEFAULT 'skip',

				-- Repository status and metadata
				status TEXT NOT NULL DEFAULT 'inactive',
				last_sync_at DATETIME,
				last_sync_error TEXT,
				last_sync_duration INTEGER, -- Duration in nanoseconds
				last_commit_hash TEXT,
				payload_count INTEGER DEFAULT 0,
				auto_sync BOOLEAN DEFAULT 0,
				sync_interval TEXT,
				description TEXT,
				tags TEXT, -- JSON array
				config TEXT, -- JSON object

				-- Discovery and organization settings
				discovery_patterns TEXT, -- JSON array
				category_mapping TEXT, -- JSON object
				domain_mapping TEXT, -- JSON object

				-- Statistics and metadata
				total_size INTEGER DEFAULT 0,
				last_modified DATETIME,
				statistics TEXT, -- JSON object

				-- Audit fields
				created_by TEXT,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_by TEXT,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

				-- Constraints
				FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE SET NULL,
				CHECK (clone_depth >= 0),
				CHECK (payload_count >= 0),
				CHECK (total_size >= 0),
				CHECK (status IN ('active', 'inactive', 'syncing', 'error', 'cloning')),
				CHECK (auth_type IN ('none', 'ssh', 'https', 'token')),
				CHECK (conflict_strategy IN ('skip', 'overwrite', 'error'))
			);

			-- Create indexes for performance
			CREATE INDEX IF NOT EXISTS idx_payload_repositories_name ON payload_repositories(name);
			CREATE INDEX IF NOT EXISTS idx_payload_repositories_url ON payload_repositories(url);
			CREATE INDEX IF NOT EXISTS idx_payload_repositories_status ON payload_repositories(status);
			CREATE INDEX IF NOT EXISTS idx_payload_repositories_auth_type ON payload_repositories(auth_type);
			CREATE INDEX IF NOT EXISTS idx_payload_repositories_auto_sync ON payload_repositories(auto_sync);
			CREATE INDEX IF NOT EXISTS idx_payload_repositories_last_sync_at ON payload_repositories(last_sync_at);
			CREATE INDEX IF NOT EXISTS idx_payload_repositories_created_at ON payload_repositories(created_at);
			CREATE INDEX IF NOT EXISTS idx_payload_repositories_credential_id ON payload_repositories(credential_id);

			-- Composite indexes for common query patterns
			CREATE INDEX IF NOT EXISTS idx_payload_repositories_status_auto_sync ON payload_repositories(status, auto_sync);
			CREATE INDEX IF NOT EXISTS idx_payload_repositories_auto_sync_last_sync ON payload_repositories(auto_sync, last_sync_at) WHERE auto_sync = 1;
			`,
		},
		{
			Version: 10,
			Name:    "add_payload_repository_fields",
			SQL: `
			-- Migration 010: Add repository tracking fields to payloads table
			-- Requirements: 3.4 (track repository source information), 5.7 (checksum-based change detection)
			-- Reversible: To rollback, run:
			--   DROP INDEX IF EXISTS idx_payloads_no_repository;
			--   DROP INDEX IF EXISTS idx_payloads_repository_tracking;
			--   DROP INDEX IF EXISTS idx_payloads_checksum;
			--   DROP INDEX IF EXISTS idx_payloads_repository_path;
			--   DROP INDEX IF EXISTS idx_payloads_repository_id;
			--   ALTER TABLE payloads DROP COLUMN checksum;
			--   ALTER TABLE payloads DROP COLUMN repository_path;
			--   ALTER TABLE payloads DROP COLUMN repository_id;

			-- Add repository tracking fields to payloads table (Requirement 3.4)
			ALTER TABLE payloads ADD COLUMN repository_id TEXT;
			ALTER TABLE payloads ADD COLUMN repository_path TEXT;

			-- Add checksum field for change detection (Requirement 5.7)
			ALTER TABLE payloads ADD COLUMN checksum TEXT;

			-- Create foreign key constraint to payload_repositories table
			-- Note: SQLite doesn't support adding foreign key constraints to existing tables
			-- We'll handle referential integrity at the application level

			-- Create indexes for improved query performance
			CREATE INDEX IF NOT EXISTS idx_payloads_repository_id ON payloads(repository_id);
			CREATE INDEX IF NOT EXISTS idx_payloads_repository_path ON payloads(repository_path);
			CREATE INDEX IF NOT EXISTS idx_payloads_checksum ON payloads(checksum);

			-- Create composite index for repository-based queries
			CREATE INDEX IF NOT EXISTS idx_payloads_repository_tracking ON payloads(repository_id, repository_path) WHERE repository_id IS NOT NULL;

			-- Create index for finding payloads without repository association
			CREATE INDEX IF NOT EXISTS idx_payloads_no_repository ON payloads(id) WHERE repository_id IS NULL;
			`,
		},
		{
			Version: 11,
			Name:    "add_plugin_name_to_payloads",
			SQL: `
			-- Migration 011: Add plugin_name field to payloads table
			-- Support domain/plugin organization structure
			-- Reversible: To rollback, run:
			--   DROP INDEX IF EXISTS idx_payloads_plugin_name;
			--   ALTER TABLE payloads DROP COLUMN plugin_name;

			-- Add plugin_name field to track which plugin each payload belongs to
			ALTER TABLE payloads ADD COLUMN plugin_name TEXT;

			-- Create index for plugin-based queries
			CREATE INDEX IF NOT EXISTS idx_payloads_plugin_name ON payloads(plugin_name);

			-- Create composite index for domain/plugin queries
			CREATE INDEX IF NOT EXISTS idx_payloads_domain_plugin ON payloads(domain, plugin_name);
			`,
		},
	}
}