// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package dao

import (
	"context"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

// SQLiteFactory represents a SQLite database factory.
type SQLiteFactory struct {
	db *sqlx.DB
}

// NewSQLiteFactory creates a new SQLite factory.
func NewSQLiteFactory(dsn string) (*SQLiteFactory, error) {
	db, err := sqlx.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	// Configure SQLite connection
	db.SetMaxOpenConns(1) // SQLite recommendation for concurrent writes
	db.SetMaxIdleConns(1)

	// Enable foreign key constraints
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		return nil, err
	}

	// Set journal mode to WAL for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		db.Close()
		return nil, err
	}

	return &SQLiteFactory{db: db}, nil
}

// DB returns the underlying SQLite database connection.
func (f *SQLiteFactory) DB() *sqlx.DB {
	return f.db
}

// Begin starts a new database transaction.
func (f *SQLiteFactory) Begin() (*sqlx.Tx, error) {
	return f.db.Beginx()
}

// Close closes the database connection.
func (f *SQLiteFactory) Close() error {
	return f.db.Close()
}

// Health checks database connectivity.
func (f *SQLiteFactory) Health() error {
	return f.db.Ping()
}

// WithTransaction executes a function within a database transaction.
func (f *SQLiteFactory) WithTransaction(ctx context.Context, fn func(tx *sqlx.Tx) error) error {
	tx, err := f.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit()
}

// SQLiteRepository represents a complete data access layer with SQLite backend.
type SQLiteRepository struct {
	*SQLiteFactory

	targets         *Target
	scans           *Scan
	findings        *Finding
	credentials     *Credential
	reports         *Report
	reportSchedules *ReportSchedule
	payloads        *Payload
	pluginStats     *PluginStats
}

// NewSQLiteRepository creates a new SQLite repository.
func NewSQLiteRepository(dsn string) (*SQLiteRepository, error) {
	factory, err := NewSQLiteFactory(dsn)
	if err != nil {
		return nil, err
	}

	// Apply migrations
	if err := ApplyMigrations(factory.DB()); err != nil {
		return nil, err
	}

	// Initialize accessors
	targets := &Target{}
	targets.Init(factory)

	scans := &Scan{}
	scans.Init(factory)

	findings := &Finding{}
	findings.Init(factory)

	credentials := &Credential{}
	credentials.Init(factory)

	reports := &Report{}
	reports.Init(factory)

	reportSchedules := &ReportSchedule{}
	reportSchedules.Init(factory)

	payloads := &Payload{}
	payloads.Init(factory)

	pluginStats := &PluginStats{}
	pluginStats.Init(factory)

	return &SQLiteRepository{
		SQLiteFactory:   factory,
		targets:         targets,
		scans:           scans,
		findings:        findings,
		credentials:     credentials,
		reports:         reports,
		reportSchedules: reportSchedules,
		payloads:        payloads,
		pluginStats:     pluginStats,
	}, nil
}

// Targets returns the target accessor.
func (r *SQLiteRepository) Targets() TargetAccessor {
	return r.targets
}

// Scans returns the scan accessor.
func (r *SQLiteRepository) Scans() ScanAccessor {
	return r.scans
}

// Findings returns the finding accessor.
func (r *SQLiteRepository) Findings() FindingAccessor {
	return r.findings
}

// Credentials returns the credential accessor.
func (r *SQLiteRepository) Credentials() CredentialAccessor {
	return r.credentials
}

// Reports returns the report accessor.
func (r *SQLiteRepository) Reports() ReportAccessor {
	return r.reports
}

// ReportSchedules returns the report schedule accessor.
func (r *SQLiteRepository) ReportSchedules() ReportScheduleAccessor {
	return r.reportSchedules
}

// Payloads returns the payload accessor.
func (r *SQLiteRepository) Payloads() PayloadAccessor {
	return r.payloads
}

// PluginStats returns the plugin stats accessor.
func (r *SQLiteRepository) PluginStats() PluginStatsAccessor {
	return r.pluginStats
}

// GetDB returns the underlying database connection for health checks.
func (r *SQLiteRepository) GetDB() *sqlx.DB {
	return r.DB()
}