// Package testutil provides enhanced database testing utilities for Gibson Framework
package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/dao"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

// TestDatabase provides an enhanced test database instance with comprehensive utilities
type TestDatabase struct {
	DB       *sqlx.DB
	Path     string
	tempDir  string
	t        *testing.T
}

// TestDatabaseConfig allows customization of test database setup
type TestDatabaseConfig struct {
	InMemory       bool
	EnableWAL      bool
	EnableFK       bool
	CacheSize      int64  // In KB, default 64MB
	JournalMode    string // WAL, DELETE, TRUNCATE, PERSIST, MEMORY, OFF
	Synchronous    string // OFF, NORMAL, FULL, EXTRA
	TempStore      string // DEFAULT, FILE, MEMORY
}

// DefaultTestDatabaseConfig returns a sensible default configuration for testing
func DefaultTestDatabaseConfig() *TestDatabaseConfig {
	return &TestDatabaseConfig{
		InMemory:    false, // Use file-based for better debugging
		EnableWAL:   true,
		EnableFK:    true,
		CacheSize:   64 * 1024, // 64MB
		JournalMode: "WAL",
		Synchronous: "NORMAL",
		TempStore:   "MEMORY",
	}
}

// NewTestDatabase creates a new test database instance with default configuration
func NewTestDatabase(t *testing.T) *TestDatabase {
	return NewTestDatabaseWithConfig(t, DefaultTestDatabaseConfig())
}

// NewTestDatabaseWithConfig creates a new test database with custom configuration
func NewTestDatabaseWithConfig(t *testing.T, config *TestDatabaseConfig) *TestDatabase {
	var dbPath string
	var tempDir string

	if config.InMemory {
		dbPath = ":memory:"
	} else {
		tempDir = t.TempDir()
		dbPath = filepath.Join(tempDir, "test.db")
	}

	db, err := sqlx.Open("sqlite3", dbPath)
	require.NoError(t, err)

	testDB := &TestDatabase{
		DB:      db,
		Path:    dbPath,
		tempDir: tempDir,
		t:       t,
	}

	// Apply configuration
	testDB.applyConfiguration(config)

	return testDB
}

// applyConfiguration applies the database configuration settings
func (td *TestDatabase) applyConfiguration(config *TestDatabaseConfig) {
	pragmas := []string{}

	// Foreign keys
	if config.EnableFK {
		pragmas = append(pragmas, "PRAGMA foreign_keys = ON")
	}

	// Journal mode
	if config.JournalMode != "" {
		pragmas = append(pragmas, fmt.Sprintf("PRAGMA journal_mode = %s", config.JournalMode))
	}

	// Synchronous mode
	if config.Synchronous != "" {
		pragmas = append(pragmas, fmt.Sprintf("PRAGMA synchronous = %s", config.Synchronous))
	}

	// Cache size
	if config.CacheSize > 0 {
		pragmas = append(pragmas, fmt.Sprintf("PRAGMA cache_size = -%d", config.CacheSize))
	}

	// Temp store
	if config.TempStore != "" {
		pragmas = append(pragmas, fmt.Sprintf("PRAGMA temp_store = %s", config.TempStore))
	}

	// Additional pragmas for testing performance and reliability
	pragmas = append(pragmas, []string{
		"PRAGMA busy_timeout = 30000",      // 30 second busy timeout
		"PRAGMA wal_autocheckpoint = 1000", // Checkpoint every 1000 pages
		"PRAGMA optimize",                   // Optimize query performance
	}...)

	for _, pragma := range pragmas {
		_, err := td.DB.Exec(pragma)
		require.NoError(td.t, err, "Failed to execute pragma: %s", pragma)
	}
}

// Close closes the test database and cleans up resources
func (td *TestDatabase) Close() error {
	if td.DB != nil {
		return td.DB.Close()
	}
	return nil
}

// CreateAllTables creates all the required tables for comprehensive testing
func (td *TestDatabase) CreateAllTables() {
	// Apply DAO migrations (this creates all the main tables)
	require.NoError(td.t, dao.ApplyMigrations(td.DB))

	// Create additional tables for testing
	td.createAuditTable()
	td.createConfigTable()
}

// CreateTestTables creates the basic test tables (from original helpers.go)
func (td *TestDatabase) CreateTestTables() {
	schema := `
	CREATE TABLE IF NOT EXISTS targets (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		provider TEXT NOT NULL,
		model TEXT,
		url TEXT,
		api_version TEXT,
		credential_id TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		description TEXT,
		tags TEXT,
		headers TEXT,
		config TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		target_id TEXT NOT NULL,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		progress REAL DEFAULT 0.0,
		error TEXT,
		started_by TEXT,
		started_at DATETIME,
		completed_at DATETIME,
		scheduled_for DATETIME,
		options TEXT,
		statistics TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (target_id) REFERENCES targets(id)
	);

	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		target_id TEXT NOT NULL,
		plugin_id TEXT,
		title TEXT NOT NULL,
		description TEXT,
		severity TEXT NOT NULL,
		confidence REAL NOT NULL,
		risk_score REAL,
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
		metadata TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id),
		FOREIGN KEY (target_id) REFERENCES targets(id)
	);

	CREATE TABLE IF NOT EXISTS plugins (
		name TEXT PRIMARY KEY,
		version TEXT NOT NULL,
		description TEXT,
		author TEXT,
		domains TEXT,
		capabilities TEXT,
		config TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		installed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Indexes for better query performance
	CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
	CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
	CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
	CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
	CREATE INDEX IF NOT EXISTS idx_findings_target_id ON findings(target_id);
	CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
	CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
	CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at);
	`

	_, err := td.DB.Exec(schema)
	require.NoError(td.t, err)
}

// createCredentialsTable creates the credentials table for testing
func (td *TestDatabase) createCredentialsTable() {
	schema := `
	CREATE TABLE IF NOT EXISTS credentials (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		provider TEXT NOT NULL,
		type TEXT NOT NULL,
		encrypted_value BLOB NOT NULL,
		salt BLOB NOT NULL,
		nonce BLOB NOT NULL,
		description TEXT,
		tags TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		auto_rotate BOOLEAN DEFAULT FALSE,
		rotation_interval TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_used DATETIME,
		last_rotated DATETIME
	);

	CREATE TABLE IF NOT EXISTS credential_history (
		id TEXT PRIMARY KEY,
		credential_id TEXT NOT NULL,
		old_encrypted_value BLOB NOT NULL,
		old_salt BLOB NOT NULL,
		old_nonce BLOB NOT NULL,
		rotated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		rotation_reason TEXT,
		FOREIGN KEY (credential_id) REFERENCES credentials(id)
	);

	CREATE INDEX IF NOT EXISTS idx_credentials_name ON credentials(name);
	CREATE INDEX IF NOT EXISTS idx_credentials_provider ON credentials(provider);
	CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(type);
	CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status);
	CREATE INDEX IF NOT EXISTS idx_credential_history_credential_id ON credential_history(credential_id);
	`

	_, err := td.DB.Exec(schema)
	require.NoError(td.t, err)
}

// createAuditTable creates the audit table for testing
func (td *TestDatabase) createAuditTable() {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		user_id TEXT,
		action TEXT NOT NULL,
		resource_type TEXT NOT NULL,
		resource_id TEXT NOT NULL,
		old_values TEXT,
		new_values TEXT,
		ip_address TEXT,
		user_agent TEXT,
		session_id TEXT,
		success BOOLEAN NOT NULL DEFAULT TRUE,
		error_message TEXT,
		metadata TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
	`

	_, err := td.DB.Exec(schema)
	require.NoError(td.t, err)
}

// createConfigTable creates the config table for testing
func (td *TestDatabase) createConfigTable() {
	schema := `
	CREATE TABLE IF NOT EXISTS config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		description TEXT,
		category TEXT,
		is_sensitive BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_config_category ON config(category);
	`

	_, err := td.DB.Exec(schema)
	require.NoError(td.t, err)
}

// SeedData provides methods to seed test data
type SeedData struct {
	db *TestDatabase
}

// GetSeedData returns a SeedData instance for populating test data
func (td *TestDatabase) GetSeedData() *SeedData {
	return &SeedData{db: td}
}

// SeedBasicData creates a basic set of test data for comprehensive testing
func (sd *SeedData) SeedBasicData() {
	ctx := context.Background()

	// Seed targets
	targets := []struct {
		id       string
		name     string
		typ      string
		provider string
		url      string
	}{
		{"target-web-001", "Production Web App", "api", "openai", "https://app.example.com"},
		{"target-api-001", "REST API Gateway", "api", "anthropic", "https://api.example.com"},
		{"target-ai-001", "AI Chatbot Service", "api", "openai", "https://chat.example.com"},
	}

	for _, target := range targets {
		query := `INSERT INTO targets (id, name, type, provider, url, status, description, tags, config) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
		_, err := sd.db.DB.ExecContext(ctx, query,
			target.id,
			target.name,
			target.typ,
			target.provider,
			target.url,
			"active",
			"Seed test target",
			`["test", "seed"]`,
			`{"timeout": 30}`,
		)
		require.NoError(sd.db.t, err)
	}

	// Seed scans
	scans := []struct {
		id       string
		targetID string
		name     string
		typ      string
		status   string
	}{
		{"scan-001", "target-web-001", "Web Security Scan", "basic", "completed"},
		{"scan-002", "target-api-001", "API Security Test", "advanced", "running"},
		{"scan-003", "target-ai-001", "AI Safety Assessment", "custom", "completed"},
	}

	for _, scan := range scans {
		query := `INSERT INTO scans (id, target_id, name, type, status, progress, started_at, options) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
		_, err := sd.db.DB.ExecContext(ctx, query,
			scan.id,
			scan.targetID,
			scan.name,
			scan.typ,
			scan.status,
			75.0,
			time.Now().Add(-2*time.Hour),
			`{"plugins": ["comprehensive"]}`,
		)
		require.NoError(sd.db.t, err)
	}

	// Seed findings
	findings := []struct {
		id       string
		scanID   string
		targetID string
		title    string
		severity string
		category string
	}{
		{"finding-001", "scan-001", "target-web-001", "SQL Injection", "critical", "injection"},
		{"finding-002", "scan-001", "target-web-001", "XSS Vulnerability", "high", "xss"},
		{"finding-003", "scan-003", "target-ai-001", "Prompt Injection", "high", "prompt-injection"},
	}

	for _, finding := range findings {
		query := `INSERT INTO findings (id, scan_id, target_id, title, description, severity, confidence, category, status, plugin_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		_, err := sd.db.DB.ExecContext(ctx, query,
			finding.id,
			finding.scanID,
			finding.targetID,
			finding.title,
			fmt.Sprintf("Test finding: %s", finding.title),
			finding.severity,
			0.9,
			finding.category,
			"new",
			"test-plugin",
		)
		require.NoError(sd.db.t, err)
	}
}

// SeedPayloads creates test payload data
func (sd *SeedData) SeedPayloads() {
	// TODO: Update to use model-based DAO implementation
	// This function is deprecated and should be removed or updated
	// Current payload DAO tests are in internal/dao/payload_dao_test.go
}

// SeedReports creates test report data
func (sd *SeedData) SeedReports() {
	// TODO: Update to use model-based DAO implementation
	// This function is deprecated and should be removed or updated
}

// SeedPluginStats creates test plugin statistics data
func (sd *SeedData) SeedPluginStats() {
	// TODO: Update to use model-based DAO implementation
	// This function is deprecated and should be removed or updated
}

// SeedAll creates a complete set of test data across all tables
func (sd *SeedData) SeedAll() {
	sd.SeedBasicData()
	sd.SeedPayloads()
	sd.SeedReports()
	sd.SeedPluginStats()
}

// TestHelper provides utility methods for testing
type TestHelper struct {
	db *TestDatabase
}

// GetTestHelper returns a TestHelper instance
func (td *TestDatabase) GetTestHelper() *TestHelper {
	return &TestHelper{db: td}
}

// AssertTableExists verifies that a table exists in the database
func (th *TestHelper) AssertTableExists(tableName string) {
	var count int
	query := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`
	err := th.db.DB.Get(&count, query, tableName)
	require.NoError(th.db.t, err)
	require.Equal(th.db.t, 1, count, "Table %s should exist", tableName)
}

// AssertIndexExists verifies that an index exists in the database
func (th *TestHelper) AssertIndexExists(indexName string) {
	var count int
	query := `SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`
	err := th.db.DB.Get(&count, query, indexName)
	require.NoError(th.db.t, err)
	require.Equal(th.db.t, 1, count, "Index %s should exist", indexName)
}

// CountRows returns the number of rows in a table
func (th *TestHelper) CountRows(tableName string) int {
	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)
	err := th.db.DB.Get(&count, query)
	require.NoError(th.db.t, err)
	return count
}

// CleanTable truncates all data from a table
func (th *TestHelper) CleanTable(tableName string) {
	query := fmt.Sprintf("DELETE FROM %s", tableName)
	_, err := th.db.DB.Exec(query)
	require.NoError(th.db.t, err)
}

// CleanAllTables truncates all test tables
func (th *TestHelper) CleanAllTables() {
	tables := []string{
		"credential_history",
		"credentials",
		"plugin_stats",
		"reports",
		"payloads",
		"findings",
		"scans",
		"targets",
		"plugins",
		"audit_logs",
		"config",
	}

	// Disable foreign keys temporarily for cleanup
	_, err := th.db.DB.Exec("PRAGMA foreign_keys = OFF")
	require.NoError(th.db.t, err)

	for _, table := range tables {
		th.CleanTable(table)
	}

	// Re-enable foreign keys
	_, err = th.db.DB.Exec("PRAGMA foreign_keys = ON")
	require.NoError(th.db.t, err)
}

// ExecuteInTransaction executes a function within a database transaction
func (th *TestHelper) ExecuteInTransaction(fn func(*sql.Tx) error) {
	tx, err := th.db.DB.Begin()
	require.NoError(th.db.t, err)

	err = fn(tx)
	if err != nil {
		tx.Rollback()
		require.NoError(th.db.t, err)
		return
	}

	err = tx.Commit()
	require.NoError(th.db.t, err)
}

// WaitForCondition waits for a condition to become true within a timeout
func (th *TestHelper) WaitForCondition(condition func() bool, timeout time.Duration, message string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			th.db.t.Fatalf("Condition not met within timeout: %s", message)
		case <-ticker.C:
			if condition() {
				return
			}
		}
	}
}

// GetDatabaseInfo returns diagnostic information about the database
func (th *TestHelper) GetDatabaseInfo() map[string]interface{} {
	info := make(map[string]interface{})

	// Get database size
	var pageCount, pageSize int64
	err := th.db.DB.Get(&pageCount, "PRAGMA page_count")
	require.NoError(th.db.t, err)
	err = th.db.DB.Get(&pageSize, "PRAGMA page_size")
	require.NoError(th.db.t, err)

	info["size_bytes"] = pageCount * pageSize
	info["page_count"] = pageCount
	info["page_size"] = pageSize

	// Get table information
	tables := []struct {
		Name string `db:"name"`
	}{}
	err = th.db.DB.Select(&tables, "SELECT name FROM sqlite_master WHERE type='table'")
	require.NoError(th.db.t, err)

	tableInfo := make(map[string]int)
	for _, table := range tables {
		count := th.CountRows(table.Name)
		tableInfo[table.Name] = count
	}
	info["tables"] = tableInfo

	return info
}