// Package test provides common testing utilities and helpers for Gibson Framework
package test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-sdk/pkg/plugin"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

// TestDatabase provides a test database instance
type TestDatabase struct {
	DB   *sqlx.DB
	Path string
}

// NewTestDatabase creates a new test database instance
func NewTestDatabase(t *testing.T) *TestDatabase {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sqlx.Open("sqlite3", dbPath)
	require.NoError(t, err)

	// Enable foreign keys and other pragmas for testing
	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA cache_size = -64000", // 64MB cache
		"PRAGMA temp_store = MEMORY",
	}

	for _, pragma := range pragmas {
		_, err := db.Exec(pragma)
		require.NoError(t, err)
	}

	return &TestDatabase{
		DB:   db,
		Path: dbPath,
	}
}

// Close closes the test database
func (td *TestDatabase) Close() error {
	if td.DB != nil {
		return td.DB.Close()
	}
	return nil
}

// CreateTestTables creates test tables for testing
func (td *TestDatabase) CreateTestTables(t *testing.T) {
	schema := `
	CREATE TABLE IF NOT EXISTS targets (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		url TEXT,
		credentials TEXT, -- JSON
		config TEXT,      -- JSON
		tags TEXT,        -- JSON
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		target_id TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		started_at DATETIME,
		completed_at DATETIME,
		config TEXT,    -- JSON
		metadata TEXT,  -- JSON
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (target_id) REFERENCES targets(id)
	);

	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		severity TEXT NOT NULL,
		confidence TEXT NOT NULL,
		category TEXT NOT NULL,
		domain TEXT NOT NULL,
		evidence TEXT,    -- JSON
		location TEXT,
		payload TEXT,
		response TEXT,
		remediation TEXT,
		references TEXT,  -- JSON
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		plugin_id TEXT,
		tags TEXT,        -- JSON
		metadata TEXT,    -- JSON
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (scan_id) REFERENCES scans(id)
	);

	CREATE TABLE IF NOT EXISTS plugins (
		name TEXT PRIMARY KEY,
		version TEXT NOT NULL,
		description TEXT,
		author TEXT,
		domains TEXT,      -- JSON
		capabilities TEXT, -- JSON
		config TEXT,       -- JSON
		status TEXT NOT NULL DEFAULT 'active',
		installed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Indexes for better query performance
	CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
	CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
	CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
	CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain);
	`

	_, err := td.DB.Exec(schema)
	require.NoError(t, err)
}

// InsertTestTarget inserts a test target
func (td *TestDatabase) InsertTestTarget(t *testing.T, target TestTarget) {
	query := `
		INSERT INTO targets (id, name, type, url, credentials, config, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := td.DB.Exec(query,
		target.ID,
		target.Name,
		target.Type,
		target.URL,
		target.Credentials,
		target.Config,
		target.Tags,
	)
	require.NoError(t, err)
}

// TestTarget represents a test target
type TestTarget struct {
	ID          string
	Name        string
	Type        string
	URL         string
	Credentials string
	Config      string
	Tags        string
}

// DefaultTestTarget returns a default test target
func DefaultTestTarget() TestTarget {
	return TestTarget{
		ID:          "test-target-001",
		Name:        "Test API Server",
		Type:        "api",
		URL:         "http://localhost:8080",
		Credentials: `{"api_key": "test-key"}`,
		Config:      `{"timeout": 30}`,
		Tags:        `["test", "api"]`,
	}
}

// TestScan represents a test scan
type TestScan struct {
	ID          string
	TargetID    string
	Status      string
	StartedAt   *time.Time
	CompletedAt *time.Time
	Config      string
	Metadata    string
}

// DefaultTestScan returns a default test scan
func DefaultTestScan(targetID string) TestScan {
	now := time.Now()
	return TestScan{
		ID:        "test-scan-001",
		TargetID:  targetID,
		Status:    "running",
		StartedAt: &now,
		Config:    `{"plugins": ["test-plugin"]}`,
		Metadata:  `{"created_by": "test"}`,
	}
}

// TestFinding represents a test finding
type TestFinding struct {
	ID          string
	ScanID      string
	Title       string
	Description string
	Severity    string
	Confidence  string
	Category    string
	Domain      string
	Evidence    string
	Location    string
	Payload     string
	Response    string
	Remediation string
	References  string
	PluginID    string
	Tags        string
	Metadata    string
}

// DefaultTestFinding returns a default test finding
func DefaultTestFinding(scanID string) TestFinding {
	return TestFinding{
		ID:          "test-finding-001",
		ScanID:      scanID,
		Title:       "SQL Injection Vulnerability",
		Description: "Potential SQL injection vulnerability detected",
		Severity:    "high",
		Confidence:  "high",
		Category:    "injection",
		Domain:      "interface",
		Evidence:    `{"query": "' OR '1'='1", "response_time": 150}`,
		Location:    "/api/users?id=1",
		Payload:     "' OR '1'='1",
		Response:    "HTTP 200 - User data returned",
		Remediation: "Use parameterized queries",
		References:  `["https://owasp.org/Top10/A03_2021-Injection/"]`,
		PluginID:    "sql-injection-scanner",
		Tags:        `["sql", "injection"]`,
		Metadata:    `{"tool_version": "1.0.0"}`,
	}
}

// MockSecurityPlugin provides a mock implementation for testing
type MockSecurityPlugin struct {
	InfoResponse     *plugin.PluginInfo
	ExecuteResponse  *plugin.AssessResponse
	ValidateError    error
	HealthError      error
	ExecuteError     error
	ExecuteDelay     time.Duration
}

// NewMockSecurityPlugin creates a new mock security plugin
func NewMockSecurityPlugin() *MockSecurityPlugin {
	return &MockSecurityPlugin{
		InfoResponse: &plugin.PluginInfo{
			Name:         "mock-plugin",
			Version:      "1.0.0",
			Description:  "Mock security plugin for testing",
			Author:       "Test Suite",
			Domains:      []plugin.SecurityDomain{plugin.DomainInterface},
			Capabilities: []string{"assess", "validate"},
			Config:       map[string]string{"timeout": "30s"},
		},
		ExecuteResponse: &plugin.AssessResponse{
			Success:   true,
			Completed: true,
			Findings:  []*plugin.Finding{},
			StartTime: time.Now(),
			EndTime:   time.Now(),
			Duration:  time.Second,
			Metadata:  map[string]string{"test": "true"},
		},
	}
}

func (m *MockSecurityPlugin) GetInfo(ctx context.Context) (*plugin.PluginInfo, error) {
	if m.InfoResponse == nil {
		return nil, fmt.Errorf("no info response configured")
	}
	return m.InfoResponse, nil
}

func (m *MockSecurityPlugin) Execute(ctx context.Context, request *plugin.AssessRequest) (*plugin.AssessResponse, error) {
	if m.ExecuteDelay > 0 {
		time.Sleep(m.ExecuteDelay)
	}

	if m.ExecuteError != nil {
		return nil, m.ExecuteError
	}

	if m.ExecuteResponse == nil {
		return nil, fmt.Errorf("no execute response configured")
	}

	return m.ExecuteResponse, nil
}

func (m *MockSecurityPlugin) Validate(ctx context.Context, request *plugin.AssessRequest) error {
	return m.ValidateError
}

func (m *MockSecurityPlugin) Health(ctx context.Context) error {
	return m.HealthError
}

// TestLogger creates a logger suitable for testing
func TestLogger(t *testing.T) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}

	// Use a text handler for easier test debugging
	handler := slog.NewTextHandler(os.Stdout, opts)
	return slog.New(handler)
}

// AssertEventually asserts that a condition becomes true within a timeout
func AssertEventually(t *testing.T, condition func() bool, timeout time.Duration, message string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.Fatalf("Condition not met within timeout: %s", message)
		case <-ticker.C:
			if condition() {
				return
			}
		}
	}
}

// CreateTestTarget creates a test target from plugin.Target
func CreateTestTarget(id, name, targetType string) *plugin.Target {
	return &plugin.Target{
		ID:          id,
		Name:        name,
		Type:        targetType,
		URL:         "http://localhost:8080",
		Credentials: map[string]string{"api_key": "test-key"},
		Config:      map[string]string{"timeout": "30s"},
		Tags:        []string{"test"},
	}
}

// CreateTestAssessRequest creates a test assessment request
func CreateTestAssessRequest(target *plugin.Target, scanID string) *plugin.AssessRequest {
	return &plugin.AssessRequest{
		Target:   target,
		Config:   map[string]interface{}{"test_mode": true},
		ScanID:   scanID,
		Timeout:  30 * time.Second,
		Metadata: map[string]string{"test": "true"},
	}
}

// CreateTestFinding creates a test finding
func CreateTestFinding(id, title, severity string) *plugin.Finding {
	return &plugin.Finding{
		ID:          id,
		Title:       title,
		Description: "Test finding for unit tests",
		Severity:    plugin.SeverityLevel(severity),
		Confidence:  plugin.ConfidenceHigh,
		Category:    "test",
		Domain:      plugin.DomainInterface,
		Evidence:    map[string]interface{}{"test": true},
		Location:    "/test/endpoint",
		Payload:     "test payload",
		Response:    "test response",
		Remediation: "Test remediation steps",
		References:  []string{"https://example.com/test"},
		Timestamp:   time.Now(),
		PluginID:    "test-plugin",
		Tags:        []string{"test"},
		Metadata:    map[string]string{"test": "true"},
	}
}