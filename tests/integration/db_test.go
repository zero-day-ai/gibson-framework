// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package integration_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/dao"
	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/zero-day-ai/gibson-framework/internal/testutil"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDatabaseInitialization tests database setup and migration process
func TestDatabaseInitialization(t *testing.T) {
	tests := []struct {
		name     string
		config   *testutil.TestDatabaseConfig
		wantErr  bool
		checkWAL bool
	}{
		{
			name:     "in-memory database",
			config:   &testutil.TestDatabaseConfig{InMemory: true, EnableFK: true},
			wantErr:  false,
			checkWAL: false,
		},
		{
			name:     "file-based WAL mode",
			config:   testutil.DefaultTestDatabaseConfig(),
			wantErr:  false,
			checkWAL: true,
		},
		{
			name: "custom configuration",
			config: &testutil.TestDatabaseConfig{
				InMemory:    false,
				EnableWAL:   true,
				EnableFK:    true,
				CacheSize:   32 * 1024, // 32MB
				JournalMode: "WAL",
				Synchronous: "FULL",
				TempStore:   "MEMORY",
			},
			wantErr:  false,
			checkWAL: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDB := testutil.NewTestDatabaseWithConfig(t, tt.config)
			defer testDB.Close()

			// Test database connection
			err := testDB.DB.Ping()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Create all tables
			testDB.CreateAllTables()

			// Verify essential tables exist
			helper := testDB.GetTestHelper()
			expectedTables := []string{
				"targets", "scans", "findings", "credentials",
				"reports", "payloads", "plugin_stats",
			}

			for _, table := range expectedTables {
				helper.AssertTableExists(table)
			}

			// Test WAL mode if enabled
			if tt.checkWAL {
				var journalMode string
				err := testDB.DB.Get(&journalMode, "PRAGMA journal_mode")
				require.NoError(t, err)
				assert.Equal(t, "wal", journalMode)
			}

			// Test foreign key constraints
			if tt.config.EnableFK {
				var fkEnabled int
				err := testDB.DB.Get(&fkEnabled, "PRAGMA foreign_keys")
				require.NoError(t, err)
				assert.Equal(t, 1, fkEnabled)
			}
		})
	}
}

// TestDatabaseCRUDOperations tests CRUD operations for all entities
func TestDatabaseCRUDOperations(t *testing.T) {
	testDB := testutil.NewTestDatabase(t)
	defer testDB.Close()

	testDB.CreateAllTables()
	ctx := context.Background()

	// Initialize repository
	repo, err := dao.NewSQLiteRepository(testDB.Path)
	require.NoError(t, err)
	defer repo.Close()

	t.Run("Target CRUD Operations", func(t *testing.T) {
		testTargetCRUD(t, ctx, repo)
	})

	t.Run("Credential CRUD Operations", func(t *testing.T) {
		testCredentialCRUD(t, ctx, repo)
	})

	t.Run("Scan CRUD Operations", func(t *testing.T) {
		testScanCRUD(t, ctx, repo)
	})

	t.Run("Finding CRUD Operations", func(t *testing.T) {
		testFindingCRUD(t, ctx, repo)
	})

	t.Run("Report CRUD Operations", func(t *testing.T) {
		testReportCRUD(t, ctx, repo)
	})

	t.Run("Payload CRUD Operations", func(t *testing.T) {
		testPayloadCRUD(t, ctx, repo)
	})

	t.Run("Plugin Stats CRUD Operations", func(t *testing.T) {
		testPluginStatsCRUD(t, ctx, repo)
	})
}

// TestTransactionHandling tests transaction rollback and commit behavior
func TestTransactionHandling(t *testing.T) {
	testDB := testutil.NewTestDatabase(t)
	defer testDB.Close()

	testDB.CreateAllTables()
	ctx := context.Background()

	repo, err := dao.NewSQLiteRepository(testDB.Path)
	require.NoError(t, err)
	defer repo.Close()

	t.Run("Transaction Commit", func(t *testing.T) {
		// Test successful transaction
		err := repo.WithTransaction(ctx, func(tx *sqlx.Tx) error {
			target := createTestTarget()
			return repo.Targets().Create(ctx, target)
		})
		require.NoError(t, err)

		// Verify data persisted
		targets, err := repo.Targets().List(ctx)
		require.NoError(t, err)
		assert.Len(t, targets, 1)
	})

	t.Run("Transaction Rollback", func(t *testing.T) {
		initialCount := testDB.GetTestHelper().CountRows("targets")

		// Test transaction rollback
		err := repo.WithTransaction(ctx, func(tx *sqlx.Tx) error {
			target := createTestTarget()
			target.Name = "rollback-test"
			if err := repo.Targets().Create(ctx, target); err != nil {
				return err
			}
			// Force error to trigger rollback
			return fmt.Errorf("forced rollback")
		})
		require.Error(t, err)

		// Verify data was not persisted
		finalCount := testDB.GetTestHelper().CountRows("targets")
		assert.Equal(t, initialCount, finalCount)
	})
}

// TestConcurrentAccess tests concurrent database operations
func TestConcurrentAccess(t *testing.T) {
	testDB := testutil.NewTestDatabaseWithConfig(t, &testutil.TestDatabaseConfig{
		InMemory:    false,
		EnableWAL:   true,
		EnableFK:    true,
		JournalMode: "WAL",
		Synchronous: "NORMAL",
	})
	defer testDB.Close()

	testDB.CreateAllTables()
	ctx := context.Background()

	repo, err := dao.NewSQLiteRepository(testDB.Path)
	require.NoError(t, err)
	defer repo.Close()

	t.Run("Concurrent Target Creation", func(t *testing.T) {
		const numGoroutines = 10
		const targetsPerGoroutine = 5

		var wg sync.WaitGroup
		errCh := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(routineID int) {
				defer wg.Done()

				for j := 0; j < targetsPerGoroutine; j++ {
					target := createTestTarget()
					target.Name = fmt.Sprintf("concurrent-target-%d-%d", routineID, j)

					if err := repo.Targets().Create(ctx, target); err != nil {
						errCh <- fmt.Errorf("routine %d, target %d: %w", routineID, j, err)
						return
					}
				}
			}(i)
		}

		wg.Wait()
		close(errCh)

		// Check for errors
		for err := range errCh {
			t.Errorf("Concurrent operation failed: %v", err)
		}

		// Verify all targets were created
		targets, err := repo.Targets().List(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(targets), numGoroutines*targetsPerGoroutine)
	})

	t.Run("Concurrent Scan Updates", func(t *testing.T) {
		// Create a target first
		target := createTestTarget()
		target.Name = "concurrent-scan-target"
		require.NoError(t, repo.Targets().Create(ctx, target))

		// Create multiple scans
		scanIDs := make([]uuid.UUID, 5)
		for i := range scanIDs {
			scan := createTestScan(target.ID)
			scan.Name = fmt.Sprintf("concurrent-scan-%d", i)
			require.NoError(t, repo.Scans().Create(ctx, scan))
			scanIDs[i] = scan.ID
		}

		// Update scans concurrently
		var wg sync.WaitGroup
		errCh := make(chan error, len(scanIDs))

		for _, scanID := range scanIDs {
			wg.Add(1)
			go func(id uuid.UUID) {
				defer wg.Done()

				// Simulate scan progress updates
				for progress := 10.0; progress <= 100.0; progress += 10.0 {
					if err := repo.Scans().UpdateProgress(ctx, id, progress); err != nil {
						errCh <- fmt.Errorf("failed to update scan %s progress: %w", id, err)
						return
					}
					time.Sleep(1 * time.Millisecond) // Small delay to simulate work
				}
			}(scanID)
		}

		wg.Wait()
		close(errCh)

		// Check for errors
		for err := range errCh {
			t.Errorf("Concurrent scan update failed: %v", err)
		}

		// Verify final state
		for _, scanID := range scanIDs {
			scan, err := repo.Scans().Get(ctx, scanID)
			require.NoError(t, err)
			assert.Equal(t, 100.0, scan.Progress)
		}
	})
}

// TestDatabaseConstraints tests foreign key constraints and data validation
func TestDatabaseConstraints(t *testing.T) {
	testDB := testutil.NewTestDatabase(t)
	defer testDB.Close()

	testDB.CreateAllTables()
	ctx := context.Background()

	repo, err := dao.NewSQLiteRepository(testDB.Path)
	require.NoError(t, err)
	defer repo.Close()

	t.Run("Foreign Key Constraints", func(t *testing.T) {
		nonExistentTargetID := uuid.New()

		// Try to create scan with non-existent target
		scan := createTestScan(nonExistentTargetID)
		err := repo.Scans().Create(ctx, scan)
		assert.Error(t, err, "Should fail due to foreign key constraint")

		// Create valid target first
		target := createTestTarget()
		require.NoError(t, repo.Targets().Create(ctx, target))

		// Now scan creation should succeed
		scan.TargetID = target.ID
		require.NoError(t, repo.Scans().Create(ctx, scan))

		// Try to delete target with existing scans
		err = repo.Targets().Delete(ctx, target.ID)
		assert.Error(t, err, "Should fail due to foreign key constraint")

		// Delete scan first
		require.NoError(t, repo.Scans().Delete(ctx, scan.ID))

		// Now target deletion should succeed
		require.NoError(t, repo.Targets().Delete(ctx, target.ID))
	})

	t.Run("Unique Constraints", func(t *testing.T) {
		target1 := createTestTarget()
		target1.Name = "unique-target"
		require.NoError(t, repo.Targets().Create(ctx, target1))

		// Try to create another target with same name
		target2 := createTestTarget()
		target2.Name = "unique-target"
		err := repo.Targets().Create(ctx, target2)
		assert.Error(t, err, "Should fail due to unique constraint on name")
	})
}

// testTargetCRUD tests Target entity CRUD operations
func testTargetCRUD(t *testing.T, ctx context.Context, repo *dao.SQLiteRepository) {
	// Create
	target := createTestTarget()
	err := repo.Targets().Create(ctx, target)
	require.NoError(t, err)

	// Read
	retrieved, err := repo.Targets().Get(ctx, target.ID)
	require.NoError(t, err)
	assert.Equal(t, target.Name, retrieved.Name)
	assert.Equal(t, target.Provider, retrieved.Provider)

	// Update
	retrieved.Description = "Updated description"
	err = repo.Targets().Update(ctx, retrieved)
	require.NoError(t, err)

	updated, err := repo.Targets().Get(ctx, target.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated description", updated.Description)

	// List operations
	targets, err := repo.Targets().List(ctx)
	require.NoError(t, err)
	assert.Greater(t, len(targets), 0)

	// Provider-specific list
	providerTargets, err := repo.Targets().ListByProvider(ctx, target.Provider)
	require.NoError(t, err)
	assert.Greater(t, len(providerTargets), 0)

	// Status operations
	err = repo.Targets().UpdateStatus(ctx, target.ID, model.TargetStatusInactive)
	require.NoError(t, err)

	inactiveTargets, err := repo.Targets().ListByStatus(ctx, model.TargetStatusInactive)
	require.NoError(t, err)
	assert.Greater(t, len(inactiveTargets), 0)

	// Delete
	err = repo.Targets().Delete(ctx, target.ID)
	require.NoError(t, err)

	_, err = repo.Targets().Get(ctx, target.ID)
	assert.Error(t, err, "Should not find deleted target")
}

// testCredentialCRUD tests Credential entity CRUD operations
func testCredentialCRUD(t *testing.T, ctx context.Context, repo *dao.SQLiteRepository) {
	// Create
	credential := createTestCredential()
	err := repo.Credentials().Create(ctx, credential)
	require.NoError(t, err)

	// Read
	retrieved, err := repo.Credentials().Get(ctx, credential.ID)
	require.NoError(t, err)
	assert.Equal(t, credential.Name, retrieved.Name)
	assert.Equal(t, credential.Type, retrieved.Type)
	assert.Equal(t, credential.Provider, retrieved.Provider)

	// Update
	retrieved.Description = "Updated credential description"
	err = repo.Credentials().Update(ctx, retrieved)
	require.NoError(t, err)

	// List operations
	credentials, err := repo.Credentials().List(ctx)
	require.NoError(t, err)
	assert.Greater(t, len(credentials), 0)

	// Provider-specific operations
	providerCredentials, err := repo.Credentials().ListByProvider(ctx, credential.Provider)
	require.NoError(t, err)
	assert.Greater(t, len(providerCredentials), 0)

	// Status operations
	statusCredentials, err := repo.Credentials().ListByStatus(ctx, model.CredentialStatusActive)
	require.NoError(t, err)
	assert.Greater(t, len(statusCredentials), 0)

	// Update last used
	err = repo.Credentials().UpdateLastUsed(ctx, credential.ID)
	require.NoError(t, err)

	// Delete
	err = repo.Credentials().Delete(ctx, credential.ID)
	require.NoError(t, err)
}

// testScanCRUD tests Scan entity CRUD operations
func testScanCRUD(t *testing.T, ctx context.Context, repo *dao.SQLiteRepository) {
	// Create target first
	target := createTestTarget()
	require.NoError(t, repo.Targets().Create(ctx, target))

	// Create
	scan := createTestScan(target.ID)
	err := repo.Scans().Create(ctx, scan)
	require.NoError(t, err)

	// Read
	retrieved, err := repo.Scans().Get(ctx, scan.ID)
	require.NoError(t, err)
	assert.Equal(t, scan.TargetID, retrieved.TargetID)
	assert.Equal(t, scan.Type, retrieved.Type)

	// Update
	retrieved.Progress = 50.0
	err = repo.Scans().Update(ctx, retrieved)
	require.NoError(t, err)

	// Progress update
	err = repo.Scans().UpdateProgress(ctx, scan.ID, 75.0)
	require.NoError(t, err)

	updated, err := repo.Scans().Get(ctx, scan.ID)
	require.NoError(t, err)
	assert.Equal(t, 75.0, updated.Progress)

	// Status update
	err = repo.Scans().UpdateStatus(ctx, scan.ID, model.ScanStatusCompleted)
	require.NoError(t, err)

	// List operations
	scans, err := repo.Scans().List(ctx)
	require.NoError(t, err)
	assert.Greater(t, len(scans), 0)

	// Target-specific scans
	targetScans, err := repo.Scans().GetByTargetID(ctx, target.ID)
	require.NoError(t, err)
	assert.Greater(t, len(targetScans), 0)

	// Status-specific scans
	completedScans, err := repo.Scans().ListByStatus(ctx, model.ScanStatusCompleted)
	require.NoError(t, err)
	assert.Greater(t, len(completedScans), 0)

	// Delete
	err = repo.Scans().Delete(ctx, scan.ID)
	require.NoError(t, err)
}

// testFindingCRUD tests Finding entity CRUD operations
func testFindingCRUD(t *testing.T, ctx context.Context, repo *dao.SQLiteRepository) {
	// Create target and scan first
	target := createTestTarget()
	require.NoError(t, repo.Targets().Create(ctx, target))

	scan := createTestScan(target.ID)
	require.NoError(t, repo.Scans().Create(ctx, scan))

	// Create
	finding := createTestFinding(scan.ID, target.ID)
	err := repo.Findings().Create(ctx, finding)
	require.NoError(t, err)

	// Read
	retrieved, err := repo.Findings().Get(ctx, finding.ID)
	require.NoError(t, err)
	assert.Equal(t, finding.Title, retrieved.Title)
	assert.Equal(t, finding.Severity, retrieved.Severity)

	// Update
	retrieved.Status = model.FindingStatusReviewed
	err = repo.Findings().Update(ctx, retrieved)
	require.NoError(t, err)

	// Status update
	err = repo.Findings().UpdateStatus(ctx, finding.ID, model.FindingStatusAccepted)
	require.NoError(t, err)

	// List operations
	findings, err := repo.Findings().List(ctx)
	require.NoError(t, err)
	assert.Greater(t, len(findings), 0)

	// Scan-specific findings
	scanFindings, err := repo.Findings().GetByScanID(ctx, scan.ID)
	require.NoError(t, err)
	assert.Greater(t, len(scanFindings), 0)

	// Target-specific findings
	targetFindings, err := repo.Findings().GetByTargetID(ctx, target.ID)
	require.NoError(t, err)
	assert.Greater(t, len(targetFindings), 0)

	// Severity-based filtering
	criticalFindings, err := repo.Findings().ListBySeverity(ctx, model.SeverityCritical)
	require.NoError(t, err)
	if finding.Severity == model.SeverityCritical {
		assert.Greater(t, len(criticalFindings), 0)
	}

	// High severity findings
	highSevFindings, err := repo.Findings().GetHighSeverityFindings(ctx)
	require.NoError(t, err)
	if finding.Severity == model.SeverityCritical || finding.Severity == model.SeverityHigh {
		assert.Greater(t, len(highSevFindings), 0)
	}

	// Count by severity
	severityCount, err := repo.Findings().CountBySeverity(ctx)
	require.NoError(t, err)
	assert.Greater(t, len(severityCount), 0)

	// Delete
	err = repo.Findings().Delete(ctx, finding.ID)
	require.NoError(t, err)
}

// testReportCRUD tests Report entity CRUD operations
func testReportCRUD(t *testing.T, ctx context.Context, repo *dao.SQLiteRepository) {
	// Create target first
	target := createTestTarget()
	require.NoError(t, repo.Targets().Create(ctx, target))

	// Create
	report := createTestReport(&target.ID, nil)
	err := repo.Reports().Create(ctx, report)
	require.NoError(t, err)

	// Read
	retrieved, err := repo.Reports().Get(ctx, report.ID)
	require.NoError(t, err)
	assert.Equal(t, report.Name, retrieved.Name)
	assert.Equal(t, report.Type, retrieved.Type)

	// Update
	retrieved.Status = model.ReportStatusGenerating
	err = repo.Reports().Update(ctx, retrieved)
	require.NoError(t, err)

	// List operations
	reports, err := repo.Reports().List(ctx)
	require.NoError(t, err)
	assert.Greater(t, len(reports), 0)

	// Target-specific reports
	targetReports, err := repo.Reports().GetByTargetID(ctx, target.ID)
	require.NoError(t, err)
	assert.Greater(t, len(targetReports), 0)

	// Status-based filtering
	generatingReports, err := repo.Reports().ListByStatus(ctx, model.ReportStatusGenerating)
	require.NoError(t, err)
	assert.Greater(t, len(generatingReports), 0)

	// Type-based filtering
	typeReports, err := repo.Reports().ListByType(ctx, report.Type)
	require.NoError(t, err)
	assert.Greater(t, len(typeReports), 0)

	// Delete
	err = repo.Reports().Delete(ctx, report.ID)
	require.NoError(t, err)
}

// testPayloadCRUD tests Payload entity CRUD operations
func testPayloadCRUD(t *testing.T, ctx context.Context, repo *dao.SQLiteRepository) {
	// Create
	payload := createTestPayload()
	err := repo.Payloads().Create(ctx, payload)
	require.NoError(t, err)

	// Read
	retrieved, err := repo.Payloads().Get(ctx, payload.ID)
	require.NoError(t, err)
	assert.Equal(t, payload.Name, retrieved.Name)
	assert.Equal(t, payload.Category, retrieved.Category)

	// Update
	retrieved.Description = "Updated payload description"
	err = repo.Payloads().Update(ctx, retrieved)
	require.NoError(t, err)

	// List operations
	payloads, err := repo.Payloads().List(ctx)
	require.NoError(t, err)
	assert.Greater(t, len(payloads), 0)

	// Category-based filtering
	categoryPayloads, err := repo.Payloads().ListByCategory(ctx, payload.Category)
	require.NoError(t, err)
	assert.Greater(t, len(categoryPayloads), 0)

	// Domain-based filtering
	domainPayloads, err := repo.Payloads().ListByDomain(ctx, payload.Domain)
	require.NoError(t, err)
	assert.Greater(t, len(domainPayloads), 0)

	// Enabled payloads
	enabledPayloads, err := repo.Payloads().ListEnabled(ctx)
	require.NoError(t, err)
	if payload.Enabled {
		assert.Greater(t, len(enabledPayloads), 0)
	}

	// Usage stats update
	err = repo.Payloads().UpdateUsageStats(ctx, payload.ID, true)
	require.NoError(t, err)

	// Most used payloads
	mostUsed, err := repo.Payloads().GetMostUsed(ctx, 10)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(mostUsed), 0)

	// Delete
	err = repo.Payloads().Delete(ctx, payload.ID)
	require.NoError(t, err)
}

// testPluginStatsCRUD tests PluginStats entity CRUD operations
func testPluginStatsCRUD(t *testing.T, ctx context.Context, repo *dao.SQLiteRepository) {
	// Create target for association
	target := createTestTarget()
	require.NoError(t, repo.Targets().Create(ctx, target))

	// Create
	stats := createTestPluginStats(&target.ID, nil)
	err := repo.PluginStats().RecordMetric(ctx, stats.PluginName, stats.PluginVersion,
		stats.MetricName, stats.MetricType, stats.Value, stats.Unit,
		stats.Tags, &target.ID, nil)
	require.NoError(t, err)

	// List operations
	pluginStats, err := repo.PluginStats().ListByPlugin(ctx, stats.PluginName)
	require.NoError(t, err)
	assert.Greater(t, len(pluginStats), 0)

	// Metric-based filtering
	metricStats, err := repo.PluginStats().ListByMetric(ctx, stats.PluginName, stats.MetricName)
	require.NoError(t, err)
	assert.Greater(t, len(metricStats), 0)

	// Time range filtering
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)
	timeRangeStats, err := repo.PluginStats().ListByTimeRange(ctx, start, end)
	require.NoError(t, err)
	assert.Greater(t, len(timeRangeStats), 0)

	// Target-based filtering
	targetStats, err := repo.PluginStats().GetByTargetID(ctx, target.ID)
	require.NoError(t, err)
	assert.Greater(t, len(targetStats), 0)

	// Aggregated stats
	aggregated, err := repo.PluginStats().GetAggregatedStats(ctx, stats.PluginName,
		stats.MetricName, start, end)
	require.NoError(t, err)
	assert.Greater(t, len(aggregated), 0)

	// Top plugins
	topPlugins, err := repo.PluginStats().GetTopPluginsByMetric(ctx, stats.MetricName,
		stats.MetricType, 5)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(topPlugins), 0)

	// Cleanup old stats
	deleted, err := repo.PluginStats().DeleteOldStats(ctx, time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, deleted, int64(0))
}

// Helper functions to create test data

func createTestTarget() *model.Target {
	return &model.Target{
		ID:          uuid.New(),
		Name:        fmt.Sprintf("test-target-%d", time.Now().UnixNano()),
		Type:        model.TargetTypeAPI,
		Provider:    model.ProviderOpenAI,
		Model:       "gpt-4",
		URL:         "https://api.openai.com/v1",
		Status:      model.TargetStatusActive,
		Description: "Test target for integration testing",
		Tags:        []string{"test", "integration"},
		Headers:     map[string]string{"Content-Type": "application/json"},
		Config: map[string]interface{}{
			"timeout": 30,
			"retries": 3,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func createTestCredential() *model.Credential {
	return &model.Credential{
		ID:                uuid.New(),
		Name:              fmt.Sprintf("test-credential-%d", time.Now().UnixNano()),
		Type:              model.CredentialTypeAPIKey,
		Provider:          model.ProviderOpenAI,
		Status:            model.CredentialStatusActive,
		Description:       "Test credential for integration testing",
		EncryptedValue:    []byte("encrypted-test-value"),
		EncryptionIV:      []byte("test-iv-value"),
		KeyDerivationSalt: []byte("test-salt-value"),
		Tags:              []string{"test", "integration"},
		RotationInfo: model.CredentialRotationInfo{
			Enabled:          false,
			AutoRotate:       false,
			RotationInterval: "30d",
		},
		Usage:     model.CredentialUsage{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func createTestScan(targetID uuid.UUID) *model.Scan {
	now := time.Now()
	return &model.Scan{
		ID:       uuid.New(),
		TargetID: targetID,
		Name:     fmt.Sprintf("test-scan-%d", now.UnixNano()),
		Type:     model.ScanTypeBasic,
		Status:   model.ScanStatusPending,
		Progress: 0.0,
		Options: map[string]interface{}{
			"timeout": 300,
			"plugins": []string{"test-plugin"},
		},
		Statistics: map[string]interface{}{},
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

func createTestFinding(scanID, targetID uuid.UUID) *model.Finding {
	return &model.Finding{
		ID:          uuid.New(),
		ScanID:      scanID,
		TargetID:    targetID,
		Title:       fmt.Sprintf("Test Finding %d", time.Now().UnixNano()),
		Description: "Test security finding for integration testing",
		Severity:    model.SeverityHigh,
		Confidence:  0.9,
		RiskScore:   7.5,
		Category:    "test-category",
		Status:      model.FindingStatusNew,
		Evidence:    "Test evidence data",
		Remediation: "Test remediation steps",
		Location:    "test/location",
		Metadata: map[string]interface{}{
			"test_field": "test_value",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func createTestReport(targetID, scanID *uuid.UUID) *model.Report {
	return &model.Report{
		ID:       uuid.New(),
		Name:     fmt.Sprintf("test-report-%d", time.Now().UnixNano()),
		Type:     model.ReportTypeScanSummary,
		Status:   model.ReportStatusPending,
		Format:   model.ReportFormatJSON,
		TargetID: targetID,
		ScanID:   scanID,
		Config: map[string]interface{}{
			"include_details": true,
			"format_version":  "1.0",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func createTestPayload() *model.Payload {
	return &model.Payload{
		ID:          uuid.New(),
		Name:        fmt.Sprintf("test-payload-%d", time.Now().UnixNano()),
		Category:    model.PayloadCategoryModel,
		Domain:      "test-domain",
		Type:        model.PayloadTypePrompt,
		Version:     1,
		Content:     "Test payload content for security testing",
		Description: "Test payload for integration testing",
		Severity:    "medium",
		Tags:        []string{"test", "integration"},
		Variables: map[string]interface{}{
			"target": "{{TARGET_URL}}",
		},
		Config: map[string]interface{}{
			"timeout": 30,
		},
		Language:         "en",
		Enabled:          true,
		Validated:        false,
		ValidationResult: map[string]interface{}{},
		UsageCount:       0,
		SuccessRate:      0.0,
		CreatedBy:        "integration-test",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

func createTestPluginStats(targetID, scanID *uuid.UUID) *model.PluginStats {
	tags := map[string]interface{}{
		"version": "1.0.0",
		"type":    "test",
	}

	return &model.PluginStats{
		ID:            uuid.New(),
		PluginName:    "test-plugin",
		PluginVersion: "1.0.0",
		MetricName:    "execution_time",
		MetricType:    model.PluginMetricTypeTimer,
		Value:         150.5,
		Unit:          "ms",
		Tags:          tags,
		TargetID:      targetID,
		ScanID:        scanID,
		Timestamp:     time.Now(),
		CreatedAt:     time.Now(),
	}
}