// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package watch

import (
	"context"
	"testing"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/dao"
	"github.com/gibson-sec/gibson-framework-2/internal/model"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockTargetAccessor implements dao.TargetAccessor for testing
type MockTargetAccessor struct {
	targets []*model.Target
}

func (m *MockTargetAccessor) Init(dao.Factory) {}
func (m *MockTargetAccessor) TableName() string { return "targets" }
func (m *MockTargetAccessor) Get(ctx context.Context, id uuid.UUID) (*model.Target, error) { return nil, nil }
func (m *MockTargetAccessor) List(ctx context.Context) ([]*model.Target, error) { return m.targets, nil }
func (m *MockTargetAccessor) ListByProvider(ctx context.Context, provider model.Provider) ([]*model.Target, error) { return nil, nil }
func (m *MockTargetAccessor) ListByStatus(ctx context.Context, status model.TargetStatus) ([]*model.Target, error) { return nil, nil }
func (m *MockTargetAccessor) Create(ctx context.Context, target *model.Target) error { return nil }
func (m *MockTargetAccessor) Update(ctx context.Context, target *model.Target) error { return nil }
func (m *MockTargetAccessor) UpdateStatus(ctx context.Context, id uuid.UUID, status model.TargetStatus) error { return nil }
func (m *MockTargetAccessor) Delete(ctx context.Context, id uuid.UUID) error { return nil }
func (m *MockTargetAccessor) DeleteByName(ctx context.Context, name string) error { return nil }
func (m *MockTargetAccessor) GetByName(ctx context.Context, name string) (*model.Target, error) { return nil, nil }
func (m *MockTargetAccessor) ExistsByName(ctx context.Context, name string) (bool, error) { return false, nil }
func (m *MockTargetAccessor) CountByProvider(ctx context.Context, provider model.Provider) (int, error) { return 0, nil }
func (m *MockTargetAccessor) ListActiveTargets(ctx context.Context) ([]*model.Target, error) { return nil, nil }

// MockScanAccessor implements dao.ScanAccessor for testing
type MockScanAccessor struct {
	scans []*model.Scan
}

func (m *MockScanAccessor) Init(dao.Factory) {}
func (m *MockScanAccessor) TableName() string { return "scans" }
func (m *MockScanAccessor) Get(ctx context.Context, id uuid.UUID) (*model.Scan, error) { return nil, nil }
func (m *MockScanAccessor) List(ctx context.Context) ([]*model.Scan, error) { return m.scans, nil }
func (m *MockScanAccessor) Create(ctx context.Context, scan *model.Scan) error { return nil }
func (m *MockScanAccessor) Update(ctx context.Context, scan *model.Scan) error { return nil }
func (m *MockScanAccessor) Delete(ctx context.Context, id uuid.UUID) error { return nil }
func (m *MockScanAccessor) GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Scan, error) { return nil, nil }
func (m *MockScanAccessor) ListByStatus(ctx context.Context, status model.ScanStatus) ([]*model.Scan, error) { return nil, nil }
func (m *MockScanAccessor) UpdateProgress(ctx context.Context, id uuid.UUID, progress float64) error { return nil }
func (m *MockScanAccessor) UpdateStatus(ctx context.Context, id uuid.UUID, status model.ScanStatus) error { return nil }
func (m *MockScanAccessor) GetRunningScans(ctx context.Context) ([]*model.Scan, error) { return nil, nil }

// MockFindingAccessor implements dao.FindingAccessor for testing
type MockFindingAccessor struct {
	findings []*model.Finding
}

func (m *MockFindingAccessor) Init(dao.Factory) {}
func (m *MockFindingAccessor) TableName() string { return "findings" }
func (m *MockFindingAccessor) Get(ctx context.Context, id uuid.UUID) (*model.Finding, error) { return nil, nil }
func (m *MockFindingAccessor) List(ctx context.Context) ([]*model.Finding, error) { return m.findings, nil }
func (m *MockFindingAccessor) Create(ctx context.Context, finding *model.Finding) error { return nil }
func (m *MockFindingAccessor) Update(ctx context.Context, finding *model.Finding) error { return nil }
func (m *MockFindingAccessor) Delete(ctx context.Context, id uuid.UUID) error { return nil }
func (m *MockFindingAccessor) GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.Finding, error) { return nil, nil }
func (m *MockFindingAccessor) GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Finding, error) { return nil, nil }
func (m *MockFindingAccessor) ListBySeverity(ctx context.Context, severity model.Severity) ([]*model.Finding, error) { return nil, nil }
func (m *MockFindingAccessor) ListByStatus(ctx context.Context, status model.FindingStatus) ([]*model.Finding, error) { return nil, nil }
func (m *MockFindingAccessor) UpdateStatus(ctx context.Context, id uuid.UUID, status model.FindingStatus) error { return nil }
func (m *MockFindingAccessor) CountBySeverity(ctx context.Context) (map[model.Severity]int, error) { return nil, nil }
func (m *MockFindingAccessor) GetHighSeverityFindings(ctx context.Context) ([]*model.Finding, error) { return nil, nil }

// MockCredentialAccessor implements dao.CredentialAccessor for testing
type MockCredentialAccessor struct {
	credentials []*model.Credential
}

func (m *MockCredentialAccessor) Init(dao.Factory) {}
func (m *MockCredentialAccessor) TableName() string { return "credentials" }
func (m *MockCredentialAccessor) Get(ctx context.Context, id uuid.UUID) (*model.Credential, error) { return nil, nil }
func (m *MockCredentialAccessor) List(ctx context.Context) ([]*model.Credential, error) { return m.credentials, nil }
func (m *MockCredentialAccessor) Create(ctx context.Context, credential *model.Credential) error { return nil }
func (m *MockCredentialAccessor) Update(ctx context.Context, credential *model.Credential) error { return nil }
func (m *MockCredentialAccessor) Delete(ctx context.Context, id uuid.UUID) error { return nil }
func (m *MockCredentialAccessor) GetByName(ctx context.Context, name string) (*model.Credential, error) { return nil, nil }
func (m *MockCredentialAccessor) ListByProvider(ctx context.Context, provider model.Provider) ([]*model.Credential, error) { return nil, nil }
func (m *MockCredentialAccessor) ListByStatus(ctx context.Context, status model.CredentialStatus) ([]*model.Credential, error) { return nil, nil }
func (m *MockCredentialAccessor) UpdateLastUsed(ctx context.Context, id uuid.UUID) error { return nil }
func (m *MockCredentialAccessor) GetActiveCredentials(ctx context.Context) ([]*model.Credential, error) { return nil, nil }
func (m *MockCredentialAccessor) RotateCredential(ctx context.Context, id uuid.UUID, rotationInfo model.CredentialRotationInfo) error { return nil }

// MockPluginStatsAccessor implements dao.PluginStatsAccessor for testing
type MockPluginStatsAccessor struct {
	stats []*model.PluginStats
}

func (m *MockPluginStatsAccessor) Init(dao.Factory) {}
func (m *MockPluginStatsAccessor) TableName() string { return "plugin_stats" }
func (m *MockPluginStatsAccessor) Get(ctx context.Context, id uuid.UUID) (*model.PluginStats, error) { return nil, nil }
func (m *MockPluginStatsAccessor) List(ctx context.Context) ([]*model.PluginStats, error) { return m.stats, nil }
func (m *MockPluginStatsAccessor) Create(ctx context.Context, stats *model.PluginStats) error { return nil }
func (m *MockPluginStatsAccessor) Update(ctx context.Context, stats *model.PluginStats) error { return nil }
func (m *MockPluginStatsAccessor) Delete(ctx context.Context, id uuid.UUID) error { return nil }
func (m *MockPluginStatsAccessor) ListByPlugin(ctx context.Context, pluginName string) ([]*model.PluginStats, error) { return nil, nil }
func (m *MockPluginStatsAccessor) ListByMetric(ctx context.Context, pluginName, metricName string) ([]*model.PluginStats, error) { return nil, nil }
func (m *MockPluginStatsAccessor) ListByTimeRange(ctx context.Context, start, end time.Time) ([]*model.PluginStats, error) { return nil, nil }
func (m *MockPluginStatsAccessor) GetAggregatedStats(ctx context.Context, pluginName, metricName string, start, end time.Time) (map[string]float64, error) { return nil, nil }
func (m *MockPluginStatsAccessor) GetTimeSeriesData(ctx context.Context, pluginName, metricName string, start, end time.Time, interval string) ([]*model.PluginStats, error) { return nil, nil }
func (m *MockPluginStatsAccessor) GetTopPluginsByMetric(ctx context.Context, metricName string, metricType model.PluginMetricType, limit int) (map[string]float64, error) { return nil, nil }
func (m *MockPluginStatsAccessor) GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.PluginStats, error) { return nil, nil }
func (m *MockPluginStatsAccessor) GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.PluginStats, error) { return nil, nil }
func (m *MockPluginStatsAccessor) DeleteOldStats(ctx context.Context, before time.Time) (int64, error) { return 0, nil }
func (m *MockPluginStatsAccessor) RecordMetric(ctx context.Context, pluginName, pluginVersion, metricName string, metricType model.PluginMetricType, value float64, unit string, tags map[string]interface{}, targetID, scanID *uuid.UUID) error { return nil }

// MockFullRepository implements dao.Repository for testing with actual data
type MockFullRepository struct {
	targetAccessor       *MockTargetAccessor
	scanAccessor         *MockScanAccessor
	findingAccessor      *MockFindingAccessor
	credentialAccessor   *MockCredentialAccessor
	pluginStatsAccessor  *MockPluginStatsAccessor
}

func NewMockFullRepository() *MockFullRepository {
	return &MockFullRepository{
		targetAccessor:       &MockTargetAccessor{targets: createMockTargets()},
		scanAccessor:         &MockScanAccessor{scans: createMockScans()},
		findingAccessor:      &MockFindingAccessor{findings: createMockFindings()},
		credentialAccessor:   &MockCredentialAccessor{credentials: createMockCredentials()},
		pluginStatsAccessor:  &MockPluginStatsAccessor{stats: createMockPluginStats()},
	}
}

// Factory interface methods
func (m *MockFullRepository) DB() *sqlx.DB { return nil }
func (m *MockFullRepository) Begin() (*sqlx.Tx, error) { return nil, nil }
func (m *MockFullRepository) Close() error { return nil }
func (m *MockFullRepository) Health() error { return nil }

// Transactor methods
func (m *MockFullRepository) WithTransaction(ctx context.Context, fn func(tx *sqlx.Tx) error) error { return nil }

// Repository accessor methods
func (m *MockFullRepository) Targets() dao.TargetAccessor { return m.targetAccessor }
func (m *MockFullRepository) Scans() dao.ScanAccessor { return m.scanAccessor }
func (m *MockFullRepository) Findings() dao.FindingAccessor { return m.findingAccessor }
func (m *MockFullRepository) Credentials() dao.CredentialAccessor { return m.credentialAccessor }
func (m *MockFullRepository) Reports() dao.ReportAccessor { return nil }
func (m *MockFullRepository) ReportSchedules() dao.ReportScheduleAccessor { return nil }
func (m *MockFullRepository) Payloads() dao.PayloadAccessor { return nil }
func (m *MockFullRepository) PluginStats() dao.PluginStatsAccessor { return m.pluginStatsAccessor }

// Helper functions to create mock data
func createMockTargets() []*model.Target {
	return []*model.Target{
		{
			ID:       uuid.New(),
			Name:     "Test Target 1",
			Type:     model.TargetTypeAPI,
			Provider: model.ProviderOpenAI,
			Status:   model.TargetStatusActive,
			Model:    "gpt-4",
			URL:      "https://api.openai.com/v1",
		},
		{
			ID:       uuid.New(),
			Name:     "Test Target 2",
			Type:     model.TargetTypeModel,
			Provider: model.ProviderAnthropic,
			Status:   model.TargetStatusActive,
			Model:    "claude-3",
			URL:      "https://api.anthropic.com/v1",
		},
	}
}

func createMockScans() []*model.Scan {
	return []*model.Scan{
		{
			ID:       uuid.New(),
			TargetID: uuid.New(),
			Name:     "Test Scan 1",
			Type:     model.ScanTypeBasic,
			Status:   model.ScanStatusCompleted,
			Progress: 100.0,
		},
		{
			ID:       uuid.New(),
			TargetID: uuid.New(),
			Name:     "Test Scan 2",
			Type:     model.ScanTypeAdvanced,
			Status:   model.ScanStatusRunning,
			Progress: 75.5,
		},
		{
			ID:       uuid.New(),
			TargetID: uuid.New(),
			Name:     "Test Scan 3",
			Type:     model.ScanTypeCustom,
			Status:   model.ScanStatusPending,
			Progress: 0.0,
		},
	}
}

func createMockFindings() []*model.Finding {
	return []*model.Finding{
		{
			ID:          uuid.New(),
			ScanID:      uuid.New(),
			TargetID:    uuid.New(),
			Title:       "Critical Security Finding",
			Description: "A critical security vulnerability was detected",
			Severity:    model.SeverityCritical,
			Confidence:  0.95,
			RiskScore:   9.5,
			Status:      model.FindingStatusNew,
		},
		{
			ID:          uuid.New(),
			ScanID:      uuid.New(),
			TargetID:    uuid.New(),
			Title:       "Medium Risk Finding",
			Description: "A medium risk security issue was found",
			Severity:    model.SeverityMedium,
			Confidence:  0.80,
			RiskScore:   5.5,
			Status:      model.FindingStatusReviewed,
		},
	}
}

func createMockCredentials() []*model.Credential {
	return []*model.Credential{
		{
			ID:       uuid.New(),
			Name:     "OpenAI API Key",
			Type:     model.CredentialTypeAPIKey,
			Provider: model.ProviderOpenAI,
			Status:   model.CredentialStatusActive,
		},
		{
			ID:       uuid.New(),
			Name:     "Anthropic API Key",
			Type:     model.CredentialTypeAPIKey,
			Provider: model.ProviderAnthropic,
			Status:   model.CredentialStatusActive,
		},
		{
			ID:       uuid.New(),
			Name:     "Test OAuth Token",
			Type:     model.CredentialTypeOAuth,
			Provider: model.ProviderGoogle,
			Status:   model.CredentialStatusExpired,
		},
	}
}

func createMockPluginStats() []*model.PluginStats {
	return []*model.PluginStats{
		{
			ID:            uuid.New(),
			PluginName:    "security-scanner",
			PluginVersion: "1.0.0",
			MetricName:    "scans_completed",
			MetricType:    model.PluginMetricTypeCounter,
			Value:         42.0,
			Unit:          "count",
		},
		{
			ID:            uuid.New(),
			PluginName:    "vulnerability-detector",
			PluginVersion: "2.1.0",
			MetricName:    "findings_detected",
			MetricType:    model.PluginMetricTypeGauge,
			Value:         15.0,
			Unit:          "count",
		},
	}
}

// Test function to verify sync methods work with real data
func TestScannerWatcherClean_SyncWithRealData(t *testing.T) {
	mockRepo := NewMockFullRepository()

	tests := []struct {
		name           string
		resource       ScannerResource
		expectedCount  int
	}{
		{
			name:          "sync targets",
			resource:      TargetResource,
			expectedCount: 2, // Based on createMockTargets()
		},
		{
			name:          "sync scans",
			resource:      ScanResource,
			expectedCount: 3, // Based on createMockScans()
		},
		{
			name:          "sync findings",
			resource:      FindingResource,
			expectedCount: 2, // Based on createMockFindings()
		},
		{
			name:          "sync credentials",
			resource:      CredentialResource,
			expectedCount: 3, // Based on createMockCredentials()
		},
		{
			name:          "sync plugins",
			resource:      PluginResource,
			expectedCount: 2, // Based on createMockPluginStats()
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watcher := NewScannerWatcherClean(tt.resource, mockRepo)
			require.NotNil(t, watcher)

			// Start the watcher
			ctx := context.Background()
			err := watcher.Start(ctx)
			require.NoError(t, err)

			// Let sync run once
			time.Sleep(100 * time.Millisecond)

			// Verify watcher is active and has synced
			assert.True(t, watcher.IsActive())
			assert.False(t, watcher.LastSync().IsZero())

			// Stop the watcher
			err = watcher.Stop()
			require.NoError(t, err)
			assert.False(t, watcher.IsActive())
		})
	}
}

func TestFactoryClean_WithRealRepository(t *testing.T) {
	mockRepo := NewMockFullRepository()
	factory := NewFactoryClean(mockRepo)

	// Create default watchers
	factory.CreateDefaultWatchers()

	// Verify all watchers are created
	watchers := factory.ListWatchers()
	assert.Len(t, watchers, 5)

	// Start the factory
	ctx := context.Background()
	factory.Start(ctx)

	// Verify factory is active
	assert.True(t, factory.IsActive())

	// Wait for initial sync
	time.Sleep(200 * time.Millisecond)

	// Check sync status
	syncStatus := factory.WaitForCacheSync(ctx)
	for resource, synced := range syncStatus {
		assert.True(t, synced, "Resource %s should be synced", resource)
	}

	// Terminate the factory
	factory.Terminate()
	assert.False(t, factory.IsActive())
}