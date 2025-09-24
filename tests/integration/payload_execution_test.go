// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson-framework/pkg/services"
	coremodels "github.com/zero-day-ai/gibson-framework/pkg/core/models"
)

// MockPayloadRepository implements PayloadRepository for testing
type MockPayloadRepository struct {
	payloads map[string][]*coremodels.PayloadDB
}

func NewMockPayloadRepository() *MockPayloadRepository {
	return &MockPayloadRepository{
		payloads: make(map[string][]*coremodels.PayloadDB),
	}
}

func (m *MockPayloadRepository) Create(ctx context.Context, payload *coremodels.PayloadDB) coremodels.Result[*coremodels.PayloadDB] {
	domain := payload.Domain
	m.payloads[domain] = append(m.payloads[domain], payload)
	return coremodels.Ok(payload)
}

func (m *MockPayloadRepository) List(ctx context.Context) coremodels.Result[[]*coremodels.PayloadDB] {
	var allPayloads []*coremodels.PayloadDB
	for _, domainPayloads := range m.payloads {
		allPayloads = append(allPayloads, domainPayloads...)
	}
	return coremodels.Ok(allPayloads)
}

func (m *MockPayloadRepository) ListByDomain(ctx context.Context, domain string) coremodels.Result[[]*coremodels.PayloadDB] {
	if payloads, exists := m.payloads[domain]; exists {
		return coremodels.Ok(payloads)
	}
	return coremodels.Ok([]*coremodels.PayloadDB{})
}

func (m *MockPayloadRepository) ListByPlugin(ctx context.Context, plugin string) coremodels.Result[[]*coremodels.PayloadDB] {
	var pluginPayloads []*coremodels.PayloadDB
	for _, domainPayloads := range m.payloads {
		for _, payload := range domainPayloads {
			if payload.PluginName == plugin {
				pluginPayloads = append(pluginPayloads, payload)
			}
		}
	}
	return coremodels.Ok(pluginPayloads)
}

// Implement other required interface methods (simplified for testing)
func (m *MockPayloadRepository) GetByID(ctx context.Context, id uuid.UUID) coremodels.Result[*coremodels.PayloadDB] {
	return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("not implemented"))
}

func (m *MockPayloadRepository) GetByRepositoryPath(ctx context.Context, repositoryID uuid.UUID, repositoryPath string) coremodels.Result[*coremodels.PayloadDB] {
	return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("not implemented"))
}

func (m *MockPayloadRepository) Update(ctx context.Context, payload *coremodels.PayloadDB) coremodels.Result[*coremodels.PayloadDB] {
	return coremodels.Ok(payload)
}

func (m *MockPayloadRepository) Delete(ctx context.Context, id uuid.UUID) coremodels.Result[bool] {
	return coremodels.Ok(true)
}

func (m *MockPayloadRepository) CreateBatch(ctx context.Context, payloads []*coremodels.PayloadDB) coremodels.Result[[]*coremodels.PayloadDB] {
	for _, payload := range payloads {
		m.Create(ctx, payload)
	}
	return coremodels.Ok(payloads)
}

func (m *MockPayloadRepository) UpdateBatch(ctx context.Context, payloads []*coremodels.PayloadDB) coremodels.Result[[]*coremodels.PayloadDB] {
	return coremodels.Ok(payloads)
}

func (m *MockPayloadRepository) ListByRepository(ctx context.Context, repositoryID uuid.UUID) coremodels.Result[[]*coremodels.PayloadDB] {
	return m.List(ctx)
}

func (m *MockPayloadRepository) CountByRepository(ctx context.Context, repositoryID uuid.UUID) coremodels.Result[int64] {
	result := m.List(ctx)
	if result.IsErr() {
		return coremodels.Err[int64](result.Error())
	}
	return coremodels.Ok(int64(len(result.Unwrap())))
}

func (m *MockPayloadRepository) DeleteOrphaned(ctx context.Context, repositoryID uuid.UUID, validPaths []string) coremodels.Result[int64] {
	return coremodels.Ok(int64(0))
}

func (m *MockPayloadRepository) GetChecksumByPath(ctx context.Context, repositoryID uuid.UUID, repositoryPath string) coremodels.Result[string] {
	return coremodels.Ok("test-checksum")
}

func (m *MockPayloadRepository) UpdateChecksum(ctx context.Context, id uuid.UUID, checksum string) coremodels.Result[bool] {
	return coremodels.Ok(true)
}

// TestCompletePayloadExecutionFlow tests the complete flow from discovery to execution
func TestCompletePayloadExecutionFlow(t *testing.T) {
	ctx := context.Background()

	// Setup test data
	mockRepo := NewMockPayloadRepository()

	// Create test payloads for different domains
	testPayloads := []*coremodels.PayloadDB{
		{
			Name:        "Model Test Payload",
			Domain:      "model",
			PluginName:  "prompt-injection",
			Content:     "Test prompt injection",
			Category:    coremodels.PayloadCategoryModel,
			Type:        coremodels.PayloadTypePrompt,
			Severity:    "high",
			Enabled:     true,
		},
		{
			Name:        "Data Test Payload",
			Domain:      "data",
			PluginName:  "data-poisoning",
			Content:     "Test data poisoning",
			Category:    coremodels.PayloadCategoryData,
			Type:        coremodels.PayloadTypeData,
			Severity:    "critical",
			Enabled:     true,
		},
		{
			Name:        "Interface Test Payload",
			Domain:      "interface",
			PluginName:  "api-abuse",
			Content:     "Test API abuse",
			Category:    coremodels.PayloadCategoryInterface,
			Type:        coremodels.PayloadTypeQuery,
			Severity:    "medium",
			Enabled:     true,
		},
	}

	// Add test payloads to mock repository
	for _, payload := range testPayloads {
		payload.SetDefaults()
		mockRepo.Create(ctx, payload)
	}

	// Create scan service with progress tracking
	var progressMessages []string
	config := services.ScanConfig{
		Workers: 3,
		ProgressCallback: func(message string) {
			progressMessages = append(progressMessages, message)
		},
	}

	scanService := services.NewScanService(nil, config)
	scanService.SetPayloadRepository(mockRepo)

	// Test 1: Execute all domains
	t.Run("ExecuteAllDomains", func(t *testing.T) {
		progressMessages = nil // Reset progress messages

		result := scanService.ExecuteByDomain(ctx, "test-target", []string{})

		require.True(t, result.IsOk(), "Scan execution should succeed")

		scanResult := result.Unwrap()
		assert.Equal(t, 3, scanResult.TotalPayloads, "Should process all test payloads")
		assert.Equal(t, 3, scanResult.ExecutedCount, "Should execute all payloads")
		assert.Greater(t, scanResult.Duration, time.Duration(0), "Should track execution duration")

		// Verify domain statistics
		assert.Len(t, scanResult.DomainStats, 3, "Should have stats for 3 domains")
		assert.Contains(t, scanResult.DomainStats, "model")
		assert.Contains(t, scanResult.DomainStats, "data")
		assert.Contains(t, scanResult.DomainStats, "interface")

		// Verify progress tracking
		assert.NotEmpty(t, progressMessages, "Should generate progress messages")

		// Check for domain execution messages
		foundDomainMessages := 0
		for _, msg := range progressMessages {
			if strings.Contains(msg, "Executing domain:") {
				foundDomainMessages++
			}
		}
		assert.Equal(t, 3, foundDomainMessages, "Should report execution of 3 domains")
	})

	// Test 2: Execute specific domain
	t.Run("ExecuteSpecificDomain", func(t *testing.T) {
		progressMessages = nil

		result := scanService.ExecuteByDomain(ctx, "test-target", []string{"model"})

		require.True(t, result.IsOk(), "Domain-specific scan should succeed")

		scanResult := result.Unwrap()
		assert.Equal(t, 1, scanResult.TotalPayloads, "Should process only model domain payloads")
		assert.Equal(t, 1, scanResult.ExecutedCount, "Should execute only model payloads")

		// Should only have model domain stats
		assert.Len(t, scanResult.DomainStats, 1, "Should have stats for only 1 domain")
		assert.Contains(t, scanResult.DomainStats, "model")
	})

	// Test 3: Skip empty domains
	t.Run("SkipEmptyDomains", func(t *testing.T) {
		progressMessages = nil

		result := scanService.ExecuteByDomain(ctx, "test-target", []string{"infrastructure", "output", "process"})

		require.True(t, result.IsOk(), "Should succeed even with empty domains")

		scanResult := result.Unwrap()
		assert.Equal(t, 0, scanResult.TotalPayloads, "Should have no payloads from empty domains")
		assert.Equal(t, 0, scanResult.ExecutedCount, "Should execute no payloads")

		// Check for skip messages
		foundSkipMessages := 0
		for _, msg := range progressMessages {
			if strings.Contains(msg, "Skipping empty domain:") {
				foundSkipMessages++
			}
		}
		assert.Equal(t, 3, foundSkipMessages, "Should report skipping 3 empty domains")
	})

	// Test 4: Parallel execution within plugins
	t.Run("ParallelExecution", func(t *testing.T) {
		// Add multiple payloads to same plugin to test parallel execution
		extraPayloads := []*coremodels.PayloadDB{
			{
				Name:        "Model Test Payload 2",
				Domain:      "model",
				PluginName:  "prompt-injection",
				Content:     "Test prompt injection 2",
				Category:    coremodels.PayloadCategoryModel,
				Type:        coremodels.PayloadTypePrompt,
				Severity:    "medium",
				Enabled:     true,
			},
			{
				Name:        "Model Test Payload 3",
				Domain:      "model",
				PluginName:  "prompt-injection",
				Content:     "Test prompt injection 3",
				Category:    coremodels.PayloadCategoryModel,
				Type:        coremodels.PayloadTypePrompt,
				Severity:    "low",
				Enabled:     true,
			},
		}

		for _, payload := range extraPayloads {
			payload.SetDefaults()
			mockRepo.Create(ctx, payload)
		}

		progressMessages = nil
		startTime := time.Now()

		result := scanService.ExecuteByDomain(ctx, "test-target", []string{"model"})

		executionTime := time.Since(startTime)

		require.True(t, result.IsOk(), "Parallel execution should succeed")

		scanResult := result.Unwrap()
		assert.Equal(t, 3, scanResult.TotalPayloads, "Should process all model payloads")
		assert.Equal(t, 3, scanResult.ExecutedCount, "Should execute all model payloads")

		// Verify plugin grouping worked
		modelStats := scanResult.DomainStats["model"]
		assert.Equal(t, 1, modelStats.PluginCount, "Should group payloads by plugin")
		assert.Equal(t, 3, modelStats.PayloadCount, "Should count all payloads in plugin")

		// Parallel execution should be faster than sequential (with some tolerance)
		// Each payload simulates 100ms execution, so 3 sequential would be ~300ms
		// Parallel with 3 workers should be ~100ms
		assert.Less(t, executionTime, 250*time.Millisecond, "Parallel execution should be faster than sequential")
	})
}

// TestPayloadSynchronizerIntegration tests the payload synchronizer with test repository
func TestPayloadSynchronizerIntegration(t *testing.T) {
	ctx := context.Background()

	// Get path to test repository
	testRepoPath := filepath.Join("..", "..", "testdata", "test-payload-repo")

	// Check if test repository exists
	if _, err := os.Stat(testRepoPath); os.IsNotExist(err) {
		t.Skip("Test payload repository not found, skipping integration test")
	}

	// Create payload synchronizer
	config := services.PayloadSyncConfig{
		BatchSize: 10,
	}

	synchronizer := services.NewPayloadSynchronizer(nil, config)

	// Test payload discovery
	t.Run("DiscoverPayloads", func(t *testing.T) {
		// Create a mock repository record
		repository := &coremodels.PayloadRepositoryDB{
			LocalPath: testRepoPath,
		}
		repository.SetDefaults()

		mockRepo := NewMockPayloadRepository()

		// Test sync operation (will test discovery internally)
		result := synchronizer.SyncRepositoryPayloads(ctx, repository, mockRepo)

		require.True(t, result.IsOk(), "Payload synchronization should succeed")

		syncResult := result.Unwrap()
		assert.Greater(t, syncResult.TotalFiles, 0, "Should discover payload files")
		assert.Greater(t, syncResult.ProcessedFiles, 0, "Should process payload files")
		assert.Equal(t, 0, syncResult.ErrorFiles, "Should have no error files in test repo")

		// Verify specific payloads were discovered
		allPayloads := mockRepo.List(ctx)
		require.True(t, allPayloads.IsOk(), "Should be able to list payloads")

		payloads := allPayloads.Unwrap()
		assert.Greater(t, len(payloads), 0, "Should have discovered payloads")

		// Check that payloads have proper domain/plugin information
		foundDomains := make(map[string]bool)
		foundPlugins := make(map[string]bool)

		for _, payload := range payloads {
			assert.NotEmpty(t, payload.Domain, "Payload should have domain")
			assert.NotEmpty(t, payload.PluginName, "Payload should have plugin name")
			assert.NotEmpty(t, payload.Content, "Payload should have content")

			foundDomains[payload.Domain] = true
			foundPlugins[payload.PluginName] = true
		}

		// Should find payloads from multiple domains
		assert.True(t, foundDomains["model"], "Should find model domain payloads")
		assert.True(t, foundDomains["data"], "Should find data domain payloads")
		assert.True(t, foundDomains["interface"], "Should find interface domain payloads")

		// Should find payloads from multiple plugins
		assert.True(t, foundPlugins["prompt-injection"], "Should find prompt-injection plugin")
		assert.True(t, foundPlugins["data-poisoning"], "Should find data-poisoning plugin")
	})
}

// TestResultsOrganizerIntegration tests the results organizer
func TestResultsOrganizerIntegration(t *testing.T) {
	organizer := services.NewResultsOrganizer()

	// Create test scan result with domain statistics
	scanResult := services.ScanResult{
		TotalPayloads: 10,
		ExecutedCount: 10,
		SuccessCount:  8,
		FailureCount:  2,
		DomainStats: map[string]services.DomainStat{
			"model": {
				Domain:        "model",
				PayloadCount:  5,
				ExecutedCount: 5,
				SuccessCount:  4,
				FailureCount:  1,
			},
			"data": {
				Domain:        "data",
				PayloadCount:  3,
				ExecutedCount: 3,
				SuccessCount:  2,
				FailureCount:  1,
			},
			"interface": {
				Domain:        "interface",
				PayloadCount:  2,
				ExecutedCount: 2,
				SuccessCount:  2,
				FailureCount:  0,
			},
		},
	}

	// Test results organization
	t.Run("OrganizeResults", func(t *testing.T) {
		findings := organizer.CreateFindingsFromScanResult(scanResult)
		organized := organizer.OrganizeScanResults(scanResult, findings)

		assert.Greater(t, len(findings), 0, "Should create findings from scan result")
		assert.Equal(t, len(findings), organized.Stats.Total, "Total should match findings count")

		// Should have findings with different severities
		assert.Greater(t, organized.Stats.High, 0, "Should have high severity findings for failures")

		// Verify severity order
		severityOrder := organizer.GetSeverityOrder()
		assert.Equal(t, []string{"critical", "high", "medium", "low"}, severityOrder)

		// Verify color mapping
		assert.Equal(t, "red", organizer.GetSeverityColor("critical"))
		assert.Equal(t, "orange", organizer.GetSeverityColor("high"))
		assert.Equal(t, "yellow", organizer.GetSeverityColor("medium"))
		assert.Equal(t, "blue", organizer.GetSeverityColor("low"))
	})

	// Test statistics formatting
	t.Run("FormatStatistics", func(t *testing.T) {
		stats := services.SeverityStats{
			Critical: 2,
			High:     3,
			Medium:   4,
			Low:      1,
			Total:    10,
		}

		formatted := organizer.FormatSeverityStats(stats)
		assert.Contains(t, formatted, "Total: 10")
		assert.Contains(t, formatted, "Critical: 2")
		assert.Contains(t, formatted, "High: 3")
		assert.Contains(t, formatted, "Medium: 4")
		assert.Contains(t, formatted, "Low: 1")
	})
}