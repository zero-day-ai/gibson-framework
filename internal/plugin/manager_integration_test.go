// +build integration

package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-plugin-sdk/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPluginManager_IntegrationWorkflow tests the complete plugin lifecycle
func TestPluginManager_IntegrationWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Parallel()

	// Setup test environment
	tmpDir := t.TempDir()

	// Create a comprehensive test plugin
	pluginName := "test-security-plugin"
	err := setupCompleteTestPlugin(tmpDir, pluginName)
	require.NoError(t, err)

	// Create manager with realistic configuration
	manager := NewManager(tmpDir,
		WithLogger(slog.Default()),
		WithGRPC(true),
		WithMaxPlugins(5),
		WithTimeout(30*time.Second),
	)

	ctx := context.Background()

	// Test discovery phase
	t.Run("discovery", func(t *testing.T) {
		plugins, err := manager.Discover()
		require.NoError(t, err)
		assert.Len(t, plugins, 1)
		assert.Contains(t, plugins, pluginName)
	})

	// Test loading phase
	t.Run("loading", func(t *testing.T) {
		err := manager.Load(pluginName)
		require.NoError(t, err)

		// Verify plugin is loaded
		instance, err := manager.Get(pluginName)
		require.NoError(t, err)
		assert.Equal(t, pluginName, instance.Name)
		assert.Equal(t, HealthHealthy, instance.Health)
	})

	// Test plugin functionality
	t.Run("functionality", func(t *testing.T) {
		instance, err := manager.Get(pluginName)
		require.NoError(t, err)

		// Test GetInfo
		info, err := instance.Plugin.GetInfo(ctx)
		require.NoError(t, err)
		assert.Equal(t, pluginName, info.Name)
		assert.NotEmpty(t, info.Version)

		// Test Health Check
		err = instance.Plugin.Health(ctx)
		require.NoError(t, err)

		// Test Validate
		request := &plugin.AssessRequest{
			Target: &plugin.Target{
				ID:   "test-target",
				Name: "Test Target",
				Type: "api",
				URL:  "http://localhost:8080",
			},
			Config: map[string]interface{}{"test": true},
			ScanID: "test-scan-001",
		}

		err = instance.Plugin.Validate(ctx, request)
		require.NoError(t, err)

		// Test Execute
		response, err := instance.Plugin.Execute(ctx, request)
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.True(t, response.Completed)
		assert.NotNil(t, response.Findings)
	})

	// Test health monitoring
	t.Run("health_monitoring", func(t *testing.T) {
		healthResults := manager.HealthCheck()
		assert.Len(t, healthResults, 1)
		assert.Equal(t, HealthHealthy, healthResults[pluginName])
	})

	// Test reloading
	t.Run("reloading", func(t *testing.T) {
		err := manager.Reload(pluginName)
		require.NoError(t, err)

		// Verify plugin is still functional after reload
		instance, err := manager.Get(pluginName)
		require.NoError(t, err)
		assert.Equal(t, HealthHealthy, instance.Health)
	})

	// Test unloading
	t.Run("unloading", func(t *testing.T) {
		err := manager.Unload(pluginName)
		require.NoError(t, err)

		// Verify plugin is unloaded
		_, err = manager.Get(pluginName)
		assert.Error(t, err)
	})

	// Test shutdown
	t.Run("shutdown", func(t *testing.T) {
		// Load plugin again for shutdown test
		err := manager.Load(pluginName)
		require.NoError(t, err)

		manager.Shutdown()

		// Verify all plugins are shut down
		instances := manager.List()
		assert.Len(t, instances, 0)
	})
}

// TestPluginManager_StressTest tests the manager under load
func TestPluginManager_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	t.Parallel()

	tmpDir := t.TempDir()

	// Create multiple test plugins
	numPlugins := 5
	pluginNames := make([]string, numPlugins)
	for i := 0; i < numPlugins; i++ {
		pluginName := fmt.Sprintf("stress-plugin-%d", i)
		pluginNames[i] = pluginName
		err := setupCompleteTestPlugin(tmpDir, pluginName)
		require.NoError(t, err)
	}

	manager := NewManager(tmpDir,
		WithMaxPlugins(numPlugins),
		WithTimeout(10*time.Second),
	)

	// Test concurrent loading
	t.Run("concurrent_loading", func(t *testing.T) {
		var wg sync.WaitGroup
		errors := make(chan error, numPlugins)

		for _, pluginName := range pluginNames {
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				if err := manager.Load(name); err != nil {
					errors <- err
				}
			}(pluginName)
		}

		wg.Wait()
		close(errors)

		// Check for errors
		for err := range errors {
			t.Errorf("Plugin loading failed: %v", err)
		}

		// Verify all plugins loaded
		instances := manager.List()
		assert.Len(t, instances, numPlugins)
	})

	// Test concurrent execution
	t.Run("concurrent_execution", func(t *testing.T) {
		var wg sync.WaitGroup
		numExecutions := 20
		results := make(chan bool, numExecutions)

		ctx := context.Background()
		request := &plugin.AssessRequest{
			Target: &plugin.Target{
				ID:   "stress-target",
				Name: "Stress Test Target",
				Type: "api",
			},
			ScanID: "stress-scan",
		}

		for i := 0; i < numExecutions; i++ {
			wg.Add(1)
			go func(execID int) {
				defer wg.Done()

				// Round robin plugin selection
				pluginName := pluginNames[execID%len(pluginNames)]
				instance, err := manager.Get(pluginName)
				if err != nil {
					results <- false
					return
				}

				response, err := instance.Plugin.Execute(ctx, request)
				if err != nil || !response.Success {
					results <- false
					return
				}

				results <- true
			}(i)
		}

		wg.Wait()
		close(results)

		// Count successful executions
		successCount := 0
		for result := range results {
			if result {
				successCount++
			}
		}

		// Expect at least 90% success rate
		minSuccessRate := float64(numExecutions) * 0.9
		assert.GreaterOrEqual(t, float64(successCount), minSuccessRate,
			"Success rate too low: %d/%d", successCount, numExecutions)
	})

	// Cleanup
	manager.Shutdown()
}

// TestPluginManager_ErrorRecovery tests error handling and recovery
func TestPluginManager_ErrorRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping error recovery test in short mode")
	}

	tmpDir := t.TempDir()

	// Create a plugin that will have issues
	problemPlugin := "problem-plugin"
	err := setupProblematicTestPlugin(tmpDir, problemPlugin)
	require.NoError(t, err)

	manager := NewManager(tmpDir,
		WithTimeout(5*time.Second),
	)

	t.Run("load_failure_recovery", func(t *testing.T) {
		// Try to load the problematic plugin
		err := manager.Load(problemPlugin)
		assert.Error(t, err)

		// Manager should still be functional
		plugins, err := manager.Discover()
		assert.NoError(t, err)
		assert.Len(t, plugins, 1)

		// Should be able to load good plugins
		goodPlugin := "good-plugin"
		err = setupCompleteTestPlugin(tmpDir, goodPlugin)
		require.NoError(t, err)

		err = manager.Load(goodPlugin)
		assert.NoError(t, err)
	})

	manager.Shutdown()
}

// setupCompleteTestPlugin creates a realistic test plugin with all components
func setupCompleteTestPlugin(tmpDir, pluginName string) error {
	pluginDir := filepath.Join(tmpDir, pluginName)
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return err
	}

	// Create detailed manifest
	manifest := fmt.Sprintf(`name: %s
version: 1.2.0
description: Comprehensive test security plugin for integration testing
author: Gibson Framework Test Suite
executable: %s
args:
  - "--mode=test"
  - "--verbose"
env:
  TEST_MODE: "true"
  LOG_LEVEL: "debug"
timeout: 30s
max_memory: 268435456
domains:
  - interface
  - model
capabilities:
  - assess
  - validate
  - monitor
config:
  max_requests: 100
  timeout_seconds: 30
  enable_logging: true
`, pluginName, pluginName)

	manifestPath := filepath.Join(pluginDir, "plugin.yml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
		return err
	}

	// Create a dummy executable (in real scenario, this would be the actual plugin binary)
	execPath := filepath.Join(pluginDir, pluginName)
	execContent := "#!/bin/bash\n# Dummy plugin executable for testing\necho 'Test plugin started'\n"
	if err := os.WriteFile(execPath, []byte(execContent), 0755); err != nil {
		return err
	}

	return nil
}

// setupProblematicTestPlugin creates a plugin that will cause loading issues
func setupProblematicTestPlugin(tmpDir, pluginName string) error {
	pluginDir := filepath.Join(tmpDir, pluginName)
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return err
	}

	// Create manifest with issues (missing executable)
	manifest := fmt.Sprintf(`name: %s
version: 1.0.0
description: Problematic test plugin
author: Test
executable: nonexistent-binary
args: []
env: {}
timeout: 30s
domains:
  - interface
capabilities:
  - assess
`, pluginName)

	manifestPath := filepath.Join(pluginDir, "plugin.yml")
	return os.WriteFile(manifestPath, []byte(manifest), 0644)
}