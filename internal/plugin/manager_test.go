package plugin

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	sdkplugin "github.com/zero-day-ai/gibson-sdk/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_Discovery(t *testing.T) {
	// Table-driven tests following k9s pattern
	uu := map[string]struct {
		setupFunc      func(string) error
		expectedCount  int
		expectedPlugin string
		wantErr        bool
	}{
		"single_plugin_yml": {
			setupFunc: func(tmpDir string) error {
				return setupTestPlugin(tmpDir, "test-plugin", "plugin.yml")
			},
			expectedCount:  1,
			expectedPlugin: "test-plugin",
		},
		"single_plugin_yaml": {
			setupFunc: func(tmpDir string) error {
				return setupTestPlugin(tmpDir, "yaml-plugin", "plugin.yaml")
			},
			expectedCount:  1,
			expectedPlugin: "yaml-plugin",
		},
		"no_plugins": {
			setupFunc: func(tmpDir string) error {
				return nil // Empty directory
			},
			expectedCount: 0,
		},
		"multiple_plugins": {
			setupFunc: func(tmpDir string) error {
				if err := setupTestPlugin(tmpDir, "plugin1", "plugin.yml"); err != nil {
					return err
				}
				return setupTestPlugin(tmpDir, "plugin2", "plugin.yml")
			},
			expectedCount: 2,
		},
		"nonexistent_directory": {
			setupFunc: func(tmpDir string) error {
				return os.RemoveAll(tmpDir) // Remove the directory
			},
			expectedCount: 0,
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Setup test case
			err := u.setupFunc(tmpDir)
			require.NoError(t, err)

			// Create manager and test discovery
			manager := NewManager(tmpDir)
			plugins, err := manager.Discover()

			if u.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, plugins, u.expectedCount)

			if u.expectedPlugin != "" && len(plugins) > 0 {
				assert.Contains(t, plugins, u.expectedPlugin)
			}
		})
	}
}

func TestManager_NewManager(t *testing.T) {
	uu := map[string]struct {
		opts     []ManagerOption
		expected *Manager
	}{
		"default_options": {
			opts: nil,
			expected: &Manager{
				useGRPC:       true,
				maxPlugins:    10,
				pluginTimeout: 30 * time.Second,
			},
		},
		"with_logger": {
			opts: []ManagerOption{WithLogger(slog.Default())},
			expected: &Manager{
				logger:        slog.Default(),
				useGRPC:       true,
				maxPlugins:    10,
				pluginTimeout: 30 * time.Second,
			},
		},
		"with_grpc_disabled": {
			opts: []ManagerOption{WithGRPC(false)},
			expected: &Manager{
				useGRPC:       false,
				maxPlugins:    10,
				pluginTimeout: 30 * time.Second,
			},
		},
		"with_max_plugins": {
			opts: []ManagerOption{WithMaxPlugins(5)},
			expected: &Manager{
				useGRPC:       true,
				maxPlugins:    5,
				pluginTimeout: 30 * time.Second,
			},
		},
		"with_timeout": {
			opts: []ManagerOption{WithTimeout(60 * time.Second)},
			expected: &Manager{
				useGRPC:       true,
				maxPlugins:    10,
				pluginTimeout: 60 * time.Second,
			},
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			manager := NewManager("/test/dir", u.opts...)

			assert.Equal(t, "/test/dir", manager.pluginDir)
			assert.Equal(t, u.expected.useGRPC, manager.useGRPC)
			assert.Equal(t, u.expected.maxPlugins, manager.maxPlugins)
			assert.Equal(t, u.expected.pluginTimeout, manager.pluginTimeout)
			assert.NotNil(t, manager.plugins)
			assert.NotNil(t, manager.logger)
		})
	}
}

func TestManager_PluginInstance(t *testing.T) {
	// Test plugin instance structure
	now := time.Now()
	config := &PluginConfig{Name: "test"}

	instance := &PluginInstance{
		Name:     "test",
		Path:     "/test/path",
		Config:   config,
		LastUsed: now,
		UseCount: 0,
		Health:   HealthHealthy,
	}

	assert.Equal(t, "test", instance.Name)
	assert.Equal(t, "/test/path", instance.Path)
	assert.Equal(t, config, instance.Config)
	assert.Equal(t, now, instance.LastUsed)
	assert.Equal(t, int64(0), instance.UseCount)
	assert.Equal(t, HealthHealthy, instance.Health)
}

func TestManager_List(t *testing.T) {
	manager := NewManager("/test")

	// Initially empty
	instances := manager.List()
	assert.Len(t, instances, 0)

	// Add some mock instances
	manager.plugins["plugin1"] = &PluginInstance{Name: "plugin1", Health: HealthHealthy}
	manager.plugins["plugin2"] = &PluginInstance{Name: "plugin2", Health: HealthUnhealthy}

	instances = manager.List()
	assert.Len(t, instances, 2)

	names := make([]string, len(instances))
	for i, instance := range instances {
		names[i] = instance.Name
	}
	assert.Contains(t, names, "plugin1")
	assert.Contains(t, names, "plugin2")
}

func TestManager_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	manager := NewManager("/test")

	// Test concurrent access to plugin list
	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			instances := manager.List()
			assert.NotNil(t, instances)
		}(i)
	}

	// Concurrent writes (mocked)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			manager.mutex.Lock()
			manager.plugins[string(rune('a'+id))] = &PluginInstance{
				Name:   string(rune('a' + id)),
				Health: HealthHealthy,
			}
			manager.mutex.Unlock()
		}(i)
	}

	wg.Wait()

	// Verify final state
	instances := manager.List()
	assert.Len(t, instances, numGoroutines)
}

func TestHealthStatus_Values(t *testing.T) {
	uu := map[string]HealthStatus{
		"unknown":   HealthUnknown,
		"healthy":   HealthHealthy,
		"unhealthy": HealthUnhealthy,
		"crashed":   HealthCrashed,
		"disabled":  HealthDisabled,
	}

	for expected, status := range uu {
		t.Run(expected, func(t *testing.T) {
			assert.Equal(t, expected, string(status))
		})
	}
}

func TestSecurityPlugin_Interface(t *testing.T) {
	// Test that our SQL injection plugin implements the interface
	var _ sdkplugin.SecurityPlugin = &testPlugin{}
}

// testPlugin is a minimal plugin implementation for testing
type testPlugin struct{}

func (p *testPlugin) GetInfo(ctx context.Context) (*sdkplugin.PluginInfo, error) {
	return &sdkplugin.PluginInfo{
		Name:         "test-plugin",
		Version:      "1.0.0",
		Description:  "Test plugin",
		Author:       "Test",
		Domains:      []sdkplugin.SecurityDomain{sdkplugin.DomainInterface},
		Capabilities: []string{"test"},
		Config:       make(map[string]string),
	}, nil
}

func (p *testPlugin) Execute(ctx context.Context, request *sdkplugin.AssessRequest) (*sdkplugin.AssessResponse, error) {
	return &sdkplugin.AssessResponse{
		Success:   true,
		Completed: true,
		Findings:  []*sdkplugin.Finding{},
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Duration:  0,
		Metadata:  make(map[string]string),
	}, nil
}

func (p *testPlugin) Validate(ctx context.Context, request *sdkplugin.AssessRequest) error {
	return nil
}

func (p *testPlugin) Health(ctx context.Context) error {
	return nil
}

// setupTestPlugin creates a test plugin directory with manifest
func setupTestPlugin(tmpDir, pluginName, manifestName string) error {
	pluginDir := filepath.Join(tmpDir, pluginName)
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return err
	}

	manifest := `name: ` + pluginName + `
version: 1.0.0
description: Test plugin
author: Test
executable: test
args: []
env: {}
timeout: 30s
domains:
  - interface
capabilities:
  - test
`
	manifestPath := filepath.Join(pluginDir, manifestName)
	return os.WriteFile(manifestPath, []byte(manifest), 0644)
}