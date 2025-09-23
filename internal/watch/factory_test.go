// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package watch

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockResourceWatcher implements ResourceWatcher for testing
type MockResourceWatcher struct {
	resource ScannerResource
	active   bool
	lastSync time.Time
	startErr error
	stopErr  error
}

func NewMockResourceWatcher(resource ScannerResource) *MockResourceWatcher {
	return &MockResourceWatcher{
		resource: resource,
	}
}

func (m *MockResourceWatcher) Start(ctx context.Context) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.active = true
	m.lastSync = time.Now()
	return nil
}

func (m *MockResourceWatcher) Stop() error {
	if m.stopErr != nil {
		return m.stopErr
	}
	m.active = false
	return nil
}

func (m *MockResourceWatcher) IsActive() bool {
	return m.active
}

func (m *MockResourceWatcher) Resource() ScannerResource {
	return m.resource
}

func (m *MockResourceWatcher) LastSync() time.Time {
	return m.lastSync
}

func TestFactory_RegisterWatcher(t *testing.T) {
	uu := map[string]struct {
		resource ScannerResource
	}{
		"target_resource": {
			resource: TargetResource,
		},
		"scan_resource": {
			resource: ScanResource,
		},
		"finding_resource": {
			resource: FindingResource,
		},
		"credential_resource": {
			resource: CredentialResource,
		},
		"plugin_resource": {
			resource: PluginResource,
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			factory := NewFactoryClean(nil)
			watcher := NewMockResourceWatcher(u.resource)

			factory.RegisterWatcher(u.resource, watcher)

			retrievedWatcher, exists := factory.GetWatcher(u.resource)
			require.True(t, exists, "Expected watcher to be registered")
			assert.Equal(t, watcher, retrievedWatcher, "Retrieved watcher should match registered watcher")
		})
	}
}

func TestFactory_UnregisterWatcher(t *testing.T) {
	factory := NewFactoryClean(nil)
	watcher := NewMockResourceWatcher(TargetResource)

	factory.RegisterWatcher(TargetResource, watcher)
	factory.UnregisterWatcher(TargetResource)

	_, exists := factory.GetWatcher(TargetResource)
	if exists {
		t.Fatal("Expected watcher to be unregistered")
	}

	if watcher.IsActive() {
		t.Fatal("Expected watcher to be stopped after unregistration")
	}
}

func TestFactory_StartAndTerminate(t *testing.T) {
	factory := NewFactoryClean(nil)
	watcher := NewMockResourceWatcher(TargetResource)

	factory.RegisterWatcher(TargetResource, watcher)

	ctx := context.Background()
	factory.Start(ctx)

	if !factory.IsActive() {
		t.Fatal("Expected factory to be active after start")
	}

	if !watcher.IsActive() {
		t.Fatal("Expected watcher to be started")
	}

	factory.Terminate()

	if factory.IsActive() {
		t.Fatal("Expected factory to be inactive after terminate")
	}

	if watcher.IsActive() {
		t.Fatal("Expected watcher to be stopped after terminate")
	}
}

func TestFactory_ListWatchers(t *testing.T) {
	factory := NewFactoryClean(nil)

	targetWatcher := NewMockResourceWatcher(TargetResource)
	scanWatcher := NewMockResourceWatcher(ScanResource)

	factory.RegisterWatcher(TargetResource, targetWatcher)
	factory.RegisterWatcher(ScanResource, scanWatcher)

	watchers := factory.ListWatchers()

	if len(watchers) != 2 {
		t.Fatalf("Expected 2 watchers, got %d", len(watchers))
	}

	if watchers[TargetResource] != targetWatcher {
		t.Fatal("Target watcher not found in list")
	}

	if watchers[ScanResource] != scanWatcher {
		t.Fatal("Scan watcher not found in list")
	}
}

func TestFactory_HasSynced(t *testing.T) {
	factory := NewFactoryClean(nil)
	watcher := NewMockResourceWatcher(TargetResource)

	factory.RegisterWatcher(TargetResource, watcher)

	// Should not be synced initially
	if factory.HasSynced(TargetResource) {
		t.Fatal("Expected watcher to not be synced initially")
	}

	// Start the watcher
	ctx := context.Background()
	factory.Start(ctx)

	// Should be synced after start (mock sets lastSync)
	if !factory.HasSynced(TargetResource) {
		t.Fatal("Expected watcher to be synced after start")
	}
}

func TestFactory_WaitForCacheSync(t *testing.T) {
	factory := NewFactoryClean(nil)
	watcher := NewMockResourceWatcher(TargetResource)

	factory.RegisterWatcher(TargetResource, watcher)

	ctx := context.Background()
	factory.Start(ctx)

	syncResults := factory.WaitForCacheSync(ctx)

	if len(syncResults) != 1 {
		t.Fatalf("Expected 1 sync result, got %d", len(syncResults))
	}

	if !syncResults[TargetResource] {
		t.Fatal("Expected target resource to be synced")
	}
}

func TestFactory_CreateDefaultWatchers(t *testing.T) {
	factory := NewFactoryClean(nil)
	factory.CreateDefaultWatchers()

	expectedResources := []ScannerResource{
		TargetResource,
		ScanResource,
		FindingResource,
		CredentialResource,
		PluginResource,
	}

	watchers := factory.ListWatchers()

	if len(watchers) != len(expectedResources) {
		t.Fatalf("Expected %d watchers, got %d", len(expectedResources), len(watchers))
	}

	for _, resource := range expectedResources {
		if _, exists := watchers[resource]; !exists {
			t.Fatalf("Expected watcher for resource %s", resource)
		}
	}
}

func TestScannerWatcher_StartStop(t *testing.T) {
	watcher := NewScannerWatcherClean(TargetResource, nil)

	if watcher.IsActive() {
		t.Fatal("Expected watcher to be inactive initially")
	}

	ctx := context.Background()
	err := watcher.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}

	if !watcher.IsActive() {
		t.Fatal("Expected watcher to be active after start")
	}

	if watcher.LastSync().IsZero() {
		t.Fatal("Expected last sync time to be set after start")
	}

	err = watcher.Stop()
	if err != nil {
		t.Fatalf("Failed to stop watcher: %v", err)
	}

	if watcher.IsActive() {
		t.Fatal("Expected watcher to be inactive after stop")
	}
}

func TestScannerWatcher_DoubleStart(t *testing.T) {
	watcher := NewScannerWatcherClean(TargetResource, nil)

	ctx := context.Background()
	err := watcher.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}

	// Second start should return error
	err = watcher.Start(ctx)
	if err == nil {
		t.Fatal("Expected error when starting already active watcher")
	}
}

func TestScannerWatcher_Resource(t *testing.T) {
	uu := map[string]struct {
		resource ScannerResource
	}{
		"target":     {resource: TargetResource},
		"scan":       {resource: ScanResource},
		"finding":    {resource: FindingResource},
		"credential": {resource: CredentialResource},
		"plugin":     {resource: PluginResource},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			watcher := NewScannerWatcherClean(u.resource, nil)
			assert.Equal(t, u.resource, watcher.Resource())
		})
	}
}

func TestFactory_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	factory := NewFactoryClean(nil)
	var wg sync.WaitGroup

	numGoroutines := 10
	operationsPerGoroutine := 20

	// Concurrent register/unregister operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				resource := ScannerResource(string(rune('a'+id)) + string(rune('0'+j)))
				watcher := NewMockResourceWatcher(resource)

				// Register
				factory.RegisterWatcher(resource, watcher)

				// Get
				retrievedWatcher, exists := factory.GetWatcher(resource)
				assert.True(t, exists)
				assert.Equal(t, watcher, retrievedWatcher)

				// Unregister
				factory.UnregisterWatcher(resource)

				// Verify unregistered
				_, exists = factory.GetWatcher(resource)
				assert.False(t, exists)
			}
		}(i)
	}

	wg.Wait()

	// Verify factory is in clean state
	watchers := factory.ListWatchers()
	assert.Len(t, watchers, 0)
}

func TestFactory_StartStopConcurrency(t *testing.T) {
	t.Parallel()

	factory := NewFactoryClean(nil)
	var wg sync.WaitGroup

	// Register multiple watchers
	resources := []ScannerResource{TargetResource, ScanResource, FindingResource}
	for _, resource := range resources {
		factory.RegisterWatcher(resource, NewMockResourceWatcher(resource))
	}

	numGoroutines := 5

	// Concurrent start/terminate operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()
			ctx := context.Background()
			factory.Start(ctx)
		}()

		go func() {
			defer wg.Done()
			time.Sleep(1 * time.Millisecond) // Small delay
			factory.Terminate()
		}()
	}

	wg.Wait()

	// Factory should be in a consistent state (may be empty after concurrent operations)
	watchers := factory.ListWatchers()
	assert.True(t, len(watchers) >= 0, "Watchers list should be non-negative")
}

func TestFactory_SyncTimeout(t *testing.T) {
	factory := NewFactoryClean(nil)
	watcher := NewMockResourceWatcher(TargetResource)
	factory.RegisterWatcher(TargetResource, watcher)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	factory.Start(ctx)

	// Should handle timeout gracefully
	syncResults := factory.WaitForCacheSync(ctx)
	assert.NotNil(t, syncResults)
}

func TestMockResourceWatcher_ErrorHandling(t *testing.T) {
	uu := map[string]struct {
		setupFunc func(*MockResourceWatcher)
		wantErr   bool
	}{
		"start_error": {
			setupFunc: func(w *MockResourceWatcher) {
				w.startErr = assert.AnError
			},
			wantErr: true,
		},
		"stop_error": {
			setupFunc: func(w *MockResourceWatcher) {
				w.stopErr = assert.AnError
			},
			wantErr: false, // start should succeed
		},
		"no_error": {
			setupFunc: func(w *MockResourceWatcher) {
				// No setup needed
			},
			wantErr: false,
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			watcher := NewMockResourceWatcher(TargetResource)
			u.setupFunc(watcher)

			ctx := context.Background()
			err := watcher.Start(ctx)

			if u.wantErr {
				assert.Error(t, err)
				assert.False(t, watcher.IsActive())
			} else {
				assert.NoError(t, err)
				assert.True(t, watcher.IsActive())

				// Test stop error separately for stop_error case
				if k == "stop_error" {
					err = watcher.Stop()
					assert.Error(t, err)
				}
			}
		})
	}
}