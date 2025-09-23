// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package watch

import (
	"context"
	"testing"
	"time"
)

func TestMinimalFactory_RegisterWatcher(t *testing.T) {
	repo := &MockRepository{}
	factory := NewMinimalFactory(repo)
	watcher := NewMinimalScannerWatcher(TargetResource, repo)

	factory.RegisterWatcher(TargetResource, watcher)

	retrievedWatcher, exists := factory.GetWatcher(TargetResource)
	if !exists {
		t.Fatal("Expected watcher to be registered")
	}

	if retrievedWatcher != watcher {
		t.Fatal("Retrieved watcher does not match registered watcher")
	}
}

func TestMinimalFactory_UnregisterWatcher(t *testing.T) {
	repo := &MockRepository{}
	factory := NewMinimalFactory(repo)
	watcher := NewMinimalScannerWatcher(TargetResource, repo)

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

func TestMinimalFactory_StartAndTerminate(t *testing.T) {
	repo := &MockRepository{}
	factory := NewMinimalFactory(repo)
	watcher := NewMinimalScannerWatcher(TargetResource, repo)

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

func TestMinimalFactory_CreateDefaultWatchers(t *testing.T) {
	repo := &MockRepository{}
	factory := NewMinimalFactory(repo)
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

func TestMinimalScannerWatcher_StartStop(t *testing.T) {
	repo := &MockRepository{}
	watcher := NewMinimalScannerWatcher(TargetResource, repo)

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

func TestMinimalScannerWatcher_DoubleStart(t *testing.T) {
	repo := &MockRepository{}
	watcher := NewMinimalScannerWatcher(TargetResource, repo)

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

func TestMinimalFactory_HasSynced(t *testing.T) {
	repo := &MockRepository{}
	factory := NewMinimalFactory(repo)
	watcher := NewMinimalScannerWatcher(TargetResource, repo)

	factory.RegisterWatcher(TargetResource, watcher)

	// Should not be synced initially
	if factory.HasSynced(TargetResource) {
		t.Fatal("Expected watcher to not be synced initially")
	}

	// Start the watcher
	ctx := context.Background()
	factory.Start(ctx)

	// Should be synced after start (minimal watcher sets lastSync)
	if !factory.HasSynced(TargetResource) {
		t.Fatal("Expected watcher to be synced after start")
	}
}

func TestMinimalFactory_WaitForCacheSync(t *testing.T) {
	repo := &MockRepository{}
	factory := NewMinimalFactory(repo)
	watcher := NewMinimalScannerWatcher(TargetResource, repo)

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

func TestMinimalScannerWatcher_SyncLoop(t *testing.T) {
	repo := &MockRepository{}
	watcher := NewMinimalScannerWatcher(TargetResource, repo)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := watcher.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}

	// Let it run for a short time to ensure sync loop is working
	time.Sleep(50 * time.Millisecond)

	if !watcher.IsActive() {
		t.Fatal("Expected watcher to remain active")
	}

	// Cancel context and verify it stops
	cancel()
	time.Sleep(10 * time.Millisecond)

	err = watcher.Stop()
	if err != nil {
		t.Fatalf("Failed to stop watcher: %v", err)
	}
}