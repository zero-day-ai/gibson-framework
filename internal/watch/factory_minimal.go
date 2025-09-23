// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package watch

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/slogs"
)

// Repository interface for dependency injection (minimal version for testing)
type Repository interface {
	Health() error
}

// MockRepository implements Repository for testing
type MockRepository struct{}

func (m *MockRepository) Health() error {
	return nil
}

// ScannerWatcher implements ResourceWatcher for scanner resources (minimal version)
type MinimalScannerWatcher struct {
	resource   ScannerResource
	repository Repository
	ctx        context.Context
	cancel     context.CancelFunc
	active     bool
	lastSync   time.Time
	mx         sync.RWMutex
}

// NewMinimalScannerWatcher creates a new scanner resource watcher for testing
func NewMinimalScannerWatcher(resource ScannerResource, repository Repository) *MinimalScannerWatcher {
	return &MinimalScannerWatcher{
		resource:   resource,
		repository: repository,
	}
}

// Start begins watching for resource changes
func (w *MinimalScannerWatcher) Start(ctx context.Context) error {
	w.mx.Lock()
	defer w.mx.Unlock()

	if w.active {
		return fmt.Errorf("watcher for %s already active", w.resource)
	}

	w.ctx, w.cancel = context.WithCancel(ctx)
	w.active = true
	w.lastSync = time.Now()

	slog.Debug("Scanner watcher started",
		slogs.ResKind, string(w.resource),
		slogs.Status, "active",
	)

	// Start background synchronization routine
	go w.syncLoop()

	return nil
}

// Stop halts the resource watcher
func (w *MinimalScannerWatcher) Stop() error {
	w.mx.Lock()
	defer w.mx.Unlock()

	if !w.active {
		return nil
	}

	if w.cancel != nil {
		w.cancel()
	}
	w.active = false

	slog.Debug("Scanner watcher stopped",
		slogs.ResKind, string(w.resource),
		slogs.Status, "stopped",
	)

	return nil
}

// IsActive returns true if watcher is active
func (w *MinimalScannerWatcher) IsActive() bool {
	w.mx.RLock()
	defer w.mx.RUnlock()
	return w.active
}

// Resource returns the resource type this watcher manages
func (w *MinimalScannerWatcher) Resource() ScannerResource {
	return w.resource
}

// LastSync returns the last synchronization time
func (w *MinimalScannerWatcher) LastSync() time.Time {
	w.mx.RLock()
	defer w.mx.RUnlock()
	return w.lastSync
}

// syncLoop runs the synchronization loop for this resource
func (w *MinimalScannerWatcher) syncLoop() {
	ticker := time.NewTicker(defaultResync)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.sync()
		}
	}
}

// sync performs synchronization for this resource type
func (w *MinimalScannerWatcher) sync() {
	w.mx.Lock()
	defer w.mx.Unlock()

	if !w.active {
		return
	}

	start := time.Now()

	// Perform basic health check
	if w.repository != nil {
		if err := w.repository.Health(); err != nil {
			slog.Error("Repository health check failed", slogs.Error, err)
			return
		}
	}

	w.lastSync = time.Now()
	duration := w.lastSync.Sub(start)

	slog.Debug("Resource synchronized",
		slogs.ResKind, string(w.resource),
		slogs.Duration, duration,
		slogs.Status, "synced",
	)
}

// MinimalFactory tracks various scanner resource watchers (minimal version for testing)
type MinimalFactory struct {
	watchers   map[ScannerResource]ResourceWatcher
	repository Repository
	stopChan   chan struct{}
	mx         sync.RWMutex
}

// NewMinimalFactory returns a new minimal scanner resource factory for testing
func NewMinimalFactory(repository Repository) *MinimalFactory {
	return &MinimalFactory{
		repository: repository,
		watchers:   make(map[ScannerResource]ResourceWatcher),
	}
}

// Start initializes the watchers until caller cancels the context
func (f *MinimalFactory) Start(ctx context.Context) {
	f.mx.Lock()
	defer f.mx.Unlock()

	slog.Debug("Factory started", slogs.Factory, "scanner_resources")
	f.stopChan = make(chan struct{})

	// Start all registered watchers
	for resource, watcher := range f.watchers {
		slog.Debug("Starting watcher", slogs.ResKind, string(resource))
		if err := watcher.Start(ctx); err != nil {
			slog.Error("Failed to start watcher",
				slogs.ResKind, string(resource),
				slogs.Error, err,
			)
		}
	}
}

// Terminate terminates all watchers
func (f *MinimalFactory) Terminate() {
	f.mx.Lock()
	defer f.mx.Unlock()

	if f.stopChan != nil {
		close(f.stopChan)
		f.stopChan = nil
	}

	// Stop all watchers
	for resource, watcher := range f.watchers {
		slog.Debug("Stopping watcher", slogs.ResKind, string(resource))
		if err := watcher.Stop(); err != nil {
			slog.Error("Failed to stop watcher",
				slogs.ResKind, string(resource),
				slogs.Error, err,
			)
		}
	}

	// Clear all watchers
	for k := range f.watchers {
		delete(f.watchers, k)
	}

	slog.Debug("Factory terminated", slogs.Factory, "scanner_resources")
}

// RegisterWatcher registers a new resource watcher
func (f *MinimalFactory) RegisterWatcher(resource ScannerResource, watcher ResourceWatcher) {
	f.mx.Lock()
	defer f.mx.Unlock()

	f.watchers[resource] = watcher

	slog.Debug("Watcher registered",
		slogs.ResKind, string(resource),
		slogs.Factory, "scanner_resources",
	)
}

// UnregisterWatcher removes a resource watcher
func (f *MinimalFactory) UnregisterWatcher(resource ScannerResource) {
	f.mx.Lock()
	defer f.mx.Unlock()

	if watcher, exists := f.watchers[resource]; exists {
		_ = watcher.Stop()
		delete(f.watchers, resource)

		slog.Debug("Watcher unregistered",
			slogs.ResKind, string(resource),
			slogs.Factory, "scanner_resources",
		)
	}
}

// GetWatcher returns a watcher for the specified resource
func (f *MinimalFactory) GetWatcher(resource ScannerResource) (ResourceWatcher, bool) {
	f.mx.RLock()
	defer f.mx.RUnlock()

	watcher, exists := f.watchers[resource]
	return watcher, exists
}

// ListWatchers returns all registered watchers
func (f *MinimalFactory) ListWatchers() map[ScannerResource]ResourceWatcher {
	f.mx.RLock()
	defer f.mx.RUnlock()

	result := make(map[ScannerResource]ResourceWatcher, len(f.watchers))
	for k, v := range f.watchers {
		result[k] = v
	}
	return result
}

// HasSynced checks if a resource watcher has completed initial sync
func (f *MinimalFactory) HasSynced(resource ScannerResource) bool {
	f.mx.RLock()
	defer f.mx.RUnlock()

	watcher, exists := f.watchers[resource]
	if !exists {
		return false
	}

	return watcher.IsActive() && !watcher.LastSync().IsZero()
}

// WaitForCacheSync waits for all watchers to complete their initial sync
func (f *MinimalFactory) WaitForCacheSync(ctx context.Context) map[ScannerResource]bool {
	result := make(map[ScannerResource]bool)

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, defaultWaitTime)
	defer cancel()

	f.mx.RLock()
	watchers := make(map[ScannerResource]ResourceWatcher)
	for k, v := range f.watchers {
		watchers[k] = v
	}
	f.mx.RUnlock()

	// Check each watcher
	for resource, watcher := range watchers {
		select {
		case <-timeoutCtx.Done():
			result[resource] = false
			slog.Warn("Cache sync timeout",
				slogs.ResKind, string(resource),
				slogs.Status, "timeout",
			)
		default:
			synced := watcher.IsActive() && !watcher.LastSync().IsZero()
			result[resource] = synced

			slog.Debug("Cache sync status",
				slogs.ResKind, string(resource),
				slogs.Status, fmt.Sprintf("synced=%v", synced),
			)
		}
	}

	return result
}

// Repository returns the underlying repository
func (f *MinimalFactory) Repository() Repository {
	return f.repository
}

// IsActive returns true if the factory is currently active
func (f *MinimalFactory) IsActive() bool {
	f.mx.RLock()
	defer f.mx.RUnlock()
	return f.stopChan != nil
}

// CreateDefaultWatchers creates watchers for all standard scanner resources
func (f *MinimalFactory) CreateDefaultWatchers() {
	resources := []ScannerResource{
		TargetResource,
		ScanResource,
		FindingResource,
		CredentialResource,
		PluginResource,
	}

	for _, resource := range resources {
		watcher := NewMinimalScannerWatcher(resource, f.repository)
		f.RegisterWatcher(resource, watcher)
	}

	slog.Debug("Default watchers created",
		slogs.Factory, "scanner_resources",
		slogs.Count, len(resources),
	)
}