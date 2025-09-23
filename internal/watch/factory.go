// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package watch

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/dao"
	"github.com/gibson-sec/gibson-framework-2/internal/slogs"
)

const (
	defaultResync   = 10 * time.Minute
	defaultWaitTime = 500 * time.Millisecond
)

// ScannerResource represents different types of resources the factory can manage
type ScannerResource string

const (
	TargetResource     ScannerResource = "targets"
	ScanResource       ScannerResource = "scans"
	FindingResource    ScannerResource = "findings"
	CredentialResource ScannerResource = "credentials"
	PluginResource     ScannerResource = "plugins"
)

// ResourceWatcher defines interface for watching resource changes
type ResourceWatcher interface {
	// Start begins watching for resource changes
	Start(ctx context.Context) error

	// Stop halts the resource watcher
	Stop() error

	// IsActive returns true if watcher is active
	IsActive() bool

	// Resource returns the resource type this watcher manages
	Resource() ScannerResource

	// LastSync returns the last synchronization time
	LastSync() time.Time
}

// RepositoryInterface extends the dao.Repository interface for watch operations
type RepositoryInterface interface {
	dao.Repository
}

// ScannerWatcherClean implements ResourceWatcher for scanner resources (clean version)
type ScannerWatcherClean struct {
	resource   ScannerResource
	repository RepositoryInterface
	ctx        context.Context
	cancel     context.CancelFunc
	active     bool
	lastSync   time.Time
	mx         sync.RWMutex
}

// NewScannerWatcherClean creates a new scanner resource watcher
func NewScannerWatcherClean(resource ScannerResource, repository RepositoryInterface) *ScannerWatcherClean {
	return &ScannerWatcherClean{
		resource:   resource,
		repository: repository,
	}
}

// Start begins watching for resource changes
func (w *ScannerWatcherClean) Start(ctx context.Context) error {
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
func (w *ScannerWatcherClean) Stop() error {
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
func (w *ScannerWatcherClean) IsActive() bool {
	w.mx.RLock()
	defer w.mx.RUnlock()
	return w.active
}

// Resource returns the resource type this watcher manages
func (w *ScannerWatcherClean) Resource() ScannerResource {
	return w.resource
}

// LastSync returns the last synchronization time
func (w *ScannerWatcherClean) LastSync() time.Time {
	w.mx.RLock()
	defer w.mx.RUnlock()
	return w.lastSync
}

// syncLoop runs the synchronization loop for this resource
func (w *ScannerWatcherClean) syncLoop() {
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
func (w *ScannerWatcherClean) sync() {
	w.mx.Lock()
	defer w.mx.Unlock()

	if !w.active {
		return
	}

	start := time.Now()

	// Perform resource-specific synchronization
	switch w.resource {
	case TargetResource:
		w.syncTargets()
	case ScanResource:
		w.syncScans()
	case FindingResource:
		w.syncFindings()
	case CredentialResource:
		w.syncCredentials()
	case PluginResource:
		w.syncPlugins()
	}

	w.lastSync = time.Now()
	duration := w.lastSync.Sub(start)

	slog.Debug("Resource synchronized",
		slogs.ResKind, string(w.resource),
		slogs.Duration, duration,
		slogs.Status, "synced",
	)
}

// syncTargets synchronizes target resources
func (w *ScannerWatcherClean) syncTargets() {
	if w.repository == nil {
		return
	}

	ctx := context.Background()
	targets, err := w.repository.Targets().List(ctx)
	if err != nil {
		slog.Error("Failed to sync targets", slogs.Error, err)
		return
	}

	count := len(targets)
	status := "success"

	slog.Debug("Targets synchronized",
		slogs.Count, count,
		slogs.ResKind, string(TargetResource),
		slogs.Status, status,
	)
}

// syncScans synchronizes scan resources
func (w *ScannerWatcherClean) syncScans() {
	if w.repository == nil {
		return
	}

	ctx := context.Background()
	scans, err := w.repository.Scans().List(ctx)
	if err != nil {
		slog.Error("Failed to sync scans", slogs.Error, err)
		return
	}

	count := len(scans)
	status := "success"

	slog.Debug("Scans synchronized",
		slogs.Count, count,
		slogs.ResKind, string(ScanResource),
		slogs.Status, status,
	)
}

// syncFindings synchronizes finding resources
func (w *ScannerWatcherClean) syncFindings() {
	if w.repository == nil {
		return
	}

	ctx := context.Background()
	findings, err := w.repository.Findings().List(ctx)
	if err != nil {
		slog.Error("Failed to sync findings", slogs.Error, err)
		return
	}

	count := len(findings)
	status := "success"

	slog.Debug("Findings synchronized",
		slogs.Count, count,
		slogs.ResKind, string(FindingResource),
		slogs.Status, status,
	)
}

// syncCredentials synchronizes credential resources
func (w *ScannerWatcherClean) syncCredentials() {
	if w.repository == nil {
		return
	}

	ctx := context.Background()
	credentials, err := w.repository.Credentials().List(ctx)
	if err != nil {
		slog.Error("Failed to sync credentials", slogs.Error, err)
		return
	}

	count := len(credentials)
	status := "success"

	slog.Debug("Credentials synchronized",
		slogs.Count, count,
		slogs.ResKind, string(CredentialResource),
		slogs.Status, status,
	)
}

// syncPlugins synchronizes plugin resources
func (w *ScannerWatcherClean) syncPlugins() {
	if w.repository == nil {
		return
	}

	ctx := context.Background()
	pluginStats, err := w.repository.PluginStats().List(ctx)
	if err != nil {
		slog.Error("Failed to sync plugin stats", slogs.Error, err)
		return
	}

	count := len(pluginStats)
	status := "success"

	// For plugins, we count plugin stats as a proxy for plugin activity
	slog.Debug("Plugins synchronized",
		slogs.Count, count,
		slogs.ResKind, string(PluginResource),
		slogs.Status, status,
	)
}

// FactoryClean tracks various scanner resource watchers following k9s factory pattern
type FactoryClean struct {
	watchers   map[ScannerResource]ResourceWatcher
	repository RepositoryInterface
	stopChan   chan struct{}
	mx         sync.RWMutex
}

// NewFactoryClean returns a new scanner resource factory
func NewFactoryClean(repository RepositoryInterface) *FactoryClean {
	return &FactoryClean{
		repository: repository,
		watchers:   make(map[ScannerResource]ResourceWatcher),
	}
}

// Start initializes the watchers until caller cancels the context
func (f *FactoryClean) Start(ctx context.Context) {
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
func (f *FactoryClean) Terminate() {
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
func (f *FactoryClean) RegisterWatcher(resource ScannerResource, watcher ResourceWatcher) {
	f.mx.Lock()
	defer f.mx.Unlock()

	f.watchers[resource] = watcher

	slog.Debug("Watcher registered",
		slogs.ResKind, string(resource),
		slogs.Factory, "scanner_resources",
	)
}

// UnregisterWatcher removes a resource watcher
func (f *FactoryClean) UnregisterWatcher(resource ScannerResource) {
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
func (f *FactoryClean) GetWatcher(resource ScannerResource) (ResourceWatcher, bool) {
	f.mx.RLock()
	defer f.mx.RUnlock()

	watcher, exists := f.watchers[resource]
	return watcher, exists
}

// ListWatchers returns all registered watchers
func (f *FactoryClean) ListWatchers() map[ScannerResource]ResourceWatcher {
	f.mx.RLock()
	defer f.mx.RUnlock()

	result := make(map[ScannerResource]ResourceWatcher, len(f.watchers))
	for k, v := range f.watchers {
		result[k] = v
	}
	return result
}

// HasSynced checks if a resource watcher has completed initial sync
func (f *FactoryClean) HasSynced(resource ScannerResource) bool {
	f.mx.RLock()
	defer f.mx.RUnlock()

	watcher, exists := f.watchers[resource]
	if !exists {
		return false
	}

	return watcher.IsActive() && !watcher.LastSync().IsZero()
}

// WaitForCacheSync waits for all watchers to complete their initial sync
func (f *FactoryClean) WaitForCacheSync(ctx context.Context) map[ScannerResource]bool {
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
func (f *FactoryClean) Repository() RepositoryInterface {
	return f.repository
}

// IsActive returns true if the factory is currently active
func (f *FactoryClean) IsActive() bool {
	f.mx.RLock()
	defer f.mx.RUnlock()
	return f.stopChan != nil
}

// CreateDefaultWatchers creates watchers for all standard scanner resources
func (f *FactoryClean) CreateDefaultWatchers() {
	resources := []ScannerResource{
		TargetResource,
		ScanResource,
		FindingResource,
		CredentialResource,
		PluginResource,
	}

	for _, resource := range resources {
		watcher := NewScannerWatcherClean(resource, f.repository)
		f.RegisterWatcher(resource, watcher)
	}

	slog.Debug("Default watchers created",
		slogs.Factory, "scanner_resources",
		slogs.Count, len(resources),
	)
}