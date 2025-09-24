// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package pool

import (
	"context"
	"log/slog"
	"sync"

	"github.com/zero-day-ai/gibson-framework/internal/slogs"
)

const DefaultPoolSize = 10

// JobFn represents a function that can be executed by the worker pool
type JobFn func(ctx context.Context) error

// WorkerPool manages a pool of workers for concurrent execution following k9s patterns
type WorkerPool struct {
	// Semaphore channel for limiting concurrency
	semC chan struct{}

	// Error channel for collecting errors from workers
	errC chan error

	// Context for cancellation
	ctx      context.Context
	cancelFn context.CancelFunc

	// Mutex for protecting shared state
	mx sync.RWMutex

	// WaitGroup for tracking active jobs
	wg sync.WaitGroup

	// WaitGroup for error collection goroutine
	wge sync.WaitGroup

	// Collected errors from workers
	errs []error

	// Pool configuration
	size int
	name string

	// Track if pool has been drained to prevent double-close
	drained bool
}

// NewWorkerPool creates a new worker pool with specified context and size
func NewWorkerPool(ctx context.Context, size int) *WorkerPool {
	return NewNamedWorkerPool(ctx, size, "default")
}

// NewNamedWorkerPool creates a new worker pool with a specific name for logging
func NewNamedWorkerPool(ctx context.Context, size int, name string) *WorkerPool {
	if size <= 0 {
		size = DefaultPoolSize
	}

	poolCtx, cancelFn := context.WithCancel(ctx)

	p := &WorkerPool{
		semC:     make(chan struct{}, size),
		errC:     make(chan error, 1),
		cancelFn: cancelFn,
		ctx:      poolCtx,
		size:     size,
		name:     name,
	}

	// Start error collection goroutine
	p.wge.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		p.collectErrors()
	}(&p.wge)

	slog.Debug("Worker pool created",
		slogs.Name, name,
		slogs.Count, size,
		slogs.Status, "initialized",
	)

	return p
}

// Add submits a job to the worker pool for execution
func (p *WorkerPool) Add(job JobFn) {
	// Acquire semaphore slot (blocks if pool is full)
	p.semC <- struct{}{}

	// Increment wait group for this job
	p.wg.Add(1)

	// Launch worker goroutine
	go func(ctx context.Context, wg *sync.WaitGroup, semC <-chan struct{}, errC chan<- error) {
		defer func() {
			// Release semaphore slot
			<-semC
			// Mark job as done
			wg.Done()
		}()

		// Execute the job
		if err := job(ctx); err != nil {
			slog.Error("Worker job failed",
				slogs.Name, p.name,
				slogs.Error, err,
			)
			// Send error to collection channel (non-blocking)
			select {
			case errC <- err:
			default:
				// Channel full, log error instead
				slog.Warn("Error channel full, dropping error",
					slogs.Name, p.name,
					slogs.Error, err,
				)
			}
		}
	}(p.ctx, &p.wg, p.semC, p.errC)
}

// AddWithPriority adds a job with priority (higher priority jobs are executed first)
// Note: This is a simplified priority implementation
func (p *WorkerPool) AddWithPriority(job JobFn, priority int) {
	// For now, just add the job normally
	// A full priority implementation would require a priority queue
	p.Add(job)
}

// Drain waits for all jobs to complete and returns collected errors
func (p *WorkerPool) Drain() []error {
	// Check if already drained to prevent double-close panic
	p.mx.Lock()
	if p.drained {
		p.mx.Unlock()
		return p.errs
	}
	p.drained = true
	p.mx.Unlock()

	// Wait for all jobs to complete BEFORE canceling context
	// This allows running jobs to finish execution
	p.wg.Wait()

	// Cancel context only after jobs are done to clean up resources
	if p.cancelFn != nil {
		p.cancelFn()
		p.cancelFn = nil
	}

	// Close channels to terminate error collection goroutine
	close(p.semC)
	close(p.errC)

	// Wait for error collection to finish
	p.wge.Wait()

	// Return collected errors
	p.mx.RLock()
	defer p.mx.RUnlock()

	slog.Debug("Worker pool drained",
		slogs.Name, p.name,
		slogs.Count, len(p.errs),
		slogs.Status, "drained",
	)

	return p.errs
}

// Size returns the maximum number of concurrent workers
func (p *WorkerPool) Size() int {
	return p.size
}

// Name returns the pool name
func (p *WorkerPool) Name() string {
	return p.name
}

// ActiveJobs returns the number of currently active jobs
func (p *WorkerPool) ActiveJobs() int {
	return len(p.semC)
}

// AvailableSlots returns the number of available worker slots
func (p *WorkerPool) AvailableSlots() int {
	return p.size - len(p.semC)
}

// IsFull returns true if the pool is at capacity
func (p *WorkerPool) IsFull() bool {
	return len(p.semC) >= p.size
}

// collectErrors runs in a goroutine to collect errors from workers
func (p *WorkerPool) collectErrors() {
	for err := range p.errC {
		if err != nil {
			p.mx.Lock()
			p.errs = append(p.errs, err)
			p.mx.Unlock()
		}
	}
}

// BatchExecutor provides utilities for executing multiple jobs with coordination
type BatchExecutor struct {
	pool   *WorkerPool
	jobs   []JobFn
	ctx    context.Context
	cancel context.CancelFunc
}

// NewBatchExecutor creates a new batch executor for coordinated job execution
func NewBatchExecutor(ctx context.Context, poolSize int) *BatchExecutor {
	batchCtx, cancel := context.WithCancel(ctx)

	return &BatchExecutor{
		pool:   NewNamedWorkerPool(batchCtx, poolSize, "batch"),
		ctx:    batchCtx,
		cancel: cancel,
	}
}

// AddJob adds a job to the batch
func (b *BatchExecutor) AddJob(job JobFn) {
	b.jobs = append(b.jobs, job)
}

// Execute runs all jobs in the batch and waits for completion
func (b *BatchExecutor) Execute() []error {
	defer b.cancel()

	// Submit all jobs to the pool
	for _, job := range b.jobs {
		b.pool.Add(job)
	}

	// Wait for completion and return errors
	return b.pool.Drain()
}

// ExecuteWithTimeout executes the batch with a timeout
func (b *BatchExecutor) ExecuteWithTimeout(ctx context.Context) []error {
	// Create a context that respects both the timeout and cancellation
	mergedCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Monitor for context cancellation
	go func() {
		select {
		case <-mergedCtx.Done():
			b.cancel()
		case <-b.ctx.Done():
			// Batch already completed
		}
	}()

	return b.Execute()
}

// ScannerPool provides specialized worker pool for scanner operations
type ScannerPool struct {
	*WorkerPool
	scanJobs    int
	pluginJobs  int
	mx          sync.RWMutex
}

// NewScannerPool creates a worker pool optimized for scanner operations
func NewScannerPool(ctx context.Context, size int) *ScannerPool {
	return &ScannerPool{
		WorkerPool: NewNamedWorkerPool(ctx, size, "scanner"),
	}
}

// AddScanJob adds a scan-specific job to the pool
func (s *ScannerPool) AddScanJob(job JobFn) {
	s.mx.Lock()
	s.scanJobs++
	s.mx.Unlock()

	wrappedJob := func(ctx context.Context) error {
		defer func() {
			s.mx.Lock()
			s.scanJobs--
			s.mx.Unlock()
		}()
		return job(ctx)
	}

	s.Add(wrappedJob)
}

// AddPluginJob adds a plugin-specific job to the pool
func (s *ScannerPool) AddPluginJob(job JobFn) {
	s.mx.Lock()
	s.pluginJobs++
	s.mx.Unlock()

	wrappedJob := func(ctx context.Context) error {
		defer func() {
			s.mx.Lock()
			s.pluginJobs--
			s.mx.Unlock()
		}()
		return job(ctx)
	}

	s.Add(wrappedJob)
}

// ScanJobCount returns the number of active scan jobs
func (s *ScannerPool) ScanJobCount() int {
	s.mx.RLock()
	defer s.mx.RUnlock()
	return s.scanJobs
}

// PluginJobCount returns the number of active plugin jobs
func (s *ScannerPool) PluginJobCount() int {
	s.mx.RLock()
	defer s.mx.RUnlock()
	return s.pluginJobs
}

// Stats returns pool statistics
func (s *ScannerPool) Stats() map[string]int {
	s.mx.RLock()
	defer s.mx.RUnlock()

	return map[string]int{
		"size":         s.Size(),
		"active":       s.ActiveJobs(),
		"available":    s.AvailableSlots(),
		"scan_jobs":    s.scanJobs,
		"plugin_jobs":  s.pluginJobs,
	}
}