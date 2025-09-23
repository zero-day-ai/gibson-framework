// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package pool

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerPool_Creation(t *testing.T) {
	ctx := context.Background()
	pool := NewWorkerPool(ctx, 5)

	if pool.Size() != 5 {
		t.Fatalf("Expected pool size 5, got %d", pool.Size())
	}

	if pool.Name() != "default" {
		t.Fatalf("Expected pool name 'default', got %s", pool.Name())
	}

	if pool.ActiveJobs() != 0 {
		t.Fatalf("Expected 0 active jobs, got %d", pool.ActiveJobs())
	}

	if pool.AvailableSlots() != 5 {
		t.Fatalf("Expected 5 available slots, got %d", pool.AvailableSlots())
	}
}

func TestWorkerPool_NamedCreation(t *testing.T) {
	ctx := context.Background()
	pool := NewNamedWorkerPool(ctx, 3, "test-pool")

	if pool.Size() != 3 {
		t.Fatalf("Expected pool size 3, got %d", pool.Size())
	}

	if pool.Name() != "test-pool" {
		t.Fatalf("Expected pool name 'test-pool', got %s", pool.Name())
	}
}

func TestWorkerPool_DefaultSize(t *testing.T) {
	ctx := context.Background()
	pool := NewWorkerPool(ctx, 0) // Should use default size

	if pool.Size() != DefaultPoolSize {
		t.Fatalf("Expected pool size %d, got %d", DefaultPoolSize, pool.Size())
	}
}

func TestWorkerPool_JobExecution(t *testing.T) {
	ctx := context.Background()
	pool := NewWorkerPool(ctx, 2)

	var counter int64

	// Add a simple job
	pool.Add(func(ctx context.Context) error {
		atomic.AddInt64(&counter, 1)
		return nil
	})

	// Drain and check results
	errors := pool.Drain()

	if len(errors) != 0 {
		t.Fatalf("Expected no errors, got %d", len(errors))
	}

	if atomic.LoadInt64(&counter) != 1 {
		t.Fatalf("Expected counter to be 1, got %d", counter)
	}
}

func TestWorkerPool_ConcurrentJobs(t *testing.T) {
	ctx := context.Background()
	pool := NewWorkerPool(ctx, 3)

	var counter int64
	jobCount := 10

	// Add multiple jobs
	for i := 0; i < jobCount; i++ {
		pool.Add(func(ctx context.Context) error {
			atomic.AddInt64(&counter, 1)
			time.Sleep(10 * time.Millisecond) // Simulate work
			return nil
		})
	}

	// Drain and check results
	errors := pool.Drain()

	if len(errors) != 0 {
		t.Fatalf("Expected no errors, got %d", len(errors))
	}

	if atomic.LoadInt64(&counter) != int64(jobCount) {
		t.Fatalf("Expected counter to be %d, got %d", jobCount, counter)
	}
}

func TestWorkerPool_ErrorCollection(t *testing.T) {
	ctx := context.Background()
	pool := NewWorkerPool(ctx, 2)

	expectedError := errors.New("test error")

	// Add jobs with errors
	pool.Add(func(ctx context.Context) error {
		return expectedError
	})

	pool.Add(func(ctx context.Context) error {
		return nil // Success
	})

	pool.Add(func(ctx context.Context) error {
		return expectedError
	})

	// Drain and check errors
	collectedErrors := pool.Drain()

	if len(collectedErrors) != 2 {
		t.Fatalf("Expected 2 errors, got %d", len(collectedErrors))
	}

	for _, err := range collectedErrors {
		if err != expectedError {
			t.Fatalf("Expected error %v, got %v", expectedError, err)
		}
	}
}

func TestWorkerPool_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := NewWorkerPool(ctx, 2)

	var started int64
	var completed int64

	// Add jobs that check for cancellation
	for i := 0; i < 5; i++ {
		pool.Add(func(ctx context.Context) error {
			atomic.AddInt64(&started, 1)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
				atomic.AddInt64(&completed, 1)
				return nil
			}
		})
	}

	// Cancel context immediately
	cancel()

	// Drain the pool
	errors := pool.Drain()

	// Some jobs should have been cancelled
	startedCount := atomic.LoadInt64(&started)
	completedCount := atomic.LoadInt64(&completed)

	if startedCount == 0 {
		t.Fatal("Expected some jobs to have started")
	}

	if completedCount == startedCount {
		t.Fatal("Expected some jobs to be cancelled")
	}

	// Should have some cancellation errors
	if len(errors) == 0 {
		t.Fatal("Expected some cancellation errors")
	}
}

func TestWorkerPool_CapacityLimiting(t *testing.T) {
	ctx := context.Background()
	pool := NewWorkerPool(ctx, 2) // Small pool

	var running int64
	var maxConcurrent int64

	var wg sync.WaitGroup
	jobCount := 5

	// Add jobs that track concurrency
	for i := 0; i < jobCount; i++ {
		wg.Add(1)
		pool.Add(func(ctx context.Context) error {
			defer wg.Done()

			current := atomic.AddInt64(&running, 1)
			defer atomic.AddInt64(&running, -1)

			// Update max concurrent if current is higher
			for {
				max := atomic.LoadInt64(&maxConcurrent)
				if current <= max || atomic.CompareAndSwapInt64(&maxConcurrent, max, current) {
					break
				}
			}

			time.Sleep(50 * time.Millisecond)
			return nil
		})
	}

	// Wait for all jobs and drain
	wg.Wait()
	pool.Drain()

	// Should not exceed pool size
	max := atomic.LoadInt64(&maxConcurrent)
	if max > 2 {
		t.Fatalf("Expected max concurrent jobs <= 2, got %d", max)
	}
}

func TestBatchExecutor_Execute(t *testing.T) {
	ctx := context.Background()
	batch := NewBatchExecutor(ctx, 3)

	var counter int64

	// Add multiple jobs to batch
	for i := 0; i < 5; i++ {
		batch.AddJob(func(ctx context.Context) error {
			atomic.AddInt64(&counter, 1)
			return nil
		})
	}

	// Execute batch
	errors := batch.Execute()

	if len(errors) != 0 {
		t.Fatalf("Expected no errors, got %d", len(errors))
	}

	if atomic.LoadInt64(&counter) != 5 {
		t.Fatalf("Expected counter to be 5, got %d", counter)
	}
}

func TestBatchExecutor_ExecuteWithTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	batch := NewBatchExecutor(context.Background(), 2)

	var completed int64

	// Add jobs that might timeout
	for i := 0; i < 3; i++ {
		batch.AddJob(func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond): // Longer than timeout
				atomic.AddInt64(&completed, 1)
				return nil
			}
		})
	}

	// Execute with timeout
	errors := batch.ExecuteWithTimeout(ctx)

	// Should have timeout errors
	if len(errors) == 0 {
		t.Fatal("Expected timeout errors")
	}

	// Not all jobs should complete
	if atomic.LoadInt64(&completed) == 3 {
		t.Fatal("Expected some jobs to timeout")
	}
}

func TestScannerPool_ScanJobs(t *testing.T) {
	ctx := context.Background()
	pool := NewScannerPool(ctx, 3)

	var wg sync.WaitGroup
	wg.Add(2)

	// Add scan jobs
	pool.AddScanJob(func(ctx context.Context) error {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		return nil
	})

	pool.AddScanJob(func(ctx context.Context) error {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		return nil
	})

	// Check scan job count
	if pool.ScanJobCount() != 2 {
		t.Fatalf("Expected 2 scan jobs, got %d", pool.ScanJobCount())
	}

	// Wait for completion
	wg.Wait()
	pool.Drain()

	// Job count should be zero after completion
	if pool.ScanJobCount() != 0 {
		t.Fatalf("Expected 0 scan jobs after completion, got %d", pool.ScanJobCount())
	}
}

func TestScannerPool_PluginJobs(t *testing.T) {
	ctx := context.Background()
	pool := NewScannerPool(ctx, 3)

	var wg sync.WaitGroup
	wg.Add(3)

	// Add plugin jobs
	for i := 0; i < 3; i++ {
		pool.AddPluginJob(func(ctx context.Context) error {
			defer wg.Done()
			time.Sleep(30 * time.Millisecond)
			return nil
		})
	}

	// Check plugin job count
	if pool.PluginJobCount() != 3 {
		t.Fatalf("Expected 3 plugin jobs, got %d", pool.PluginJobCount())
	}

	// Wait for completion
	wg.Wait()
	pool.Drain()

	// Job count should be zero after completion
	if pool.PluginJobCount() != 0 {
		t.Fatalf("Expected 0 plugin jobs after completion, got %d", pool.PluginJobCount())
	}
}

func TestScannerPool_Stats(t *testing.T) {
	ctx := context.Background()
	pool := NewScannerPool(ctx, 5)

	stats := pool.Stats()

	expectedStats := map[string]int{
		"size":        5,
		"active":      0,
		"available":   5,
		"scan_jobs":   0,
		"plugin_jobs": 0,
	}

	for key, expectedValue := range expectedStats {
		if stats[key] != expectedValue {
			t.Fatalf("Expected %s to be %d, got %d", key, expectedValue, stats[key])
		}
	}
}