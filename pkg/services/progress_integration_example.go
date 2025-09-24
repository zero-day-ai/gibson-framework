// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/zero-day-ai/gibson-framework/pkg/core/models"
	"github.com/google/uuid"
)

// ExampleGitServiceWithProgress demonstrates how to integrate progress reporting
// with Git operations following requirements 5.1 and 5.2
type ExampleGitServiceWithProgress struct {
	gitService *GitService
	progress   *ProgressReporter
}

// NewExampleGitServiceWithProgress creates a new Git service with progress reporting
func NewExampleGitServiceWithProgress(gitConfig GitServiceConfig, outputFormat string, verbose bool) *ExampleGitServiceWithProgress {
	gitService := NewGitService(gitConfig)
	progressReporter := NewProgressReporter(os.Stdout, outputFormat, verbose, true)

	return &ExampleGitServiceWithProgress{
		gitService: gitService,
		progress:   progressReporter,
	}
}

// CloneRepositoryWithProgress demonstrates cloning a repository with progress tracking
func (gs *ExampleGitServiceWithProgress) CloneRepositoryWithProgress(ctx context.Context, options GitCloneOptions) models.Result[*SyncStatistics] {
	// Generate operation ID
	operationID := uuid.New().String()
	repoName := extractRepoName(options.URL)

	// Start progress tracking
	opCtx, updateFunc := gs.progress.StartOperation(ctx, operationID, "clone")

	// Initialize statistics
	stats := &SyncStatistics{
		RepositoryID:   operationID,
		RepositoryName: repoName,
		RepositoryURL:  options.URL,
		Operation:      "clone",
		StartTime:      time.Now(),
	}

	// Update progress callback to include our progress reporting
	_ = options.Progress // Store original (unused in demo)
	options.Progress = gs.progress.CreateGitProgressCallback(updateFunc)

	// Phase 1: Validation
	updateFunc(ProgressUpdate{
		Phase:    "validating",
		Progress: 0.1,
		Message:  "Validating repository URL and credentials",
	})

	// Validate repository (this would be a real validation call)
	validateResult := gs.simulateValidateRepository(options.URL)
	if validateResult.IsErr() {
		stats.Success = false
		stats.Error = validateResult.Error().Error()
		stats.EndTime = time.Now()
		stats.Duration = stats.EndTime.Sub(stats.StartTime)

		updateFunc(ProgressUpdate{
			Phase:   "failed",
			Progress: 0.0,
			Message: "Repository validation failed",
			Error:   validateResult.Error(),
		})

		gs.progress.CompleteOperation(operationID, stats)
		return models.Err[*SyncStatistics](validateResult.Error())
	}

	// Phase 2: Git Clone
	updateFunc(ProgressUpdate{
		Phase:    "cloning",
		Progress: 0.2,
		Message:  "Starting repository clone",
		Statistics: map[string]interface{}{
			"url":        options.URL,
			"local_path": options.LocalPath,
			"depth":      options.Depth,
		},
	})

	// Simulate clone operation (in real implementation, this would call the actual GitService)
	cloneResult := gs.simulateCloneOperation(opCtx, options, updateFunc)
	if cloneResult.IsErr() {
		stats.Success = false
		stats.Error = cloneResult.Error().Error()
		stats.EndTime = time.Now()
		stats.Duration = stats.EndTime.Sub(stats.StartTime)

		updateFunc(ProgressUpdate{
			Phase:   "failed",
			Progress: 0.5,
			Message: "Clone operation failed",
			Error:   cloneResult.Error(),
		})

		gs.progress.CompleteOperation(operationID, stats)
		return models.Err[*SyncStatistics](cloneResult.Error())
	}

	// Update statistics from clone result
	cloneStats := cloneResult.Unwrap()
	stats.CommitHash = cloneStats.CommitHash
	stats.FilesChanged = cloneStats.FilesChanged
	stats.BytesDownloaded = cloneStats.BytesDownloaded
	stats.TotalSize = cloneStats.TotalSize

	// Phase 3: Payload Discovery
	discoveryStart := time.Now()
	updateFunc(ProgressUpdate{
		Phase:    "discovering",
		Progress: 0.7,
		Message:  "Discovering payloads in repository",
	})

	// Simulate payload discovery
	discoveryResult := gs.simulatePayloadDiscovery(options.LocalPath, updateFunc)
	if discoveryResult.IsErr() {
		stats.Success = false
		stats.Error = discoveryResult.Error().Error()
		stats.EndTime = time.Now()
		stats.Duration = stats.EndTime.Sub(stats.StartTime)

		updateFunc(ProgressUpdate{
			Phase:   "failed",
			Progress: 0.7,
			Message: "Payload discovery failed",
			Error:   discoveryResult.Error(),
		})

		gs.progress.CompleteOperation(operationID, stats)
		return models.Err[*SyncStatistics](discoveryResult.Error())
	}

	discoveryStats := discoveryResult.Unwrap()
	stats.PayloadsDiscovered = discoveryStats.PayloadsDiscovered
	stats.PayloadsAdded = discoveryStats.PayloadsAdded
	stats.PayloadsSkipped = discoveryStats.PayloadsSkipped
	stats.PayloadsErrored = discoveryStats.PayloadsErrored
	stats.DiscoveryTime = time.Since(discoveryStart)

	// Phase 4: Database Sync
	syncStart := time.Now()
	updateFunc(ProgressUpdate{
		Phase:    "syncing",
		Progress: 0.9,
		Message:  "Synchronizing payloads to database",
		Statistics: map[string]interface{}{
			"payloads_found": stats.PayloadsDiscovered,
		},
	})

	// Simulate database sync
	syncResult := gs.simulateDatabaseSync(discoveryStats, updateFunc)
	if syncResult.IsErr() {
		stats.Success = false
		stats.Error = syncResult.Error().Error()
		stats.EndTime = time.Now()
		stats.Duration = stats.EndTime.Sub(stats.StartTime)

		updateFunc(ProgressUpdate{
			Phase:   "failed",
			Progress: 0.9,
			Message: "Database sync failed",
			Error:   syncResult.Error(),
		})

		gs.progress.CompleteOperation(operationID, stats)
		return models.Err[*SyncStatistics](syncResult.Error())
	}

	stats.ProcessingTime = time.Since(syncStart)
	stats.PayloadCount = int64(stats.PayloadsAdded)

	// Complete successfully
	stats.Success = true
	stats.EndTime = time.Now()
	stats.Duration = stats.EndTime.Sub(stats.StartTime)

	// Calculate performance metrics
	if stats.Duration > 0 {
		mbps := float64(stats.BytesDownloaded) / (1024 * 1024) / stats.Duration.Seconds()
		stats.CloneSpeed = fmt.Sprintf("%.1f MB/s", mbps)

		if stats.DiscoveryTime > 0 {
			payloadsPerSec := float64(stats.PayloadsDiscovered) / stats.DiscoveryTime.Seconds()
			stats.ProcessingSpeed = fmt.Sprintf("%.1f payloads/s", payloadsPerSec)
		}
	}

	updateFunc(ProgressUpdate{
		Phase:    "completed",
		Progress: 1.0,
		Message:  fmt.Sprintf("Successfully cloned repository with %d payloads", stats.PayloadsAdded),
		Statistics: map[string]interface{}{
			"total_payloads": stats.PayloadsAdded,
			"duration":       stats.Duration.String(),
			"clone_speed":    stats.CloneSpeed,
		},
	})

	// Complete the operation and display final statistics
	gs.progress.CompleteOperation(operationID, stats)

	return models.Ok(stats)
}

// simulateCloneOperation simulates a Git clone operation with progress updates
func (gs *ExampleGitServiceWithProgress) simulateCloneOperation(ctx context.Context, options GitCloneOptions, updateFunc func(ProgressUpdate)) models.Result[*SyncStatistics] {
	// Simulate clone phases with progress updates
	phases := []struct {
		name     string
		progress float64
		duration time.Duration
		message  string
	}{
		{"counting", 0.3, 500 * time.Millisecond, "Counting objects"},
		{"compressing", 0.4, 300 * time.Millisecond, "Compressing objects"},
		{"downloading", 0.6, 2 * time.Second, "Downloading repository"},
		{"resolving", 0.65, 500 * time.Millisecond, "Resolving deltas"},
	}

	bytesDownloaded := int64(0)
	for i, phase := range phases {
		select {
		case <-ctx.Done():
			return models.Err[*SyncStatistics](ctx.Err())
		default:
		}

		updateFunc(ProgressUpdate{
			Phase:    phase.name,
			Progress: phase.progress,
			Message:  phase.message,
		})

		// Simulate work
		time.Sleep(phase.duration)

		// Simulate bytes downloaded
		bytesDownloaded += int64((i + 1) * 256 * 1024) // Simulate increasing download
	}

	return models.Ok(&SyncStatistics{
		CommitHash:      "abc123def456789",
		FilesChanged:    150,
		BytesDownloaded: bytesDownloaded,
		TotalSize:       bytesDownloaded,
	})
}

// simulatePayloadDiscovery simulates payload discovery with progress updates
func (gs *ExampleGitServiceWithProgress) simulatePayloadDiscovery(localPath string, updateFunc func(ProgressUpdate)) models.Result[*SyncStatistics] {
	// Simulate discovering payloads in batches
	totalFiles := 150
	payloadsFound := 0
	skipped := 0
	errors := 0

	for i := 0; i < totalFiles; i += 10 {
		select {
		case <-time.After(50 * time.Millisecond):
		}

		batch := 10
		if i+batch > totalFiles {
			batch = totalFiles - i
		}

		// Simulate payload validation
		validPayloads := batch - 2 // Assume 2 files per batch are not payloads
		payloadsFound += validPayloads
		skipped += 2

		progress := float64(i+batch) / float64(totalFiles) * 0.2 + 0.7 // Scale to 0.7-0.9 range

		updateFunc(ProgressUpdate{
			Progress: progress,
			Message:  fmt.Sprintf("Discovered %d payloads (%d files processed)", payloadsFound, i+batch),
			Statistics: map[string]interface{}{
				"files_processed": i + batch,
				"payloads_found":  payloadsFound,
				"skipped":         skipped,
			},
		})
	}

	return models.Ok(&SyncStatistics{
		PayloadsDiscovered: payloadsFound,
		PayloadsAdded:      payloadsFound, // All discovered payloads are new in clone
		PayloadsSkipped:    skipped,
		PayloadsErrored:    errors,
	})
}

// simulateDatabaseSync simulates synchronizing payloads to database
func (gs *ExampleGitServiceWithProgress) simulateDatabaseSync(discoveryStats *SyncStatistics, updateFunc func(ProgressUpdate)) models.Result[bool] {
	totalPayloads := discoveryStats.PayloadsDiscovered
	processed := 0

	// Process payloads in batches
	batchSize := 25
	for processed < totalPayloads {
		batch := batchSize
		if processed+batch > totalPayloads {
			batch = totalPayloads - processed
		}

		// Simulate database operations
		time.Sleep(100 * time.Millisecond)

		processed += batch
		progress := 0.9 + (float64(processed)/float64(totalPayloads))*0.1 // Scale to 0.9-1.0

		updateFunc(ProgressUpdate{
			Progress: progress,
			Message:  fmt.Sprintf("Synchronized %d/%d payloads to database", processed, totalPayloads),
			Statistics: map[string]interface{}{
				"payloads_synced": processed,
				"batch_size":      batch,
			},
		})
	}

	return models.Ok(true)
}

// simulateValidateRepository simulates repository validation
func (gs *ExampleGitServiceWithProgress) simulateValidateRepository(url string) models.Result[bool] {
	// Simulate validation logic
	time.Sleep(200 * time.Millisecond)

	// Simple validation - just check URL format
	if url == "" {
		return models.Err[bool](fmt.Errorf("empty repository URL"))
	}

	return models.Ok(true)
}

// extractRepoName extracts repository name from URL
func extractRepoName(url string) string {
	// Simple extraction logic for demonstration
	parts := []rune(url)
	name := ""
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == '/' {
			break
		}
		name = string(parts[i]) + name
	}

	// Remove .git suffix if present
	if len(name) > 4 && name[len(name)-4:] == ".git" {
		name = name[:len(name)-4]
	}

	if name == "" {
		name = "unknown-repository"
	}

	return name
}

// SyncRepositoryWithProgress demonstrates synchronizing an existing repository with progress tracking
func (gs *ExampleGitServiceWithProgress) SyncRepositoryWithProgress(ctx context.Context, repoPath string, repoName string, repoURL string) models.Result[*SyncStatistics] {
	operationID := uuid.New().String()

	// Start progress tracking
	_, updateFunc := gs.progress.StartOperation(ctx, operationID, "sync")

	stats := &SyncStatistics{
		RepositoryID:   operationID,
		RepositoryName: repoName,
		RepositoryURL:  repoURL,
		Operation:      "sync",
		StartTime:      time.Now(),
	}

	// Phase 1: Git Pull
	updateFunc(ProgressUpdate{
		Phase:    "pulling",
		Progress: 0.2,
		Message:  "Pulling latest changes from remote",
	})

	// Simulate git pull operation
	time.Sleep(1 * time.Second)

	updateFunc(ProgressUpdate{
		Phase:    "checking",
		Progress: 0.4,
		Message:  "Checking for payload changes",
	})

	// Simulate change detection
	time.Sleep(500 * time.Millisecond)

	// Phase 2: Incremental payload discovery
	discoveryStart := time.Now()
	updateFunc(ProgressUpdate{
		Phase:    "discovering",
		Progress: 0.6,
		Message:  "Discovering new and modified payloads",
	})

	// Simulate incremental discovery (fewer payloads than full clone)
	discoveryResult := gs.simulateIncrementalDiscovery(updateFunc)
	if discoveryResult.IsErr() {
		stats.Success = false
		stats.Error = discoveryResult.Error().Error()
		stats.EndTime = time.Now()
		stats.Duration = stats.EndTime.Sub(stats.StartTime)

		gs.progress.CompleteOperation(operationID, stats)
		return models.Err[*SyncStatistics](discoveryResult.Error())
	}

	discoveryStats := discoveryResult.Unwrap()
	stats.PayloadsDiscovered = discoveryStats.PayloadsDiscovered
	stats.PayloadsAdded = discoveryStats.PayloadsAdded
	stats.PayloadsUpdated = discoveryStats.PayloadsUpdated
	stats.PayloadsRemoved = discoveryStats.PayloadsRemoved
	stats.PayloadsSkipped = discoveryStats.PayloadsSkipped
	stats.DiscoveryTime = time.Since(discoveryStart)

	// Phase 3: Database sync
	syncStart := time.Now()
	updateFunc(ProgressUpdate{
		Phase:    "syncing",
		Progress: 0.8,
		Message:  "Updating database with changes",
	})

	syncResult := gs.simulateDatabaseSync(discoveryStats, updateFunc)
	if syncResult.IsErr() {
		stats.Success = false
		stats.Error = syncResult.Error().Error()
		stats.EndTime = time.Now()
		stats.Duration = stats.EndTime.Sub(stats.StartTime)

		gs.progress.CompleteOperation(operationID, stats)
		return models.Err[*SyncStatistics](syncResult.Error())
	}

	stats.ProcessingTime = time.Since(syncStart)
	stats.PayloadCount = int64(stats.PayloadsAdded + stats.PayloadsUpdated)

	// Complete successfully
	stats.Success = true
	stats.EndTime = time.Now()
	stats.Duration = stats.EndTime.Sub(stats.StartTime)
	stats.CommitHash = "def456abc789012" // Simulate new commit hash

	updateFunc(ProgressUpdate{
		Phase:    "completed",
		Progress: 1.0,
		Message:  fmt.Sprintf("Sync completed: %d added, %d updated, %d removed", stats.PayloadsAdded, stats.PayloadsUpdated, stats.PayloadsRemoved),
	})

	gs.progress.CompleteOperation(operationID, stats)
	return models.Ok(stats)
}

// simulateIncrementalDiscovery simulates discovering changes in an existing repository
func (gs *ExampleGitServiceWithProgress) simulateIncrementalDiscovery(updateFunc func(ProgressUpdate)) models.Result[*SyncStatistics] {
	// Simulate smaller change set for sync operation
	time.Sleep(200 * time.Millisecond)

	updateFunc(ProgressUpdate{
		Progress: 0.7,
		Message:  "Analyzing payload changes",
		Statistics: map[string]interface{}{
			"files_analyzed": 50,
		},
	})

	return models.Ok(&SyncStatistics{
		PayloadsDiscovered: 15, // Fewer changes in sync vs clone
		PayloadsAdded:      5,
		PayloadsUpdated:    7,
		PayloadsRemoved:    3,
		PayloadsSkipped:    0,
		PayloadsErrored:    0,
	})
}