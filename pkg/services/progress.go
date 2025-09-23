// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gibson-sec/gibson-framework-2/pkg/core/models"
)

// ProgressReporter provides progress tracking and statistics reporting for Git operations
// Following requirement 5.1 (progress indicators during long operations) and 5.2 (continue to serve cached payloads)
type ProgressReporter struct {
	output       io.Writer
	format       string
	verbose      bool
	showProgress bool
	mu           sync.RWMutex
	activeOps    map[string]*OperationProgress
}

// OperationProgress tracks progress for a single operation
type OperationProgress struct {
	ID          string                 `json:"id"`
	Operation   string                 `json:"operation"`
	Phase       string                 `json:"phase"`
	StartTime   time.Time              `json:"start_time"`
	UpdateTime  time.Time              `json:"update_time"`
	Completed   bool                   `json:"completed"`
	Progress    float64                `json:"progress"` // 0.0 to 1.0
	Message     string                 `json:"message"`
	Error       error                  `json:"error,omitempty"`
	Statistics  map[string]interface{} `json:"statistics,omitempty"`
	cancel      context.CancelFunc
	updates     chan ProgressUpdate
}

// ProgressUpdate represents a single progress update
type ProgressUpdate struct {
	Phase      string                 `json:"phase"`
	Progress   float64                `json:"progress"`
	Message    string                 `json:"message"`
	Statistics map[string]interface{} `json:"statistics,omitempty"`
	Error      error                  `json:"error,omitempty"`
}

// SyncStatistics represents detailed statistics from a sync operation
type SyncStatistics struct {
	RepositoryID      string        `json:"repository_id"`
	RepositoryName    string        `json:"repository_name"`
	RepositoryURL     string        `json:"repository_url"`
	Operation         string        `json:"operation"` // "clone" or "sync"
	StartTime         time.Time     `json:"start_time"`
	EndTime           time.Time     `json:"end_time"`
	Duration          time.Duration `json:"duration"`
	Success           bool          `json:"success"`
	Error             string        `json:"error,omitempty"`

	// Git operation statistics
	CommitHash        string `json:"commit_hash,omitempty"`
	PreviousCommit    string `json:"previous_commit,omitempty"`
	FilesChanged      int    `json:"files_changed"`
	BytesDownloaded   int64  `json:"bytes_downloaded"`

	// Payload discovery statistics
	PayloadsDiscovered int `json:"payloads_discovered"`
	PayloadsAdded      int `json:"payloads_added"`
	PayloadsUpdated    int `json:"payloads_updated"`
	PayloadsRemoved    int `json:"payloads_removed"`
	PayloadsSkipped    int `json:"payloads_skipped"`
	PayloadsErrored    int `json:"payloads_errored"`

	// Performance metrics
	CloneSpeed        string `json:"clone_speed,omitempty"`        // MB/s
	ProcessingSpeed   string `json:"processing_speed,omitempty"`   // payloads/s
	DiscoveryTime     time.Duration `json:"discovery_time"`
	ProcessingTime    time.Duration `json:"processing_time"`

	// Repository metadata
	TotalSize         int64             `json:"total_size"`
	PayloadCount      int64             `json:"payload_count"`
	ConflictsResolved int               `json:"conflicts_resolved"`
	Details           map[string]interface{} `json:"details,omitempty"`
}

// NewProgressReporter creates a new progress reporter
func NewProgressReporter(output io.Writer, format string, verbose bool, showProgress bool) *ProgressReporter {
	if output == nil {
		output = os.Stdout
	}
	if format == "" {
		format = "text"
	}

	return &ProgressReporter{
		output:       output,
		format:       format,
		verbose:      verbose,
		showProgress: showProgress,
		activeOps:    make(map[string]*OperationProgress),
	}
}

// StartOperation begins tracking a new operation
// Returns a context that can be used to send progress updates
func (pr *ProgressReporter) StartOperation(ctx context.Context, id, operation string) (context.Context, func(ProgressUpdate)) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	// Create cancellable context for this operation
	opCtx, cancel := context.WithCancel(ctx)

	// Create progress tracking
	progress := &OperationProgress{
		ID:        id,
		Operation: operation,
		Phase:     "initializing",
		StartTime: time.Now(),
		UpdateTime: time.Now(),
		Progress:  0.0,
		Message:   fmt.Sprintf("Starting %s operation", operation),
		Statistics: make(map[string]interface{}),
		cancel:    cancel,
		updates:   make(chan ProgressUpdate, 100), // Buffered to avoid blocking
	}

	pr.activeOps[id] = progress

	// Start progress update handler
	go pr.handleProgressUpdates(progress)

	// Show initial progress
	pr.displayProgress(progress)

	// Return update function
	updateFunc := func(update ProgressUpdate) {
		select {
		case progress.updates <- update:
		case <-opCtx.Done():
			// Operation cancelled, don't send updates
		default:
			// Channel full, skip this update to avoid blocking
		}
	}

	return opCtx, updateFunc
}

// CompleteOperation marks an operation as completed
func (pr *ProgressReporter) CompleteOperation(id string, statistics *SyncStatistics) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	progress, exists := pr.activeOps[id]
	if !exists {
		return
	}

	// Update final state
	progress.Completed = true
	progress.Progress = 1.0
	progress.UpdateTime = time.Now()
	progress.cancel() // Stop the progress handler

	// Close updates channel
	close(progress.updates)

	// Display final progress and statistics
	pr.displayProgress(progress)
	if statistics != nil {
		pr.DisplayStatistics(statistics)
	}

	// Clean up completed operation
	delete(pr.activeOps, id)
}

// handleProgressUpdates processes progress updates for an operation
func (pr *ProgressReporter) handleProgressUpdates(progress *OperationProgress) {
	ticker := time.NewTicker(500 * time.Millisecond) // Update display every 500ms
	defer ticker.Stop()

	for {
		select {
		case update, ok := <-progress.updates:
			if !ok {
				return // Channel closed, operation completed
			}

			pr.mu.Lock()
			if update.Phase != "" {
				progress.Phase = update.Phase
			}
			if update.Progress >= 0 {
				progress.Progress = update.Progress
			}
			if update.Message != "" {
				progress.Message = update.Message
			}
			if update.Error != nil {
				progress.Error = update.Error
			}
			if update.Statistics != nil {
				for k, v := range update.Statistics {
					progress.Statistics[k] = v
				}
			}
			progress.UpdateTime = time.Now()
			pr.mu.Unlock()

		case <-ticker.C:
			// Regular display update
			pr.mu.RLock()
			if !progress.Completed {
				pr.displayProgress(progress)
			}
			pr.mu.RUnlock()

		case <-context.Background().Done():
			return
		}
	}
}

// displayProgress shows current progress based on format
func (pr *ProgressReporter) displayProgress(progress *OperationProgress) {
	if !pr.showProgress {
		return
	}

	switch pr.format {
	case "json":
		pr.displayProgressJSON(progress)
	case "yaml":
		pr.displayProgressYAML(progress)
	default:
		pr.displayProgressText(progress)
	}
}

// displayProgressText shows progress in human-readable text format
func (pr *ProgressReporter) displayProgressText(progress *OperationProgress) {
	elapsed := time.Since(progress.StartTime)

	// Create progress bar
	barWidth := 40
	filled := int(progress.Progress * float64(barWidth))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	// Format output
	output := fmt.Sprintf("\r%s [%s] %.1f%% - %s (%s)",
		progress.Operation,
		bar,
		progress.Progress*100,
		progress.Message,
		elapsed.Round(time.Second))

	if progress.Error != nil {
		output += fmt.Sprintf(" ERROR: %v", progress.Error)
	}

	// Add verbose statistics
	if pr.verbose && len(progress.Statistics) > 0 {
		output += "\n"
		for key, value := range progress.Statistics {
			output += fmt.Sprintf("  %s: %v\n", key, value)
		}
	}

	fmt.Fprint(pr.output, output)

	if progress.Completed {
		fmt.Fprintln(pr.output) // New line when completed
	}
}

// displayProgressJSON shows progress in JSON format
func (pr *ProgressReporter) displayProgressJSON(progress *OperationProgress) {
	data, _ := json.Marshal(progress)
	fmt.Fprintln(pr.output, string(data))
}

// displayProgressYAML shows progress in YAML format (simplified)
func (pr *ProgressReporter) displayProgressYAML(progress *OperationProgress) {
	fmt.Fprintf(pr.output, "operation: %s\n", progress.Operation)
	fmt.Fprintf(pr.output, "phase: %s\n", progress.Phase)
	fmt.Fprintf(pr.output, "progress: %.2f\n", progress.Progress)
	fmt.Fprintf(pr.output, "message: %s\n", progress.Message)
	fmt.Fprintf(pr.output, "elapsed: %s\n", time.Since(progress.StartTime).Round(time.Second))

	if progress.Error != nil {
		fmt.Fprintf(pr.output, "error: %v\n", progress.Error)
	}

	if pr.verbose && len(progress.Statistics) > 0 {
		fmt.Fprintln(pr.output, "statistics:")
		for key, value := range progress.Statistics {
			fmt.Fprintf(pr.output, "  %s: %v\n", key, value)
		}
	}
	fmt.Fprintln(pr.output, "---")
}

// DisplayStatistics displays final operation statistics
func (pr *ProgressReporter) DisplayStatistics(stats *SyncStatistics) {
	switch pr.format {
	case "json":
		pr.displayStatisticsJSON(stats)
	case "yaml":
		pr.displayStatisticsYAML(stats)
	default:
		pr.displayStatisticsText(stats)
	}
}

// displayStatisticsText shows statistics in human-readable format
func (pr *ProgressReporter) displayStatisticsText(stats *SyncStatistics) {
	fmt.Fprintln(pr.output)
	fmt.Fprintln(pr.output, "=== Sync Statistics ===")
	fmt.Fprintf(pr.output, "Repository: %s (%s)\n", stats.RepositoryName, stats.RepositoryURL)
	fmt.Fprintf(pr.output, "Operation: %s\n", stats.Operation)
	fmt.Fprintf(pr.output, "Duration: %v\n", stats.Duration.Round(time.Millisecond))
	fmt.Fprintf(pr.output, "Status: %s\n", func() string {
		if stats.Success {
			return "✓ Success"
		}
		return "✗ Failed"
	}())

	if stats.Error != "" {
		fmt.Fprintf(pr.output, "Error: %s\n", stats.Error)
	}

	if stats.CommitHash != "" {
		fmt.Fprintf(pr.output, "Commit: %s\n", stats.CommitHash)
		if stats.PreviousCommit != "" && stats.PreviousCommit != stats.CommitHash {
			fmt.Fprintf(pr.output, "Previous: %s\n", stats.PreviousCommit)
		}
	}

	// Payload statistics
	fmt.Fprintln(pr.output)
	fmt.Fprintln(pr.output, "Payload Summary:")
	fmt.Fprintf(pr.output, "  Discovered: %d\n", stats.PayloadsDiscovered)
	fmt.Fprintf(pr.output, "  Added: %d\n", stats.PayloadsAdded)
	fmt.Fprintf(pr.output, "  Updated: %d\n", stats.PayloadsUpdated)
	fmt.Fprintf(pr.output, "  Removed: %d\n", stats.PayloadsRemoved)
	fmt.Fprintf(pr.output, "  Skipped: %d\n", stats.PayloadsSkipped)

	if stats.PayloadsErrored > 0 {
		fmt.Fprintf(pr.output, "  Errors: %d\n", stats.PayloadsErrored)
	}

	if stats.ConflictsResolved > 0 {
		fmt.Fprintf(pr.output, "  Conflicts Resolved: %d\n", stats.ConflictsResolved)
	}

	// Performance metrics
	if pr.verbose {
		fmt.Fprintln(pr.output)
		fmt.Fprintln(pr.output, "Performance:")
		fmt.Fprintf(pr.output, "  Repository Size: %s\n", formatBytes(stats.TotalSize))
		fmt.Fprintf(pr.output, "  Total Payloads: %d\n", stats.PayloadCount)

		if stats.CloneSpeed != "" {
			fmt.Fprintf(pr.output, "  Download Speed: %s\n", stats.CloneSpeed)
		}

		if stats.ProcessingSpeed != "" {
			fmt.Fprintf(pr.output, "  Processing Speed: %s\n", stats.ProcessingSpeed)
		}

		if stats.DiscoveryTime > 0 {
			fmt.Fprintf(pr.output, "  Discovery Time: %v\n", stats.DiscoveryTime.Round(time.Millisecond))
		}

		if stats.ProcessingTime > 0 {
			fmt.Fprintf(pr.output, "  Processing Time: %v\n", stats.ProcessingTime.Round(time.Millisecond))
		}
	}

	fmt.Fprintln(pr.output)
}

// displayStatisticsJSON shows statistics in JSON format
func (pr *ProgressReporter) displayStatisticsJSON(stats *SyncStatistics) {
	data, _ := json.MarshalIndent(stats, "", "  ")
	fmt.Fprintln(pr.output, string(data))
}

// displayStatisticsYAML shows statistics in YAML format (simplified)
func (pr *ProgressReporter) displayStatisticsYAML(stats *SyncStatistics) {
	fmt.Fprintf(pr.output, "repository_name: %s\n", stats.RepositoryName)
	fmt.Fprintf(pr.output, "repository_url: %s\n", stats.RepositoryURL)
	fmt.Fprintf(pr.output, "operation: %s\n", stats.Operation)
	fmt.Fprintf(pr.output, "duration: %v\n", stats.Duration)
	fmt.Fprintf(pr.output, "success: %t\n", stats.Success)

	if stats.Error != "" {
		fmt.Fprintf(pr.output, "error: %s\n", stats.Error)
	}

	fmt.Fprintln(pr.output, "payload_summary:")
	fmt.Fprintf(pr.output, "  discovered: %d\n", stats.PayloadsDiscovered)
	fmt.Fprintf(pr.output, "  added: %d\n", stats.PayloadsAdded)
	fmt.Fprintf(pr.output, "  updated: %d\n", stats.PayloadsUpdated)
	fmt.Fprintf(pr.output, "  removed: %d\n", stats.PayloadsRemoved)
	fmt.Fprintf(pr.output, "  skipped: %d\n", stats.PayloadsSkipped)

	if stats.PayloadsErrored > 0 {
		fmt.Fprintf(pr.output, "  errors: %d\n", stats.PayloadsErrored)
	}
}

// GetActiveOperations returns information about currently active operations
func (pr *ProgressReporter) GetActiveOperations() map[string]*OperationProgress {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	// Return copy to avoid race conditions
	result := make(map[string]*OperationProgress)
	for k, v := range pr.activeOps {
		// Create copy of the operation progress
		progress := *v
		result[k] = &progress
	}

	return result
}

// CancelOperation cancels an active operation
func (pr *ProgressReporter) CancelOperation(id string) models.Result[bool] {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	progress, exists := pr.activeOps[id]
	if !exists {
		return models.Err[bool](fmt.Errorf("operation %s not found", id))
	}

	progress.cancel()
	progress.Completed = true
	progress.Error = fmt.Errorf("operation cancelled")
	progress.UpdateTime = time.Now()

	// Clean up
	close(progress.updates)
	delete(pr.activeOps, id)

	return models.Ok(true)
}

// formatBytes formats byte size in human readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// CreateGitProgressCallback creates a progress callback for go-git operations
// This integrates with go-git's progress reporting
func (pr *ProgressReporter) CreateGitProgressCallback(updateFunc func(ProgressUpdate)) func(string) {
	return func(message string) {
		// Parse git progress messages and convert to our format
		if strings.Contains(message, "Counting objects") {
			updateFunc(ProgressUpdate{
				Phase:    "counting",
				Progress: 0.1,
				Message:  "Counting objects",
			})
		} else if strings.Contains(message, "Compressing objects") {
			updateFunc(ProgressUpdate{
				Phase:    "compressing",
				Progress: 0.3,
				Message:  "Compressing objects",
			})
		} else if strings.Contains(message, "Receiving objects") {
			updateFunc(ProgressUpdate{
				Phase:    "downloading",
				Progress: 0.5,
				Message:  "Downloading repository",
			})
		} else if strings.Contains(message, "Resolving deltas") {
			updateFunc(ProgressUpdate{
				Phase:    "resolving",
				Progress: 0.8,
				Message:  "Resolving deltas",
			})
		} else if strings.Contains(message, "done") {
			updateFunc(ProgressUpdate{
				Phase:    "completed",
				Progress: 1.0,
				Message:  "Git operation completed",
			})
		}
	}
}