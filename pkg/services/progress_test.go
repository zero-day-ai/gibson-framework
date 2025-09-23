// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProgressReporter(t *testing.T) {
	tests := []struct {
		name         string
		format       string
		verbose      bool
		showProgress bool
		expectedFmt  string
	}{
		{
			name:         "default format",
			format:       "",
			verbose:      false,
			showProgress: true,
			expectedFmt:  "text",
		},
		{
			name:         "json format",
			format:       "json",
			verbose:      true,
			showProgress: true,
			expectedFmt:  "json",
		},
		{
			name:         "yaml format",
			format:       "yaml",
			verbose:      false,
			showProgress: false,
			expectedFmt:  "yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			reporter := NewProgressReporter(&buf, tt.format, tt.verbose, tt.showProgress)

			assert.NotNil(t, reporter)
			assert.Equal(t, tt.expectedFmt, reporter.format)
			assert.Equal(t, tt.verbose, reporter.verbose)
			assert.Equal(t, tt.showProgress, reporter.showProgress)
			assert.NotNil(t, reporter.activeOps)
		})
	}
}

func TestProgressReporter_StartOperation(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewProgressReporter(&buf, "text", false, true)

	ctx := context.Background()
	opCtx, updateFunc := reporter.StartOperation(ctx, "test-op", "clone")

	// Check that operation was registered
	activeOps := reporter.GetActiveOperations()
	assert.Len(t, activeOps, 1)

	op, exists := activeOps["test-op"]
	require.True(t, exists)
	assert.Equal(t, "test-op", op.ID)
	assert.Equal(t, "clone", op.Operation)
	assert.Equal(t, "initializing", op.Phase)
	assert.Equal(t, 0.0, op.Progress)
	assert.False(t, op.Completed)

	// Test context cancellation
	assert.NotNil(t, opCtx)
	assert.NotNil(t, updateFunc)

	// Clean up
	reporter.CompleteOperation("test-op", nil)
}

func TestProgressReporter_ProgressUpdates(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewProgressReporter(&buf, "json", false, false) // Disable progress display for testing

	ctx := context.Background()
	_, updateFunc := reporter.StartOperation(ctx, "test-op", "sync")

	// Send progress updates
	updateFunc(ProgressUpdate{
		Phase:    "discovering",
		Progress: 0.3,
		Message:  "Discovering payloads",
		Statistics: map[string]interface{}{
			"files_scanned": 50,
		},
	})

	// Give time for update to be processed
	time.Sleep(100 * time.Millisecond)

	// Check operation state
	activeOps := reporter.GetActiveOperations()
	op := activeOps["test-op"]
	assert.Equal(t, "discovering", op.Phase)
	assert.Equal(t, 0.3, op.Progress)
	assert.Equal(t, "Discovering payloads", op.Message)
	assert.Equal(t, 50, op.Statistics["files_scanned"])

	// Send error update
	updateFunc(ProgressUpdate{
		Progress: 0.5,
		Error:    assert.AnError,
	})

	time.Sleep(100 * time.Millisecond)

	activeOps = reporter.GetActiveOperations()
	op = activeOps["test-op"]
	assert.Equal(t, 0.5, op.Progress)
	assert.NotNil(t, op.Error)

	// Clean up
	reporter.CompleteOperation("test-op", nil)
}

func TestProgressReporter_CompleteOperation(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewProgressReporter(&buf, "text", false, false)

	// Start operation
	ctx := context.Background()
	_, _ = reporter.StartOperation(ctx, "test-op", "clone")

	// Verify operation is active
	activeOps := reporter.GetActiveOperations()
	assert.Len(t, activeOps, 1)

	// Complete operation with statistics
	stats := &SyncStatistics{
		RepositoryID:       "test-repo",
		RepositoryName:     "test-repository",
		RepositoryURL:      "https://github.com/test/repo.git",
		Operation:          "clone",
		StartTime:          time.Now().Add(-5 * time.Minute),
		EndTime:            time.Now(),
		Duration:           5 * time.Minute,
		Success:            true,
		PayloadsDiscovered: 100,
		PayloadsAdded:      100,
		TotalSize:          1024 * 1024, // 1MB
		PayloadCount:       100,
	}

	reporter.CompleteOperation("test-op", stats)

	// Verify operation is removed from active operations
	activeOps = reporter.GetActiveOperations()
	assert.Len(t, activeOps, 0)

	// Check output contains statistics
	output := buf.String()
	assert.Contains(t, output, "test-repository")
	assert.Contains(t, output, "clone")
	assert.Contains(t, output, "Success")
	assert.Contains(t, output, "Discovered: 100")
	assert.Contains(t, output, "Added: 100")
}

func TestProgressReporter_JSONOutput(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewProgressReporter(&buf, "json", false, false)

	stats := &SyncStatistics{
		RepositoryID:       "test-repo",
		RepositoryName:     "test-repository",
		RepositoryURL:      "https://github.com/test/repo.git",
		Operation:          "sync",
		StartTime:          time.Now().Add(-2 * time.Minute),
		EndTime:            time.Now(),
		Duration:           2 * time.Minute,
		Success:            true,
		PayloadsDiscovered: 50,
		PayloadsAdded:      10,
		PayloadsUpdated:    5,
		PayloadsSkipped:    35,
		TotalSize:          512 * 1024, // 512KB
		PayloadCount:       50,
	}

	reporter.DisplayStatistics(stats)

	// Verify JSON output
	output := buf.String()
	var parsedStats SyncStatistics
	err := json.Unmarshal([]byte(output), &parsedStats)
	require.NoError(t, err)

	assert.Equal(t, stats.RepositoryName, parsedStats.RepositoryName)
	assert.Equal(t, stats.Operation, parsedStats.Operation)
	assert.Equal(t, stats.Success, parsedStats.Success)
	assert.Equal(t, stats.PayloadsDiscovered, parsedStats.PayloadsDiscovered)
	assert.Equal(t, stats.PayloadsAdded, parsedStats.PayloadsAdded)
}

func TestProgressReporter_YAMLOutput(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewProgressReporter(&buf, "yaml", false, false)

	stats := &SyncStatistics{
		RepositoryName:     "test-repository",
		RepositoryURL:      "https://github.com/test/repo.git",
		Operation:          "sync",
		Duration:           3 * time.Minute,
		Success:            true,
		PayloadsDiscovered: 75,
		PayloadsAdded:      25,
		PayloadsUpdated:    10,
		PayloadsRemoved:    5,
		PayloadsSkipped:    35,
	}

	reporter.DisplayStatistics(stats)

	output := buf.String()
	assert.Contains(t, output, "repository_name: test-repository")
	assert.Contains(t, output, "operation: sync")
	assert.Contains(t, output, "success: true")
	assert.Contains(t, output, "discovered: 75")
	assert.Contains(t, output, "added: 25")
	assert.Contains(t, output, "updated: 10")
	assert.Contains(t, output, "removed: 5")
	assert.Contains(t, output, "skipped: 35")
}

func TestProgressReporter_CancelOperation(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewProgressReporter(&buf, "text", false, false)

	ctx := context.Background()
	_, _ = reporter.StartOperation(ctx, "test-op", "clone")

	// Verify operation is active
	activeOps := reporter.GetActiveOperations()
	assert.Len(t, activeOps, 1)

	// Cancel operation
	result := reporter.CancelOperation("test-op")
	assert.True(t, result.IsOk())
	assert.True(t, result.Unwrap())

	// Verify operation is removed
	activeOps = reporter.GetActiveOperations()
	assert.Len(t, activeOps, 0)

	// Test cancelling non-existent operation
	result = reporter.CancelOperation("non-existent")
	assert.True(t, result.IsErr())
	assert.Contains(t, result.Error().Error(), "operation non-existent not found")
}

func TestProgressReporter_GitProgressCallback(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewProgressReporter(&buf, "text", false, false)

	var lastUpdate ProgressUpdate
	updateFunc := func(update ProgressUpdate) {
		lastUpdate = update
	}

	callback := reporter.CreateGitProgressCallback(updateFunc)

	// Test different git messages
	testCases := []struct {
		message       string
		expectedPhase string
		expectedMsg   string
		minProgress   float64
	}{
		{
			message:       "Counting objects: 100, done.",
			expectedPhase: "counting",
			expectedMsg:   "Counting objects",
			minProgress:   0.1,
		},
		{
			message:       "Compressing objects: 100% (50/50), done.",
			expectedPhase: "compressing",
			expectedMsg:   "Compressing objects",
			minProgress:   0.3,
		},
		{
			message:       "Receiving objects: 100% (100/100), 1.5 MiB | 500 KiB/s, done.",
			expectedPhase: "downloading",
			expectedMsg:   "Downloading repository",
			minProgress:   0.5,
		},
		{
			message:       "Resolving deltas: 100% (25/25), done.",
			expectedPhase: "resolving",
			expectedMsg:   "Resolving deltas",
			minProgress:   0.8,
		},
		{
			message:       "done.",
			expectedPhase: "completed",
			expectedMsg:   "Git operation completed",
			minProgress:   1.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.message, func(t *testing.T) {
			callback(tc.message)
			assert.Equal(t, tc.expectedPhase, lastUpdate.Phase)
			assert.Equal(t, tc.expectedMsg, lastUpdate.Message)
			assert.GreaterOrEqual(t, lastUpdate.Progress, tc.minProgress)
		})
	}
}

func TestFormatBytes(t *testing.T) {
	testCases := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
		{1536 * 1024 * 1024, "1.5 GB"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := formatBytes(tc.bytes)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestProgressReporter_TextProgressDisplay(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewProgressReporter(&buf, "text", false, false)

	progress := &OperationProgress{
		ID:        "test-op",
		Operation: "clone",
		Phase:     "downloading",
		StartTime: time.Now().Add(-30 * time.Second),
		Progress:  0.6,
		Message:   "Downloading repository",
		Statistics: map[string]interface{}{
			"bytes_downloaded": 1024 * 1024,
		},
	}

	reporter.displayProgressText(progress)

	output := buf.String()
	assert.Contains(t, output, "clone")
	assert.Contains(t, output, "60.0%")
	assert.Contains(t, output, "Downloading repository")
	assert.Contains(t, output, "30s")

	// Check progress bar
	assert.Contains(t, output, "█") // Should contain filled characters
	assert.Contains(t, output, "░") // Should contain empty characters
}

func TestProgressReporter_VerboseOutput(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewProgressReporter(&buf, "text", true, false) // Verbose mode

	stats := &SyncStatistics{
		RepositoryName:    "test-repository",
		RepositoryURL:     "https://github.com/test/repo.git",
		Operation:         "sync",
		Duration:          2 * time.Minute,
		Success:           true,
		TotalSize:         2 * 1024 * 1024, // 2MB
		PayloadCount:      150,
		CloneSpeed:        "1.5 MB/s",
		ProcessingSpeed:   "50 payloads/s",
		DiscoveryTime:     30 * time.Second,
		ProcessingTime:    90 * time.Second,
		PayloadsDiscovered: 150,
		PayloadsAdded:     100,
		PayloadsUpdated:   25,
		PayloadsSkipped:   25,
	}

	reporter.DisplayStatistics(stats)

	output := buf.String()
	// Should include performance metrics in verbose mode
	assert.Contains(t, output, "Performance:")
	assert.Contains(t, output, "2.0 MB")
	assert.Contains(t, output, "1.5 MB/s")
	assert.Contains(t, output, "50 payloads/s")
	assert.Contains(t, output, "Discovery Time:")
	assert.Contains(t, output, "Processing Time:")
}

func TestProgressReporter_ErrorHandling(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewProgressReporter(&buf, "text", false, false)

	// Test error in statistics
	stats := &SyncStatistics{
		RepositoryName: "test-repository",
		Operation:      "clone",
		Duration:       1 * time.Minute,
		Success:        false,
		Error:          "authentication failed",
		PayloadsErrored: 5,
	}

	reporter.DisplayStatistics(stats)

	output := buf.String()
	assert.Contains(t, output, "✗ Failed")
	assert.Contains(t, output, "authentication failed")
	assert.Contains(t, output, "Errors: 5")
}

func TestProgressReporter_ConcurrentOperations(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewProgressReporter(&buf, "text", false, false)

	ctx := context.Background()

	// Start multiple operations
	_, update1 := reporter.StartOperation(ctx, "op1", "clone")
	_, update2 := reporter.StartOperation(ctx, "op2", "sync")

	// Send updates concurrently
	go func() {
		for i := 0; i < 10; i++ {
			update1(ProgressUpdate{
				Progress: float64(i) / 10.0,
				Message:  "Clone progress",
			})
			time.Sleep(10 * time.Millisecond)
		}
	}()

	go func() {
		for i := 0; i < 5; i++ {
			update2(ProgressUpdate{
				Progress: float64(i) / 5.0,
				Message:  "Sync progress",
			})
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// Wait for updates
	time.Sleep(200 * time.Millisecond)

	// Check both operations are tracked
	activeOps := reporter.GetActiveOperations()
	assert.Len(t, activeOps, 2)

	// Complete operations
	reporter.CompleteOperation("op1", nil)
	reporter.CompleteOperation("op2", nil)

	// Verify cleanup
	activeOps = reporter.GetActiveOperations()
	assert.Len(t, activeOps, 0)
}