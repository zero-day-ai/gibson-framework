// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/zero-day-ai/gibson-framework/pkg/core/models"
)

// CLIProgressDemo demonstrates how progress reporting integrates with CLI commands
// This shows the implementation for requirements 5.1 and 5.2
func CLIProgressDemo() {
	fmt.Println("=== Gibson Progress Tracking Demo ===")
	fmt.Println()

	// Demo 1: Clone operation with text progress
	fmt.Println("Demo 1: Repository Clone with Text Progress")
	fmt.Println("-------------------------------------------")

	gitConfig := GitServiceConfig{
		DefaultDepth:   1,
		DefaultBranch: "main",
		BaseDir:       "/tmp/gibson-repos",
	}

	service := NewExampleGitServiceWithProgress(gitConfig, "text", false)

	cloneOptions := GitCloneOptions{
		URL:       "https://github.com/example/security-payloads.git",
		LocalPath: "/tmp/gibson-repos/security-payloads",
		Depth:     1,
		AuthType:  models.PayloadRepositoryAuthTypeHTTPS,
	}

	ctx := context.Background()
	result := service.CloneRepositoryWithProgress(ctx, cloneOptions)

	if result.IsErr() {
		fmt.Printf("Clone failed: %v\n", result.Error())
	} else {
		fmt.Println("Clone completed successfully!")
	}

	fmt.Println()
	time.Sleep(1 * time.Second)

	// Demo 2: Sync operation with verbose JSON output
	fmt.Println("Demo 2: Repository Sync with JSON Output")
	fmt.Println("----------------------------------------")

	serviceJSON := NewExampleGitServiceWithProgress(gitConfig, "json", true)

	syncResult := serviceJSON.SyncRepositoryWithProgress(
		ctx,
		"/tmp/gibson-repos/security-payloads",
		"security-payloads",
		"https://github.com/example/security-payloads.git",
	)

	if syncResult.IsErr() {
		fmt.Printf("Sync failed: %v\n", syncResult.Error())
	} else {
		fmt.Println("Sync completed successfully!")
	}

	fmt.Println()
	time.Sleep(1 * time.Second)

	// Demo 3: YAML output with verbose statistics
	fmt.Println("Demo 3: Repository Operation with YAML Output")
	fmt.Println("---------------------------------------------")

	serviceYAML := NewExampleGitServiceWithProgress(gitConfig, "yaml", true)

	// Create some sample statistics to display
	stats := &SyncStatistics{
		RepositoryID:       "demo-repo-123",
		RepositoryName:     "ml-security-datasets",
		RepositoryURL:      "https://github.com/example/ml-security-datasets.git",
		Operation:          "clone",
		StartTime:          time.Now().Add(-3 * time.Minute),
		EndTime:            time.Now(),
		Duration:           3 * time.Minute,
		Success:            true,
		CommitHash:         "a1b2c3d4e5f6",
		FilesChanged:       234,
		BytesDownloaded:    15 * 1024 * 1024, // 15MB
		PayloadsDiscovered: 450,
		PayloadsAdded:      450,
		PayloadsUpdated:    0,
		PayloadsRemoved:    0,
		PayloadsSkipped:    23,
		PayloadsErrored:    2,
		TotalSize:          15 * 1024 * 1024,
		PayloadCount:       450,
		CloneSpeed:         "5.2 MB/s",
		ProcessingSpeed:    "150 payloads/s",
		DiscoveryTime:      45 * time.Second,
		ProcessingTime:     90 * time.Second,
		ConflictsResolved:  0,
	}

	serviceYAML.progress.DisplayStatistics(stats)

	fmt.Println()

	// Demo 4: Multiple concurrent operations
	fmt.Println("Demo 4: Concurrent Operations Tracking")
	fmt.Println("--------------------------------------")

	progressReporter := NewProgressReporter(os.Stdout, "text", false, true)

	// Start multiple operations
	ctx1, update1 := progressReporter.StartOperation(ctx, "repo1", "clone")
	ctx2, update2 := progressReporter.StartOperation(ctx, "repo2", "sync")

	// Simulate concurrent progress
	go func() {
		for i := 0; i <= 10; i++ {
			select {
			case <-ctx1.Done():
				return
			default:
			}

			update1(ProgressUpdate{
				Progress: float64(i) / 10.0,
				Message:  fmt.Sprintf("Cloning repository 1... (%d/10)", i),
				Phase:    "downloading",
			})
			time.Sleep(200 * time.Millisecond)
		}
	}()

	go func() {
		for i := 0; i <= 5; i++ {
			select {
			case <-ctx2.Done():
				return
			default:
			}

			update2(ProgressUpdate{
				Progress: float64(i) / 5.0,
				Message:  fmt.Sprintf("Syncing repository 2... (%d/5)", i),
				Phase:    "syncing",
			})
			time.Sleep(400 * time.Millisecond)
		}
	}()

	// Let operations run
	time.Sleep(2500 * time.Millisecond)

	// Show active operations
	activeOps := progressReporter.GetActiveOperations()
	fmt.Printf("\nActive operations: %d\n", len(activeOps))
	for id, op := range activeOps {
		fmt.Printf("  %s: %s (%.1f%% complete)\n", id, op.Operation, op.Progress*100)
	}

	// Complete operations
	progressReporter.CompleteOperation("repo1", &SyncStatistics{
		RepositoryName: "test-repo-1",
		Operation:      "clone",
		Success:        true,
		Duration:       2 * time.Second,
		PayloadsAdded:  125,
	})

	progressReporter.CompleteOperation("repo2", &SyncStatistics{
		RepositoryName: "test-repo-2",
		Operation:      "sync",
		Success:        true,
		Duration:       2 * time.Second,
		PayloadsUpdated: 45,
	})

	fmt.Println("\nDemo completed!")
}

// ProgressIntegrationExample shows how to integrate with existing CLI patterns
func ProgressIntegrationExample(outputFormat string, verbose bool, watch bool) {
	fmt.Printf("=== Progress Integration Example ===\n")
	fmt.Printf("Output format: %s, Verbose: %t, Watch: %t\n\n", outputFormat, verbose, watch)

	// Create progress reporter based on CLI flags
	progressReporter := NewProgressReporter(os.Stdout, outputFormat, verbose, true)

	ctx := context.Background()

	// Simulate repository operations based on CLI command patterns
	if watch {
		// Watch mode - show continuous updates
		fmt.Println("Starting watch mode...")

		operationCtx, updateFunc := progressReporter.StartOperation(ctx, "watch-demo", "sync")

		// Simulate long-running sync with periodic updates
		go func() {
			phases := []string{"validating", "pulling", "analyzing", "processing", "completing"}
			for i, phase := range phases {
				select {
				case <-operationCtx.Done():
					return
				default:
				}

				updateFunc(ProgressUpdate{
					Phase:    phase,
					Progress: float64(i+1) / float64(len(phases)),
					Message:  fmt.Sprintf("Watch mode: %s repository", phase),
					Statistics: map[string]interface{}{
						"phase_number": i + 1,
						"total_phases": len(phases),
						"timestamp":    time.Now().Format(time.RFC3339),
					},
				})

				time.Sleep(1 * time.Second)
			}
		}()

		// Let it run for demo
		time.Sleep(6 * time.Second)

		progressReporter.CompleteOperation("watch-demo", &SyncStatistics{
			RepositoryName:  "watch-demo-repo",
			Operation:       "sync",
			Success:         true,
			Duration:        5 * time.Second,
			PayloadsUpdated: 42,
		})

	} else {
		// Single operation mode
		fmt.Println("Starting single operation...")

		operationCtx, updateFunc := progressReporter.StartOperation(ctx, "single-demo", "clone")

		// Simulate quick operation
		for i := 0; i <= 4; i++ {
			select {
			case <-operationCtx.Done():
				return
			default:
			}

			phase := "downloading"
			if i == 4 {
				phase = "completed"
			}

			updateFunc(ProgressUpdate{
				Phase:    phase,
				Progress: float64(i) / 4.0,
				Message:  fmt.Sprintf("Single operation progress: %d/4", i),
			})

			time.Sleep(500 * time.Millisecond)
		}

		progressReporter.CompleteOperation("single-demo", &SyncStatistics{
			RepositoryName: "single-demo-repo",
			Operation:      "clone",
			Success:        true,
			Duration:       2 * time.Second,
			PayloadsAdded:  89,
		})
	}

	fmt.Println("Integration example completed!")
}

// CachedPayloadExample demonstrates requirement 5.2 - continue to serve cached payloads
func CachedPayloadExample() {
	fmt.Println("=== Cached Payload Service Demo ===")
	fmt.Println("Demonstrating requirement 5.2: Continue to serve cached payloads during operations")
	fmt.Println()

	progressReporter := NewProgressReporter(os.Stdout, "text", true, true)
	ctx := context.Background()

	// Simulate starting a long-running sync operation
	fmt.Println("1. Starting background repository sync...")
	syncCtx, syncUpdate := progressReporter.StartOperation(ctx, "background-sync", "sync")

	// Start background sync
	go func() {
		phases := []struct {
			name     string
			duration time.Duration
			progress float64
		}{
			{"connecting", 500 * time.Millisecond, 0.1},
			{"pulling", 1500 * time.Millisecond, 0.4},
			{"analyzing", 1000 * time.Millisecond, 0.7},
			{"processing", 1000 * time.Millisecond, 0.9},
			{"completing", 300 * time.Millisecond, 1.0},
		}

		for _, phase := range phases {
			select {
			case <-syncCtx.Done():
				return
			default:
			}

			syncUpdate(ProgressUpdate{
				Phase:    phase.name,
				Progress: phase.progress,
				Message:  fmt.Sprintf("Background sync: %s", phase.name),
				Statistics: map[string]interface{}{
					"background_operation": true,
					"allows_cached_access": true,
				},
			})

			time.Sleep(phase.duration)
		}
	}()

	// Simulate serving cached payloads while sync is running
	fmt.Println("2. Serving cached payloads while sync is in progress...")
	time.Sleep(500 * time.Millisecond) // Let sync start

	// Show active operations
	activeOps := progressReporter.GetActiveOperations()
	if len(activeOps) > 0 {
		fmt.Printf("   Active sync operations: %d\n", len(activeOps))
		for id, op := range activeOps {
			fmt.Printf("   - %s: %s (%.1f%% complete)\n", id, op.Phase, op.Progress*100)
		}
	}

	// Simulate serving payloads from cache
	cachedPayloads := []string{
		"sql-injection-basic.yaml",
		"xss-reflected.yaml",
		"prompt-injection-jailbreak.yaml",
		"model-extraction-attack.yaml",
		"data-poisoning-sample.yaml",
	}

	fmt.Println("   Serving cached payloads (non-blocking):")
	for i, payload := range cachedPayloads {
		time.Sleep(200 * time.Millisecond) // Simulate payload serving
		fmt.Printf("   ✓ Served: %s\n", payload)

		// Show sync is still progressing
		if i == 2 { // Midway through serving
			activeOps := progressReporter.GetActiveOperations()
			if len(activeOps) > 0 {
				for _, op := range activeOps {
					fmt.Printf("     (Background sync: %s - %.1f%%)\n", op.Phase, op.Progress*100)
				}
			}
		}
	}

	// Wait for sync to complete
	fmt.Println("3. Waiting for background sync to complete...")
	time.Sleep(2 * time.Second) // Wait for sync to finish

	// Complete the sync operation
	progressReporter.CompleteOperation("background-sync", &SyncStatistics{
		RepositoryName:     "background-repo",
		Operation:          "sync",
		Success:            true,
		Duration:           4 * time.Second,
		PayloadsDiscovered: 25,
		PayloadsUpdated:    8,
		PayloadsAdded:      3,
	})

	fmt.Println()
	fmt.Println("✓ Demonstration complete!")
	fmt.Println("  - Background sync completed successfully")
	fmt.Println("  - Cached payloads were served throughout the operation")
	fmt.Println("  - No service interruption occurred")
}