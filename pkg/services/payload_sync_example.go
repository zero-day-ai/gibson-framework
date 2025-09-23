// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"context"
	"log"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	coremodels "github.com/gibson-sec/gibson-framework-2/pkg/core/models"
	"github.com/gibson-sec/gibson-framework-2/pkg/core/database/repositories"
)

// ExamplePayloadSynchronizerUsage demonstrates how to use the PayloadSynchronizer
func ExamplePayloadSynchronizerUsage() {
	// This is a demonstration of how the PayloadSynchronizer would be used
	// In a real application, you would have an actual database connection

	// Create a mock database connection (would be real in actual usage)
	var db *sqlx.DB // This would be your actual database connection

	// Create payload repository
	payloadRepo := repositories.NewPayloadRepository(db)

	// Create synchronizer with configuration
	config := PayloadSyncConfig{
		BatchSize: 50, // Process 50 payloads at a time
		DiscoveryPaths: []string{
			"*.yaml", "*.yml", "*.json", "*.txt", "*.payload",
		},
	}
	synchronizer := NewPayloadSynchronizer(db, config)

	// Example repository to sync
	repository := &coremodels.PayloadRepositoryDB{
		ID:        uuid.New(),
		Name:      "example-payload-repo",
		URL:       "https://github.com/example/payloads.git",
		LocalPath: "/tmp/gibson-repos/example-payload-repo",
		Status:    coremodels.PayloadRepositoryStatusActive,
	}

	// Perform synchronization
	ctx := context.Background()
	result := synchronizer.SyncRepositoryPayloads(ctx, repository, payloadRepo)

	if result.IsErr() {
		log.Printf("Synchronization failed: %v", result.Error())
		return
	}

	syncResult := result.Unwrap()
	log.Printf("Synchronization completed successfully:")
	log.Printf("  Total files: %d", syncResult.TotalFiles)
	log.Printf("  Processed files: %d", syncResult.ProcessedFiles)
	log.Printf("  New payloads: %d", syncResult.NewPayloads)
	log.Printf("  Updated payloads: %d", syncResult.UpdatedPayloads)
	log.Printf("  Skipped files: %d", syncResult.SkippedFiles)
	log.Printf("  Error files: %d", syncResult.ErrorFiles)
	log.Printf("  Orphaned cleaned: %d", syncResult.OrphanedCleaned)
	log.Printf("  Duration: %v", syncResult.Duration)

	// Get synchronization statistics
	statsResult := synchronizer.GetSyncStatistics(ctx, repository.ID, payloadRepo)
	if statsResult.IsOk() {
		stats := statsResult.Unwrap()
		log.Printf("Repository statistics:")
		log.Printf("  Total payloads: %v", stats["total_payloads"])
		log.Printf("  Enabled payloads: %v", stats["enabled_payloads"])
		log.Printf("  Categories: %v", stats["categories"])
	}

	// Validate repository structure
	validationResult := synchronizer.ValidateRepositoryStructure(repository.LocalPath)
	if validationResult.IsOk() {
		validation := validationResult.Unwrap()
		log.Printf("Repository validation:")
		log.Printf("  Is valid: %v", validation["is_valid"])
		log.Printf("  Has payloads: %v", validation["has_payloads"])
		log.Printf("  Payload count: %v", validation["payload_count"])
		log.Printf("  Supported formats: %v", validation["supported_formats"])
	}
}

// ExamplePayloadSyncConfig shows different configuration options
func ExamplePayloadSyncConfig() {
	// Basic configuration
	basicConfig := PayloadSyncConfig{
		BatchSize: 100, // Default batch size
		DiscoveryPaths: []string{
			"*.yaml", "*.yml", "*.json", "*.txt", "*.payload",
		},
	}

	// Advanced configuration for large repositories
	advancedConfig := PayloadSyncConfig{
		BatchSize: 500, // Larger batches for better performance
		DiscoveryPaths: []string{
			"*.yaml", "*.yml", // YAML payload files
			"*.json",           // JSON payload files
			"*.txt",            // Text payload files
			"*.payload",        // Custom payload extension
			"*.md",             // Markdown files (may contain payloads)
			"*.py",             // Python scripts
			"*.js",             // JavaScript files
			"*.sql",            // SQL queries
		},
	}

	// Configuration for specific payload types only
	restrictedConfig := PayloadSyncConfig{
		BatchSize: 25, // Smaller batches for careful processing
		DiscoveryPaths: []string{
			"injection/*.txt",     // Only injection payloads
			"jailbreak/*.yaml",    // Only jailbreak payloads
			"adversarial/*.json",  // Only adversarial payloads
		},
	}

	log.Printf("Basic config: %+v", basicConfig)
	log.Printf("Advanced config: %+v", advancedConfig)
	log.Printf("Restricted config: %+v", restrictedConfig)
}