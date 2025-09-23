// +build ignore

// This is a demonstration program showing the disk space health check functionality.
// Build and run with: go run cmd/examples/disk_health_demo.go

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/health"
)

func main() {
	fmt.Println("Gibson Framework - Disk Space Health Check Demo")
	fmt.Println(strings.Repeat("=", 50))

	// Get Gibson home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get user home directory: %v", err)
	}
	gibsonDir := filepath.Join(homeDir, ".gibson")

	// Create health checker
	healthChecker := health.NewHealthChecker("demo-v1.0.0")

	// Register disk space health check for Gibson directory
	healthChecker.RegisterCheck("gibson_disk_space",
		health.DiskSpaceHealthCheck(gibsonDir, 5)) // 5GB minimum free space

	// Also check the current working directory
	cwd, _ := os.Getwd()
	healthChecker.RegisterCheck("current_dir_disk_space",
		health.DiskSpaceHealthCheck(cwd, 1)) // 1GB minimum free space

	// Run health checks
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("Running health checks...")
	result := healthChecker.CheckHealth(ctx)

	// Display results
	fmt.Printf("\nOverall Status: %s\n", result.Status)
	fmt.Printf("Timestamp: %s\n", result.Timestamp.Format(time.RFC3339))
	fmt.Printf("Version: %s\n", result.Version)
	fmt.Printf("Uptime: %s\n", result.Uptime)

	fmt.Println("\nHealth Check Details:")
	fmt.Println(strings.Repeat("-", 80))

	for checkName, check := range result.Checks {
		fmt.Printf("\n[%s] %s\n", checkName, check.Status)
		fmt.Printf("Message: %s\n", check.Message)
		if check.Error != "" {
			fmt.Printf("Error: %s\n", check.Error)
		}
		fmt.Printf("Duration: %s\n", check.Duration)

		// Display disk space details in a readable format
		if check.Details != nil {
			fmt.Println("Details:")
			if path, ok := check.Details["path"].(string); ok {
				fmt.Printf("  Path: %s\n", path)
			}
			if totalFormatted, ok := check.Details["total_formatted"].(string); ok {
				fmt.Printf("  Total Space: %s\n", totalFormatted)
			}
			if usedFormatted, ok := check.Details["used_formatted"].(string); ok {
				fmt.Printf("  Used Space: %s\n", usedFormatted)
			}
			if freeFormatted, ok := check.Details["free_formatted"].(string); ok {
				fmt.Printf("  Free Space: %s\n", freeFormatted)
			}
			if usedPercent, ok := check.Details["used_percent"].(float64); ok {
				fmt.Printf("  Usage: %.1f%%\n", usedPercent)
			}
			if minFreeGB, ok := check.Details["min_free_gb"].(uint64); ok && minFreeGB > 0 {
				fmt.Printf("  Minimum Required: %dGB\n", minFreeGB)
			}
		}
		fmt.Println(strings.Repeat("-", 40))
	}

	// Also show JSON output for API usage
	fmt.Println("\nJSON Output (for API integration):")
	fmt.Println(strings.Repeat("=", 50))

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal JSON: %v", err)
	} else {
		fmt.Println(string(jsonData))
	}

	// Demonstrate threshold behavior
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("Threshold Information:")
	fmt.Println("• 0-79% usage: ✅ Healthy")
	fmt.Println("• 80-89% usage: ⚠️  Degraded (Warning)")
	fmt.Println("• 90%+ usage: ❌ Unhealthy (Critical)")
	fmt.Println("\nNote: Additional checks are performed against minimum free space requirements.")
}