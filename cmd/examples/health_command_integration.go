// +build ignore

// Example of how to integrate disk space monitoring into a Gibson CLI command
// This shows integration patterns for the health system

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/health"
	"github.com/spf13/cobra"
)

// Example CLI command that integrates health checking
func newHealthCommand() *cobra.Command {
	var (
		outputFormat string
		gibsonPath   string
		minFreeGB    uint64
		timeout      time.Duration
	)

	cmd := &cobra.Command{
		Use:   "health",
		Short: "Check Gibson framework health including disk space",
		Long: `Performs comprehensive health checks including:
- Disk space monitoring for Gibson directory
- Memory usage analysis
- System metrics collection
- Threshold-based alerting`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHealthCheck(cmd.Context(), healthCheckConfig{
				OutputFormat: outputFormat,
				GibsonPath:   gibsonPath,
				MinFreeGB:    minFreeGB,
				Timeout:      timeout,
			})
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table",
		"Output format: table, json, yaml")
	cmd.Flags().StringVar(&gibsonPath, "path", "",
		"Path to check disk space (default: ~/.gibson)")
	cmd.Flags().Uint64Var(&minFreeGB, "min-free", 5,
		"Minimum free disk space in GB")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second,
		"Timeout for health checks")

	return cmd
}

type healthCheckConfig struct {
	OutputFormat string
	GibsonPath   string
	MinFreeGB    uint64
	Timeout      time.Duration
}

func runHealthCheck(ctx context.Context, config healthCheckConfig) error {
	// Create health checker
	checker := health.NewHealthChecker("gibson-v2.0.0")

	// Resolve Gibson path
	checkPath := config.GibsonPath
	if checkPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		checkPath = filepath.Join(homeDir, ".gibson")
	}

	// Register disk space check
	checker.RegisterCheck("disk_space",
		health.DiskSpaceHealthCheck(checkPath, config.MinFreeGB))

	// Register memory check (example with 512MB limit)
	checker.RegisterCheck("memory",
		health.MemoryHealthCheck(512))

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	// Run health checks
	result := checker.CheckHealth(timeoutCtx)

	// Output results based on format
	switch config.OutputFormat {
	case "json":
		return outputJSON(result)
	case "yaml":
		return outputYAML(result)
	default:
		return outputTable(result)
	}
}

func outputJSON(result *health.HealthResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputYAML(result *health.HealthResult) error {
	// In a real implementation, you'd use a YAML library like gopkg.in/yaml.v3
	fmt.Println("# YAML output would be implemented with yaml library")
	return outputJSON(result) // Fallback to JSON for demo
}

func outputTable(result *health.HealthResult) error {
	fmt.Printf("Gibson Framework Health Check\n")
	fmt.Printf("Status: %s\n", result.Status)
	fmt.Printf("Timestamp: %s\n", result.Timestamp.Format(time.RFC3339))
	fmt.Printf("Version: %s\n", result.Version)
	fmt.Printf("Uptime: %s\n\n", result.Uptime)

	if len(result.Checks) == 0 {
		fmt.Println("No health checks registered")
		return nil
	}

	// Table header
	fmt.Printf("%-20s %-12s %-10s %s\n", "CHECK", "STATUS", "DURATION", "MESSAGE")
	fmt.Printf("%s\n", "-------------------------------------------------------------")

	// Health check results
	for name, check := range result.Checks {
		statusIcon := getStatusIcon(check.Status)
		fmt.Printf("%-20s %s%-10s %-10s %s\n",
			name, statusIcon, check.Status, check.Duration, check.Message)

		// Show disk space details if available
		if name == "disk_space" && check.Details != nil {
			if usage, ok := check.Details["used_percent"].(float64); ok {
				fmt.Printf("%20s Usage: %.1f%%", "", usage)
				if total, ok := check.Details["total_formatted"].(string); ok {
					fmt.Printf(" (%s total)", total)
				}
				fmt.Println()
			}
		}
	}

	// Return error code based on status
	if result.Status == health.StatusUnhealthy {
		os.Exit(1)
	} else if result.Status == health.StatusDegraded {
		os.Exit(2)
	}

	return nil
}

func getStatusIcon(status health.Status) string {
	switch status {
	case health.StatusHealthy:
		return "✅ "
	case health.StatusDegraded:
		return "⚠️  "
	case health.StatusUnhealthy:
		return "❌ "
	default:
		return "❓ "
	}
}

// Example of how to use this in main
func main() {
	cmd := newHealthCommand()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Example of additional health checks you might want to add:

// Database connectivity health check
func registerDatabaseCheck(checker *health.HealthChecker, db interface{}) {
	// Implementation would depend on your database layer
	// checker.RegisterCheck("database", health.DatabaseHealthCheck(db))
}

// Plugin system health check
func registerPluginChecks(checker *health.HealthChecker) {
	// Example: Check if core plugins are loaded and healthy
	// checker.RegisterCheck("plugins", health.PluginHealthCheck("core_plugins", pluginHealthFunc))
}

// Network connectivity check
func registerNetworkChecks(checker *health.HealthChecker) {
	// Example: Check external dependencies
	// checker.RegisterCheck("api_connectivity",
	//     health.HTTPEndpointHealthCheck("external_api", "https://api.example.com/health", 5*time.Second))
}