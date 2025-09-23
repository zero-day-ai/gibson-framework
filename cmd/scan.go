// SPDX-License-Identifier: MIT
// Copyright Authors of Gibson

package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/gibson-sec/gibson-framework-2/internal/view"
	"github.com/spf13/cobra"
)

var (
	scanTargetFlag  *string
	scanTypeFlag    *string
	scanOutputFlag  *string
	scanIDFlag      *string
	scanAllFlag     *bool
	scanPluginsFlag *string
	scanVerboseFlag *bool
)

// scanCmd creates the scan command following k9s patterns
func scanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "scan",
		Aliases: []string{"s"},
		Short:   "Manage security scans",
		Long:    "Start, stop, list, and manage AI/ML security scans",
	}

	// Add subcommands
	cmd.AddCommand(
		scanStartCmd(),
		scanStopCmd(),
		scanListCmd(),
		scanStatusCmd(),
		scanDeleteCmd(),
		scanResultsCmd(),
		scanBatchCmd(),
	)

	return cmd
}

// scanStartCmd starts a new security scan
func scanStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "start [TARGET]",
		Aliases: []string{"begin", "run"},
		Short:   "Start a new security scan",
		Long:    "Start a new security scan against the specified target with optional scan type and plugins",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runScanStart,
		Example: `  # Start a scan against a target
  gibson scan start my-target

  # Start a specific type of scan
  gibson scan start my-target --type injection

  # Start scan with specific plugins
  gibson scan start my-target --plugins "sql-injection,xss"

  # Start scan with JSON output
  gibson scan start my-target --output json`,
	}

	// Add flags following k9s pointer patterns
	scanTargetFlag = cmd.Flags().StringP("target", "t", "", "Target to scan (if not provided as argument)")
	scanTypeFlag = cmd.Flags().String("type", "", "Type of scan to perform (injection, model, infrastructure)")
	scanOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	scanPluginsFlag = cmd.Flags().String("plugins", "", "Comma-separated list of plugins to use")
	scanVerboseFlag = cmd.Flags().BoolP("verbose", "v", false, "Enable verbose output showing API requests and responses")

	return cmd
}

// scanStopCmd stops a running scan
func scanStopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "stop [SCAN_ID]",
		Aliases: []string{"terminate", "kill"},
		Short:   "Stop a running scan",
		Long:    "Stop a running security scan by its ID",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runScanStop,
		Example: `  # Stop a specific scan
  gibson scan stop scan-123

  # Stop all running scans
  gibson scan stop --all`,
	}

	scanIDFlag = cmd.Flags().String("id", "", "Scan ID to stop (if not provided as argument)")
	scanAllFlag = cmd.Flags().BoolP("all", "a", false, "Stop all running scans")

	return cmd
}

// scanListCmd lists scans
func scanListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "get"},
		Short:   "List security scans",
		Long:    "List all security scans with their status and details",
		RunE:    runScanList,
		Example: `  # List all scans
  gibson scan list

  # List scans in JSON format
  gibson scan list --output json

  # List only running scans
  gibson scan list --status running`,
	}

	scanOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().String("status", "", "Filter by scan status (running, completed, failed)")

	return cmd
}

// scanStatusCmd shows detailed scan status
func scanStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "status [SCAN_ID]",
		Aliases: []string{"info", "describe"},
		Short:   "Show detailed scan status",
		Long:    "Show detailed status and progress information for a specific scan",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runScanStatus,
		Example: `  # Show status of a specific scan
  gibson scan status scan-123

  # Show status with JSON output
  gibson scan status scan-123 --output json`,
	}

	scanIDFlag = cmd.Flags().String("id", "", "Scan ID to show status for (if not provided as argument)")
	scanOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// scanDeleteCmd deletes completed scans
func scanDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete [SCAN_ID]",
		Aliases: []string{"del", "rm"},
		Short:   "Delete completed scans",
		Long:    "Delete completed or failed scans and their results",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runScanDelete,
		Example: `  # Delete a specific scan
  gibson scan delete scan-123

  # Delete all completed scans
  gibson scan delete --all --status completed`,
	}

	scanIDFlag = cmd.Flags().String("id", "", "Scan ID to delete (if not provided as argument)")
	scanAllFlag = cmd.Flags().BoolP("all", "a", false, "Delete all scans matching criteria")
	cmd.Flags().String("status", "", "Filter by scan status when deleting")

	return cmd
}

// scanResultsCmd shows detailed scan results
func scanResultsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "results [SCAN_ID]",
		Aliases: []string{"res", "findings"},
		Short:   "View detailed scan results",
		Long:    "View detailed scan results with findings organized by severity, support for filtering and export formats",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runScanResults,
		Example: `  # View results for a specific scan
  gibson scan results scan-123

  # View results with severity filtering
  gibson scan results scan-123 --severity high,critical

  # View results in JSON format
  gibson scan results scan-123 --output json

  # Export results to file
  gibson scan results scan-123 --export results.json

  # View results with detailed findings
  gibson scan results scan-123 --detailed`,
	}

	scanIDFlag = cmd.Flags().String("id", "", "Scan ID to show results for (if not provided as argument)")
	scanOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().String("severity", "", "Filter by finding severity (critical, high, medium, low)")
	cmd.Flags().String("category", "", "Filter by finding category (injection, model, infrastructure)")
	cmd.Flags().String("export", "", "Export results to file")
	cmd.Flags().BoolP("detailed", "d", false, "Show detailed finding information")
	cmd.Flags().BoolP("summary", "s", false, "Show only summary statistics")

	return cmd
}

// scanBatchCmd runs multiple scans in parallel
func scanBatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "batch [TARGETS...]",
		Aliases: []string{"multi", "parallel"},
		Short:   "Run batch scanning functionality",
		Long:    "Run multiple scans in parallel with progress tracking and result aggregation",
		Args:    cobra.MinimumNArgs(0),
		RunE:    runScanBatch,
		Example: `  # Run batch scan on multiple targets
  gibson scan batch target1 target2 target3

  # Run batch scan from file
  gibson scan batch --file targets.txt

  # Run batch scan with specific type
  gibson scan batch --targets "target1,target2" --type injection

  # Run with limited concurrency
  gibson scan batch target1 target2 --workers 2

  # Show progress during batch scanning
  gibson scan batch target1 target2 --progress`,
	}

	cmd.Flags().String("file", "", "File containing list of targets (one per line)")
	cmd.Flags().String("targets", "", "Comma-separated list of targets")
	scanTypeFlag = cmd.Flags().String("type", "", "Type of scan to perform on all targets")
	scanPluginsFlag = cmd.Flags().String("plugins", "", "Plugins to use for all targets")
	scanOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().IntP("workers", "w", 3, "Number of concurrent scans")
	cmd.Flags().BoolP("progress", "p", false, "Show progress during scanning")
	cmd.Flags().BoolP("aggregate", "a", false, "Aggregate results into single report")
	cmd.Flags().String("export", "", "Export aggregated results to file")

	return cmd
}

// runScanStart implements the scan start command
func runScanStart(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get target from positional argument or flag
	target := getValue(scanTargetFlag)
	if len(args) > 0 {
		target = args[0]
	}

	// Operation completed - silent logging

	// Create scan view controller
	scanView, err := view.NewScanView()
	if err != nil {
		return fmt.Errorf("failed to create scan view: %w", err)
	}

	// Start the scan through the view layer
	return scanView.StartScan(ctx, view.ScanStartOptions{
		Target:  target,
		Type:    getValue(scanTypeFlag),
		Plugins: getValue(scanPluginsFlag),
		Output:  getValue(scanOutputFlag),
		Verbose: *scanVerboseFlag,
	})
}

// runScanStop implements the scan stop command
func runScanStop(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get scan ID from positional argument or flag
	scanID := getValue(scanIDFlag)
	if len(args) > 0 {
		scanID = args[0]
	}

	// Operation completed - silent logging

	// Create scan view controller
	scanView, err := view.NewScanView()
	if err != nil {
		return fmt.Errorf("failed to create scan view: %w", err)
	}

	// Stop the scan through the view layer
	return scanView.StopScan(ctx, view.ScanStopOptions{
		ID:  scanID,
		All: getBoolValue(scanAllFlag),
	})
}

// runScanList implements the scan list command
func runScanList(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create scan view controller
	scanView, err := view.NewScanView()
	if err != nil {
		return fmt.Errorf("failed to create scan view: %w", err)
	}

	// List scans through the view layer
	return scanView.ListScans(ctx, view.ScanListOptions{
		Output: getValue(scanOutputFlag),
	})
}

// runScanStatus implements the scan status command
func runScanStatus(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create scan view controller
	scanView, err := view.NewScanView()
	if err != nil {
		return fmt.Errorf("failed to create scan view: %w", err)
	}

	// Get scan status through the view layer
	return scanView.GetScanStatus(ctx, view.ScanStatusOptions{
		ID:     getValue(scanIDFlag),
		Output: getValue(scanOutputFlag),
	})
}

// runScanDelete implements the scan delete command
func runScanDelete(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get scan ID from positional argument or flag
	scanID, _ := cmd.Flags().GetString("id")
	if len(args) > 0 {
		scanID = args[0]
	}

	all, _ := cmd.Flags().GetBool("all")

	// Validate that we have either scan ID or --all flag
	if scanID == "" && !all {
		return fmt.Errorf("either scan ID or --all flag must be specified")
	}

	// Operation completed - silent logging

	// Create scan view controller
	scanView, err := view.NewScanView()
	if err != nil {
		return fmt.Errorf("failed to create scan view: %w", err)
	}

	// Delete scan through the view layer
	return scanView.DeleteScan(ctx, view.ScanDeleteOptions{
		ID:  scanID,
		All: all,
	})
}

// runScanResults implements the scan results command
func runScanResults(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get scan ID from positional argument or flag
	scanID := getValue(scanIDFlag)
	if len(args) > 0 {
		scanID = args[0]
	}

	if scanID == "" {
		return fmt.Errorf("scan ID is required")
	}

	severity, _ := cmd.Flags().GetString("severity")
	category, _ := cmd.Flags().GetString("category")
	exportFile, _ := cmd.Flags().GetString("export")
	detailed, _ := cmd.Flags().GetBool("detailed")
	summary, _ := cmd.Flags().GetBool("summary")

	// Operation completed - silent logging

	// Create scan view controller
	scanView, err := view.NewScanView()
	if err != nil {
		return fmt.Errorf("failed to create scan view: %w", err)
	}

	// Get scan results through the view layer
	return scanView.GetScanResults(ctx, view.ScanResultsOptions{
		ID:         scanID,
		Output:     getValue(scanOutputFlag),
		Severity:   severity,
		Category:   category,
		ExportFile: exportFile,
		Detailed:   detailed,
		Summary:    summary,
	})
}

// runScanBatch implements the scan batch command
func runScanBatch(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Collect targets from various sources
	var targets []string

	// From positional arguments
	targets = append(targets, args...)

	// From --targets flag (comma-separated)
	targetsFlag, _ := cmd.Flags().GetString("targets")
	if targetsFlag != "" {
		targets = append(targets, parseCommaSeparated(targetsFlag)...)
	}

	// From file
	targetFile, _ := cmd.Flags().GetString("file")
	if targetFile != "" {
		fileTargets, err := loadTargetsFromFile(targetFile)
		if err != nil {
			return fmt.Errorf("failed to load targets from file: %w", err)
		}
		targets = append(targets, fileTargets...)
	}

	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	workers, _ := cmd.Flags().GetInt("workers")
	progress, _ := cmd.Flags().GetBool("progress")
	aggregate, _ := cmd.Flags().GetBool("aggregate")
	exportFile, _ := cmd.Flags().GetString("export")

	// Operation completed - silent logging

	// Create scan view controller
	scanView, err := view.NewScanView()
	if err != nil {
		return fmt.Errorf("failed to create scan view: %w", err)
	}

	// Run batch scan through the view layer
	return scanView.RunBatchScan(ctx, view.ScanBatchOptions{
		Targets:    targets,
		Type:       getValue(scanTypeFlag),
		Plugins:    getValue(scanPluginsFlag),
		Output:     getValue(scanOutputFlag),
		Workers:    workers,
		Progress:   progress,
		Aggregate:  aggregate,
		ExportFile: exportFile,
	})
}

// parseCommaSeparated splits a comma-separated string into slice
func parseCommaSeparated(input string) []string {
	if input == "" {
		return nil
	}
	var result []string
	for _, item := range strings.Split(input, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// loadTargetsFromFile loads target list from a file (one per line)
func loadTargetsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open targets file: %w", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Validate target name
		if len(line) > 255 {
			return nil, fmt.Errorf("target name on line %d exceeds maximum length of 255 characters", lineNum)
		}

		targets = append(targets, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading targets file: %w", err)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets found in file %s", filename)
	}

	return targets, nil
}

// getValue safely gets the value from a string pointer
func getValue(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}

// getBoolValue safely gets the value from a bool pointer
func getBoolValue(ptr *bool) bool {
	if ptr == nil {
		return false
	}
	return *ptr
}