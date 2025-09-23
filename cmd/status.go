// SPDX-License-Identifier: MIT
// Copyright Authors of Gibson

package cmd

import (
	"context"
	"fmt"

	"github.com/gibson-sec/gibson-framework-2/internal/view"
	"github.com/spf13/cobra"
)

var (
	statusOutputFlag    *string
	statusVerboseFlag   *bool
	statusWatchFlag     *bool
	statusRefreshFlag   *int
	statusComponentFlag *string
)

// statusCmd creates the status command following k9s patterns
func statusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "status",
		Aliases: []string{"stat", "info"},
		Short:   "Show Gibson system status",
		Long:    "Display comprehensive status information for Gibson including active scans, targets, plugins, and system health",
		RunE:    runStatus,
		Example: `  # Show general system status
  gibson status

  # Show status with detailed information
  gibson status --verbose

  # Show status in JSON format
  gibson status --output json

  # Watch status with live updates
  gibson status --watch

  # Show status for specific component
  gibson status --component scans

  # Show status with custom refresh rate
  gibson status --watch --refresh 5`,
	}

	// Add flags following k9s pointer patterns
	statusOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	statusVerboseFlag = cmd.Flags().BoolP("verbose", "v", false, "Show detailed status information")
	statusWatchFlag = cmd.Flags().BoolP("watch", "w", false, "Watch status with live updates")
	statusRefreshFlag = cmd.Flags().IntP("refresh", "r", 2, "Refresh interval in seconds for watch mode")
	statusComponentFlag = cmd.Flags().StringP("component", "c", "", "Show status for specific component (scans, targets, plugins, system)")

	return cmd
}

// runStatus implements the status command
func runStatus(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create a generic status view
	statusView, err := view.NewGenericView()
	if err != nil {
		return fmt.Errorf("failed to create status view: %w", err)
	}

	// Get system status through the view layer
	return statusView.ShowSystemStatus(ctx, view.SystemStatusOptions{
		Output:    getValue(statusOutputFlag),
		Verbose:   getBoolValue(statusVerboseFlag),
		Watch:     getBoolValue(statusWatchFlag),
		Refresh:   getIntValue(statusRefreshFlag),
		Component: getValue(statusComponentFlag),
	})
}

// getIntValue safely gets the value from an int pointer
func getIntValue(ptr *int) int {
	if ptr == nil {
		return 0
	}
	return *ptr
}

