// SPDX-License-Identifier: MIT
// Copyright Authors of Gibson

package cmd

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson-framework/internal/view"
	"github.com/spf13/cobra"
)

var (
	consolePromptFlag    *string
	consoleHistoryFlag   *bool
	consoleBatchFlag     *string
	consoleTimeoutFlag   *int
	consoleReadOnlyFlag  *bool
)

// consoleCmd creates the console command following k9s patterns
func consoleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "console",
		Aliases: []string{"repl", "shell", "interactive"},
		Short:   "Start Gibson interactive console",
		Long: `Start an interactive REPL (Read-Eval-Print Loop) console for Gibson.
The console provides an interactive environment to execute Gibson commands
with features like command history, tab completion, and context persistence.

The console supports all Gibson commands and provides additional interactive
features like command history navigation and auto-completion.`,
		RunE: runConsole,
		Example: `  # Start interactive console
  gibson console

  # Start console with custom prompt
  gibson console --prompt "gibson> "

  # Start console without history
  gibson console --no-history

  # Run batch commands from file
  gibson console --batch commands.txt

  # Start console in read-only mode
  gibson console --readonly

  # Start console with custom timeout
  gibson console --timeout 300`,
	}

	// Add flags following k9s pointer patterns
	consolePromptFlag = cmd.Flags().StringP("prompt", "p", "gibson> ", "Custom prompt for the console")
	consoleHistoryFlag = cmd.Flags().BoolP("history", "H", true, "Enable command history (default: true)")
	consoleBatchFlag = cmd.Flags().StringP("batch", "b", "", "Execute commands from file")
	consoleTimeoutFlag = cmd.Flags().IntP("timeout", "t", 0, "Session timeout in seconds (0 = no timeout)")
	consoleReadOnlyFlag = cmd.Flags().Bool("readonly", false, "Start console in read-only mode")

	// Make --no-history work as expected
	cmd.Flags().BoolP("no-history", "", false, "Disable command history")
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if noHistory, _ := cmd.Flags().GetBool("no-history"); noHistory {
			*consoleHistoryFlag = false
		}
		return nil
	}

	return cmd
}

// runConsole implements the console command
func runConsole(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create a console view
	consoleView := view.NewConsoleView()
	if consoleView == nil {
		return fmt.Errorf("failed to create console view")
	}

	// Start the interactive console through the view layer
	return consoleView.StartConsole(ctx, view.ConsoleOptions{
		Prompt:    getValue(consolePromptFlag),
		History:   getBoolValue(consoleHistoryFlag),
		BatchFile: getValue(consoleBatchFlag),
		Timeout:   getIntValue(consoleTimeoutFlag),
		ReadOnly:  getBoolValue(consoleReadOnlyFlag),
	})
}