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
	helpTopicFlag      *string
	helpInteractiveFlag *bool
	helpFormatFlag     *string
	helpSearchFlag     *string
	helpVerboseFlag    *bool
)

// helpCmd creates the help command following k9s patterns
func helpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "help [topic]",
		Aliases: []string{"docs", "manual", "guide"},
		Short:   "Enhanced help system for Gibson",
		Long: `Enhanced help system providing comprehensive documentation, examples,
and interactive help for Gibson AI/ML security testing framework.

The help system provides:
  • Interactive help browser with navigation
  • Topic-based documentation with examples
  • API reference and usage patterns
  • Quick start guides and tutorials
  • Search functionality across all help content

You can browse help topics interactively or get specific help on topics.`,
		RunE: runHelp,
		Example: `  # Show interactive help browser
  gibson help

  # Get help on specific topic
  gibson help scanning

  # Search help content
  gibson help --search "plugins"

  # Show help in JSON format
  gibson help --format json

  # Get verbose help with examples
  gibson help --verbose

  # Interactive help browser
  gibson help --interactive

  # Help on specific command
  gibson help scan
  gibson help target`,
	}

	// Add flags following k9s pointer patterns
	helpTopicFlag = cmd.Flags().StringP("topic", "t", "", "Specific help topic to display")
	helpInteractiveFlag = cmd.Flags().BoolP("interactive", "i", false, "Start interactive help browser")
	helpFormatFlag = cmd.Flags().StringP("format", "f", "text", "Output format (text, json, yaml)")
	helpSearchFlag = cmd.Flags().StringP("search", "s", "", "Search help content")
	helpVerboseFlag = cmd.Flags().BoolP("verbose", "v", false, "Show detailed help with examples")

	return cmd
}

// runHelp implements the help command
func runHelp(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Determine the topic from args or flag
	topic := getValue(helpTopicFlag)
	if len(args) > 0 {
		topic = args[0]
	}

	// Operation completed - silent logging

	// Create a help view
	helpView := view.NewHelpView()
	if helpView == nil {
		return fmt.Errorf("failed to create help view")
	}

	// Show help through the view layer
	return helpView.ShowHelp(ctx, view.HelpOptions{
		Topic:       topic,
		Interactive: getBoolValue(helpInteractiveFlag),
		Format:      getValue(helpFormatFlag),
		Search:      getValue(helpSearchFlag),
		Verbose:     getBoolValue(helpVerboseFlag),
	})
}