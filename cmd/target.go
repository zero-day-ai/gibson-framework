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
	targetNameFlag     *string
	targetProviderFlag *string
	targetModelFlag    *string
	targetURLFlag      *string
	targetIDFlag       *string
	targetOutputFlag   *string
	targetConfigFlag   *string
	targetAPIKeyFlag   *string
	targetAllFlag      *bool
	targetForceFlag    *bool
)

// targetCmd creates the target command following k9s patterns
func targetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "target",
		Aliases: []string{"t", "targets"},
		Short:   "Manage AI/ML targets",
		Long:    "Add, list, delete, and test AI/ML targets for security scanning",
	}

	// Add subcommands
	cmd.AddCommand(
		targetAddCmd(),
		targetListCmd(),
		targetDeleteCmd(),
		targetTestCmd(),
		targetUpdateCmd(),
		targetInfoCmd(),
		targetGetCmd(),
	)

	return cmd
}

// targetAddCmd adds a new target
func targetAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "add [NAME]",
		Aliases: []string{"create", "new"},
		Short:   "Add a new AI/ML target",
		Long:    "Add a new AI/ML target for security scanning with specified provider and configuration",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runTargetAdd(c, args)
		},
		Example: `  # Add an OpenAI target with API key
  gibson target add openai-gpt4 --provider openai --model gpt-4 --api-key $OPENAI_API_KEY

  # Add an Anthropic target with credential reference
  gibson target add claude-sonnet --provider anthropic --model claude-3-sonnet --credential anthropic-api-key

  # Add target using credential ID
  gibson target add claude-opus --provider anthropic --model claude-3-opus --credential 123e4567-e89b-12d3-a456-426614174000

  # Add a custom API target
  gibson target add custom-api --provider custom --url https://api.example.com/v1/chat --credential custom-cred

  # Add target with config file
  gibson target add my-target --config ./target-config.yaml`,
	}

	// Add flags following k9s pointer patterns
	cmd.Flags().StringP("name", "n", "", "Target name (if not provided as argument)")
	cmd.Flags().StringP("provider", "p", "", "AI provider (openai, anthropic, huggingface, custom)")
	cmd.Flags().StringP("model", "m", "", "Model name or ID")
	cmd.Flags().StringP("url", "u", "", "API endpoint URL (for custom providers)")
	cmd.Flags().StringP("api-key", "k", "", "API key for authentication")
	cmd.Flags().StringP("credential", "r", "", "Credential name or ID to link to this target")
	cmd.Flags().StringP("config", "c", "", "Configuration file path")
	cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	// Add validation help
	cmd.SetUsageTemplate(cmd.UsageTemplate() + `
Validation Requirements:
  • Anthropic targets: requires --provider anthropic and either --api-key or --credential
  • OpenAI targets: requires --provider openai and either --api-key or --credential
  • Azure targets: requires --provider azure, --url, and either --api-key or --credential
  • Custom targets: requires --provider, --url, and either --api-key or --credential

Credential Options:
  • Use --credential with credential name: --credential "my-anthropic-key"
  • Use --credential with credential ID: --credential "123e4567-e89b-12d3-a456-426614174000"
  • Use --api-key with raw API key: --api-key "$ANTHROPIC_API_KEY"

Create credentials first: gibson credential add <name> --provider <provider> --value <api-key>
`)

	return cmd
}

// targetListCmd lists targets
func targetListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List AI/ML targets",
		Long:    "List all configured AI/ML targets with their details and status",
		RunE:    runTargetList,
		Example: `  # List all targets
  gibson target list

  # List targets in JSON format
  gibson target list --output json

  # List only active targets
  gibson target list --status active`,
	}

	targetOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().String("provider", "", "Filter by provider")
	cmd.Flags().String("status", "", "Filter by status (active, inactive, error)")

	return cmd
}

// targetDeleteCmd deletes targets
func targetDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete [NAME]",
		Aliases: []string{"del", "rm"},
		Short:   "Delete AI/ML targets",
		Long:    "Delete one or more AI/ML targets by name or ID",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runTargetDelete,
		Example: `  # Delete a specific target
  gibson target delete my-target

  # Delete target by ID
  gibson target delete --id target-123

  # Delete all inactive targets
  gibson target delete --all --status inactive`,
	}

	targetNameFlag = cmd.Flags().StringP("name", "n", "", "Target name (if not provided as argument)")
	targetIDFlag = cmd.Flags().String("id", "", "Target ID to delete")
	targetAllFlag = cmd.Flags().BoolP("all", "a", false, "Delete all targets matching criteria")
	cmd.Flags().String("status", "", "Filter by status when deleting")
	targetForceFlag = cmd.Flags().BoolP("force", "f", false, "Force deletion without confirmation")

	return cmd
}

// targetTestCmd tests target connectivity
func targetTestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "test [NAME]",
		Aliases: []string{"check", "validate"},
		Short:   "Test AI/ML target connectivity",
		Long:    "Test connectivity and authentication for AI/ML targets",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runTargetTest,
		Example: `  # Test a specific target
  gibson target test my-target

  # Test target by ID
  gibson target test --id target-123

  # Test all targets
  gibson target test --all

  # Test with verbose output
  gibson target test my-target --verbose`,
	}

	targetNameFlag = cmd.Flags().StringP("name", "n", "", "Target name (if not provided as argument)")
	targetIDFlag = cmd.Flags().String("id", "", "Target ID to test")
	cmd.Flags().BoolP("all", "a", false, "Test all targets")
	cmd.Flags().BoolP("verbose", "v", false, "Show detailed test results")
	targetOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// targetUpdateCmd updates target configuration
func targetUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "update [NAME]",
		Aliases: []string{"edit", "modify"},
		Short:   "Update AI/ML target configuration",
		Long:    "Update configuration for an existing AI/ML target with validation and verification",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runTargetUpdate,
		Example: `  # Update target model
  gibson target update my-target --model gpt-4-turbo

  # Update API key
  gibson target update my-target --api-key $NEW_API_KEY

  # Update multiple fields
  gibson target update my-target --model claude-3-opus --url https://new-api.example.com

  # Update with custom headers
  gibson target update my-target --headers "Authorization=Bearer token,Content-Type=application/json"

  # Update from configuration file
  gibson target update my-target --config ./updated-config.yaml

  # Update with validation
  gibson target update my-target --model gpt-4 --validate

  # Update and test connection
  gibson target update my-target --url https://new-endpoint.com --test-connection`,
	}

	targetNameFlag = cmd.Flags().StringP("name", "n", "", "Target name (if not provided as argument)")
	targetIDFlag = cmd.Flags().String("id", "", "Target ID to update")
	targetProviderFlag = cmd.Flags().StringP("provider", "p", "", "Update AI provider")
	targetModelFlag = cmd.Flags().StringP("model", "m", "", "Update model name or ID")
	targetURLFlag = cmd.Flags().StringP("url", "u", "", "Update API endpoint URL")
	targetAPIKeyFlag = cmd.Flags().StringP("api-key", "k", "", "Update API key")
	targetConfigFlag = cmd.Flags().StringP("config", "c", "", "Update from configuration file")
	targetOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().String("headers", "", "Custom HTTP headers (comma-separated key=value pairs)")
	cmd.Flags().String("description", "", "Update target description")
	cmd.Flags().StringSlice("tags", []string{}, "Update target tags")
	cmd.Flags().BoolP("validate", "v", false, "Validate configuration before updating")
	cmd.Flags().Bool("test-connection", false, "Test connection after update")
	cmd.Flags().BoolP("force", "f", false, "Force update without confirmation")

	return cmd
}

// targetInfoCmd shows detailed target information
func targetInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "info [NAME]",
		Aliases: []string{"describe", "show"},
		Short:   "Show detailed target information",
		Long:    "Show detailed information and configuration for a specific AI/ML target",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runTargetInfo,
		Example: `  # Show target information
  gibson target info my-target

  # Show target info by ID
  gibson target info --id target-123

  # Show info with JSON output
  gibson target info my-target --output json`,
	}

	targetNameFlag = cmd.Flags().StringP("name", "n", "", "Target name (if not provided as argument)")
	targetIDFlag = cmd.Flags().String("id", "", "Target ID to show info for")
	targetOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// targetGetCmd gets specific target details
func targetGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "get [NAME]",
		Aliases: []string{"show", "view"},
		Short:   "Get specific target details",
		Long:    "Get specific target details with configuration and scan history, including connection status and recent activity",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runTargetGet,
		Example: `  # Get target details
  gibson target get my-target

  # Get target by ID
  gibson target get --id target-123

  # Get target with scan history
  gibson target get my-target --history

  # Get target configuration only
  gibson target get my-target --config-only

  # Get target with JSON output
  gibson target get my-target --output json`,
	}

	targetNameFlag = cmd.Flags().StringP("name", "n", "", "Target name (if not provided as argument)")
	targetIDFlag = cmd.Flags().String("id", "", "Target ID to get details for")
	targetOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().Bool("history", false, "Include scan history")
	cmd.Flags().Bool("config-only", false, "Show only configuration details")
	cmd.Flags().Bool("status", false, "Include connection status check")

	return cmd
}

// runTargetAdd implements the target add command
func runTargetAdd(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get target name from positional argument or flag
	name, _ := cmd.Flags().GetString("name")
	if len(args) > 0 {
		name = args[0]
	}

	provider, _ := cmd.Flags().GetString("provider")
	model, _ := cmd.Flags().GetString("model")
	url, _ := cmd.Flags().GetString("url")
	apiKey, _ := cmd.Flags().GetString("api-key")
	credential, _ := cmd.Flags().GetString("credential")
	config, _ := cmd.Flags().GetString("config")
	output, _ := cmd.Flags().GetString("output")

	// Use credential flag if provided, otherwise fall back to api-key
	if credential != "" {
		apiKey = credential
	}

	// Operation completed - silent logging

	// Create target view controller
	targetView, err := view.NewTargetView()
	if err != nil {
		return fmt.Errorf("failed to create target view: %w", err)
	}

	// Add target through the view layer
	return targetView.AddTarget(ctx, view.TargetAddOptions{
		Name:     name,
		Provider: provider,
		Model:    model,
		URL:      url,
		APIKey:   apiKey,
		Config:   config,
		Output:   output,
	})
}

// runTargetList implements the target list command
func runTargetList(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create target view controller
	targetView, err := view.NewTargetView()
	if err != nil {
		return fmt.Errorf("failed to create target view: %w", err)
	}

	// List targets through the view layer
	return targetView.ListTargets(ctx, view.TargetListOptions{
		Output: getValue(targetOutputFlag),
	})
}

// runTargetDelete implements the target delete command
func runTargetDelete(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get target name from positional argument or flag
	targetName, _ := cmd.Flags().GetString("name")
	if len(args) > 0 {
		targetName = args[0]
	}

	targetID, _ := cmd.Flags().GetString("id")

	// Validate that we have either name or ID
	if targetName == "" && targetID == "" {
		return fmt.Errorf("either target name or ID must be specified")
	}

	// Operation completed - silent logging

	// Create target view controller
	targetView, err := view.NewTargetView()
	if err != nil {
		return fmt.Errorf("failed to create target view: %w", err)
	}

	// Delete target through the view layer
	return targetView.DeleteTarget(ctx, view.TargetDeleteOptions{
		Name: targetName,
		ID:   targetID,
	})
}

// runTargetTest implements the target test command
func runTargetTest(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create target view controller
	targetView, err := view.NewTargetView()
	if err != nil {
		return fmt.Errorf("failed to create target view: %w", err)
	}

	// Test target through the view layer
	return targetView.TestTarget(ctx, view.TargetTestOptions{
		Name:   getValue(targetNameFlag),
		ID:     getValue(targetIDFlag),
		Output: getValue(targetOutputFlag),
	})
}

// runTargetUpdate implements the target update command
func runTargetUpdate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get target name from positional argument or flag
	name := getValue(targetNameFlag)
	if len(args) > 0 {
		name = args[0]
	}

	if name == "" && getValue(targetIDFlag) == "" {
		return fmt.Errorf("either target name or ID must be specified")
	}

	// Get all the update flags
	headers, _ := cmd.Flags().GetString("headers")
	description, _ := cmd.Flags().GetString("description")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	validate, _ := cmd.Flags().GetBool("validate")
	testConnection, _ := cmd.Flags().GetBool("test-connection")
	force, _ := cmd.Flags().GetBool("force")

	// Operation completed - silent logging

	// Create target view controller
	targetView, err := view.NewTargetView()
	if err != nil {
		return fmt.Errorf("failed to create target view: %w", err)
	}

	// Update target through the view layer
	return targetView.UpdateTarget(ctx, view.TargetUpdateOptions{
		Name:           name,
		ID:             getValue(targetIDFlag),
		Provider:       getValue(targetProviderFlag),
		Model:          getValue(targetModelFlag),
		URL:            getValue(targetURLFlag),
		APIKey:         getValue(targetAPIKeyFlag),
		Config:         getValue(targetConfigFlag),
		Output:         getValue(targetOutputFlag),
		Headers:        headers,
		Description:    description,
		Tags:           tags,
		Validate:       validate,
		TestConnection: testConnection,
		Force:          force,
	})
}

// runTargetInfo implements the target info command
func runTargetInfo(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create target view controller
	targetView, err := view.NewTargetView()
	if err != nil {
		return fmt.Errorf("failed to create target view: %w", err)
	}

	// Get target info through the view layer
	return targetView.GetTarget(ctx, view.TargetGetOptions{
		Name:       getValue(targetNameFlag),
		ID:         getValue(targetIDFlag),
		Output:     getValue(targetOutputFlag),
		History:    false,
		ConfigOnly: true,
		Status:     false,
	})
}

// runTargetGet implements the target get command
func runTargetGet(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get target name from positional argument or flag
	name := getValue(targetNameFlag)
	if len(args) > 0 {
		name = args[0]
	}

	if name == "" && getValue(targetIDFlag) == "" {
		return fmt.Errorf("either target name or ID must be specified")
	}

	history, _ := cmd.Flags().GetBool("history")
	configOnly, _ := cmd.Flags().GetBool("config-only")
	status, _ := cmd.Flags().GetBool("status")

	// Operation completed - silent logging

	// Create target view controller
	targetView, err := view.NewTargetView()
	if err != nil {
		return fmt.Errorf("failed to create target view: %w", err)
	}

	// Get target details through the view layer
	return targetView.GetTarget(ctx, view.TargetGetOptions{
		Name:       name,
		ID:         getValue(targetIDFlag),
		Output:     getValue(targetOutputFlag),
		History:    history,
		ConfigOnly: configOnly,
		Status:     status,
	})
}