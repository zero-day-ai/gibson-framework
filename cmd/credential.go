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
	credentialNameFlag       *string
	credentialProviderFlag   *string
	credentialTypeFlag       *string
	credentialAPIKeyFlag     *string
	credentialIDFlag         *string
	credentialOutputFlag     *string
	credentialDescriptionFlag *string
	credentialTagsFlag       *[]string
	credentialStatusFlag     *string
	credentialAllFlag        *bool
	credentialForceFlag      *bool
	credentialValueFlag      *string
	credentialAutoRotateFlag *bool
	credentialRotationIntervalFlag *string
	credentialFileFlag       *string
)

// credentialCmd creates the credential command following k9s patterns
func credentialCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "credential",
		Aliases: []string{"cred", "credentials"},
		Short:   "Manage AI/ML provider credentials",
		Long:    "Add, list, delete, validate, rotate, and manage AI/ML provider credentials with AES-256-GCM encryption",
	}

	// Add all 9 subcommands
	cmd.AddCommand(
		credentialAddCmd(),
		credentialListCmd(),
		credentialShowCmd(),
		credentialUpdateCmd(),
		credentialDeleteCmd(),
		credentialValidateCmd(),
		credentialRotateCmd(),
		credentialExportCmd(),
		credentialImportCmd(),
	)

	return cmd
}

// credentialAddCmd adds a new credential
func credentialAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "add [NAME]",
		Aliases: []string{"create", "new"},
		Short:   "Add a new AI/ML provider credential",
		Long:    "Add a new AI/ML provider credential with AES-256-GCM encryption for secure storage",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runCredentialAdd(c, args)
		},
		Example: `  # Add an OpenAI API key
  gibson credential add openai-key --provider openai --type api_key --api-key $OPENAI_API_KEY

  # Add an Anthropic credential with description
  gibson credential add claude-key --provider anthropic --type api_key --api-key $ANTHROPIC_API_KEY --description "Claude API key for testing"

  # Add a credential with auto-rotation
  gibson credential add auto-key --provider openai --type api_key --api-key $KEY --auto-rotate --rotation-interval 30d

  # Add a credential with tags
  gibson credential add dev-key --provider openai --type api_key --api-key $KEY --tags dev,testing`,
	}

	// Add flags following k9s pointer patterns
	cmd.Flags().StringP("name", "n", "", "Credential name (if not provided as argument)")
	cmd.Flags().StringP("provider", "p", "", "AI provider (openai, anthropic, huggingface, azure, google, custom)")
	cmd.Flags().StringP("type", "t", "api_key", "Credential type (api_key, oauth, bearer, basic, custom)")
	cmd.Flags().StringP("api-key", "k", "", "API key or credential value")
	cmd.Flags().StringP("description", "d", "", "Credential description")
	cmd.Flags().StringSliceP("tags", "", []string{}, "Tags for the credential (comma-separated)")
	cmd.Flags().BoolP("auto-rotate", "", false, "Enable automatic credential rotation")
	cmd.Flags().StringP("rotation-interval", "", "30d", "Rotation interval (e.g., 7d, 30d, 90d)")
	cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// credentialListCmd lists credentials
func credentialListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "get"},
		Short:   "List AI/ML provider credentials",
		Long:    "List all configured AI/ML provider credentials with their status and metadata (sensitive data is never displayed)",
		RunE:    runCredentialList,
		Example: `  # List all credentials
  gibson credential list

  # List credentials in JSON format
  gibson credential list --output json

  # List only active credentials
  gibson credential list --status active

  # List credentials for specific provider
  gibson credential list --provider openai`,
	}

	credentialOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().String("provider", "", "Filter by provider")
	cmd.Flags().String("status", "", "Filter by status (active, inactive, expired, revoked)")
	cmd.Flags().String("type", "", "Filter by credential type")

	return cmd
}

// credentialShowCmd shows detailed credential information
func credentialShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "show [NAME]",
		Aliases: []string{"describe", "info"},
		Short:   "Show detailed credential information",
		Long:    "Show detailed information for a specific credential including usage statistics and rotation info (sensitive data is never displayed)",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runCredentialShow,
		Example: `  # Show credential information
  gibson credential show my-credential

  # Show credential info by ID
  gibson credential show --id cred-123

  # Show info with JSON output
  gibson credential show my-credential --output json`,
	}

	credentialNameFlag = cmd.Flags().StringP("name", "n", "", "Credential name (if not provided as argument)")
	credentialIDFlag = cmd.Flags().String("id", "", "Credential ID to show info for")
	credentialOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// credentialUpdateCmd updates credential configuration
func credentialUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "update [NAME]",
		Aliases: []string{"edit", "modify"},
		Short:   "Update credential configuration",
		Long:    "Update configuration for an existing credential including value, status, and rotation settings",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runCredentialUpdate,
		Example: `  # Update credential value
  gibson credential update my-credential --api-key $NEW_API_KEY

  # Update credential status
  gibson credential update my-credential --status inactive

  # Update multiple fields
  gibson credential update my-credential --description "Updated description" --tags prod,live

  # Enable auto-rotation
  gibson credential update my-credential --auto-rotate --rotation-interval 7d`,
	}

	credentialNameFlag = cmd.Flags().StringP("name", "n", "", "Credential name (if not provided as argument)")
	credentialIDFlag = cmd.Flags().String("id", "", "Credential ID to update")
	credentialProviderFlag = cmd.Flags().StringP("provider", "p", "", "Update AI provider")
	credentialTypeFlag = cmd.Flags().StringP("type", "t", "", "Update credential type")
	credentialAPIKeyFlag = cmd.Flags().StringP("api-key", "k", "", "Update API key or credential value")
	credentialDescriptionFlag = cmd.Flags().StringP("description", "d", "", "Update description")
	credentialTagsFlag = cmd.Flags().StringSliceP("tags", "", []string{}, "Update tags (comma-separated)")
	credentialStatusFlag = cmd.Flags().StringP("status", "s", "", "Update status (active, inactive, expired, revoked)")
	credentialAutoRotateFlag = cmd.Flags().BoolP("auto-rotate", "", false, "Update auto-rotation setting")
	credentialRotationIntervalFlag = cmd.Flags().StringP("rotation-interval", "", "", "Update rotation interval")
	credentialOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// credentialDeleteCmd deletes credentials
func credentialDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "delete [NAME]",
		Aliases: []string{"del", "rm"},
		Short:   "Delete AI/ML provider credentials",
		Long:    "Delete one or more AI/ML provider credentials by name or ID",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runCredentialDelete,
		Example: `  # Delete a specific credential
  gibson credential delete my-credential

  # Delete credential by ID
  gibson credential delete --id cred-123

  # Delete all inactive credentials
  gibson credential delete --all --status inactive

  # Force deletion without confirmation
  gibson credential delete my-credential --force`,
	}

	credentialNameFlag = cmd.Flags().StringP("name", "n", "", "Credential name (if not provided as argument)")
	credentialIDFlag = cmd.Flags().String("id", "", "Credential ID to delete")
	credentialAllFlag = cmd.Flags().BoolP("all", "a", false, "Delete all credentials matching criteria")
	cmd.Flags().String("status", "", "Filter by status when deleting")
	credentialForceFlag = cmd.Flags().BoolP("force", "f", false, "Force deletion without confirmation")

	return cmd
}

// credentialValidateCmd validates credential connectivity
func credentialValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "validate [NAME]",
		Aliases: []string{"check", "test"},
		Short:   "Validate credential connectivity",
		Long:    "Test credential validity and connectivity with the AI/ML provider",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runCredentialValidate,
		Example: `  # Validate a specific credential
  gibson credential validate my-credential

  # Validate credential by ID
  gibson credential validate --id cred-123

  # Validate all active credentials
  gibson credential validate --all

  # Validate with verbose output
  gibson credential validate my-credential --verbose`,
	}

	credentialNameFlag = cmd.Flags().StringP("name", "n", "", "Credential name (if not provided as argument)")
	credentialIDFlag = cmd.Flags().String("id", "", "Credential ID to validate")
	credentialAllFlag = cmd.Flags().BoolP("all", "a", false, "Validate all active credentials")
	cmd.Flags().BoolP("verbose", "v", false, "Show detailed validation results")
	credentialOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// credentialRotateCmd rotates credentials
func credentialRotateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rotate [NAME]",
		Aliases: []string{"refresh"},
		Short:   "Rotate credential values",
		Long:    "Rotate credential values and update rotation history",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runCredentialRotate,
		Example: `  # Rotate a specific credential
  gibson credential rotate my-credential --value $NEW_API_KEY

  # Rotate credential by ID
  gibson credential rotate --id cred-123 --value $NEW_API_KEY

  # Rotate all credentials that need rotation
  gibson credential rotate --all`,
	}

	credentialNameFlag = cmd.Flags().StringP("name", "n", "", "Credential name (if not provided as argument)")
	credentialIDFlag = cmd.Flags().String("id", "", "Credential ID to rotate")
	credentialValueFlag = cmd.Flags().StringP("value", "v", "", "New credential value")
	credentialAllFlag = cmd.Flags().BoolP("all", "a", false, "Rotate all credentials that need rotation")
	credentialOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// credentialExportCmd exports credentials
func credentialExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "export",
		Aliases: []string{"backup"},
		Short:   "Export credential metadata",
		Long:    "Export credential metadata (without sensitive values) to a file for backup or migration",
		RunE:    runCredentialExport,
		Example: `  # Export all credentials to JSON
  gibson credential export --output json --file credentials.json

  # Export specific provider credentials
  gibson credential export --provider openai --file openai-creds.yaml

  # Export only active credentials
  gibson credential export --status active --file active-creds.json`,
	}

	credentialFileFlag = cmd.Flags().StringP("file", "f", "", "Output file path")
	cmd.Flags().String("provider", "", "Filter by provider")
	cmd.Flags().String("status", "", "Filter by status")
	credentialOutputFlag = cmd.Flags().StringP("output", "o", "json", "Output format (json, yaml)")

	return cmd
}

// credentialImportCmd imports credentials
func credentialImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "import",
		Aliases: []string{"restore"},
		Short:   "Import credential metadata",
		Long:    "Import credential metadata from a file (credential values must be set separately for security)",
		RunE:    runCredentialImport,
		Example: `  # Import credentials from JSON file
  gibson credential import --file credentials.json

  # Import credentials from YAML file
  gibson credential import --file credentials.yaml

  # Import with dry-run to preview changes
  gibson credential import --file credentials.json --dry-run`,
	}

	credentialFileFlag = cmd.Flags().StringP("file", "f", "", "Input file path")
	cmd.Flags().BoolP("dry-run", "", false, "Show what would be imported without making changes")
	credentialForceFlag = cmd.Flags().BoolP("force", "", false, "Overwrite existing credentials")
	credentialOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// runCredentialAdd implements the credential add command
func runCredentialAdd(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get credential name from positional argument or flag
	name, _ := cmd.Flags().GetString("name")
	if len(args) > 0 {
		name = args[0]
	}

	provider, _ := cmd.Flags().GetString("provider")
	credType, _ := cmd.Flags().GetString("type")
	apiKey, _ := cmd.Flags().GetString("api-key")
	description, _ := cmd.Flags().GetString("description")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	autoRotate, _ := cmd.Flags().GetBool("auto-rotate")
	rotationInterval, _ := cmd.Flags().GetString("rotation-interval")
	output, _ := cmd.Flags().GetString("output")

	// Operation completed - silent logging

	// Create credential view controller
	credentialView, err := view.NewCredentialView()
	if err != nil {
		return fmt.Errorf("failed to create credential view: %w", err)
	}

	// Add credential through the view layer
	return credentialView.AddCredential(ctx, view.CredentialAddOptions{
		Name:             name,
		Provider:         provider,
		Type:             credType,
		APIKey:           apiKey,
		Description:      description,
		Tags:             tags,
		AutoRotate:       autoRotate,
		RotationInterval: rotationInterval,
		Output:           output,
	})
}

// runCredentialList implements the credential list command
func runCredentialList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create credential view controller
	credentialView, err := view.NewCredentialView()
	if err != nil {
		return fmt.Errorf("failed to create credential view: %w", err)
	}

	// List credentials through the view layer
	output, _ := cmd.Flags().GetString("output")
	return credentialView.ListCredentials(ctx, view.CredentialListOptions{
		Output: output,
	})
}

// runCredentialShow implements the credential show command
func runCredentialShow(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get credential name from positional argument or flag
	name, _ := cmd.Flags().GetString("name")
	if len(args) > 0 {
		name = args[0]
	}

	id, _ := cmd.Flags().GetString("id")
	output, _ := cmd.Flags().GetString("output")

	// Operation completed - silent logging

	// Create credential view controller
	credentialView, err := view.NewCredentialView()
	if err != nil {
		return fmt.Errorf("failed to create credential view: %w", err)
	}

	// Get credential info through the view layer
	return credentialView.GetCredentialInfo(ctx, view.CredentialShowOptions{
		Name:   name,
		ID:     id,
		Output: output,
	})
}

// runCredentialUpdate implements the credential update command
func runCredentialUpdate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get credential name from positional argument or flag
	name, _ := cmd.Flags().GetString("name")
	if len(args) > 0 {
		name = args[0]
	}

	id, _ := cmd.Flags().GetString("id")
	provider, _ := cmd.Flags().GetString("provider")
	credType, _ := cmd.Flags().GetString("type")
	apiKey, _ := cmd.Flags().GetString("api-key")
	description, _ := cmd.Flags().GetString("description")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	status, _ := cmd.Flags().GetString("status")
	autoRotate, _ := cmd.Flags().GetBool("auto-rotate")
	rotationInterval, _ := cmd.Flags().GetString("rotation-interval")
	output, _ := cmd.Flags().GetString("output")

	// Operation completed - silent logging

	// Create credential view controller
	credentialView, err := view.NewCredentialView()
	if err != nil {
		return fmt.Errorf("failed to create credential view: %w", err)
	}

	// Update credential through the view layer
	return credentialView.UpdateCredential(ctx, view.CredentialUpdateOptions{
		Name:             name,
		ID:               id,
		Provider:         provider,
		Type:             credType,
		APIKey:           apiKey,
		Description:      description,
		Tags:             tags,
		Status:           status,
		AutoRotate:       &autoRotate,
		RotationInterval: rotationInterval,
		Output:           output,
	})
}

// runCredentialDelete implements the credential delete command
func runCredentialDelete(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get credential name from positional argument or flag
	credentialName, _ := cmd.Flags().GetString("name")
	if len(args) > 0 {
		credentialName = args[0]
	}

	credentialID, _ := cmd.Flags().GetString("id")
	all, _ := cmd.Flags().GetBool("all")
	force, _ := cmd.Flags().GetBool("force")

	// Validate that we have either name or ID
	if credentialName == "" && credentialID == "" && !all {
		return fmt.Errorf("either credential name, ID, or --all flag must be specified")
	}

	// Operation completed - silent logging

	// Create credential view controller
	credentialView, err := view.NewCredentialView()
	if err != nil {
		return fmt.Errorf("failed to create credential view: %w", err)
	}

	// Delete credential through the view layer
	return credentialView.DeleteCredential(ctx, view.CredentialDeleteOptions{
		Name:  credentialName,
		ID:    credentialID,
		All:   all,
		Force: force,
	})
}

// runCredentialValidate implements the credential validate command
func runCredentialValidate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get credential name from positional argument or flag
	name, _ := cmd.Flags().GetString("name")
	if len(args) > 0 {
		name = args[0]
	}

	id, _ := cmd.Flags().GetString("id")
	all, _ := cmd.Flags().GetBool("all")
	output, _ := cmd.Flags().GetString("output")

	// Operation completed - silent logging

	// Create credential view controller
	credentialView, err := view.NewCredentialView()
	if err != nil {
		return fmt.Errorf("failed to create credential view: %w", err)
	}

	// Validate credential through the view layer
	return credentialView.ValidateCredential(ctx, view.CredentialValidateOptions{
		Name:   name,
		ID:     id,
		All:    all,
		Output: output,
	})
}

// runCredentialRotate implements the credential rotate command
func runCredentialRotate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get credential name from positional argument or flag
	name, _ := cmd.Flags().GetString("name")
	if len(args) > 0 {
		name = args[0]
	}

	id, _ := cmd.Flags().GetString("id")
	value, _ := cmd.Flags().GetString("value")
	all, _ := cmd.Flags().GetBool("all")
	output, _ := cmd.Flags().GetString("output")

	// Operation completed - silent logging

	// Create credential view controller
	credentialView, err := view.NewCredentialView()
	if err != nil {
		return fmt.Errorf("failed to create credential view: %w", err)
	}

	// Rotate credential through the view layer
	return credentialView.RotateCredential(ctx, view.CredentialRotateOptions{
		Name:   name,
		ID:     id,
		Value:  value,
		All:    all,
		Output: output,
	})
}

// runCredentialExport implements the credential export command
func runCredentialExport(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	file, _ := cmd.Flags().GetString("file")
	output, _ := cmd.Flags().GetString("output")

	// Operation completed - silent logging

	// Create credential view controller
	credentialView, err := view.NewCredentialView()
	if err != nil {
		return fmt.Errorf("failed to create credential view: %w", err)
	}

	// Export credentials through the view layer
	return credentialView.ExportCredentials(ctx, view.CredentialExportOptions{
		File:   file,
		Output: output,
	})
}

// runCredentialImport implements the credential import command
func runCredentialImport(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	file, _ := cmd.Flags().GetString("file")
	force, _ := cmd.Flags().GetBool("force")
	output, _ := cmd.Flags().GetString("output")

	// Operation completed - silent logging

	// Create credential view controller
	credentialView, err := view.NewCredentialView()
	if err != nil {
		return fmt.Errorf("failed to create credential view: %w", err)
	}

	// Import credentials through the view layer
	return credentialView.ImportCredentials(ctx, view.CredentialImportOptions{
		File:   file,
		Force:  force,
		Output: output,
	})
}