// SPDX-License-Identifier: MIT
// Copyright Authors of Gibson

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/view"
	"github.com/gibson-sec/gibson-framework-2/internal/dao"
	"github.com/gibson-sec/gibson-framework-2/pkg/core/database/repositories"
	coremodels "github.com/gibson-sec/gibson-framework-2/pkg/core/models"
	"github.com/gibson-sec/gibson-framework-2/pkg/services"
	"github.com/gibson-sec/gibson-framework-2/pkg/cli"
	"github.com/spf13/cobra"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"gopkg.in/yaml.v2"
)

var (
	payloadNameFlag        *string
	payloadContentFlag     *string
	payloadCategoryFlag    *string
	payloadTypeFlag        *string
	payloadTagsFlag        []string
	payloadDescriptionFlag *string
	payloadIDFlag          *string
	payloadOutputFlag      *string
	payloadLimitFlag       *int
	payloadOffsetFlag      *int
	payloadQueryFlag       *string
	payloadFuzzyFlag       *bool
	payloadVersionFlag     *string
	payloadForceFlag       *bool
	payloadConfirmFlag     *bool

	// Repository command flags
	repoNameFlag        *string
	repoURLFlag         *string
	repoDepthFlag       *int
	repoFullFlag        *bool
	repoBranchFlag      *string
	repoAuthTypeFlag    *string
	repoAutoSyncFlag    *bool
	repoDescriptionFlag *string
	repoTagsFlag        []string
	repoOutputFlag      *string
	repoForceFlag       *bool
)

// payloadCmd creates the payload command following k9s patterns
func payloadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "payload",
		Aliases: []string{"p", "payloads"},
		Short:   "Manage AI/ML security payloads",
		Long:    "Add, list, search, update, and remove AI/ML security test payloads with categorization and version control",
	}

	// Add subcommands
	cmd.AddCommand(
		payloadAddCmd(),
		payloadListCmd(),
		payloadSearchCmd(),
		payloadDetailsCmd(),
		payloadRemoveCmd(),
		payloadUpdateCmd(),
		payloadRepositoryCmd(),
	)

	return cmd
}

// payloadAddCmd adds a new payload
func payloadAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "add [NAME]",
		Aliases: []string{"create", "new"},
		Short:   "Add a new security payload",
		Long:    "Add a new AI/ML security test payload with categorization by attack type and tagging support",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runPayloadAdd(c, args)
		},
		Example: `  # Add a prompt injection payload
  gibson payload add injection-001 --content "Ignore previous instructions" --category injection --type prompt

  # Add a jailbreak payload with tags
  gibson payload add jailbreak-simple --content "You are DAN..." --category jailbreak --tags "dan,simple"

  # Add an adversarial payload with description
  gibson payload add adversarial-001 --content "..." --category adversarial --description "Basic adversarial example"

  # Add a data poisoning payload
  gibson payload add poison-001 --content "..." --category data --type poisoning --tags "training,backdoor"

  # Add an XSS payload for interface testing
  gibson payload add xss-basic --content "<script>alert('XSS')</script>" --category interface --type xss`,
	}

	// Add flags following k9s patterns
	cmd.Flags().StringP("name", "n", "", "Payload name (if not provided as argument)")
	cmd.Flags().StringP("content", "c", "", "Payload content or template")
	cmd.Flags().StringP("category", "", "", "Attack category (injection, jailbreak, adversarial, data, interface, infrastructure, output, process)")
	cmd.Flags().StringP("type", "t", "", "Specific attack type within category")
	cmd.Flags().StringSlice("tags", []string{}, "Tags for organization and filtering")
	cmd.Flags().StringP("description", "d", "", "Payload description")
	cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().String("version", "1.0.0", "Initial version number")

	return cmd
}

// payloadListCmd lists payloads
func payloadListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List security payloads",
		Long:    "List all security payloads with filtering by category, type, tags, and pagination support",
		RunE:    runPayloadList,
		Example: `  # List all payloads
  gibson payload list

  # List payloads by category
  gibson payload list --category injection

  # List payloads by type
  gibson payload list --type prompt

  # List with pagination
  gibson payload list --limit 10 --offset 20

  # List in JSON format
  gibson payload list --output json

  # List with specific tags
  gibson payload list --tags "simple,basic"`,
	}

	payloadOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().String("category", "", "Filter by attack category")
	cmd.Flags().String("type", "", "Filter by attack type")
	cmd.Flags().StringSlice("tags", []string{}, "Filter by tags")
	payloadLimitFlag = cmd.Flags().IntP("limit", "l", 50, "Limit number of results")
	payloadOffsetFlag = cmd.Flags().IntP("offset", "", 0, "Offset for pagination")

	return cmd
}

// payloadSearchCmd searches payloads with fuzzy matching
func payloadSearchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "search [QUERY]",
		Aliases: []string{"find", "grep"},
		Short:   "Search security payloads",
		Long:    "Search payloads with fuzzy matching against content, name, description, and tags",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runPayloadSearch,
		Example: `  # Search for payloads containing "injection"
  gibson payload search injection

  # Fuzzy search with similarity matching
  gibson payload search "prompt hack" --fuzzy

  # Search within specific category
  gibson payload search "bypass" --category jailbreak

  # Search with tags filter
  gibson payload search "simple" --tags "basic,easy"

  # Search with output format
  gibson payload search "adversarial" --output json`,
	}

	payloadQueryFlag = cmd.Flags().StringP("query", "q", "", "Search query (if not provided as argument)")
	cmd.Flags().String("category", "", "Search within specific category")
	cmd.Flags().StringSlice("tags", []string{}, "Filter search results by tags")
	payloadFuzzyFlag = cmd.Flags().BoolP("fuzzy", "f", false, "Enable fuzzy matching")
	payloadOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	payloadLimitFlag = cmd.Flags().IntP("limit", "l", 20, "Limit number of results")

	return cmd
}

// payloadDetailsCmd displays payload details
func payloadDetailsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "details [ID...]",
		Aliases: []string{"detail", "show", "get"},
		Short:   "Display detailed payload information",
		Long:    "Display complete payload content and metadata for one or more payloads by ID",
		Args:    cobra.MinimumNArgs(1),
		RunE:    runPayloadDetails,
		Example: `  # Show payload details by full UUID
  gibson payload details a1b2c3d4-e5f6-7890-abcd-ef1234567890

  # Show payload details by partial UUID (minimum 8 characters)
  gibson payload details a1b2c3d4

  # Show multiple payload details
  gibson payload details a1b2c3d4 e5f67890

  # Show details in JSON format
  gibson payload details a1b2c3d4 --output json

  # Show details in YAML format
  gibson payload details a1b2c3d4 --output yaml

  # Show only the payload content (raw output)
  gibson payload details a1b2c3d4 --output raw

  # Show details without color formatting
  gibson payload details a1b2c3d4 --no-color

  # Show multiple payloads in comparison mode
  gibson payload details a1b2c3d4 e5f67890 --compare

  # Show details with verbose information
  gibson payload details a1b2c3d4 --verbose`,
	}

	// Add flags following existing patterns
	cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml, raw)")
	cmd.Flags().Bool("no-color", false, "Disable color output")
	cmd.Flags().Bool("compare", false, "Side-by-side comparison mode for multiple payloads")
	cmd.Flags().BoolP("verbose", "v", false, "Include all fields and verbose information")

	return cmd
}

// payloadRemoveCmd removes payloads
func payloadRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "remove [NAME]",
		Aliases: []string{"delete", "del", "rm"},
		Short:   "Remove security payloads",
		Long:    "Remove one or more security payloads by name or ID with confirmation prompts",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runPayloadRemove,
		Example: `  # Remove a specific payload
  gibson payload remove injection-001

  # Remove payload by ID
  gibson payload remove --id payload-123

  # Remove without confirmation
  gibson payload remove injection-001 --force

  # Remove all payloads with specific tag
  gibson payload remove --tags "deprecated" --confirm

  # Remove all payloads in category
  gibson payload remove --category test --confirm`,
	}

	payloadNameFlag = cmd.Flags().StringP("name", "n", "", "Payload name (if not provided as argument)")
	payloadIDFlag = cmd.Flags().String("id", "", "Payload ID to remove")
	cmd.Flags().StringSlice("tags", []string{}, "Remove all payloads with these tags")
	cmd.Flags().String("category", "", "Remove all payloads in this category")
	payloadForceFlag = cmd.Flags().BoolP("force", "f", false, "Force removal without confirmation")
	payloadConfirmFlag = cmd.Flags().Bool("confirm", false, "Confirm bulk removals")

	return cmd
}

// payloadUpdateCmd updates payload configuration
func payloadUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "update [NAME]",
		Aliases: []string{"edit", "modify"},
		Short:   "Update security payload",
		Long:    "Update security payload content, metadata, and version with history tracking",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runPayloadUpdate,
		Example: `  # Update payload content
  gibson payload update injection-001 --content "New improved payload"

  # Update payload tags
  gibson payload update injection-001 --tags "advanced,tested"

  # Update with new version
  gibson payload update injection-001 --content "..." --version "2.0.0"

  # Update description and type
  gibson payload update injection-001 --description "Updated description" --type advanced

  # Update category
  gibson payload update injection-001 --category jailbreak

  # Force update without confirmation
  gibson payload update injection-001 --content "..." --force`,
	}

	payloadNameFlag = cmd.Flags().StringP("name", "n", "", "Payload name (if not provided as argument)")
	payloadIDFlag = cmd.Flags().String("id", "", "Payload ID to update")
	payloadContentFlag = cmd.Flags().StringP("content", "c", "", "Update payload content")
	payloadCategoryFlag = cmd.Flags().String("category", "", "Update attack category")
	payloadTypeFlag = cmd.Flags().StringP("type", "t", "", "Update attack type")
	cmd.Flags().StringSlice("tags", []string{}, "Update payload tags")
	payloadDescriptionFlag = cmd.Flags().StringP("description", "d", "", "Update payload description")
	payloadVersionFlag = cmd.Flags().String("version", "", "Update version number (auto-incremented if not specified)")
	payloadOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	payloadForceFlag = cmd.Flags().BoolP("force", "f", false, "Force update without confirmation")

	return cmd
}

// runPayloadAdd implements the payload add command
func runPayloadAdd(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get payload name from positional argument or flag
	name, _ := cmd.Flags().GetString("name")
	if len(args) > 0 {
		name = args[0]
	}

	content, _ := cmd.Flags().GetString("content")
	category, _ := cmd.Flags().GetString("category")
	payloadType, _ := cmd.Flags().GetString("type")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	description, _ := cmd.Flags().GetString("description")
	version, _ := cmd.Flags().GetString("version")
	output, _ := cmd.Flags().GetString("output")

	// Operation completed - silent logging

	// Create payload view controller
	payloadView, err := view.NewPayloadView()
	if err != nil {
		return fmt.Errorf("failed to create payload view: %w", err)
	}

	// Add payload through the view layer
	return payloadView.AddPayload(ctx, view.PayloadAddOptions{
		Name:        name,
		Content:     content,
		Category:    category,
		Type:        payloadType,
		Tags:        tags,
		Description: description,
		Version:     version,
		Output:      output,
	})
}

// runPayloadList implements the payload list command
func runPayloadList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	category, _ := cmd.Flags().GetString("category")
	payloadType, _ := cmd.Flags().GetString("type")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")
	output, _ := cmd.Flags().GetString("output")

	// Create payload view controller
	payloadView, err := view.NewPayloadView()
	if err != nil {
		return fmt.Errorf("failed to create payload view: %w", err)
	}

	// List payloads through the view layer
	return payloadView.ListPayloads(ctx, view.PayloadListOptions{
		Output:   output,
		Category: category,
		Type:     payloadType,
		Tags:     tags,
		Limit:    limit,
		Offset:   offset,
	})
}

// runPayloadSearch implements the payload search command
func runPayloadSearch(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get search query from positional argument or flag
	query, _ := cmd.Flags().GetString("query")
	if len(args) > 0 {
		query = args[0]
	}

	category, _ := cmd.Flags().GetString("category")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	fuzzy, _ := cmd.Flags().GetBool("fuzzy")
	limit, _ := cmd.Flags().GetInt("limit")
	output, _ := cmd.Flags().GetString("output")

	// Operation completed - silent logging

	// Create payload view controller
	payloadView, err := view.NewPayloadView()
	if err != nil {
		return fmt.Errorf("failed to create payload view: %w", err)
	}

	// Search payloads through the view layer
	return payloadView.SearchPayloads(ctx, view.PayloadSearchOptions{
		Query:    query,
		Category: category,
		Tags:     tags,
		Fuzzy:    fuzzy,
		Output:   output,
		Limit:    limit,
	})
}

// runPayloadDetails implements the payload details command
func runPayloadDetails(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	output, _ := cmd.Flags().GetString("output")
	noColor, _ := cmd.Flags().GetBool("no-color")
	compare, _ := cmd.Flags().GetBool("compare")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Operation completed - silent logging

	// Create payload view controller
	payloadView, err := view.NewPayloadView()
	if err != nil {
		return fmt.Errorf("failed to create payload view: %w", err)
	}

	// Show payload details through the view layer
	return payloadView.ShowPayloadDetails(ctx, view.PayloadDetailsOptions{
		IDs:          args,
		OutputFormat: output,
		NoColor:      noColor,
		Compare:      compare,
		Verbose:      verbose,
	})
}

// runPayloadRemove implements the payload remove command
func runPayloadRemove(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get payload name from positional argument or flag
	payloadName, _ := cmd.Flags().GetString("name")
	if len(args) > 0 {
		payloadName = args[0]
	}

	payloadID, _ := cmd.Flags().GetString("id")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	category, _ := cmd.Flags().GetString("category")
	force, _ := cmd.Flags().GetBool("force")
	confirm, _ := cmd.Flags().GetBool("confirm")

	// Validate that we have some identifier
	if payloadName == "" && payloadID == "" && len(tags) == 0 && category == "" {
		return fmt.Errorf("either payload name, ID, tags, or category must be specified")
	}

	// Operation completed - silent logging

	// Create payload view controller
	payloadView, err := view.NewPayloadView()
	if err != nil {
		return fmt.Errorf("failed to create payload view: %w", err)
	}

	// Remove payload through the view layer
	return payloadView.RemovePayloads(ctx, view.PayloadRemoveOptions{
		Name:     payloadName,
		ID:       payloadID,
		Tags:     tags,
		Category: category,
		Force:    force,
		Confirm:  confirm,
	})
}

// runPayloadUpdate implements the payload update command
func runPayloadUpdate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get payload name from positional argument or flag
	name, _ := cmd.Flags().GetString("name")
	if len(args) > 0 {
		name = args[0]
	}

	if name == "" {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("either payload name or ID must be specified")
		}
	}

	content, _ := cmd.Flags().GetString("content")
	category, _ := cmd.Flags().GetString("category")
	payloadType, _ := cmd.Flags().GetString("type")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	description, _ := cmd.Flags().GetString("description")
	version, _ := cmd.Flags().GetString("version")
	force, _ := cmd.Flags().GetBool("force")
	id, _ := cmd.Flags().GetString("id")

	// Operation completed - silent logging

	// Create payload view controller
	payloadView, err := view.NewPayloadView()
	if err != nil {
		return fmt.Errorf("failed to create payload view: %w", err)
	}

	output, _ := cmd.Flags().GetString("output")

	// Update payload through the view layer
	return payloadView.UpdatePayload(ctx, view.PayloadUpdateOptions{
		Name:        name,
		ID:          id,
		Content:     content,
		Category:    category,
		Type:        payloadType,
		Tags:        tags,
		Description: description,
		Version:     version,
		Output:      output,
		Force:       force,
	})
}

// payloadRepositoryCmd creates the repository management command
func payloadRepositoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "repository",
		Aliases: []string{"repo", "repositories"},
		Short:   "Manage Git payload repositories",
		Long:    "Add, list, sync, and remove Git repositories containing AI/ML security payloads",
	}

	// Add repository subcommands
	cmd.AddCommand(
		payloadRepositoryAddCmd(),
		payloadRepositoryListCmd(),
		payloadRepositorySyncCmd(),
		payloadRepositoryRemoveCmd(),
		payloadRepositoryGenerateTemplateCmd(),
	)

	return cmd
}

// payloadRepositoryGenerateTemplateCmd generates a new payload repository template
func payloadRepositoryGenerateTemplateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "generate-template [PATH]",
		Aliases: []string{"gen-template", "template"},
		Short:   "Generate a payload repository template",
		Long:    "Generate a complete payload repository template with manifest, compatibility matrix, schemas, and domain-specific sample payloads",
		Args:    cobra.ExactArgs(1),
		RunE:    runGenerateTemplate,
		Example: `  # Generate repository template in current directory
  gibson payload repository generate-template ./my-payload-repo

  # Generate template with force overwrite
  gibson payload repository generate-template ./existing-repo --force

  # Generate template and view structure
  gibson payload repository generate-template ./test-repo && tree ./test-repo`,
	}

	cmd.Flags().BoolP("force", "f", false, "Force overwrite if repository path already exists")
	cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// payloadRepositoryAddCmd adds a new Git repository
func payloadRepositoryAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "add [NAME] [URL]",
		Aliases: []string{"create", "new"},
		Short:   "Add a new Git payload repository",
		Long:    "Add a new Git repository containing AI/ML security payloads with authentication and clone depth options",
		Args:    cobra.MinimumNArgs(1),
		RunE:    runPayloadRepositoryAdd,
		Example: `  # Add a repository with default shallow clone (depth=1)
  gibson payload repository add my-payloads https://github.com/user/payloads.git

  # Add repository with full clone history
  gibson payload repository add comprehensive-tests https://github.com/org/tests.git --full

  # Add repository with custom clone depth
  gibson payload repository add limited-history https://github.com/org/payloads.git --depth 5

  # Add repository with SSH authentication
  gibson payload repository add private-repo git@github.com:org/private-payloads.git --auth-type ssh

  # Add repository with automatic synchronization
  gibson payload repository add auto-sync https://github.com/org/payloads.git --auto-sync --description "Auto-synced payloads"

  # Add repository with specific branch
  gibson payload repository add dev-payloads https://github.com/org/payloads.git --branch development`,
	}

	cmd.Flags().StringP("name", "n", "", "Repository name (if not provided as first argument)")
	cmd.Flags().StringP("url", "u", "", "Repository URL (if not provided as second argument)")
	cmd.Flags().IntP("depth", "d", 1, "Clone depth (default: 1 for shallow clone, 0 for full clone)")
	cmd.Flags().Bool("full", false, "Perform full clone instead of shallow clone")
	cmd.Flags().StringP("branch", "b", "main", "Branch to clone (default: main)")
	cmd.Flags().String("auth-type", "", "Authentication type (none, ssh, https, token)")
	cmd.Flags().Bool("auto-sync", false, "Enable automatic synchronization")
	cmd.Flags().String("description", "", "Repository description")
	cmd.Flags().StringSlice("tags", []string{}, "Tags for organization")
	cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().BoolP("force", "f", false, "Force add without confirmation")
	cmd.Flags().BoolP("verbose", "v", false, "Show detailed error messages and troubleshooting")
	cmd.Flags().Bool("help-errors", false, "Show comprehensive error handling guidance")

	return cmd
}

// payloadRepositoryListCmd lists Git repositories
func payloadRepositoryListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List Git payload repositories",
		Long:    "List all Git repositories with sync status, payload counts, and last sync information",
		RunE:    runPayloadRepositoryList,
		Example: `  # List all repositories
  gibson payload repository list

  # List repositories in JSON format
  gibson payload repository list --output json

  # List repositories with specific tags
  gibson payload repository list --tags "production,verified"

  # List with detailed status information
  gibson payload repository list --show-status`,
	}

	cmd.Flags().StringSlice("tags", []string{}, "Filter by tags")
	cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().Bool("show-status", false, "Show detailed sync status")

	return cmd
}

// payloadRepositorySyncCmd synchronizes repositories
func payloadRepositorySyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sync [NAME...]",
		Aliases: []string{"pull", "update"},
		Short:   "Synchronize Git payload repositories",
		Long:    "Synchronize one or more Git repositories to update payloads from remote sources",
		RunE:    runPayloadRepositorySync,
		Example: `  # Sync all repositories
  gibson payload repository sync

  # Sync specific repositories
  gibson payload repository sync my-payloads comprehensive-tests

  # Force sync even if up-to-date
  gibson payload repository sync --force

  # Sync with progress indicators
  gibson payload repository sync --progress`,
	}

	cmd.Flags().BoolP("force", "f", false, "Force sync even if up-to-date")
	cmd.Flags().Bool("progress", true, "Show progress indicators")
	cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().BoolP("verbose", "v", false, "Show detailed error messages and troubleshooting")
	cmd.Flags().Bool("help-errors", false, "Show comprehensive error handling guidance")

	return cmd
}

// payloadRepositoryRemoveCmd removes Git repositories
func payloadRepositoryRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "remove [NAME...]",
		Aliases: []string{"delete", "del", "rm"},
		Short:   "Remove Git payload repositories",
		Long:    "Remove one or more Git repositories and optionally their local payload data",
		RunE:    runPayloadRepositoryRemove,
		Example: `  # Remove a repository (keeps payloads)
  gibson payload repository remove my-payloads

  # Remove repository and all its payloads
  gibson payload repository remove my-payloads --purge-payloads

  # Remove multiple repositories
  gibson payload repository remove repo1 repo2 repo3

  # Force removal without confirmation
  gibson payload repository remove my-payloads --force`,
	}

	cmd.Flags().BoolP("force", "f", false, "Force removal without confirmation")
	cmd.Flags().Bool("purge-payloads", false, "Also remove all payloads from this repository")
	cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// runPayloadRepositoryAdd implements the repository add command
func runPayloadRepositoryAdd(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get repository name and URL from arguments or flags
	name, _ := cmd.Flags().GetString("name")
	url, _ := cmd.Flags().GetString("url")

	if len(args) > 0 {
		name = args[0]
	}
	if len(args) > 1 {
		url = args[1]
	}

	if name == "" {
		return cli.NewValidationError("repository name", name, "name cannot be empty")
	}
	if url == "" {
		return cli.NewValidationError("repository URL", url, "URL cannot be empty")
	}

	// Validate URL format
	if err := cli.ValidateRepositoryURL(url); err != nil {
		verbose, _ := cmd.Flags().GetBool("verbose")
		errorHelper := cli.NewGitErrorHelpers(verbose, false)
		errorHelper.HandleCloneError(err, name, url)
		return err
	}

	// Get flags
	depth, _ := cmd.Flags().GetInt("depth")
	full, _ := cmd.Flags().GetBool("full")
	branch, _ := cmd.Flags().GetString("branch")
	authType, _ := cmd.Flags().GetString("auth-type")
	autoSync, _ := cmd.Flags().GetBool("auto-sync")
	description, _ := cmd.Flags().GetString("description")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	outputFormat, _ := cmd.Flags().GetString("output")
	force, _ := cmd.Flags().GetBool("force")
	verbose, _ := cmd.Flags().GetBool("verbose")
	helpErrors, _ := cmd.Flags().GetBool("help-errors")

	// Show error handling guidance if requested
	if helpErrors {
		showRepositoryErrorGuidance()
		return nil
	}

	// Handle full clone flag
	if full {
		depth = 0 // 0 means full clone in git
	}

	// Initialize database and repository
	db, err := getDatabaseConnection()
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	repoRepository := repositories.NewPayloadRepositoryRepository(db)

	// Create payload repository request
	req := coremodels.PayloadRepositoryCreateRequest{
		Name:        name,
		URL:         url,
		CloneDepth:  &depth,
		IsFullClone: full,
		Branch:      branch,
		AutoSync:    autoSync,
		Description: description,
		Tags:        tags,
	}

	// Set auth type if provided
	if authType != "" {
		req.AuthType = coremodels.PayloadRepositoryAuthType(authType)
	}

	// Validate request
	if err := req.Validate(); err != nil {
		errorHelper := cli.NewGitErrorHelpers(verbose, false)
		errorHelper.HandleCloneError(err, name, url)
		return err
	}

	// Check if repository already exists
	existsResult := repoRepository.ExistsByName(ctx, name)
	if existsResult.IsErr() {
		return fmt.Errorf("failed to check if repository exists: %w", existsResult.Error())
	}
	if existsResult.Unwrap() && !force {
		return fmt.Errorf("repository '%s' already exists (use --force to overwrite)", name)
	}

	// Generate LocalPath for the repository
	repoService := services.NewPayloadRepositoryService()
	localPath, err := repoService.GenerateLocalPath(req.Name)
	if err != nil {
		return fmt.Errorf("failed to generate local path for repository: %w", err)
	}

	// Convert to database model
	repoModel := &coremodels.PayloadRepositoryDB{
		ID:               uuid.New(),
		Name:             req.Name,
		URL:              req.URL,
		LocalPath:        localPath,
		CloneDepth:       *req.CloneDepth,
		IsFullClone:      req.IsFullClone,
		Branch:           req.Branch,
		AuthType:         req.AuthType,
		ConflictStrategy: req.ConflictStrategy,
		AutoSync:         req.AutoSync,
		SyncInterval:     req.SyncInterval,
		Description:      req.Description,
		Tags:             req.Tags,
		Config:           req.Config,
	}

	// Set defaults
	repoModel.SetDefaults()

	// Create repository
	result := repoRepository.Create(ctx, repoModel)
	if result.IsErr() {
		return fmt.Errorf("failed to create repository: %w", result.Error())
	}

	createdRepo := result.Unwrap()

	// Show repository added message
	if outputFormat == "table" {
		fmt.Printf("Repository '%s' added successfully\n", name)
	}

	// Automatically sync/clone the repository
	fmt.Printf("Syncing repository '%s'...\n", name)
	syncResult := performRepositorySync(ctx, createdRepo, verbose)
	if syncResult.IsErr() {
		// Sync failed, but repository was added - show warning instead of failing completely
		fmt.Printf("Warning: Repository '%s' was added but sync failed: %v\n", name, syncResult.Error())
		fmt.Printf("You can retry sync manually with: gibson payload repository sync %s\n", name)

		// Still output the repository info showing it was added
		return outputPayloadRepository(outputFormat, []*coremodels.PayloadRepositoryDB{createdRepo}, "Repository added (sync failed)")
	} else {
		// Sync succeeded - update repository status and show success
		updatedRepo := syncResult.Unwrap()
		fmt.Printf("Repository '%s' synced successfully\n", name)
		return outputPayloadRepository(outputFormat, []*coremodels.PayloadRepositoryDB{updatedRepo}, "Repository added and synced successfully")
	}
}

// runPayloadRepositoryList implements the repository list command
func runPayloadRepositoryList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	tags, _ := cmd.Flags().GetStringSlice("tags")
	outputFormat, _ := cmd.Flags().GetString("output")
	showStatus, _ := cmd.Flags().GetBool("show-status")

	// Initialize database and repository
	db, err := getDatabaseConnection()
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	repoRepository := repositories.NewPayloadRepositoryRepository(db)

	// List repositories with sync status if requested
	var repos []*coremodels.PayloadRepositoryDB
	if showStatus {
		// Get repositories with detailed sync information
		syncInfoResult := repoRepository.ListWithSyncStatus(ctx)
		if syncInfoResult.IsErr() {
			return fmt.Errorf("failed to list repositories with sync status: %w", syncInfoResult.Error())
		}
		syncInfos := syncInfoResult.Unwrap()
		for _, info := range syncInfos {
			repos = append(repos, info.PayloadRepositoryDB)
		}
	} else {
		// Get basic repository list
		result := repoRepository.List(ctx)
		if result.IsErr() {
			return fmt.Errorf("failed to list repositories: %w", result.Error())
		}
		repos = result.Unwrap()
	}

	// Filter by tags if specified
	if len(tags) > 0 {
		filteredRepos := make([]*coremodels.PayloadRepositoryDB, 0)
		for _, repo := range repos {
			if hasAnyTag(repo.Tags, tags) {
				filteredRepos = append(filteredRepos, repo)
			}
		}
		repos = filteredRepos
	}

	// Output results
	return outputPayloadRepository(outputFormat, repos, "")
}

// runPayloadRepositorySync implements the repository sync command
func runPayloadRepositorySync(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	force, _ := cmd.Flags().GetBool("force")
	progress, _ := cmd.Flags().GetBool("progress")
	outputFormat, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")
	helpErrors, _ := cmd.Flags().GetBool("help-errors")

	// Show error handling guidance if requested
	if helpErrors {
		showSyncErrorGuidance()
		return nil
	}

	// Initialize database and repository
	db, err := getDatabaseConnection()
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	repoRepository := repositories.NewPayloadRepositoryRepository(db)
	payloadRepository := repositories.NewPayloadRepository(db)

	// Get repositories to sync
	var reposToSync []*coremodels.PayloadRepositoryDB
	if len(args) == 0 {
		// Sync all repositories
		result := repoRepository.List(ctx)
		if result.IsErr() {
			return fmt.Errorf("failed to list repositories: %w", result.Error())
		}
		reposToSync = result.Unwrap()
	} else {
		// Sync specific repositories by name
		for _, name := range args {
			result := repoRepository.GetByName(ctx, name)
			if result.IsErr() {
				return fmt.Errorf("repository '%s' not found: %w", name, result.Error())
			}
			reposToSync = append(reposToSync, result.Unwrap())
		}
	}

	if len(reposToSync) == 0 {
		fmt.Println("No repositories to sync")
		return nil
	}

	// Initialize Git service with system git enabled for SSH support
	gitConfig := services.GitServiceConfig{
		DefaultDepth:  1,
		DefaultBranch: "main",
		BaseDir:       filepath.Join(os.TempDir(), "gibson-repos"),
		UseSystemGit:  true, // Enable system git for proper SSH agent support
	}
	gitService := services.NewGitService(gitConfig)

	syncResults := make([]*coremodels.PayloadRepositoryDB, 0)

	// Sync each repository
	for _, repo := range reposToSync {
		if progress {
			fmt.Printf("Syncing repository '%s'...\n", repo.Name)
		}

		// Check if LocalPath is empty and generate one if needed
		if repo.LocalPath == "" {
			repoService := services.NewPayloadRepositoryService()
			localPath, err := repoService.GenerateLocalPath(repo.Name)
			if err != nil {
				fmt.Printf("Failed to generate local path for repository '%s': %v\n", repo.Name, err)
				continue
			}
			repo.LocalPath = localPath

			// Update repository with the new LocalPath
			updateResult := repoRepository.Update(ctx, repo)
			if updateResult.IsErr() {
				fmt.Printf("Failed to update repository '%s' with local path: %v\n", repo.Name, updateResult.Error())
				continue
			}
			repo = updateResult.Unwrap()
		}

		// Skip if not forced and repository doesn't need sync
		if !force && !repo.IsSyncRequired() && repo.Status == coremodels.PayloadRepositoryStatusActive {
			if progress {
				fmt.Printf("Repository '%s' is up to date (use --force to sync anyway)\n", repo.Name)
			}
			continue
		}

		// Check if clone is required
		if repo.IsCloneRequired() {
			// Clone repository
			cloneResult := gitService.Clone(ctx, services.GitCloneOptions{
				URL:       repo.URL,
				LocalPath: repo.LocalPath,
				Branch:    repo.Branch,
				Depth:     repo.GetCloneDepthValue(),
				AuthType:  repo.AuthType,
				Full:      repo.IsFullClone,
			})
			if cloneResult.IsErr() {
				errorHelper := cli.NewGitErrorHelpers(verbose, false)
				errorHelper.HandleCloneError(cloneResult.Error(), repo.Name, repo.URL)
				continue
			}
		} else {
			// Pull updates
			pullResult := gitService.Pull(ctx, services.GitPullOptions{
				LocalPath: repo.LocalPath,
				AuthType:  repo.AuthType,
			})
			if pullResult.IsErr() {
				errorHelper := cli.NewGitErrorHelpers(verbose, false)
				errorHelper.HandlePullError(pullResult.Error(), repo.Name, repo.LocalPath)
				continue
			}
		}

		// Update sync status
		repo.Status = coremodels.PayloadRepositoryStatusActive
		updateResult := repoRepository.Update(ctx, repo)
		if updateResult.IsErr() {
			fmt.Printf("Failed to update repository status '%s': %v\n", repo.Name, updateResult.Error())
			continue
		}
		repo = updateResult.Unwrap()

		// NOW IMPORT PAYLOADS: Initialize payload synchronizer and sync payloads
		syncConfig := services.PayloadSyncConfig{
			BatchSize: 100,
			DiscoveryPaths: []string{
				"*.yaml", "*.yml", "*.json", "*.txt", "*.payload", "*.md",
			},
		}
		payloadSynchronizer := services.NewPayloadSynchronizer(db, syncConfig)

		if progress {
			fmt.Printf("Importing payloads from repository '%s'...\n", repo.Name)
		}

		// Sync payloads from filesystem to database
		syncResult := payloadSynchronizer.SyncRepositoryPayloads(ctx, repo, payloadRepository)
		if syncResult.IsErr() {
			fmt.Printf("Warning: Payload import failed for repository '%s': %v\n", repo.Name, syncResult.Error())
			// Continue with sync - Git operations succeeded even if payload import failed
		} else {
			// Display sync results
			syncData := syncResult.Unwrap()
			if verbose {
				fmt.Printf("Payload import completed for repository '%s':\n", repo.Name)
				fmt.Printf("  Total files discovered: %d\n", syncData.TotalFiles)
				fmt.Printf("  New payloads imported: %d\n", syncData.NewPayloads)
				fmt.Printf("  Updated payloads: %d\n", syncData.UpdatedPayloads)
				fmt.Printf("  Skipped files: %d\n", syncData.SkippedFiles)
				fmt.Printf("  Error files: %d\n", syncData.ErrorFiles)
				fmt.Printf("  Import duration: %v\n", syncData.Duration)
			} else if progress {
				fmt.Printf("Imported %d payloads from repository '%s'\n", syncData.NewPayloads, repo.Name)
			}
		}

		// Update repository with sync timestamp and payload count
		now := time.Now()
		repo.LastSyncAt = &now

		// Get updated payload count for this repository
		payloadCountResult := payloadRepository.CountByRepository(ctx, repo.ID)
		if payloadCountResult.IsOk() {
			repo.PayloadCount = payloadCountResult.Unwrap()
		}

		// Final repository update with sync metadata
		finalUpdateResult := repoRepository.Update(ctx, repo)
		if finalUpdateResult.IsErr() {
			fmt.Printf("Failed to update repository sync metadata '%s': %v\n", repo.Name, finalUpdateResult.Error())
			continue
		}

		syncResults = append(syncResults, finalUpdateResult.Unwrap())

		if progress {
			fmt.Printf("Successfully synced repository '%s'\n", repo.Name)
		}
	}

	// Output results
	return outputPayloadRepository(outputFormat, syncResults, fmt.Sprintf("Synchronized %d repositories", len(syncResults)))
}

// performRepositorySync performs the actual sync/clone operation for a repository
// This is extracted from runPayloadRepositorySync to be reusable
func performRepositorySync(ctx context.Context, repo *coremodels.PayloadRepositoryDB, verbose bool) coremodels.Result[*coremodels.PayloadRepositoryDB] {
	// Initialize database connection
	db, err := getDatabaseConnection()
	if err != nil {
		return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to initialize database: %w", err))
	}
	defer db.Close()

	repoRepository := repositories.NewPayloadRepositoryRepository(db)
	payloadRepository := repositories.NewPayloadRepository(db)

	// Initialize Git service with system git enabled for SSH support
	gitConfig := services.GitServiceConfig{
		DefaultDepth:  1,
		DefaultBranch: "main",
		BaseDir:       filepath.Join(os.TempDir(), "gibson-repos"),
		UseSystemGit:  true, // Enable system git for proper SSH agent support
	}
	gitService := services.NewGitService(gitConfig)

	// Check if LocalPath is empty and generate one if needed
	if repo.LocalPath == "" {
		repoService := services.NewPayloadRepositoryService()
		localPath, err := repoService.GenerateLocalPath(repo.Name)
		if err != nil {
			return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to generate local path for repository '%s': %w", repo.Name, err))
		}
		repo.LocalPath = localPath

		// Update repository with the new LocalPath
		updateResult := repoRepository.Update(ctx, repo)
		if updateResult.IsErr() {
			return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to update repository '%s' with local path: %w", repo.Name, updateResult.Error()))
		}
		repo = updateResult.Unwrap()
	}

	// Perform clone operation (new repositories always need cloning)
	cloneResult := gitService.Clone(ctx, services.GitCloneOptions{
		URL:       repo.URL,
		LocalPath: repo.LocalPath,
		Branch:    repo.Branch,
		Depth:     repo.GetCloneDepthValue(),
		AuthType:  repo.AuthType,
		Full:      repo.IsFullClone,
	})
	if cloneResult.IsErr() {
		errorHelper := cli.NewGitErrorHelpers(verbose, false)
		errorHelper.HandleCloneError(cloneResult.Error(), repo.Name, repo.URL)
		return coremodels.Err[*coremodels.PayloadRepositoryDB](cloneResult.Error())
	}

	// Update repository status to active before payload sync
	repo.Status = coremodels.PayloadRepositoryStatusActive
	updateResult := repoRepository.Update(ctx, repo)
	if updateResult.IsErr() {
		return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to update repository status '%s': %w", repo.Name, updateResult.Error()))
	}
	repo = updateResult.Unwrap()

	// NOW IMPORT PAYLOADS: Initialize payload synchronizer and sync payloads from cloned repository
	syncConfig := services.PayloadSyncConfig{
		BatchSize: 100,
		DiscoveryPaths: []string{
			"*.yaml", "*.yml", "*.json", "*.txt", "*.payload", "*.md",
		},
	}
	payloadSynchronizer := services.NewPayloadSynchronizer(db, syncConfig)

	if verbose {
		fmt.Printf("Importing payloads from repository '%s'...\n", repo.Name)
	}

	// Sync payloads from filesystem to database
	syncResult := payloadSynchronizer.SyncRepositoryPayloads(ctx, repo, payloadRepository)
	if syncResult.IsErr() {
		fmt.Printf("Warning: Payload import failed for repository '%s': %v\n", repo.Name, syncResult.Error())
		// Don't fail the entire sync if payload import fails - repository was cloned successfully
	} else {
		// Display sync results
		syncData := syncResult.Unwrap()
		if verbose {
			fmt.Printf("Payload import completed for repository '%s':\n", repo.Name)
			fmt.Printf("  Total files discovered: %d\n", syncData.TotalFiles)
			fmt.Printf("  New payloads imported: %d\n", syncData.NewPayloads)
			fmt.Printf("  Updated payloads: %d\n", syncData.UpdatedPayloads)
			fmt.Printf("  Skipped files: %d\n", syncData.SkippedFiles)
			fmt.Printf("  Error files: %d\n", syncData.ErrorFiles)
			fmt.Printf("  Import duration: %v\n", syncData.Duration)
		} else {
			fmt.Printf("Imported %d payloads from repository '%s'\n", syncData.NewPayloads, repo.Name)
		}
	}

	// Update repository with sync timestamp and payload count
	now := time.Now()
	repo.LastSyncAt = &now

	// Get updated payload count for this repository
	payloadCountResult := payloadRepository.CountByRepository(ctx, repo.ID)
	if payloadCountResult.IsOk() {
		repo.PayloadCount = payloadCountResult.Unwrap()
	}

	// Final repository update with sync metadata
	finalUpdateResult := repoRepository.Update(ctx, repo)
	if finalUpdateResult.IsErr() {
		return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to update repository sync metadata '%s': %w", repo.Name, finalUpdateResult.Error()))
	}

	return coremodels.Ok(finalUpdateResult.Unwrap())
}

// runPayloadRepositoryRemove implements the repository remove command
func runPayloadRepositoryRemove(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	if len(args) == 0 {
		return fmt.Errorf("at least one repository name is required")
	}

	force, _ := cmd.Flags().GetBool("force")
	purgePayloads, _ := cmd.Flags().GetBool("purge-payloads")
	outputFormat, _ := cmd.Flags().GetString("output")

	// Initialize database and repository
	db, err := getDatabaseConnection()
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	repoRepository := repositories.NewPayloadRepositoryRepository(db)
	removedRepos := make([]*coremodels.PayloadRepositoryDB, 0)

	// Remove each repository
	for _, name := range args {
		// Get repository by name
		result := repoRepository.GetByName(ctx, name)
		if result.IsErr() {
			fmt.Printf("Repository '%s' not found: %v\n", name, result.Error())
			continue
		}

		repo := result.Unwrap()

		// Confirmation prompt (unless force flag is used)
		if !force {
			fmt.Printf("Are you sure you want to remove repository '%s'? [y/N]: ", name)
			var response string
			fmt.Scanln(&response)
			if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
				fmt.Printf("Skipping removal of repository '%s'\n", name)
				continue
			}
		}

		// TODO: If purgePayloads is true, remove all payloads from this repository
		if purgePayloads {
			fmt.Printf("Purging payloads for repository '%s' (not yet implemented)\n", name)
		}

		// Remove the local repository directory if it exists
		if repo.LocalPath != "" {
			if err := os.RemoveAll(repo.LocalPath); err != nil {
				// Check if directory doesn't exist (not an error)
				if !os.IsNotExist(err) {
					fmt.Printf("Warning: Failed to remove local repository directory '%s': %v\n", repo.LocalPath, err)
					// Continue with database removal even if directory deletion fails
				}
			} else {
				fmt.Printf("Removed local repository directory: %s\n", repo.LocalPath)
			}
		}

		// Remove repository from database
		deleteResult := repoRepository.Delete(ctx, repo.ID)
		if deleteResult.IsErr() {
			fmt.Printf("Failed to remove repository '%s': %v\n", name, deleteResult.Error())
			continue
		}

		removedRepos = append(removedRepos, repo)
		fmt.Printf("Successfully removed repository '%s'\n", name)
	}

	// Output results
	return outputPayloadRepository(outputFormat, removedRepos, fmt.Sprintf("Removed %d repositories", len(removedRepos)))
}

// getDatabaseConnection gets a database connection using the existing dao pattern
func getDatabaseConnection() (*sqlx.DB, error) {
	// Get Gibson home directory
	gibsonHome := os.Getenv("GIBSON_HOME")
	if gibsonHome == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		gibsonHome = filepath.Join(homeDir, ".gibson")
	}

	// Database path
	dbPath := filepath.Join(gibsonHome, "gibson.db")
	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000", dbPath)

	// Initialize SQLite factory
	factory, err := dao.NewSQLiteFactory(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to create database factory: %w", err)
	}

	return factory.DB(), nil
}

// hasAnyTag checks if any of the provided tags exist in the repository tags
func hasAnyTag(repoTags, filterTags []string) bool {
	for _, filterTag := range filterTags {
		for _, repoTag := range repoTags {
			if strings.EqualFold(repoTag, filterTag) {
				return true
			}
		}
	}
	return false
}

// outputPayloadRepository outputs repository data in the specified format
func outputPayloadRepository(format string, repos []*coremodels.PayloadRepositoryDB, message string) error {
	if message != "" && format == "table" {
		fmt.Println(message)
	}

	switch strings.ToLower(format) {
	case "json":
		return outputRepositoryJSON(repos)
	case "yaml":
		return outputRepositoryYAML(repos)
	case "table":
		return outputRepositoryTable(repos)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// outputRepositoryTable outputs repositories in table format
func outputRepositoryTable(repos []*coremodels.PayloadRepositoryDB) error {
	if len(repos) == 0 {
		fmt.Println("No repositories found")
		return nil
	}

	// Table headers
	fmt.Printf("%-20s %-40s %-10s %-10s %-8s %-10s %-15s\n",
		"NAME", "URL", "BRANCH", "STATUS", "DEPTH", "PAYLOADS", "LAST SYNC")
	fmt.Println(strings.Repeat("-", 120))

	// Table rows
	for _, repo := range repos {
		depth := "full"
		if !repo.IsFullClone {
			depth = fmt.Sprintf("%d", repo.CloneDepth)
		}

		lastSync := "Never"
		if repo.LastSyncAt != nil {
			lastSync = repo.LastSyncAt.Format("2006-01-02 15:04")
		}

		// Truncate long URLs
		url := repo.URL
		if len(url) > 38 {
			url = url[:35] + "..."
		}

		fmt.Printf("%-20s %-40s %-10s %-10s %-8s %-10d %-15s\n",
			truncateString(repo.Name, 20),
			url,
			repo.Branch,
			string(repo.Status),
			depth,
			repo.PayloadCount,
			lastSync,
		)
	}

	fmt.Printf("\nShowing %d repositories\n", len(repos))
	return nil
}

// outputRepositoryJSON outputs repositories in JSON format
func outputRepositoryJSON(repos []*coremodels.PayloadRepositoryDB) error {
	type RepositoryOutput struct {
		ID          string    `json:"id"`
		Name        string    `json:"name"`
		URL         string    `json:"url"`
		Branch      string    `json:"branch"`
		Status      string    `json:"status"`
		CloneDepth  int       `json:"clone_depth"`
		IsFullClone bool      `json:"is_full_clone"`
		PayloadCount int64    `json:"payload_count"`
		LastSyncAt  *time.Time `json:"last_sync_at"`
		Description string    `json:"description"`
		Tags        []string  `json:"tags"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
	}

	type Output struct {
		Repositories []RepositoryOutput `json:"repositories"`
	}

	output := Output{Repositories: make([]RepositoryOutput, len(repos))}
	for i, repo := range repos {
		output.Repositories[i] = RepositoryOutput{
			ID:          repo.ID.String(),
			Name:        repo.Name,
			URL:         repo.URL,
			Branch:      repo.Branch,
			Status:      string(repo.Status),
			CloneDepth:  repo.CloneDepth,
			IsFullClone: repo.IsFullClone,
			PayloadCount: repo.PayloadCount,
			LastSyncAt:  repo.LastSyncAt,
			Description: repo.Description,
			Tags:        repo.Tags,
			CreatedAt:   repo.CreatedAt,
			UpdatedAt:   repo.UpdatedAt,
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// outputRepositoryYAML outputs repositories in YAML format
func outputRepositoryYAML(repos []*coremodels.PayloadRepositoryDB) error {
	type RepositoryOutput struct {
		ID          string    `yaml:"id"`
		Name        string    `yaml:"name"`
		URL         string    `yaml:"url"`
		Branch      string    `yaml:"branch"`
		Status      string    `yaml:"status"`
		CloneDepth  int       `yaml:"clone_depth"`
		IsFullClone bool      `yaml:"is_full_clone"`
		PayloadCount int64    `yaml:"payload_count"`
		LastSyncAt  *time.Time `yaml:"last_sync_at"`
		Description string    `yaml:"description"`
		Tags        []string  `yaml:"tags"`
		CreatedAt   time.Time `yaml:"created_at"`
		UpdatedAt   time.Time `yaml:"updated_at"`
	}

	type Output struct {
		Repositories []RepositoryOutput `yaml:"repositories"`
	}

	output := Output{Repositories: make([]RepositoryOutput, len(repos))}
	for i, repo := range repos {
		output.Repositories[i] = RepositoryOutput{
			ID:          repo.ID.String(),
			Name:        repo.Name,
			URL:         repo.URL,
			Branch:      repo.Branch,
			Status:      string(repo.Status),
			CloneDepth:  repo.CloneDepth,
			IsFullClone: repo.IsFullClone,
			PayloadCount: repo.PayloadCount,
			LastSyncAt:  repo.LastSyncAt,
			Description: repo.Description,
			Tags:        repo.Tags,
			CreatedAt:   repo.CreatedAt,
			UpdatedAt:   repo.UpdatedAt,
		}
	}

	encoder := yaml.NewEncoder(os.Stdout)
	return encoder.Encode(output)
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// showRepositoryErrorGuidance displays comprehensive error handling guidance for repository operations
func showRepositoryErrorGuidance() {
	fmt.Println("Git Repository Error Handling & Troubleshooting Guide")
	fmt.Println("========================================================")
	fmt.Println()

	fmt.Println("Common Repository Issues and Solutions:")
	fmt.Println()

	fmt.Println("1. Authentication Problems:")
	fmt.Println("   • SSH Key Issues:")
	fmt.Println("     - Ensure SSH key is added to ssh-agent: ssh-add ~/.ssh/id_rsa")
	fmt.Println("     - Verify key is uploaded to Git provider (GitHub/GitLab)")
	fmt.Println("     - Test SSH connection: ssh -T git@github.com")
	fmt.Println("   • HTTPS Token Issues:")
	fmt.Println("     - Verify personal access token has correct permissions")
	fmt.Println("     - Check token expiration date")
	fmt.Println("     - Ensure token includes 'repo' scope for private repositories")
	fmt.Println()

	fmt.Println("2. Network Connectivity:")
	fmt.Println("   • Firewall/Proxy Issues:")
	fmt.Println("     - Configure Git proxy: git config --global http.proxy http://proxy:port")
	fmt.Println("     - Test connectivity: ping github.com")
	fmt.Println("     - Check corporate firewall settings")
	fmt.Println("   • DNS Resolution:")
	fmt.Println("     - Verify DNS settings: nslookup github.com")
	fmt.Println("     - Try alternative DNS servers (8.8.8.8, 1.1.1.1)")
	fmt.Println()

	fmt.Println("3. Repository Access:")
	fmt.Println("   • Permission Denied:")
	fmt.Println("     - Verify you have read access to the repository")
	fmt.Println("     - Check if repository is private and requires authentication")
	fmt.Println("     - Confirm repository URL is correct")
	fmt.Println("   • Repository Not Found:")
	fmt.Println("     - Double-check repository URL for typos")
	fmt.Println("     - Verify repository exists and hasn't been moved/deleted")
	fmt.Println("     - Check if you're using the correct case (URLs are case-sensitive)")
	fmt.Println()

	fmt.Println("4. Gibson-Specific Solutions:")
	fmt.Println("   • Credential Management:")
	fmt.Println("     - Add Git credentials: gibson credential add --name git-token --type token")
	fmt.Println("     - List credentials: gibson credential list")
	fmt.Println("     - Validate credentials: gibson credential validate --name git-token")
	fmt.Println("   • Repository Operations:")
	fmt.Println("     - Test repository access: gibson payload repository add test-repo URL --force")
	fmt.Println("     - Use verbose mode: gibson payload repository sync --verbose")
	fmt.Println("     - Check repository status: gibson payload repository list --show-status")
	fmt.Println()

	fmt.Println("5. Common Error Codes:")
	fmt.Println("   • AUTH_FAILED: Authentication credentials are invalid or missing")
	fmt.Println("   • REPO_NOT_FOUND: Repository doesn't exist or you don't have access")
	fmt.Println("   • NETWORK_ERROR: Network connectivity or DNS resolution issue")
	fmt.Println("   • INVALID_URL_FORMAT: Repository URL format is incorrect")
	fmt.Println("   • CLONE_FAILED: Git clone operation failed")
	fmt.Println()

	fmt.Println("For more help:")
	fmt.Println("   • Run commands with --verbose for detailed error information")
	fmt.Println("   • Check Gibson logs: gibson logs --component git --level error")
	fmt.Println("   • View troubleshooting guide: gibson help troubleshooting")
	fmt.Println("   • Submit issues: https://github.com/gibson-sec/gibson-framework/issues")
}

// showSyncErrorGuidance displays comprehensive error handling guidance for sync operations
func showSyncErrorGuidance() {
	fmt.Println("Git Repository Synchronization Troubleshooting Guide")
	fmt.Println("=====================================================")
	fmt.Println()

	fmt.Println("Sync Operation Issues and Solutions:")
	fmt.Println()

	fmt.Println("1. Repository State Problems:")
	fmt.Println("   • Local Repository Corruption:")
	fmt.Println("     - Remove corrupted repository: rm -rf ~/.gibson/repos/repository-name")
	fmt.Println("     - Re-clone repository: gibson payload repository sync repository-name --force")
	fmt.Println("     - Check disk space: df -h")
	fmt.Println("   • Uncommitted Changes:")
	fmt.Println("     - Gibson repositories are read-only, this shouldn't occur")
	fmt.Println("     - If it happens, remove and re-clone the repository")
	fmt.Println()

	fmt.Println("2. Network and Connectivity:")
	fmt.Println("   • Intermittent Network Issues:")
	fmt.Println("     - Retry sync operation: gibson payload repository sync --force")
	fmt.Println("     - Check network stability: ping -c 10 github.com")
	fmt.Println("     - Use wired connection if on WiFi")
	fmt.Println("   • Rate Limiting:")
	fmt.Println("     - Wait and retry later (GitHub: 60 requests/hour without auth)")
	fmt.Println("     - Use authentication to increase rate limits")
	fmt.Println("     - Implement exponential backoff for automated syncs")
	fmt.Println()

	fmt.Println("3. Authentication Issues During Sync:")
	fmt.Println("   • Expired Credentials:")
	fmt.Println("     - Update credentials: gibson credential update --name git-token")
	fmt.Println("     - Check token expiration: gibson credential show --name git-token")
	fmt.Println("     - Rotate credentials: gibson credential rotate --name git-token")
	fmt.Println("   • SSH Key Problems:")
	fmt.Println("     - Re-add SSH key to agent: ssh-add ~/.ssh/id_rsa")
	fmt.Println("     - Verify SSH connection: ssh -T git@github.com")
	fmt.Println("     - Check SSH key permissions: chmod 600 ~/.ssh/id_rsa")
	fmt.Println()

	fmt.Println("4. Payload Processing Issues:")
	fmt.Println("   • Malformed Payload Files:")
	fmt.Println("     - Check payload file format in repository")
	fmt.Println("     - Validate JSON/YAML syntax")
	fmt.Println("     - Review payload schema requirements")
	fmt.Println("   • Missing Dependencies:")
	fmt.Println("     - Ensure repository contains valid payload structure")
	fmt.Println("     - Check for required metadata files")
	fmt.Println("     - Verify payload categories are supported")
	fmt.Println()

	fmt.Println("5. Performance and Resources:")
	fmt.Println("   • Large Repository Sync:")
	fmt.Println("     - Use shallow clone: gibson payload repository add repo URL --depth 1")
	fmt.Println("     - Monitor disk space: gibson status --component system")
	fmt.Println("     - Sync specific branches: --branch main")
	fmt.Println("   • Memory Issues:")
	fmt.Println("     - Reduce concurrent syncs")
	fmt.Println("     - Check system resources: gibson status --verbose")
	fmt.Println("     - Increase system memory if needed")
	fmt.Println()

	fmt.Println("6. Recovery Procedures:")
	fmt.Println("   • Complete Sync Failure:")
	fmt.Println("     - Remove repository: gibson payload repository remove repo-name")
	fmt.Println("     - Re-add repository: gibson payload repository add repo-name URL")
	fmt.Println("     - Verify repository health: gibson payload repository list --show-status")
	fmt.Println("   • Partial Sync Success:")
	fmt.Println("     - Check which payloads were synced: gibson payload list --repository repo-name")
	fmt.Println("     - Force re-sync: gibson payload repository sync repo-name --force")
	fmt.Println("     - Monitor sync progress: gibson payload repository sync --progress")
	fmt.Println()

	fmt.Println("Diagnostic Commands:")
	fmt.Println("   • Check repository status: gibson payload repository list --show-status")
	fmt.Println("   • View sync history: gibson logs --component sync --since 24h")
	fmt.Println("   • Test Git operations: git ls-remote URL")
	fmt.Println("   • Validate payloads: gibson payload list --repository repo-name")
	fmt.Println()

	fmt.Println("Prevention Best Practices:")
	fmt.Println("   • Use stable network connections for sync operations")
	fmt.Println("   • Implement credential rotation schedules")
	fmt.Println("   • Monitor repository health regularly")
	fmt.Println("   • Keep local Gibson installation updated")
	fmt.Println("   • Use shallow clones for large repositories")
}

// runGenerateTemplate implements the repository template generation command
func runGenerateTemplate(cmd *cobra.Command, args []string) error {
	path := args[0]
	force, _ := cmd.Flags().GetBool("force")
	output, _ := cmd.Flags().GetString("output")

	// Create repository template service
	templateService := services.NewRepositoryTemplateService()

	// Generate repository template
	result := templateService.GenerateRepository(path, force)
	if result.IsErr() {
		return fmt.Errorf("failed to generate repository template: %w", result.Error())
	}

	// Output success message based on format
	switch strings.ToLower(output) {
	case "json":
		response := map[string]interface{}{
			"status": "success",
			"message": result.Unwrap(),
			"path": path,
			"timestamp": time.Now().Format(time.RFC3339),
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(response)
	case "yaml":
		response := map[string]interface{}{
			"status": "success",
			"message": result.Unwrap(),
			"path": path,
			"timestamp": time.Now().Format(time.RFC3339),
		}
		return yaml.NewEncoder(os.Stdout).Encode(response)
	default:
		fmt.Println(result.Unwrap())
		fmt.Printf("\nRepository structure created with the following contents:\n")
		fmt.Printf("  manifest.json          - Repository metadata\n")
		fmt.Printf("  compatibility.json     - Version compatibility matrix\n")
		fmt.Printf("  schemas/               - JSON schemas for validation\n")
		fmt.Printf("  README.md              - Repository documentation\n")
		fmt.Printf("  <domain>/              - Domain-specific payload directories\n")
		fmt.Printf("\nNext steps:\n")
		fmt.Printf("1. Add payloads to domain directories\n")
		fmt.Printf("2. Validate payloads: gibson payload repository add %s <repo-url>\n", filepath.Base(path))
		fmt.Printf("3. Test import: gibson payload repository sync <repo-name>\n")
	}

	return nil
}

