// SPDX-License-Identifier: MIT
// Copyright Authors of Gibson

package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/dao"
	"github.com/spf13/cobra"
)

var (
	initForceFlag       *bool
	initConfigPathFlag  *string
	initNoDatabaseFlag  *bool
	initSkipSamplesFlag *bool
	initVerboseFlag     *bool
	initQuietFlag       *bool
)

// initCmd creates the init command following the current k9s-style patterns
func initCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Gibson directory structure and configuration",
		Long: `Initialize Gibson directory structure and configuration.

This command sets up the complete Gibson environment by:
• Creating the ~/.gibson directory structure
• Generating a default configuration file (config.yaml)
• Initializing the SQLite database (gibson.db)
• Running all database migrations
• Setting up required subdirectories (plugins, payloads, reports, logs, temp)

If the ~/.gibson directory already exists, Gibson will prompt for confirmation
before reinitializing unless the --force flag is used.

Directory Structure Created:
  ~/.gibson/
  ├── config.yaml          # Main configuration file
  ├── gibson.db            # SQLite database
  ├── plugins/             # External plugins directory
  ├── payloads/            # Attack payloads directory
  ├── reports/             # Generated reports
  ├── logs/                # Application logs
  └── temp/                # Temporary files`,
		Example: `  # Initialize Gibson with default settings
  gibson init

  # Force initialization without prompting
  gibson init --force

  # Initialize with custom config location
  gibson init --config /path/to/custom/config.yaml

  # Initialize without setting up database
  gibson init --no-database

  # Quiet initialization (minimal output)
  gibson init --quiet`,
		RunE: runInit,
	}

	// Add flags following k9s pointer patterns
	initForceFlag = cmd.Flags().Bool("force", false,
		"Force initialization without prompting for confirmation")
	initConfigPathFlag = cmd.Flags().StringP("config", "c", "",
		"Custom configuration file path (default: ~/.gibson/config.yaml)")
	initNoDatabaseFlag = cmd.Flags().Bool("no-database", false,
		"Skip database initialization")
	initSkipSamplesFlag = cmd.Flags().Bool("skip-samples", false,
		"Skip creation of sample configurations and documentation")
	initVerboseFlag = cmd.Flags().BoolP("verbose", "v", false,
		"Enable verbose output during initialization")
	initQuietFlag = cmd.Flags().BoolP("quiet", "q", false,
		"Minimize output during initialization")

	return cmd
}

// runInit executes the init command
func runInit(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Override verbosity based on flags
	quiet := getBoolValue(initQuietFlag)
	verbose := getBoolValue(initVerboseFlag)
	if quiet {
		verbose = false
	}

	// Determine Gibson home directory
	gibsonHome := getGibsonHome()

	// Determine config path
	configPath := getValue(initConfigPathFlag)
	if configPath == "" {
		configPath = getDefaultConfigPath()
	}

	// Check if Gibson is already initialized
	force := getBoolValue(initForceFlag)
	if !force {
		if err := checkExistingInstallation(gibsonHome, configPath); err != nil {
			return err
		}
	}

	// Initialize step tracker
	stepTracker := &initStepTracker{
		verbose: verbose,
		quiet:   quiet,
	}

	// Step 1: Create directory structure
	if err := stepTracker.executeStep("Creating directory structure", func() error {
		return createDirectoryStructure(gibsonHome)
	}); err != nil {
		return err
	}

	// Step 2: Generate configuration file
	if err := stepTracker.executeStep("Generating configuration file", func() error {
		return generateConfigFile(configPath, gibsonHome)
	}); err != nil {
		return err
	}

	// Step 3: Initialize database (unless skipped)
	noDatabase := getBoolValue(initNoDatabaseFlag)
	if !noDatabase {
		if err := stepTracker.executeStep("Initializing database", func() error {
			return initializeDatabase(ctx, gibsonHome)
		}); err != nil {
			return err
		}
	} else {
		stepTracker.skip("Database initialization (--no-database flag)")
	}

	// Step 4: Setup encryption
	if err := stepTracker.executeStep("Setting up encryption", func() error {
		return setupEncryption(gibsonHome)
	}); err != nil {
		return err
	}

	// Step 5: Create sample configurations (unless skipped)
	skipSamples := getBoolValue(initSkipSamplesFlag)
	if !skipSamples {
		if err := stepTracker.executeStep("Creating sample configurations", func() error {
			return createSampleConfigurations(gibsonHome)
		}); err != nil {
			slog.Warn("Failed to create sample configurations", "error", err)
			// Don't fail initialization for sample configs
		}
	} else {
		stepTracker.skip("Sample configurations (--skip-samples flag)")
	}

	// Step 6: Validate installation
	if err := stepTracker.executeStep("Validating installation", func() error {
		return validateInstallation(gibsonHome, configPath, !noDatabase)
	}); err != nil {
		return err
	}

	// Print success message
	if !quiet {
		printSuccessMessage(gibsonHome, configPath, noDatabase)
	}

	return nil
}

// checkExistingInstallation checks if Gibson is already initialized and prompts for confirmation
func checkExistingInstallation(gibsonHome, configPath string) error {
	// Check if Gibson home directory exists
	if _, err := os.Stat(gibsonHome); err == nil {
		fmt.Printf("Gibson directory already exists at: %s\n", gibsonHome)

		// Check if config file exists
		if _, err := os.Stat(configPath); err == nil {
			fmt.Printf("Configuration file already exists at: %s\n", configPath)
		}

		// Prompt for confirmation
		fmt.Print("\nThis will overwrite existing configuration. Continue? [y/N]: ")
		var response string
		if _, err := fmt.Scanln(&response); err != nil {
			response = "n"
		}

		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" && response != "yes" {
			return fmt.Errorf("initialization cancelled by user")
		}
	}

	return nil
}

// createDirectoryStructure creates the required Gibson directory structure
func createDirectoryStructure(gibsonHome string) error {
	requiredDirs := getRequiredDirectories()

	for _, dir := range requiredDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Set appropriate permissions for sensitive directories
	sensitiveMode := fs.FileMode(0750)
	sensitiveDirs := []string{
		filepath.Join(gibsonHome, "logs"),
		filepath.Join(gibsonHome, "temp"),
	}

	for _, dir := range sensitiveDirs {
		if err := os.Chmod(dir, sensitiveMode); err != nil {
			return fmt.Errorf("failed to set permissions for %s: %w", dir, err)
		}
	}

	return nil
}

// generateConfigFile creates the default configuration file
func generateConfigFile(configPath, gibsonHome string) error {
	// Ensure config directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Generate configuration content
	configContent := generateConfigContent(gibsonHome)

	// Write configuration file
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// generateConfigContent generates the YAML configuration content
func generateConfigContent(gibsonHome string) string {
	// Get the config template and customize paths
	template := getConfigFileTemplate()

	// Replace template paths with actual paths
	replacements := map[string]string{
		"~/.gibson":           gibsonHome,
		"~/.gibson/gibson.db": filepath.Join(gibsonHome, "gibson.db"),
		"~/.gibson/plugins":   filepath.Join(gibsonHome, "plugins"),
		"~/.gibson/payloads":  filepath.Join(gibsonHome, "payloads"),
		"~/.gibson/reports":   filepath.Join(gibsonHome, "reports"),
		"~/.gibson/logs":      filepath.Join(gibsonHome, "logs"),
		"~/.gibson/temp":      filepath.Join(gibsonHome, "temp"),
	}

	content := template
	for old, new := range replacements {
		content = strings.ReplaceAll(content, old, new)
	}

	// Add timestamp and version info
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	header := fmt.Sprintf("# Gibson Configuration File\n# Generated on: %s\n# Framework Version: %s\n\n", timestamp, version)

	return header + content
}

// initializeDatabase creates and initializes the SQLite database
func initializeDatabase(ctx context.Context, gibsonHome string) error {
	dbPath := filepath.Join(gibsonHome, "gibson.db")

	// Build SQLite DSN with basic configuration
	// WAL mode and foreign keys are set by the factory via PRAGMA statements
	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000", dbPath)

	// Initialize SQLite repository with proper database setup and migrations
	repo, err := dao.NewSQLiteRepository(dsn)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer repo.Close()

	// Perform health check to ensure database is properly initialized
	if err := repo.Health(); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	// Database initialized successfully - silent logging
	return nil
}

// validateInstallation verifies that the installation was successful
func validateInstallation(gibsonHome, configPath string, checkDatabase bool) error {
	// Check if all required directories exist
	requiredDirs := getRequiredDirectories()
	for _, dir := range requiredDirs {
		if _, err := os.Stat(dir); err != nil {
			return fmt.Errorf("required directory missing: %s", dir)
		}
	}

	// Check if configuration file exists and is readable
	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("configuration file not found: %s", configPath)
	}

	// Check database if requested
	if checkDatabase {
		dbPath := filepath.Join(gibsonHome, "gibson.db")
		if _, err := os.Stat(dbPath); err != nil {
			return fmt.Errorf("database file not found: %s", dbPath)
		}
	}

	// Check that encryption key exists
	encryptionKeyPath := filepath.Join(gibsonHome, ".encryption_key")
	if _, err := os.Stat(encryptionKeyPath); err != nil {
		return fmt.Errorf("encryption key file not found: %s", encryptionKeyPath)
	}

	return nil
}

// printSuccessMessage displays the success message after initialization
func printSuccessMessage(gibsonHome, configPath string, skipDatabase bool) {
	// Determine if samples were created
	samplesCreated := true
	if _, err := os.Stat(filepath.Join(gibsonHome, "README.md")); err != nil {
		samplesCreated = false
	}

	fmt.Printf("\n🎉 Gibson initialization completed successfully!\n\n")
	fmt.Printf("📁 Gibson Home: %s\n", gibsonHome)
	fmt.Printf("⚙️  Config File: %s\n", configPath)

	if !skipDatabase {
		dbPath := filepath.Join(gibsonHome, "gibson.db")
		fmt.Printf("🗄️  Database: %s\n", dbPath)
	}

	if samplesCreated {
		fmt.Printf("📖 Documentation: %s/README.md\n", gibsonHome)
	}

	fmt.Println("\nNext steps:")
	fmt.Println("1. Configure your LLM provider credentials:")
	fmt.Println("   gibson credentials add --provider openai")
	fmt.Println("2. Add a target for scanning:")
	fmt.Println("   gibson target add")
	fmt.Println("3. Run your first security scan:")
	fmt.Println("   gibson scan api <target>")
	fmt.Println("4. View available plugins:")
	fmt.Println("   gibson plugin list")

	fmt.Println("\nFor help with any command, use: gibson <command> --help")
}

// initStepTracker tracks and reports initialization progress
type initStepTracker struct {
	step    int
	verbose bool
	quiet   bool
}

// executeStep executes a step with progress reporting
func (t *initStepTracker) executeStep(description string, fn func() error) error {
	t.step++

	if !t.quiet {
		if t.verbose {
			fmt.Printf("Step %d: %s...\n", t.step, description)
		} else {
			fmt.Printf("⏳ %s...", description)
		}
	}

	start := time.Now()
	err := fn()
	duration := time.Since(start)

	if !t.quiet {
		if err == nil {
			if t.verbose {
				fmt.Printf("✅ %s completed in %v\n", description, duration)
			} else {
				fmt.Printf(" ✅\n")
			}
		} else {
			if t.verbose {
				fmt.Printf("❌ %s failed after %v: %v\n", description, duration, err)
			} else {
				fmt.Printf(" ❌\n")
			}
		}
	}

	return err
}

// skip reports a skipped step
func (t *initStepTracker) skip(description string) {
	if !t.quiet {
		if t.verbose {
			fmt.Printf("⏭️  %s (skipped)\n", description)
		} else {
			fmt.Printf("⏭️  %s\n", description)
		}
	}
}

// setupEncryption sets up encryption keys for secure credential storage
func setupEncryption(gibsonHome string) error {
	// Generate a new encryption key (32 bytes for AES-256)
	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		return fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// Encode the key as base64 for storage
	encodedKey := base64.StdEncoding.EncodeToString(encryptionKey)

	// Store the key securely
	keyFile := filepath.Join(gibsonHome, ".encryption_key")
	if err := os.WriteFile(keyFile, []byte(encodedKey), 0600); err != nil {
		return fmt.Errorf("failed to store encryption key: %w", err)
	}

	// Set restrictive permissions on key file
	if err := os.Chmod(keyFile, 0600); err != nil {
		slog.Warn("Failed to set permissions on encryption key file", "error", err)
	}

	// Clear the key from memory
	for i := range encryptionKey {
		encryptionKey[i] = 0
	}

	// Encryption key generated - silent logging
	return nil
}

// createSampleConfigurations creates sample configuration files and documentation
func createSampleConfigurations(gibsonHome string) error {
	// Create README file with usage instructions
	readmeContent := `# Gibson AI Security Testing Framework

Welcome to Gibson! This directory contains your Gibson configuration and data.

## Directory Structure

- **config.yaml**: Main configuration file
- **gibson.db**: SQLite database containing scan results, targets, and settings
- **plugins/**: Directory for security testing plugins
  - **external/**: User-installed external plugins
- **payloads/**: Attack payloads and test data
- **reports/**: Generated security reports
- **logs/**: Application logs
- **temp/**: Temporary files
- **backups/**: Database backups

## Getting Started

1. **Add LLM Provider Credentials**:
   ` + "`gibson credentials add --provider openai --type api_key`" + `

2. **Add a Target for Testing**:
   ` + "`gibson target add --name \"My API\" --url \"https://api.example.com\"`" + `

3. **Run Your First Security Scan**:
   ` + "`gibson scan api https://api.example.com`" + `

4. **Generate a Security Report**:
   ` + "`gibson report generate --scan-id <scan-id>`" + `

## Configuration

Edit ` + "`config.yaml`" + ` to customize Gibson's behavior:

- **LLM Providers**: Configure API keys and endpoints
- **Security Settings**: Adjust encryption and validation
- **Plugin Settings**: Control plugin loading and discovery
- **Output Options**: Customize report formats and verbosity

## Environment Variables

Override configuration with environment variables using the GIBSON_ prefix:

` + "`GIBSON_LLM_DEFAULT_PROVIDER=anthropic gibson scan api <target>`" + `

## Security

- Credentials are encrypted using AES-256-GCM
- Database uses WAL mode for better concurrency
- All file paths are sanitized to prevent directory traversal
- Input validation prevents injection attacks

## Support

For help and documentation:
- Run ` + "`gibson --help`" + ` for command reference
- Visit: https://github.com/gibson-sec/gibson
- Report issues: https://github.com/gibson-sec/gibson/issues
`

	readmePath := filepath.Join(gibsonHome, "README.md")
	if err := os.WriteFile(readmePath, []byte(readmeContent), 0644); err != nil {
		slog.Warn("Failed to create README.md", "error", err)
	}


	// Create .gitignore file to ignore sensitive files
	gitignoreContent := `# Gibson AI Security Framework
# Ignore sensitive and temporary files

# Database files
*.db
*.db-journal
*.db-wal
*.db-shm

# Log files
logs/
*.log

# Temporary files
temp/
tmp/
*.tmp

# Backup files
backups/
*.backup

# Credentials and keys
*.key
*.pem
.encryption_key
secrets/

# External plugins (may contain proprietary code)
plugins/external/

# Reports may contain sensitive data
reports/*.json
reports/*.pdf
reports/*.html
`
	gitignorePath := filepath.Join(gibsonHome, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte(gitignoreContent), 0644); err != nil {
		slog.Warn("Failed to create .gitignore file", "error", err)
	}

	// Sample configurations created - silent logging
	return nil
}

// Configuration path helpers
// Note: getValue and getBoolValue are already defined in scan.go

func getGibsonHome() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	return filepath.Join(homeDir, ".gibson")
}

func getDefaultConfigPath() string {
	return filepath.Join(getGibsonHome(), "config.yaml")
}

func getRequiredDirectories() []string {
	gibsonHome := getGibsonHome()
	return []string{
		gibsonHome,
		filepath.Join(gibsonHome, "plugins"),
		filepath.Join(gibsonHome, "plugins", "external"),
		filepath.Join(gibsonHome, "payloads"),
		filepath.Join(gibsonHome, "reports"),
		filepath.Join(gibsonHome, "logs"),
		filepath.Join(gibsonHome, "temp"),
		filepath.Join(gibsonHome, "backups"),
	}
}

func getConfigFileTemplate() string {
	return `# Gibson AI Security Testing Framework Configuration
# This file configures all aspects of the Gibson framework

core:
  parallel_workers: 10          # Number of concurrent workers for scanning
  max_retries: 3                # Maximum retries for failed operations
  timeout: 300                  # Global timeout in seconds
  debug: false                  # Enable debug mode
  log_level: "info"             # Log level: debug, info, warn, error

database:
  path: "~/.gibson/gibson.db"   # SQLite database path
  max_connections: 25           # Maximum database connections
  wal_mode: true                # Enable WAL mode for better concurrency
  auto_vacuum: true             # Enable auto-vacuum
  busy_timeout: 5000            # Busy timeout in milliseconds

llm:
  default_provider: ""          # Default LLM provider (openai, anthropic, etc.)
  timeout: 120                  # LLM request timeout in seconds
  max_retries: 3                # Maximum retries for LLM requests
  retry_delay: 2                # Delay between retries in seconds

  providers:
    openai:
      api_key: "${OPENAI_API_KEY}"
      base_url: "https://api.openai.com/v1"
      model: "gpt-4"
      max_tokens: 4096
      temperature: 0.7

    anthropic:
      api_key: "${ANTHROPIC_API_KEY}"
      base_url: "https://api.anthropic.com"
      model: "claude-3-opus-20240229"
      max_tokens: 4096

plugins:
  directory: "~/.gibson/plugins"
  auto_discover: true           # Automatically discover plugins
  enable_external: true         # Enable external plugins
  security_mode: "strict"       # Plugin security: strict, moderate, permissive

payloads:
  directory: "~/.gibson/payloads"
  max_size: 10485760            # Maximum payload size (10MB)
  allowed_types:                # Allowed payload file types
    - ".json"
    - ".yaml"
    - ".txt"
    - ".xml"

security:
  encryption_algorithm: "AES-256-GCM"
  hash_algorithm: "SHA-256"
  validate_ssl: true            # Validate SSL certificates
  sanitize_inputs: true         # Sanitize all user inputs
  max_request_size: 52428800    # Maximum request size (50MB)

reporting:
  directory: "~/.gibson/reports"
  default_format: "json"        # Default report format: json, html, pdf
  include_metadata: true        # Include scan metadata in reports
  compress_reports: false       # Compress large reports

output:
  default_format: "table"       # Default output: table, json, yaml, csv
  color_enabled: true           # Enable colored output
  verbose: false                # Enable verbose output
  quiet: false                  # Minimize output

paths:
  logs: "~/.gibson/logs"
  temp: "~/.gibson/temp"
  backups: "~/.gibson/backups"
`
}