// Package view provides target view implementation for CLI commands
package view

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/dao"
	"github.com/gibson-sec/gibson-framework-2/internal/model"
	"github.com/gibson-sec/gibson-framework-2/internal/providers"
	"github.com/gibson-sec/gibson-framework-2/internal/service"
	"github.com/google/uuid"
	"gopkg.in/yaml.v2"
)

// targetView implements TargetViewer following k9s patterns
type targetView struct {
	serviceFactory *service.ServiceFactory
	targetService  service.TargetService
	logger         *slog.Logger
}

// NewTargetView creates a new target view instance
func NewTargetView() (*targetView, error) {
	// Initialize database connection
	gibsonHome, err := getGibsonHome()
	if err != nil {
		return nil, fmt.Errorf("failed to determine gibson home: %w", err)
	}

	// Initialize repository
	dbPath := filepath.Join(gibsonHome, "gibson.db")
	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000", dbPath)
	repo, err := dao.NewSQLiteRepository(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize repository: %w", err)
	}

	// Read encryption key
	encryptionKey, err := readEncryptionKey(gibsonHome)
	if err != nil {
		return nil, fmt.Errorf("failed to read encryption key: %w", err)
	}

	// Initialize logger
	logger := slog.Default()

	// Create service factory
	serviceFactory := service.NewServiceFactory(repo, logger, encryptionKey)

	return &targetView{
		serviceFactory: serviceFactory,
		targetService:  serviceFactory.TargetService(),
		logger:         logger,
	}, nil
}

// Command integration methods following k9s patterns

// TargetAddOptions defines options for adding a target
type TargetAddOptions struct {
	Name     string
	Provider string
	Model    string
	URL      string
	APIKey   string
	Config   string
	Output   string
}

// AddTarget adds a new AI/ML target
func (tv *targetView) AddTarget(ctx context.Context, opts TargetAddOptions) error {
	tv.logger.Info("Adding new target", "name", opts.Name, "provider", opts.Provider)

	// Validate required fields
	if opts.Name == "" {
		return fmt.Errorf("target name is required")
	}
	if opts.Provider == "" {
		return fmt.Errorf("provider is required")
	}

	// Initialize provider registry for URL resolution
	registry := providers.NewRegistry()
	provider := model.Provider(opts.Provider)

	// Resolve URL using provider registry
	resolvedURL, err := registry.ResolveURL(provider, opts.URL)
	if err != nil {
		return fmt.Errorf("failed to resolve provider URL: %w", err)
	}

	// Show info message when using default URL
	if opts.URL == "" && resolvedURL != "" {
		fmt.Printf("ℹ️  Using langchaingo default URL for provider '%s': %s\n", opts.Provider, resolvedURL)
	}

	// Resolve model with default if not specified
	providerAdapter := providers.NewProviderAdapter()
	resolvedModelResult := providerAdapter.ResolveModelWithDefault(ctx, provider, opts.Model)
	if !resolvedModelResult.IsOk() {
		return fmt.Errorf("failed to resolve model: %w", resolvedModelResult.Error())
	}
	resolvedModel := resolvedModelResult.Unwrap()

	// Show info message when using default model
	if opts.Model == "" && resolvedModel != "" {
		fmt.Printf("ℹ️  Using default model for provider '%s': %s\n", opts.Provider, resolvedModel)
	}

	// Validate model with warning only
	if resolvedModel != "" {
		if modelErr := registry.ValidateModel(provider, resolvedModel); modelErr != nil {
			fmt.Printf("⚠️  Warning: %v\n", modelErr)
		}
	}

	// Enhanced validation for API providers (Requirement 4)
	if err := tv.validateAPIProvider(opts); err != nil {
		return fmt.Errorf("API provider validation failed: %w", err)
	}

	// Check if target with this name already exists
	exists, err := tv.targetService.ExistsByName(ctx, opts.Name)
	if err != nil {
		return fmt.Errorf("failed to check if target exists: %w", err)
	}
	if exists {
		return fmt.Errorf("target with name '%s' already exists", opts.Name)
	}

	// Create target model
	target := &model.Target{
		ID:          uuid.New(),
		Name:        opts.Name,
		Type:        model.TargetTypeAPI, // Default to API
		Provider:    provider,
		Model:       resolvedModel, // Use resolved model (with defaulting)
		URL:         resolvedURL,   // Use resolved URL
		Status:      model.TargetStatusActive,
		Description: "", // Can be updated later
		Tags:        []string{},
		Headers:     make(map[string]string),
		Config:      make(map[string]interface{}),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Enhanced credential linkage (Requirement 4)
	if opts.APIKey != "" {
		credentialID, err := tv.linkCredentialToTarget(ctx, opts)
		if err != nil {
			return fmt.Errorf("failed to link credential to target: %w", err)
		}
		target.CredentialID = credentialID
	}

	// Load config from file if provided
	if opts.Config != "" {
		config, err := tv.loadConfigFromFile(opts.Config)
		if err != nil {
			return fmt.Errorf("failed to load config file: %w", err)
		}
		target.Config = config
	}

	// Create target through service
	if err := tv.targetService.Create(ctx, target); err != nil {
		return fmt.Errorf("failed to create target: %w", err)
	}

	// Display success message
	fmt.Printf("Successfully added target: %s\n", target.Name)
	fmt.Printf("ID: %s\n", target.ID)
	fmt.Printf("Provider: %s\n", target.Provider)
	fmt.Printf("Type: %s\n", target.Type)
	fmt.Printf("Status: %s\n", target.Status)
	if target.Model != "" {
		fmt.Printf("Model: %s\n", target.Model)
	}
	if target.URL != "" {
		fmt.Printf("URL: %s\n", target.URL)
	}
	if target.CredentialID != nil {
		fmt.Printf("Credential: %s\n", *target.CredentialID)
	}

	return nil
}

// TargetListOptions defines options for listing targets
type TargetListOptions struct {
	Output string
}

// ListTargets lists all targets
func (tv *targetView) ListTargets(ctx context.Context, opts TargetListOptions) error {
	tv.logger.Info("Listing targets")

	// Get targets from service
	targets, err := tv.targetService.List(ctx)
	if err != nil {
		return fmt.Errorf("failed to list targets: %w", err)
	}

	if len(targets) == 0 {
		fmt.Println("No targets found")
		return nil
	}

	if opts.Output == "json" {
		jsonData, err := json.MarshalIndent(targets, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else if opts.Output == "yaml" {
		yamlData, err := yaml.Marshal(targets)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML: %w", err)
		}
		fmt.Println(string(yamlData))
	} else {
		// Table format
		fmt.Printf("%-20s %-15s %-12s %-8s %-30s %-20s\n", "NAME", "PROVIDER", "TYPE", "STATUS", "URL", "CREATED")
		fmt.Println(strings.Repeat("-", 110))
		for _, target := range targets {
			fmt.Printf("%-20s %-15s %-12s %-8s %-30s %-20s\n",
				truncateString(target.Name, 20),
				string(target.Provider),
				string(target.Type),
				string(target.Status),
				truncateString(target.URL, 30),
				target.CreatedAt.Format("2006-01-02 15:04"),
			)
		}
	}

	return nil
}

// TargetDeleteOptions defines options for deleting targets
type TargetDeleteOptions struct {
	Name string
	ID   string
}

// DeleteTarget deletes a target
func (tv *targetView) DeleteTarget(ctx context.Context, opts TargetDeleteOptions) error {
	if opts.Name == "" && opts.ID == "" {
		return fmt.Errorf("either target name or ID must be specified")
	}

	var targetID uuid.UUID
	var targetName string
	var err error

	if opts.ID != "" {
		targetID, err = uuid.Parse(opts.ID)
		if err != nil {
			return fmt.Errorf("invalid target ID format: %w", err)
		}
		// Get target to find name for confirmation
		target, err := tv.targetService.Get(ctx, targetID)
		if err != nil {
			return fmt.Errorf("failed to get target: %w", err)
		}
		targetName = target.Name
	} else {
		// Get target by name to find ID
		target, err := tv.targetService.GetByName(ctx, opts.Name)
		if err != nil {
			return fmt.Errorf("failed to find target by name: %w", err)
		}
		targetID = target.ID
		targetName = target.Name
	}

	// Confirm deletion (unless forced in the future)
	fmt.Printf("Are you sure you want to delete target '%s'? (y/N): ", targetName)
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read user input: %w", err)
	}
	response = strings.TrimSpace(strings.ToLower(response))
	if response != "y" && response != "yes" {
		fmt.Println("Deletion cancelled")
		return nil
	}

	tv.logger.Info("Deleting target", "id", targetID, "name", targetName)

	// Delete target through service
	if err := tv.targetService.Delete(ctx, targetID); err != nil {
		return fmt.Errorf("failed to delete target: %w", err)
	}

	fmt.Printf("Successfully deleted target: %s\n", targetName)

	return nil
}

// TargetTestOptions defines options for testing targets
type TargetTestOptions struct {
	Name   string
	ID     string
	Output string
}

// TestTarget tests target connectivity
func (tv *targetView) TestTarget(ctx context.Context, opts TargetTestOptions) error {
	if opts.Name == "" && opts.ID == "" {
		return fmt.Errorf("either target name or ID must be specified")
	}

	var targetID uuid.UUID
	var target *model.Target
	var err error

	if opts.ID != "" {
		targetID, err = uuid.Parse(opts.ID)
		if err != nil {
			return fmt.Errorf("invalid target ID format: %w", err)
		}
		target, err = tv.targetService.Get(ctx, targetID)
	} else {
		target, err = tv.targetService.GetByName(ctx, opts.Name)
		targetID = target.ID
	}

	if err != nil {
		return fmt.Errorf("failed to get target: %w", err)
	}

	tv.logger.Info("Testing target connectivity", "id", targetID, "name", target.Name)

	fmt.Printf("Testing connectivity for target: %s\n", target.Name)

	// Test connection through service and our custom validation
	start := time.Now()
	var connectionError error

	// First test basic configuration validation
	if err := tv.targetService.ValidateConfiguration(ctx, target); err != nil {
		connectionError = fmt.Errorf("configuration validation failed: %w", err)
	} else {
		// Then test actual connectivity
		connectionError = tv.testTargetConnection(ctx, target)
	}

	duration := time.Since(start)

	if opts.Output == "json" {
		result := map[string]interface{}{
			"target_id":     targetID,
			"target_name":   target.Name,
			"success":       connectionError == nil,
			"response_time": duration.String(),
			"tested_at":     time.Now().Format(time.RFC3339),
		}
		if connectionError != nil {
			result["error"] = connectionError.Error()
		}
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		if connectionError != nil {
			fmt.Printf("✗ Connection test FAILED: %v\n", connectionError)
			fmt.Printf("Response time: %v\n", duration)
		} else {
			fmt.Printf("✓ Connection test SUCCESSFUL\n")
			fmt.Printf("Response time: %v\n", duration)
		}
	}

	return nil
}

// TargetUpdateOptions defines options for updating targets
type TargetUpdateOptions struct {
	Name           string
	ID             string
	Provider       string
	Model          string
	URL            string
	APIKey         string
	Config         string
	Output         string
	Headers        string
	Description    string
	Tags           []string
	Validate       bool
	TestConnection bool
	Force          bool
}

// UpdateTarget updates target configuration
func (tv *targetView) UpdateTarget(ctx context.Context, opts TargetUpdateOptions) error {
	if opts.Name == "" && opts.ID == "" {
		return fmt.Errorf("either target name or ID must be specified")
	}

	// Get the target to update
	var target *model.Target
	var err error

	if opts.ID != "" {
		targetID, parseErr := uuid.Parse(opts.ID)
		if parseErr != nil {
			return fmt.Errorf("invalid target ID format: %w", parseErr)
		}
		target, err = tv.targetService.Get(ctx, targetID)
	} else {
		target, err = tv.targetService.GetByName(ctx, opts.Name)
	}

	if err != nil {
		return fmt.Errorf("failed to get target: %w", err)
	}

	tv.logger.Info("Updating target", "id", target.ID, "name", target.Name, "validate", opts.Validate)

	// Track what fields are being updated
	updateCount := 0

	// Update fields if provided
	if opts.Provider != "" {
		target.Provider = model.Provider(opts.Provider)
		updateCount++
	}
	if opts.Model != "" {
		// Resolve model with default if being set to empty or changed
		providerAdapter := providers.NewProviderAdapter()
		resolvedModelResult := providerAdapter.ResolveModelWithDefault(ctx, target.Provider, opts.Model)
		if !resolvedModelResult.IsOk() {
			return fmt.Errorf("failed to resolve model: %w", resolvedModelResult.Error())
		}
		resolvedModel := resolvedModelResult.Unwrap()

		// Show info message when model changes or gets defaulted
		if opts.Model != target.Model {
			if opts.Model == "" {
				fmt.Printf("ℹ️  Setting default model for provider '%s': %s\n", target.Provider, resolvedModel)
			} else {
				fmt.Printf("ℹ️  Updated model to: %s\n", resolvedModel)
			}
		}

		target.Model = resolvedModel
		updateCount++
	}
	if opts.URL != "" {
		target.URL = opts.URL
		updateCount++
	}
	if opts.Description != "" {
		target.Description = opts.Description
		updateCount++
	}
	if len(opts.Tags) > 0 {
		target.Tags = opts.Tags
		updateCount++
	}
	if opts.Headers != "" {
		// Parse headers from string (assuming key=value,key2=value2 format)
		headers := make(map[string]string)
		for _, pair := range strings.Split(opts.Headers, ",") {
			parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(parts) == 2 {
				headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
		target.Headers = headers
		updateCount++
	}
	if opts.Config != "" {
		config, err := tv.loadConfigFromFile(opts.Config)
		if err != nil {
			return fmt.Errorf("failed to load config file: %w", err)
		}
		target.Config = config
		updateCount++
	}

	if updateCount == 0 {
		fmt.Println("No changes specified")
		return nil
	}

	target.UpdatedAt = time.Now()

	// Pre-update validation if requested
	if opts.Validate {
		fmt.Println("Validating configuration changes...")
		if err := tv.targetService.ValidateConfiguration(ctx, target); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		fmt.Println("✓ Configuration validation passed")
	}

	// Confirm changes if not forced
	if !opts.Force && tv.hasSignificantChanges(opts) {
		fmt.Printf("This will update target '%s' with the following changes:\n", target.Name)
		tv.showPendingChanges(opts)
		fmt.Print("Continue? (y/N): ")
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read user input: %w", err)
		}
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Update cancelled")
			return nil
		}
	}

	// Update target through service
	if err := tv.targetService.Update(ctx, target); err != nil {
		return fmt.Errorf("failed to update target: %w", err)
	}

	fmt.Printf("✓ Updated target: %s\n", target.Name)
	fmt.Printf("Updated %d field(s)\n", updateCount)

	// Post-update connection test if requested
	if opts.TestConnection {
		fmt.Println("\nTesting connection...")
		if err := tv.testTargetConnection(ctx, target); err != nil {
			fmt.Printf("⚠ Connection test failed: %v\n", err)
			fmt.Println("Target updated but connection may have issues")
		} else {
			fmt.Println("✓ Connection test successful")
		}
	}

	return nil
}

// validateTargetConfig validates the target configuration
func (tv *targetView) validateTargetConfig(target *model.Target) error {
	// Basic URL validation
	if target.URL != "" {
		parsedURL, err := url.Parse(target.URL)
		if err != nil {
			return fmt.Errorf("invalid URL format: %w", err)
		}
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return fmt.Errorf("URL must use http or https scheme")
		}
		if parsedURL.Host == "" {
			return fmt.Errorf("URL must have a valid host")
		}
	}

	// Provider-specific validation
	switch target.Provider {
	case model.ProviderOpenAI:
		if target.URL == "" {
			target.URL = "https://api.openai.com/v1" // Set default
		}
		if target.Model == "" {
			return fmt.Errorf("model is required for OpenAI provider")
		}
	case model.ProviderAnthropic:
		if target.URL == "" {
			target.URL = "https://api.anthropic.com/v1" // Set default
		}
		if target.Model == "" {
			return fmt.Errorf("model is required for Anthropic provider")
		}
	case model.ProviderHuggingFace:
		if target.Model == "" {
			return fmt.Errorf("model is required for HuggingFace provider")
		}
	case model.ProviderOllama:
		if target.URL == "" {
			target.URL = "http://localhost:11434" // Set default
		}
	}

	return nil
}

// hasSignificantChanges determines if changes require confirmation
func (tv *targetView) hasSignificantChanges(opts TargetUpdateOptions) bool {
	return opts.Provider != "" || opts.URL != "" || opts.APIKey != ""
}

// showPendingChanges displays changes that will be applied
func (tv *targetView) showPendingChanges(opts TargetUpdateOptions) {
	if opts.Provider != "" {
		fmt.Printf("  - Provider: %s\n", opts.Provider)
	}
	if opts.Model != "" {
		fmt.Printf("  - Model: %s\n", opts.Model)
	}
	if opts.URL != "" {
		fmt.Printf("  - URL: %s\n", opts.URL)
	}
	if opts.APIKey != "" {
		fmt.Printf("  - API Key: [REDACTED]\n")
	}
	if opts.Headers != "" {
		fmt.Printf("  - Headers: %s\n", opts.Headers)
	}
}

// testTargetConnection tests connectivity to the target
func (tv *targetView) testTargetConnection(ctx context.Context, target *model.Target) error {
	// Basic URL connectivity test
	if target.URL == "" {
		return fmt.Errorf("no URL configured for connectivity test")
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// For API endpoints, try a basic HEAD or GET request
	switch target.Provider {
	case model.ProviderOpenAI:
		return tv.testOpenAIConnection(ctx, client, target)
	case model.ProviderAnthropic:
		return tv.testAnthropicConnection(ctx, client, target)
	case model.ProviderOllama:
		return tv.testOllamaConnection(ctx, client, target)
	default:
		// Generic HTTP connectivity test
		return tv.testGenericHTTPConnection(ctx, client, target)
	}
}

// testOpenAIConnection tests OpenAI API connectivity
func (tv *targetView) testOpenAIConnection(ctx context.Context, client *http.Client, target *model.Target) error {
	// Test the models endpoint
	testURL := strings.TrimSuffix(target.URL, "/") + "/models"
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers if configured
	for key, value := range target.Headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("authentication failed (401) - check credentials")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP error %d", resp.StatusCode)
	}

	return nil
}

// testAnthropicConnection tests Anthropic API connectivity
func (tv *targetView) testAnthropicConnection(ctx context.Context, client *http.Client, target *model.Target) error {
	// Test a basic endpoint
	testURL := strings.TrimSuffix(target.URL, "/") + "/messages"
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", testURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	for key, value := range target.Headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("authentication failed (401) - check credentials")
	}

	return nil
}

// testOllamaConnection tests Ollama API connectivity
func (tv *targetView) testOllamaConnection(ctx context.Context, client *http.Client, target *model.Target) error {
	// Test the tags endpoint
	testURL := strings.TrimSuffix(target.URL, "/") + "/api/tags"
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP error %d", resp.StatusCode)
	}

	return nil
}

// testGenericHTTPConnection tests basic HTTP connectivity
func (tv *targetView) testGenericHTTPConnection(ctx context.Context, client *http.Client, target *model.Target) error {
	req, err := http.NewRequestWithContext(ctx, "HEAD", target.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	for key, value := range target.Headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP error %d", resp.StatusCode)
	}

	return nil
}

// TargetGetOptions defines options for getting target details
type TargetGetOptions struct {
	Name       string
	ID         string
	Output     string
	History    bool
	ConfigOnly bool
	Status     bool
}

// GetTarget gets specific target details with configuration and scan history
func (tv *targetView) GetTarget(ctx context.Context, opts TargetGetOptions) error {
	if opts.Name == "" && opts.ID == "" {
		return fmt.Errorf("either target name or ID must be specified")
	}

	// Get the target
	var target *model.Target
	var err error

	if opts.ID != "" {
		targetID, parseErr := uuid.Parse(opts.ID)
		if parseErr != nil {
			return fmt.Errorf("invalid target ID format: %w", parseErr)
		}
		target, err = tv.targetService.Get(ctx, targetID)
	} else {
		target, err = tv.targetService.GetByName(ctx, opts.Name)
	}

	if err != nil {
		return fmt.Errorf("failed to get target: %w", err)
	}

	tv.logger.Info("Getting target details", "id", target.ID, "name", target.Name)

	if opts.Output == "json" {
		result := map[string]interface{}{
			"target": target,
		}

		// Add scan history if requested
		if opts.History {
			scanService := tv.serviceFactory.ScanService()
			scans, err := scanService.GetByTargetID(ctx, target.ID)
			if err == nil {
				result["scans"] = scans
			}
		}

		// Add connection status if requested
		if opts.Status {
			start := time.Now()
			connErr := tv.testTargetConnection(ctx, target)
			duration := time.Since(start)
			status := map[string]interface{}{
				"connected":     connErr == nil,
				"last_check":    time.Now().Format(time.RFC3339),
				"response_time": duration.String(),
			}
			if connErr != nil {
				status["error"] = connErr.Error()
			}
			result["connection_status"] = status
		}

		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	if opts.Output == "yaml" {
		yamlData, err := yaml.Marshal(target)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML: %w", err)
		}
		fmt.Println(string(yamlData))
		return nil
	}

	if opts.ConfigOnly {
		fmt.Println("Configuration details:")
		fmt.Printf("  Provider: %s\n", target.Provider)
		fmt.Printf("  Model: %s\n", target.Model)
		fmt.Printf("  URL: %s\n", target.URL)
		fmt.Printf("  Status: %s\n", target.Status)
		return nil
	}

	// Show full target details
	fmt.Printf("Target Configuration: %s\n", target.Name)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("ID:           %s\n", target.ID)
	fmt.Printf("Name:         %s\n", target.Name)
	fmt.Printf("Type:         %s\n", target.Type)
	fmt.Printf("Provider:     %s\n", target.Provider)
	fmt.Printf("Model:        %s\n", target.Model)
	fmt.Printf("URL:          %s\n", target.URL)
	fmt.Printf("Status:       %s\n", target.Status)
	fmt.Printf("Description:  %s\n", target.Description)
	fmt.Printf("Tags:         %s\n", strings.Join(target.Tags, ", "))
	fmt.Printf("Created:      %s\n", target.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Last Modified: %s\n", target.UpdatedAt.Format("2006-01-02 15:04:05"))

	if target.CredentialID != nil {
		fmt.Printf("Credential ID: %s\n", *target.CredentialID)
	}

	if len(target.Headers) > 0 {
		fmt.Println("\nHeaders:")
		for key, value := range target.Headers {
			if strings.ToLower(key) == "authorization" {
				fmt.Printf("  %s: [REDACTED]\n", key)
			} else {
				fmt.Printf("  %s: %s\n", key, value)
			}
		}
	}

	if len(target.Config) > 0 {
		fmt.Println("\nConfiguration:")
		for key, value := range target.Config {
			fmt.Printf("  %s: %v\n", key, value)
		}
	}

	if opts.Status {
		fmt.Println("\nConnection Status:")
		start := time.Now()
		connErr := tv.testTargetConnection(ctx, target)
		duration := time.Since(start)
		if connErr != nil {
			fmt.Printf("  Status: ✗ Disconnected\n")
			fmt.Printf("  Error: %v\n", connErr)
		} else {
			fmt.Printf("  Status: ✓ Connected\n")
		}
		fmt.Printf("  Last Check: %s\n", time.Now().Format("2006-01-02 15:04:05"))
		fmt.Printf("  Response Time: %v\n", duration)
	}

	if opts.History {
		fmt.Println("\nScan History:")
		scanService := tv.serviceFactory.ScanService()
		scans, err := scanService.GetByTargetID(ctx, target.ID)
		if err != nil {
			fmt.Printf("  Error loading scan history: %v\n", err)
		} else if len(scans) == 0 {
			fmt.Println("  No scans found")
		} else {
			fmt.Printf("  Total Scans: %d\n", len(scans))
			fmt.Println("  Recent Scans:")
			// Show last 5 scans
			count := len(scans)
			if count > 5 {
				count = 5
			}
			for i := 0; i < count; i++ {
				scan := scans[i]
				startTime := "N/A"
				if scan.StartedAt != nil {
					startTime = scan.StartedAt.Format("2006-01-02 15:04:05")
				}
				fmt.Printf("    - %s (%s) - %s\n", scan.ID.String()[:8], startTime, scan.Status)
			}
		}
	}

	return nil
}

// Enhanced validation and credential helper methods

// validateAPIProvider validates API provider configuration using provider registry
func (tv *targetView) validateAPIProvider(opts TargetAddOptions) error {
	registry := providers.NewRegistry()
	provider := model.Provider(opts.Provider)

	// Check if provider is known
	if !registry.IsKnownProvider(provider) {
		supportedProviders := registry.GetSupportedProvidersString()
		return fmt.Errorf("unsupported provider '%s'. Supported providers: %s", opts.Provider, supportedProviders)
	}

	// For Azure and custom providers, URL is required
	if (provider == model.ProviderAzure || provider == model.ProviderCustom) && opts.URL == "" {
		return fmt.Errorf("URL is required for provider '%s'", opts.Provider)
	}

	// Validate URL format if provided
	if opts.URL != "" && !tv.isValidURL(opts.URL) {
		return fmt.Errorf("invalid URL format: %s", opts.URL)
	}

	// API key validation (can be credential ID or actual key)
	if opts.APIKey == "" {
		return fmt.Errorf("API key or credential is required for provider '%s'", opts.Provider)
	}

	return nil
}

// validateAnthropicTarget validates Anthropic API configuration (deprecated - use provider registry)
func (tv *targetView) validateAnthropicTarget(opts TargetAddOptions) error {
	// This method is deprecated in favor of provider registry validation
	// Kept for backward compatibility
	return nil
}

// validateOpenAITarget validates OpenAI API configuration (deprecated - use provider registry)
func (tv *targetView) validateOpenAITarget(opts TargetAddOptions) error {
	// This method is deprecated in favor of provider registry validation
	return nil
}

// validateAzureTarget validates Azure OpenAI configuration (deprecated - use provider registry)
func (tv *targetView) validateAzureTarget(opts TargetAddOptions) error {
	// This method is deprecated in favor of provider registry validation
	return nil
}

// validateCohereTarget validates Cohere API configuration (deprecated - use provider registry)
func (tv *targetView) validateCohereTarget(opts TargetAddOptions) error {
	// This method is deprecated in favor of provider registry validation
	return nil
}

// validateHuggingFaceTarget validates Hugging Face API configuration (deprecated - use provider registry)
func (tv *targetView) validateHuggingFaceTarget(opts TargetAddOptions) error {
	// This method is deprecated in favor of provider registry validation
	return nil
}

// validateGenericAPITarget validates generic API target configuration (deprecated - use provider registry)
func (tv *targetView) validateGenericAPITarget(opts TargetAddOptions) error {
	// This method is deprecated in favor of provider registry validation
	return nil
}

// linkCredentialToTarget finds and links a credential to a target (Requirement 4)
func (tv *targetView) linkCredentialToTarget(ctx context.Context, opts TargetAddOptions) (*uuid.UUID, error) {
	credentialService := tv.serviceFactory.CredentialService()

	// First, try to parse opts.APIKey as UUID (credential ID)
	if credentialID, err := uuid.Parse(opts.APIKey); err == nil {
		// Verify credential exists
		cred, err := credentialService.Get(ctx, credentialID)
		if err != nil {
			return nil, fmt.Errorf("credential with ID %s not found: %w", credentialID, err)
		}
		// Verify credential provider matches target provider
		if strings.ToLower(string(cred.Provider)) != strings.ToLower(opts.Provider) {
			return nil, fmt.Errorf("credential provider '%s' does not match target provider '%s'", cred.Provider, opts.Provider)
		}
		return &credentialID, nil
	}

	// If not a UUID, try to find credential by name
	creds, err := credentialService.ListByProvider(ctx, model.Provider(opts.Provider))
	if err != nil {
		return nil, fmt.Errorf("failed to list credentials for provider %s: %w", opts.Provider, err)
	}

	// Look for exact name match first
	for _, cred := range creds {
		if cred.Name == opts.APIKey {
			return &cred.ID, nil
		}
	}

	// Look for partial name match
	for _, cred := range creds {
		if strings.Contains(strings.ToLower(cred.Name), strings.ToLower(opts.APIKey)) {
			return &cred.ID, nil
		}
	}

	// No existing credential found - suggest creating one
	return nil, fmt.Errorf("no credential found for '%s'. Please create a credential first: gibson credential add %s-cred --provider %s --value <your-api-key>", opts.APIKey, opts.Provider, opts.Provider)
}

// isValidURL validates URL format
func (tv *targetView) isValidURL(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return parsedURL.Scheme != "" && parsedURL.Host != ""
}

// contains checks if a slice contains a string
func (tv *targetView) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Helper functions

// loadConfigFromFile loads configuration from a YAML or JSON file
func (tv *targetView) loadConfigFromFile(configPath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config map[string]interface{}

	// Try JSON first, then YAML
	if err := json.Unmarshal(data, &config); err != nil {
		if err := yaml.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse config file as JSON or YAML: %w", err)
		}
	}

	return config, nil
}