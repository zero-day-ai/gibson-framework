// Package view provides credential view implementation for CLI commands
package view

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/dao"
	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/zero-day-ai/gibson-framework/internal/service"
	"github.com/google/uuid"
	"gopkg.in/yaml.v2"
)

// credentialView implements CredentialViewer following k9s patterns
type credentialView struct {
	serviceFactory *service.ServiceFactory
	credentialService service.CredentialService
	logger *slog.Logger
}

// NewCredentialView creates a new credential view instance
func NewCredentialView() (*credentialView, error) {
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

	return &credentialView{
		serviceFactory: serviceFactory,
		credentialService: serviceFactory.CredentialService(),
		logger: logger,
	}, nil
}

// getGibsonHome returns the Gibson home directory
func getGibsonHome() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".gibson"), nil
}

// readEncryptionKey reads the encryption key from the gibson home directory
func readEncryptionKey(gibsonHome string) ([]byte, error) {
	keyPath := filepath.Join(gibsonHome, ".encryption_key")
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encryption key file: %w", err)
	}

	// Decode base64 key
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyData)))
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	return key, nil
}

// CredentialAddOptions defines options for adding a credential
type CredentialAddOptions struct {
	Name             string
	Provider         string
	Type             string
	APIKey           string
	Description      string
	Tags             []string
	AutoRotate       bool
	RotationInterval string
	Output           string
}

// AddCredential adds a new AI/ML credential with encryption
func (cv *credentialView) AddCredential(ctx context.Context, opts CredentialAddOptions) error {
	cv.logger.Info("Adding new credential", "name", opts.Name, "provider", opts.Provider)

	// Validate required fields
	if opts.Name == "" {
		return fmt.Errorf("credential name is required")
	}
	if opts.Provider == "" {
		return fmt.Errorf("provider is required")
	}
	if opts.APIKey == "" {
		return fmt.Errorf("API key/credential value is required")
	}

	// Convert string types to model types
	provider := model.Provider(opts.Provider)
	credType := model.CredentialType(opts.Type)
	if opts.Type == "" {
		credType = model.CredentialTypeAPIKey
	}

	// Create credential request
	req := &model.CredentialCreateRequest{
		Name:         opts.Name,
		Type:         credType,
		Provider:     provider,
		Description:  opts.Description,
		Value:        opts.APIKey,
		Tags:         opts.Tags,
		AutoRotate:   opts.AutoRotate,
		RotationInterval: opts.RotationInterval,
	}

	// Create credential through service
	credential, err := cv.credentialService.Create(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}

	// Display success message
	fmt.Printf("Successfully added credential: %s\n", credential.Name)
	fmt.Printf("ID: %s\n", credential.ID)
	fmt.Printf("Provider: %s\n", credential.Provider)
	fmt.Printf("Type: %s\n", credential.Type)
	fmt.Printf("Status: %s\n", credential.Status)
	if credential.Description != "" {
		fmt.Printf("Description: %s\n", credential.Description)
	}
	if len(credential.Tags) > 0 {
		fmt.Printf("Tags: %s\n", strings.Join(credential.Tags, ", "))
	}
	if credential.RotationInfo.Enabled {
		fmt.Printf("Auto-rotation: Enabled (%s)\n", credential.RotationInfo.RotationInterval)
	}

	return nil
}

// CredentialListOptions defines options for listing credentials
type CredentialListOptions struct {
	Output string
}

// ListCredentials lists all credentials (without sensitive data)
func (cv *credentialView) ListCredentials(ctx context.Context, opts CredentialListOptions) error {
	cv.logger.Info("Listing credentials")

	// Get credentials from service
	credentials, err := cv.credentialService.List(ctx)
	if err != nil {
		return fmt.Errorf("failed to list credentials: %w", err)
	}

	// Convert to export data (removes sensitive fields)
	exportData := make([]*model.CredentialExportData, len(credentials))
	for i, cred := range credentials {
		exportData[i] = cred.ToExportData()
	}

	if opts.Output == "json" {
		jsonData, err := json.MarshalIndent(exportData, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else if opts.Output == "yaml" {
		yamlData, err := yaml.Marshal(exportData)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML: %w", err)
		}
		fmt.Println(string(yamlData))
	} else {
		// Table format
		fmt.Printf("%-20s %-15s %-12s %-8s %-20s %-30s\n", "NAME", "PROVIDER", "TYPE", "STATUS", "CREATED", "DESCRIPTION")
		fmt.Println(strings.Repeat("-", 100))
		for _, cred := range exportData {
			fmt.Printf("%-20s %-15s %-12s %-8s %-20s %-30s\n",
				cred.Name,
				cred.Provider,
				cred.Type,
				cred.Status,
				cred.CreatedAt.Format("2006-01-02 15:04"),
				truncateString(cred.Description, 30),
			)
		}
	}

	return nil
}

// CredentialShowOptions defines options for showing credential details
type CredentialShowOptions struct {
	Name   string
	ID     string
	Output string
}

// GetCredentialInfo gets detailed credential information
func (cv *credentialView) GetCredentialInfo(ctx context.Context, opts CredentialShowOptions) error {
	if opts.Name == "" && opts.ID == "" {
		return fmt.Errorf("either credential name or ID must be specified")
	}

	var credential *model.Credential
	var err error

	if opts.ID != "" {
		// Parse UUID from string
		id, parseErr := uuid.Parse(opts.ID)
		if parseErr != nil {
			return fmt.Errorf("invalid credential ID format: %w", parseErr)
		}
		credential, err = cv.credentialService.Get(ctx, id)
	} else {
		credential, err = cv.credentialService.GetByName(ctx, opts.Name)
	}

	if err != nil {
		return fmt.Errorf("failed to get credential: %w", err)
	}

	cv.logger.Info("Getting credential info", "id", credential.ID, "name", credential.Name)

	// Convert to export data (removes sensitive fields)
	credInfo := credential.ToExportData()

	if opts.Output == "json" {
		jsonData, err := json.MarshalIndent(credInfo, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else if opts.Output == "yaml" {
		yamlData, err := yaml.Marshal(credInfo)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML: %w", err)
		}
		fmt.Println(string(yamlData))
	} else {
		// Table format
		fmt.Printf("Credential Information: %s\n", credInfo.Name)
		fmt.Println(strings.Repeat("=", 50))
		fmt.Printf("ID:           %s\n", credInfo.ID)
		fmt.Printf("Name:         %s\n", credInfo.Name)
		fmt.Printf("Provider:     %s\n", credInfo.Provider)
		fmt.Printf("Type:         %s\n", credInfo.Type)
		fmt.Printf("Status:       %s\n", credInfo.Status)
		fmt.Printf("Description:  %s\n", credInfo.Description)
		fmt.Printf("Tags:         %s\n", strings.Join(credInfo.Tags, ", "))
		fmt.Printf("Created:      %s\n", credInfo.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Updated:      %s\n", credInfo.UpdatedAt.Format("2006-01-02 15:04:05"))
		if credInfo.LastUsed != nil {
			fmt.Printf("Last Used:    %s\n", credInfo.LastUsed.Format("2006-01-02 15:04:05"))
		}

		// Usage statistics
		fmt.Println("\nUsage Statistics:")
		fmt.Printf("  Total Uses:     %d\n", credInfo.Usage.TotalUses)
		fmt.Printf("  Last 30 days:   %d\n", credInfo.Usage.UsageCount30d)
		fmt.Printf("  Last 7 days:    %d\n", credInfo.Usage.UsageCount7d)
		fmt.Printf("  Last 24 hours:  %d\n", credInfo.Usage.UsageCount24h)
		fmt.Printf("  Failures:       %d\n", credInfo.Usage.FailureCount)

		// Rotation info
		fmt.Println("\nRotation Settings:")
		fmt.Printf("  Enabled:        %v\n", credInfo.RotationInfo.Enabled)
		fmt.Printf("  Auto-rotate:    %v\n", credInfo.RotationInfo.AutoRotate)
		fmt.Printf("  Interval:       %s\n", credInfo.RotationInfo.RotationInterval)
		if credInfo.RotationInfo.NextRotation != nil {
			fmt.Printf("  Next rotation:  %s\n", credInfo.RotationInfo.NextRotation.Format("2006-01-02 15:04:05"))
		}
	}

	return nil
}

// CredentialUpdateOptions defines options for updating credentials
type CredentialUpdateOptions struct {
	Name             string
	ID               string
	Provider         string
	Type             string
	APIKey           string
	Description      string
	Tags             []string
	Status           string
	AutoRotate       *bool
	RotationInterval string
	Output           string
}

// UpdateCredential updates credential configuration
func (cv *credentialView) UpdateCredential(ctx context.Context, opts CredentialUpdateOptions) error {
	if opts.Name == "" && opts.ID == "" {
		return fmt.Errorf("either credential name or ID must be specified")
	}

	// Get credential ID
	var credentialID uuid.UUID
	var err error

	if opts.ID != "" {
		credentialID, err = uuid.Parse(opts.ID)
		if err != nil {
			return fmt.Errorf("invalid credential ID format: %w", err)
		}
	} else {
		// Get credential by name to find ID
		credential, err := cv.credentialService.GetByName(ctx, opts.Name)
		if err != nil {
			return fmt.Errorf("failed to find credential by name: %w", err)
		}
		credentialID = credential.ID
	}

	cv.logger.Info("Updating credential", "id", credentialID)

	// Build update request
	req := &model.CredentialUpdateRequest{}
	updateCount := 0

	if opts.Provider != "" {
		provider := model.Provider(opts.Provider)
		req.Provider = &provider
		updateCount++
	}
	if opts.Type != "" {
		credType := model.CredentialType(opts.Type)
		req.Type = &credType
		updateCount++
	}
	if opts.APIKey != "" {
		req.Value = &opts.APIKey
		updateCount++
	}
	if opts.Description != "" {
		req.Description = &opts.Description
		updateCount++
	}
	if len(opts.Tags) > 0 {
		req.Tags = opts.Tags
		updateCount++
	}
	if opts.Status != "" {
		status := model.CredentialStatus(opts.Status)
		req.Status = &status
		updateCount++
	}
	if opts.AutoRotate != nil {
		req.AutoRotate = opts.AutoRotate
		updateCount++
	}
	if opts.RotationInterval != "" {
		req.RotationInterval = &opts.RotationInterval
		updateCount++
	}

	if updateCount == 0 {
		fmt.Println("No changes specified")
		return nil
	}

	// Update credential through service
	updatedCredential, err := cv.credentialService.Update(ctx, credentialID, req)
	if err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}

	fmt.Printf("Successfully updated credential: %s\n", updatedCredential.Name)
	fmt.Printf("Updated %d field(s)\n", updateCount)

	return nil
}

// CredentialDeleteOptions defines options for deleting credentials
type CredentialDeleteOptions struct {
	Name  string
	ID    string
	All   bool
	Force bool
}

// DeleteCredential deletes a credential
func (cv *credentialView) DeleteCredential(ctx context.Context, opts CredentialDeleteOptions) error {
	if !opts.All && opts.Name == "" && opts.ID == "" {
		return fmt.Errorf("either credential name, ID, or --all flag must be specified")
	}

	if opts.All {
		if !opts.Force {
			fmt.Print("Are you sure you want to delete ALL credentials? (y/N): ")
			// For now, require force flag for bulk deletion
			return fmt.Errorf("bulk deletion requires --force flag for safety")
		}

		// Get all credentials
		credentials, err := cv.credentialService.List(ctx)
		if err != nil {
			return fmt.Errorf("failed to list credentials: %w", err)
		}

		fmt.Printf("Deleting %d credentials...\n", len(credentials))
		for _, cred := range credentials {
			if err := cv.credentialService.Delete(ctx, cred.ID); err != nil {
				cv.logger.Warn("Failed to delete credential", "id", cred.ID, "name", cred.Name, "error", err)
				fmt.Printf("Failed to delete credential %s: %v\n", cred.Name, err)
			} else {
				fmt.Printf("Deleted credential: %s\n", cred.Name)
			}
		}
		return nil
	}

	// Delete single credential
	var credentialID uuid.UUID
	var credentialName string
	var err error

	if opts.ID != "" {
		credentialID, err = uuid.Parse(opts.ID)
		if err != nil {
			return fmt.Errorf("invalid credential ID format: %w", err)
		}
		// Get credential to find name for confirmation
		credential, err := cv.credentialService.Get(ctx, credentialID)
		if err != nil {
			return fmt.Errorf("failed to get credential: %w", err)
		}
		credentialName = credential.Name
	} else {
		// Get credential by name to find ID
		credential, err := cv.credentialService.GetByName(ctx, opts.Name)
		if err != nil {
			return fmt.Errorf("failed to find credential by name: %w", err)
		}
		credentialID = credential.ID
		credentialName = credential.Name
	}

	if !opts.Force {
		fmt.Printf("Are you sure you want to delete credential '%s'? (y/N): ", credentialName)
		// For now, require force flag for safety
		return fmt.Errorf("credential deletion requires --force flag for safety")
	}

	cv.logger.Info("Deleting credential", "id", credentialID, "name", credentialName)

	// Delete credential through service
	if err := cv.credentialService.Delete(ctx, credentialID); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	fmt.Printf("Successfully deleted credential: %s\n", credentialName)

	return nil
}

// CredentialValidateOptions defines options for validating credentials
type CredentialValidateOptions struct {
	Name   string
	ID     string
	All    bool
	Output string
}

// ValidateCredential validates credential connectivity
func (cv *credentialView) ValidateCredential(ctx context.Context, opts CredentialValidateOptions) error {
	if !opts.All && opts.Name == "" && opts.ID == "" {
		return fmt.Errorf("either credential name, ID, or --all flag must be specified")
	}

	if opts.All {
		fmt.Println("Validating all active credentials...")
		// Get active credentials
		credentials, err := cv.credentialService.GetActiveCredentials(ctx)
		if err != nil {
			return fmt.Errorf("failed to get active credentials: %w", err)
		}

		if len(credentials) == 0 {
			fmt.Println("No active credentials found")
			return nil
		}

		for i, credential := range credentials {
			result, err := cv.credentialService.Validate(ctx, credential.ID)
			if err != nil {
				fmt.Printf("Credential %d (%s): ✗ VALIDATION_ERROR - %v\n", i+1, credential.Name, err)
				continue
			}

			status := "✓ VALID"
			if !result.Valid {
				status = "✗ INVALID"
			}
			fmt.Printf("Credential %d (%s): %s (Response time: %v)\n", i+1, credential.Name, status, result.ResponseTime)
			if result.Error != "" {
				fmt.Printf("  Error: %s\n", result.Error)
			}
		}
		return nil
	}

	// Validate single credential
	var credentialID uuid.UUID
	var credentialName string
	var err error

	if opts.ID != "" {
		credentialID, err = uuid.Parse(opts.ID)
		if err != nil {
			return fmt.Errorf("invalid credential ID format: %w", err)
		}
		// Get credential to find name
		credential, err := cv.credentialService.Get(ctx, credentialID)
		if err != nil {
			return fmt.Errorf("failed to get credential: %w", err)
		}
		credentialName = credential.Name
	} else {
		// Get credential by name to find ID
		credential, err := cv.credentialService.GetByName(ctx, opts.Name)
		if err != nil {
			return fmt.Errorf("failed to find credential by name: %w", err)
		}
		credentialID = credential.ID
		credentialName = credential.Name
	}

	cv.logger.Info("Validating credential", "id", credentialID, "name", credentialName)

	fmt.Printf("Validating credential: %s\n", credentialName)

	// Validate through service
	result, err := cv.credentialService.Validate(ctx, credentialID)
	if err != nil {
		return fmt.Errorf("failed to validate credential: %w", err)
	}

	if opts.Output == "json" {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		status := "✓ VALID"
		if !result.Valid {
			status = "✗ INVALID"
		}
		fmt.Printf("Status: %s\n", status)
		fmt.Printf("Response time: %v\n", result.ResponseTime)
		if result.Error != "" {
			fmt.Printf("Error: %s\n", result.Error)
		}
	}

	return nil
}

// CredentialRotateOptions defines options for rotating credentials
type CredentialRotateOptions struct {
	Name   string
	ID     string
	Value  string
	All    bool
	Output string
}

// RotateCredential rotates credential values
func (cv *credentialView) RotateCredential(ctx context.Context, opts CredentialRotateOptions) error {
	if !opts.All && opts.Name == "" && opts.ID == "" {
		return fmt.Errorf("either credential name, ID, or --all flag must be specified")
	}

	if opts.All {
		fmt.Println("Rotating all credentials that need rotation...")
		// Get all credentials
		credentials, err := cv.credentialService.List(ctx)
		if err != nil {
			return fmt.Errorf("failed to list credentials: %w", err)
		}

		// Filter credentials that need rotation
		var needRotation []*model.Credential
		for _, cred := range credentials {
			if cred.NeedsRotation() {
				needRotation = append(needRotation, cred)
			}
		}

		if len(needRotation) == 0 {
			fmt.Println("No credentials need rotation")
			return nil
		}

		fmt.Printf("Found %d credential(s) that need rotation\n", len(needRotation))
		for _, cred := range needRotation {
			if err := cv.credentialService.Rotate(ctx, cred.ID); err != nil {
				fmt.Printf("✗ Failed to rotate %s: %v\n", cred.Name, err)
			} else {
				fmt.Printf("✓ Rotated: %s\n", cred.Name)
			}
		}
		return nil
	}

	// Rotate single credential
	var credentialID uuid.UUID
	var credentialName string
	var err error

	if opts.ID != "" {
		credentialID, err = uuid.Parse(opts.ID)
		if err != nil {
			return fmt.Errorf("invalid credential ID format: %w", err)
		}
		// Get credential to find name
		credential, err := cv.credentialService.Get(ctx, credentialID)
		if err != nil {
			return fmt.Errorf("failed to get credential: %w", err)
		}
		credentialName = credential.Name
	} else {
		// Get credential by name to find ID
		credential, err := cv.credentialService.GetByName(ctx, opts.Name)
		if err != nil {
			return fmt.Errorf("failed to find credential by name: %w", err)
		}
		credentialID = credential.ID
		credentialName = credential.Name
	}

	// For manual rotation with new value, update the credential
	if opts.Value != "" {
		req := &model.CredentialUpdateRequest{
			Value: &opts.Value,
		}
		_, err := cv.credentialService.Update(ctx, credentialID, req)
		if err != nil {
			return fmt.Errorf("failed to update credential value: %w", err)
		}
		fmt.Printf("Successfully updated credential value for: %s\n", credentialName)
		return nil
	}

	cv.logger.Info("Rotating credential", "id", credentialID, "name", credentialName)

	// Use service rotation (currently returns not implemented)
	if err := cv.credentialService.Rotate(ctx, credentialID); err != nil {
		return fmt.Errorf("failed to rotate credential: %w", err)
	}

	fmt.Printf("Successfully rotated credential: %s\n", credentialName)

	return nil
}

// CredentialExportOptions defines options for exporting credentials
type CredentialExportOptions struct {
	File   string
	Output string
}

// ExportCredentials exports credential metadata (without sensitive values)
func (cv *credentialView) ExportCredentials(ctx context.Context, opts CredentialExportOptions) error {
	cv.logger.Info("Exporting credentials")

	// Get all credentials from service
	credentials, err := cv.credentialService.ExportAll(ctx)
	if err != nil {
		return fmt.Errorf("failed to export credentials: %w", err)
	}

	var data []byte

	if opts.Output == "yaml" {
		data, err = yaml.Marshal(credentials)
	} else {
		data, err = json.MarshalIndent(credentials, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	if opts.File != "" {
		err = os.WriteFile(opts.File, data, 0600)
		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		fmt.Printf("Exported %d credential(s) to %s\n", len(credentials), opts.File)
	} else {
		fmt.Println(string(data))
	}

	return nil
}

// CredentialImportOptions defines options for importing credentials
type CredentialImportOptions struct {
	File   string
	Force  bool
	Output string
}

// ImportCredentials imports credential metadata from file
func (cv *credentialView) ImportCredentials(ctx context.Context, opts CredentialImportOptions) error {
	if opts.File == "" {
		return fmt.Errorf("input file is required")
	}

	cv.logger.Info("Importing credentials", "file", opts.File)

	data, err := os.ReadFile(opts.File)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var credentials []model.CredentialExportData

	// Try JSON first, then YAML
	if err := json.Unmarshal(data, &credentials); err != nil {
		if err := yaml.Unmarshal(data, &credentials); err != nil {
			return fmt.Errorf("failed to parse file as JSON or YAML: %w", err)
		}
	}

	fmt.Printf("Found %d credential(s) in file\n", len(credentials))
	for _, cred := range credentials {
		fmt.Printf("  - %s (%s, %s)\n", cred.Name, cred.Provider, cred.Type)
	}

	// Import credentials (metadata only)
	importedCount := 0
	skippedCount := 0

	for _, credData := range credentials {
		// Check if credential already exists
		existing, err := cv.credentialService.GetByName(ctx, credData.Name)
		if err == nil && existing != nil {
			if !opts.Force {
				fmt.Printf("Skipping %s (already exists, use --force to overwrite)\n", credData.Name)
				skippedCount++
				continue
			}
			// Credential update logic is handled by the credential service with proper validation
			fmt.Printf("Overwriting %s (--force specified)\n", credData.Name)
		}

		// Create credential request (without sensitive value)
		req := &model.CredentialCreateRequest{
			Name:         credData.Name,
			Type:         credData.Type,
			Provider:     credData.Provider,
			Description:  credData.Description,
			Value:        "PLACEHOLDER_VALUE", // Placeholder - user must set real value
			Tags:         credData.Tags,
			AutoRotate:   credData.RotationInfo.AutoRotate,
			RotationInterval: credData.RotationInfo.RotationInterval,
		}

		_, err = cv.credentialService.Create(ctx, req)
		if err != nil {
			fmt.Printf("Failed to import %s: %v\n", credData.Name, err)
			continue
		}

		importedCount++
		fmt.Printf("Imported: %s\n", credData.Name)
	}

	fmt.Printf("\nImport completed: %d imported, %d skipped\n", importedCount, skippedCount)
	if importedCount > 0 {
		fmt.Println("Note: Imported credentials have placeholder values - update with real values using 'gibson credential update'")
	}

	return nil
}

// Helper functions

// timePtr returns a pointer to a time value
func timePtr(t time.Time) *time.Time {
	return &t
}

// truncateString truncates a string to the specified length
func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}