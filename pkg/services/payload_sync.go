// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"gopkg.in/yaml.v3"

	coremodels "github.com/gibson-sec/gibson-framework-2/pkg/core/models"
	"github.com/gibson-sec/gibson-framework-2/pkg/core/database/repositories"
)

// PayloadSynchronizer handles filesystem to database synchronization of payloads
// Implements requirements 2.2 (index new payloads), 2.4 (maintain last known good state), and 5.7 (checksum-based change detection)
type PayloadSynchronizer struct {
	db             *sqlx.DB
	batchSize      int
	discoveryPaths []string
}

// PayloadSyncConfig holds configuration for payload synchronization
type PayloadSyncConfig struct {
	BatchSize      int      `json:"batch_size"`
	DiscoveryPaths []string `json:"discovery_paths"`
}

// PayloadSyncResult holds the results of a synchronization operation
type PayloadSyncResult struct {
	TotalFiles     int                    `json:"total_files"`
	ProcessedFiles int                    `json:"processed_files"`
	NewPayloads    int                    `json:"new_payloads"`
	UpdatedPayloads int                   `json:"updated_payloads"`
	SkippedFiles   int                    `json:"skipped_files"`
	ErrorFiles     int                    `json:"error_files"`
	OrphanedCleaned int                   `json:"orphaned_cleaned"`
	Duration       time.Duration          `json:"duration"`
	Errors         []string               `json:"errors,omitempty"`
	FileDetails    map[string]FileDetail  `json:"file_details,omitempty"`
}

// FileDetail holds details about a processed file
type FileDetail struct {
	Path         string    `json:"path"`
	Checksum     string    `json:"checksum"`
	Status       string    `json:"status"` // new, updated, skipped, error
	Error        string    `json:"error,omitempty"`
	PayloadID    uuid.UUID `json:"payload_id,omitempty"`
	ProcessedAt  time.Time `json:"processed_at"`
}

// PayloadFileMetadata represents metadata extracted from payload files
type PayloadFileMetadata struct {
	Name        string                 `yaml:"name" json:"name"`
	Category    string                 `yaml:"category" json:"category"`
	Domain      string                 `yaml:"domain" json:"domain"`
	Type        string                 `yaml:"type" json:"type"`
	Description string                 `yaml:"description" json:"description"`
	Severity    string                 `yaml:"severity" json:"severity"`
	Tags        []string               `yaml:"tags" json:"tags"`
	Variables   map[string]interface{} `yaml:"variables" json:"variables"`
	Config      map[string]interface{} `yaml:"config" json:"config"`
	Language    string                 `yaml:"language" json:"language"`
	Version     int                    `yaml:"version" json:"version"`
	Content     string                 `yaml:"content" json:"content"`
}

// PayloadDefinition represents a single payload definition in payloads.json
type PayloadDefinition struct {
	ID          string                 `json:"id" validate:"required"`
	Name        string                 `json:"name" validate:"required"`
	Content     string                 `json:"content" validate:"required"`
	Domain      string                 `json:"domain" validate:"required"`
	PayloadType string                 `json:"payload_type" validate:"required"`
	Description string                 `json:"description,omitempty"`
	Severity    string                 `json:"severity,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Variables   map[string]interface{} `json:"variables,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Version     int                    `json:"version,omitempty"`
	Language    string                 `json:"language,omitempty"`
}

// PayloadRepository is an alias to the repository interface
type PayloadRepository = repositories.PayloadRepository

// NewPayloadSynchronizer creates a new PayloadSynchronizer instance
func NewPayloadSynchronizer(db *sqlx.DB, config PayloadSyncConfig) *PayloadSynchronizer {
	// Set defaults
	if config.BatchSize <= 0 {
		config.BatchSize = 100
	}
	if len(config.DiscoveryPaths) == 0 {
		config.DiscoveryPaths = []string{
			"*.yaml", "*.yml", "*.json", "*.txt", "*.payload",
		}
	}

	return &PayloadSynchronizer{
		db:             db,
		batchSize:      config.BatchSize,
		discoveryPaths: config.DiscoveryPaths,
	}
}

// SyncRepositoryPayloads synchronizes payloads from a repository's filesystem to database
// Implements requirements 2.2, 2.4, and 5.7
func (ps *PayloadSynchronizer) SyncRepositoryPayloads(ctx context.Context, repository *coremodels.PayloadRepositoryDB, payloadRepo repositories.PayloadRepository) coremodels.Result[PayloadSyncResult] {
	startTime := time.Now()
	result := PayloadSyncResult{
		FileDetails: make(map[string]FileDetail),
		Errors:      []string{},
	}

	// Discover payload files in the repository (requirement 2.2)
	filesResult := ps.discoverPayloadFiles(repository.LocalPath)
	if filesResult.IsErr() {
		return coremodels.Err[PayloadSyncResult](fmt.Errorf("failed to discover payload files: %w", filesResult.Error()))
	}

	payloadFiles := filesResult.Unwrap()
	result.TotalFiles = len(payloadFiles)

	// Process files in batches for efficiency
	batches := ps.createBatches(payloadFiles)

	for _, batch := range batches {
		batchResult := ps.processBatch(ctx, batch, repository, payloadRepo)
		if batchResult.IsErr() {
			result.Errors = append(result.Errors, batchResult.Error().Error())
			result.ErrorFiles += len(batch)
			continue
		}

		// Merge batch results
		batchData := batchResult.Unwrap()
		result.ProcessedFiles += batchData.ProcessedFiles
		result.NewPayloads += batchData.NewPayloads
		result.UpdatedPayloads += batchData.UpdatedPayloads
		result.SkippedFiles += batchData.SkippedFiles
		result.ErrorFiles += batchData.ErrorFiles

		// Merge file details
		for path, detail := range batchData.FileDetails {
			result.FileDetails[path] = detail
		}

		// Merge errors
		result.Errors = append(result.Errors, batchData.Errors...)
	}

	// Clean up orphaned payloads (requirement 2.4 - maintain last known good state)
	validPaths := make([]string, 0, len(payloadFiles))
	for _, file := range payloadFiles {
		relPath, err := filepath.Rel(repository.LocalPath, file)
		if err == nil {
			validPaths = append(validPaths, relPath)
		}
	}

	cleanupResult := payloadRepo.DeleteOrphaned(ctx, repository.ID, validPaths)
	if cleanupResult.IsOk() {
		result.OrphanedCleaned = int(cleanupResult.Unwrap())
	} else {
		result.Errors = append(result.Errors, fmt.Sprintf("cleanup failed: %v", cleanupResult.Error()))
	}

	result.Duration = time.Since(startTime)
	return coremodels.Ok(result)
}

// discoverPayloadFiles discovers payload files using domain/plugin/payloads.json structure
// Implements domain-based discovery according to Gibson's domain categories
func (ps *PayloadSynchronizer) discoverPayloadFiles(basePath string) coremodels.Result[[]string] {
	var payloadFiles []string

	// Gibson domains (not manifest domains)
	domains := []string{"model", "data", "interface", "infrastructure", "output", "process"}

	for _, domain := range domains {
		domainPath := filepath.Join(basePath, domain)

		// Skip if domain directory doesn't exist
		if _, err := os.Stat(domainPath); os.IsNotExist(err) {
			continue
		}

		// Read plugin directories within this domain
		pluginDirs, err := os.ReadDir(domainPath)
		if err != nil {
			// Log warning but continue with other domains
			continue
		}

		for _, pluginDir := range pluginDirs {
			// Skip files, only process directories
			if !pluginDir.IsDir() {
				continue
			}

			// Skip hidden directories
			if strings.HasPrefix(pluginDir.Name(), ".") {
				continue
			}

			// Look for payloads.json in this plugin directory
			payloadFile := filepath.Join(domainPath, pluginDir.Name(), "payloads.json")
			if _, err := os.Stat(payloadFile); err == nil {
				// Skip README, manifest, .gitkeep files
				if !ps.isNonPayloadFile(payloadFile) {
					payloadFiles = append(payloadFiles, payloadFile)
				}
			}
		}
	}

	return coremodels.Ok(payloadFiles)
}

// isNonPayloadFile checks if a file should be skipped (README, manifest, .gitkeep, etc.)
func (ps *PayloadSynchronizer) isNonPayloadFile(filePath string) bool {
	fileName := strings.ToLower(filepath.Base(filePath))

	// Skip common non-payload files
	skipFiles := []string{
		"readme.md", "readme.txt", "readme",
		"manifest.json", "manifest.yaml", "manifest.yml",
		".gitkeep", ".gitignore",
		"license", "license.txt", "license.md",
	}

	for _, skipFile := range skipFiles {
		if fileName == skipFile {
			return true
		}
	}

	return false
}

// createBatches splits files into batches for processing
func (ps *PayloadSynchronizer) createBatches(files []string) [][]string {
	var batches [][]string

	for i := 0; i < len(files); i += ps.batchSize {
		end := i + ps.batchSize
		if end > len(files) {
			end = len(files)
		}
		batches = append(batches, files[i:end])
	}

	return batches
}

// processBatch processes a batch of payload files
func (ps *PayloadSynchronizer) processBatch(ctx context.Context, files []string, repository *coremodels.PayloadRepositoryDB, payloadRepo repositories.PayloadRepository) coremodels.Result[PayloadSyncResult] {
	result := PayloadSyncResult{
		FileDetails: make(map[string]FileDetail),
		Errors:      []string{},
	}

	var newPayloads []*coremodels.PayloadDB
	var updatedPayloads []*coremodels.PayloadDB

	for _, filePath := range files {
		// Calculate checksum for change detection (requirement 5.7)
		checksumResult := ps.calculateFileChecksum(filePath)
		if checksumResult.IsErr() {
			detail := FileDetail{
				Path:        filePath,
				Status:      "error",
				Error:       fmt.Sprintf("checksum failed: %v", checksumResult.Error()),
				ProcessedAt: time.Now(),
			}
			result.FileDetails[filePath] = detail
			result.ErrorFiles++
			continue
		}

		fileChecksum := checksumResult.Unwrap()

		// Get relative path for repository tracking
		relPath, err := filepath.Rel(repository.LocalPath, filePath)
		if err != nil {
			detail := FileDetail{
				Path:        filePath,
				Status:      "error",
				Error:       fmt.Sprintf("path calculation failed: %v", err),
				ProcessedAt: time.Now(),
			}
			result.FileDetails[filePath] = detail
			result.ErrorFiles++
			continue
		}

		// Check if payload already exists
		existingResult := payloadRepo.GetByRepositoryPath(ctx, repository.ID, relPath)
		var existing *coremodels.PayloadDB
		if existingResult.IsOk() {
			existing = existingResult.Unwrap()
		}

		// Check if file has changed using checksum (requirement 5.7)
		if existing != nil {
			existingChecksumResult := payloadRepo.GetChecksumByPath(ctx, repository.ID, relPath)
			if existingChecksumResult.IsOk() && existingChecksumResult.Unwrap() == fileChecksum {
				// File hasn't changed, skip processing
				detail := FileDetail{
					Path:        filePath,
					Checksum:    fileChecksum,
					Status:      "skipped",
					PayloadID:   existing.ID,
					ProcessedAt: time.Now(),
				}
				result.FileDetails[filePath] = detail
				result.SkippedFiles++
				continue
			}
		}

		// Parse payload file (now returns multiple payloads)
		payloadsResult := ps.parsePayloadFile(filePath, repository, relPath)
		if payloadsResult.IsErr() {
			detail := FileDetail{
				Path:        filePath,
				Checksum:    fileChecksum,
				Status:      "error",
				Error:       fmt.Sprintf("parsing failed: %v", payloadsResult.Error()),
				ProcessedAt: time.Now(),
			}
			result.FileDetails[filePath] = detail
			result.ErrorFiles++
			continue
		}

		payloadsList := payloadsResult.Unwrap()

		// Process each payload from the file
		for _, payload := range payloadsList {
			// Check if this specific payload exists (by ID or name)
			payloadKey := fmt.Sprintf("%s:%s", relPath, payload.Name)
			existingPayload := ps.findExistingPayload(ctx, payloadRepo, repository.ID, payload, relPath)

			if existingPayload != nil {
				// Update existing payload
				payload.ID = existingPayload.ID
				payload.CreatedAt = existingPayload.CreatedAt
				payload.CreatedBy = existingPayload.CreatedBy
				updatedPayloads = append(updatedPayloads, payload)

				detail := FileDetail{
					Path:        filePath,
					Checksum:    fileChecksum,
					Status:      "updated",
					PayloadID:   payload.ID,
					ProcessedAt: time.Now(),
				}
				result.FileDetails[payloadKey] = detail
			} else {
				// New payload
				newPayloads = append(newPayloads, payload)

				detail := FileDetail{
					Path:        filePath,
					Checksum:    fileChecksum,
					Status:      "new",
					PayloadID:   payload.ID,
					ProcessedAt: time.Now(),
				}
				result.FileDetails[payloadKey] = detail
			}
		}

		result.ProcessedFiles += len(payloadsList)
	}

	// Batch create new payloads
	if len(newPayloads) > 0 {
		createResult := payloadRepo.CreateBatch(ctx, newPayloads)
		if createResult.IsOk() {
			result.NewPayloads = len(newPayloads)
		} else {
			result.Errors = append(result.Errors, fmt.Sprintf("batch create failed: %v", createResult.Error()))
			result.ErrorFiles += len(newPayloads)
		}
	}

	// Batch update existing payloads
	if len(updatedPayloads) > 0 {
		updateResult := payloadRepo.UpdateBatch(ctx, updatedPayloads)
		if updateResult.IsOk() {
			result.UpdatedPayloads = len(updatedPayloads)
		} else {
			result.Errors = append(result.Errors, fmt.Sprintf("batch update failed: %v", updateResult.Error()))
			result.ErrorFiles += len(updatedPayloads)
		}
	}

	// Update checksums for processed files
	for _, detail := range result.FileDetails {
		if detail.Status == "new" || detail.Status == "updated" {
			_ = payloadRepo.UpdateChecksum(ctx, detail.PayloadID, detail.Checksum)
		}
	}

	return coremodels.Ok(result)
}

// calculateFileChecksum calculates SHA256 checksum of a file (requirement 5.7)
func (ps *PayloadSynchronizer) calculateFileChecksum(filePath string) coremodels.Result[string] {
	file, err := os.Open(filePath)
	if err != nil {
		return coremodels.Err[string](fmt.Errorf("failed to open file: %w", err))
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return coremodels.Err[string](fmt.Errorf("failed to calculate checksum: %w", err))
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))
	return coremodels.Ok(checksum)
}

// parsePayloadFile parses a payloads.json file and creates PayloadDB models
// Now returns a slice of payloads since payloads.json contains an array
func (ps *PayloadSynchronizer) parsePayloadFile(filePath string, repository *coremodels.PayloadRepositoryDB, relativePath string) coremodels.Result[[]*coremodels.PayloadDB] {
	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("failed to read file: %w", err))
	}

	// Extract domain and plugin from file path
	domain, plugin := ps.extractDomainAndPlugin(filePath)

	// Parse as JSON array of payload definitions
	var payloadDefs []PayloadDefinition
	if err := json.Unmarshal(content, &payloadDefs); err != nil {
		return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("failed to parse payloads.json: %w", err))
	}

	// Validate that we have payloads
	if len(payloadDefs) == 0 {
		return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("payloads.json contains no payloads"))
	}

	var payloads []*coremodels.PayloadDB
	for _, def := range payloadDefs {
		// Validate required fields
		if err := ps.validatePayloadDefinition(def); err != nil {
			// Log warning and skip invalid payload
			continue
		}

		// Skip payloads with empty content
		if strings.TrimSpace(def.Content) == "" {
			continue
		}

		// Create PayloadDB model
		payload := &coremodels.PayloadDB{
			ID:               uuid.New(),
			Name:             def.Name,
			Category:         ps.mapToPayloadCategory(def.Domain),
			Domain:           domain,
			PluginName:       plugin,
			Type:             ps.mapToPayloadType(def.PayloadType),
			Version:          ps.ensureVersion(def.Version),
			Content:          def.Content,
			Description:      def.Description,
			Severity:         ps.ensureSeverity(def.Severity),
			Tags:             def.Tags,
			Variables:        def.Variables,
			Config:           def.Metadata,
			Language:         def.Language,
			Enabled:          true,
			Validated:        false,
			UsageCount:       0,
			SuccessRate:      0.0,
			RepositoryID:     &repository.ID,
			RepositoryPath:   relativePath,
			CreatedBy:        "payload_sync",
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		}

		// Set defaults and validate
		payload.SetDefaults()
		if err := payload.Validate(); err != nil {
			// Log warning and skip invalid payload
			continue
		}

		payloads = append(payloads, payload)
	}

	if len(payloads) == 0 {
		return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("no valid payloads found in file"))
	}

	return coremodels.Ok(payloads)
}

// extractDomainAndPlugin extracts domain and plugin name from file path
// Expected path: basePath/domain/plugin/payloads.json
func (ps *PayloadSynchronizer) extractDomainAndPlugin(filePath string) (domain, plugin string) {
	// Get directory containing payloads.json
	dir := filepath.Dir(filePath)
	plugin = filepath.Base(dir)

	// Get parent directory (domain)
	domainDir := filepath.Dir(dir)
	domain = filepath.Base(domainDir)

	return domain, plugin
}

// validatePayloadDefinition validates required fields in payload definition
func (ps *PayloadSynchronizer) validatePayloadDefinition(def PayloadDefinition) error {
	if strings.TrimSpace(def.ID) == "" {
		return fmt.Errorf("payload id is required")
	}
	if strings.TrimSpace(def.Name) == "" {
		return fmt.Errorf("payload name is required")
	}
	if strings.TrimSpace(def.Content) == "" {
		return fmt.Errorf("payload content is required")
	}
	if strings.TrimSpace(def.Domain) == "" {
		return fmt.Errorf("payload domain is required")
	}
	if strings.TrimSpace(def.PayloadType) == "" {
		return fmt.Errorf("payload_type is required")
	}
	return nil
}

// parsePayloadFileOld parses a payload file and creates a PayloadDB model
// This is now the old single-payload method, keeping for backward compatibility
// Use parsePayloadFileArray for new domain-based parsing
func (ps *PayloadSynchronizer) parsePayloadFileOld(filePath string, repository *coremodels.PayloadRepositoryDB, relativePath string) coremodels.Result[*coremodels.PayloadDB] {
	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("failed to read file: %w", err))
	}

	// Parse metadata based on file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	var metadata PayloadFileMetadata

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(content, &metadata); err != nil {
			// If YAML parsing fails, treat as plain content
			metadata = ps.createDefaultMetadata(filePath, string(content))
		}
	case ".json":
		if err := json.Unmarshal(content, &metadata); err != nil {
			// If JSON parsing fails, treat as plain content
			metadata = ps.createDefaultMetadata(filePath, string(content))
		}
	default:
		// Plain text or other formats
		metadata = ps.createDefaultMetadata(filePath, string(content))
	}

	// Apply repository-specific mappings
	ps.applyRepositoryMappings(&metadata, repository)

	// Create PayloadDB model
	payload := &coremodels.PayloadDB{
		ID:               uuid.New(),
		Name:             metadata.Name,
		Category:         ps.mapToPayloadCategory(metadata.Category),
		Domain:           ps.ensureDomain(metadata.Domain),
		Type:             ps.mapToPayloadType(metadata.Type),
		Version:          metadata.Version,
		Content:          metadata.Content,
		Description:      metadata.Description,
		Severity:         ps.ensureSeverity(metadata.Severity),
		Tags:             metadata.Tags,
		Variables:        metadata.Variables,
		Config:           metadata.Config,
		Language:         metadata.Language,
		Enabled:          true,
		Validated:        false,
		UsageCount:       0,
		SuccessRate:      0.0,
		RepositoryID:     &repository.ID,
		RepositoryPath:   relativePath,
		CreatedBy:        "payload_sync",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Set defaults and validate
	payload.SetDefaults()
	if err := payload.Validate(); err != nil {
		return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("payload validation failed: %w", err))
	}

	return coremodels.Ok(payload)
}

// createDefaultMetadata creates default metadata for files without structured metadata
func (ps *PayloadSynchronizer) createDefaultMetadata(filePath, content string) PayloadFileMetadata {
	fileName := filepath.Base(filePath)
	name := strings.TrimSuffix(fileName, filepath.Ext(fileName))

	// Infer category from directory structure (requirement 3.2)
	category := ps.inferCategoryFromPath(filePath)
	domain := ps.inferDomainFromPath(filePath)

	return PayloadFileMetadata{
		Name:        name,
		Category:    category,
		Domain:      domain,
		Type:        "prompt", // Default type
		Description: fmt.Sprintf("Payload from file %s", fileName),
		Severity:    "medium",
		Tags:        []string{},
		Variables:   make(map[string]interface{}),
		Config:      make(map[string]interface{}),
		Version:     1,
		Content:     content,
	}
}

// inferCategoryFromPath infers payload category from file path (requirement 3.2)
func (ps *PayloadSynchronizer) inferCategoryFromPath(filePath string) string {
	pathLower := strings.ToLower(filePath)

	if strings.Contains(pathLower, "/model/") || strings.Contains(pathLower, "model") {
		return "model"
	}
	if strings.Contains(pathLower, "/data/") || strings.Contains(pathLower, "data") {
		return "data"
	}
	if strings.Contains(pathLower, "/interface/") || strings.Contains(pathLower, "interface") {
		return "interface"
	}
	if strings.Contains(pathLower, "/infrastructure/") || strings.Contains(pathLower, "infrastructure") {
		return "infrastructure"
	}
	if strings.Contains(pathLower, "/output/") || strings.Contains(pathLower, "output") {
		return "output"
	}
	if strings.Contains(pathLower, "/process/") || strings.Contains(pathLower, "process") {
		return "process"
	}

	// Default category
	return "interface"
}

// inferDomainFromPath infers domain from file path
func (ps *PayloadSynchronizer) inferDomainFromPath(filePath string) string {
	pathLower := strings.ToLower(filePath)

	// Extract domain from path segments
	segments := strings.Split(pathLower, string(filepath.Separator))
	for _, segment := range segments {
		if len(segment) > 0 && segment != "." && segment != ".." {
			// Use first meaningful segment as domain
			return segment
		}
	}

	return "default"
}

// applyRepositoryMappings applies repository-specific category and domain mappings
func (ps *PayloadSynchronizer) applyRepositoryMappings(metadata *PayloadFileMetadata, repository *coremodels.PayloadRepositoryDB) {
	// Apply category mapping
	if repository.CategoryMapping != nil {
		if mapped, exists := repository.CategoryMapping[metadata.Category]; exists {
			metadata.Category = mapped
		}
	}

	// Apply domain mapping
	if repository.DomainMapping != nil {
		if mapped, exists := repository.DomainMapping[metadata.Domain]; exists {
			metadata.Domain = mapped
		}
	}
}

// mapToPayloadCategory maps string to PayloadCategory enum
func (ps *PayloadSynchronizer) mapToPayloadCategory(category string) coremodels.PayloadCategory {
	switch strings.ToLower(category) {
	case "model":
		return coremodels.PayloadCategoryModel
	case "data":
		return coremodels.PayloadCategoryData
	case "interface":
		return coremodels.PayloadCategoryInterface
	case "infrastructure":
		return coremodels.PayloadCategoryInfrastructure
	case "output":
		return coremodels.PayloadCategoryOutput
	case "process":
		return coremodels.PayloadCategoryProcess
	default:
		return coremodels.PayloadCategoryInterface
	}
}

// mapToPayloadType maps string to PayloadType enum
func (ps *PayloadSynchronizer) mapToPayloadType(payloadType string) coremodels.PayloadType {
	switch strings.ToLower(payloadType) {
	case "prompt":
		return coremodels.PayloadTypePrompt
	case "query":
		return coremodels.PayloadTypeQuery
	case "input":
		return coremodels.PayloadTypeInput
	case "code":
		return coremodels.PayloadTypeCode
	case "data":
		return coremodels.PayloadTypeData
	case "script":
		return coremodels.PayloadTypeScript
	default:
		return coremodels.PayloadTypePrompt
	}
}

// ensureDomain ensures domain is not empty
func (ps *PayloadSynchronizer) ensureDomain(domain string) string {
	if domain == "" {
		return "default"
	}
	return domain
}

// ensureSeverity ensures severity is valid
func (ps *PayloadSynchronizer) ensureSeverity(severity string) string {
	validSeverities := []string{"low", "medium", "high", "critical"}
	severityLower := strings.ToLower(severity)

	for _, valid := range validSeverities {
		if severityLower == valid {
			return severityLower
		}
	}

	return "medium"
}

// GetSyncStatistics returns statistics about synchronization operations
func (ps *PayloadSynchronizer) GetSyncStatistics(ctx context.Context, repositoryID uuid.UUID, payloadRepo repositories.PayloadRepository) coremodels.Result[map[string]interface{}] {
	// Get payload count for repository
	payloadsResult := payloadRepo.ListByRepository(ctx, repositoryID)
	if payloadsResult.IsErr() {
		return coremodels.Err[map[string]interface{}](payloadsResult.Error())
	}

	payloads := payloadsResult.Unwrap()
	stats := map[string]interface{}{
		"total_payloads":      len(payloads),
		"enabled_payloads":    0,
		"disabled_payloads":   0,
		"validated_payloads":  0,
		"categories":          make(map[string]int),
		"types":               make(map[string]int),
		"severities":          make(map[string]int),
		"languages":           make(map[string]int),
		"last_updated":        time.Time{},
	}

	categoryStats := stats["categories"].(map[string]int)
	typeStats := stats["types"].(map[string]int)
	severityStats := stats["severities"].(map[string]int)
	languageStats := stats["languages"].(map[string]int)
	var lastUpdated time.Time

	for _, payload := range payloads {
		if payload.Enabled {
			stats["enabled_payloads"] = stats["enabled_payloads"].(int) + 1
		} else {
			stats["disabled_payloads"] = stats["disabled_payloads"].(int) + 1
		}

		if payload.Validated {
			stats["validated_payloads"] = stats["validated_payloads"].(int) + 1
		}

		categoryStats[string(payload.Category)]++
		typeStats[string(payload.Type)]++
		severityStats[payload.Severity]++

		if payload.Language != "" {
			languageStats[payload.Language]++
		}

		if payload.UpdatedAt.After(lastUpdated) {
			lastUpdated = payload.UpdatedAt
		}
	}

	stats["last_updated"] = lastUpdated
	return coremodels.Ok(stats)
}

// ValidateRepositoryStructure validates that a repository follows expected structure
func (ps *PayloadSynchronizer) ValidateRepositoryStructure(repositoryPath string) coremodels.Result[map[string]interface{}] {
	validation := map[string]interface{}{
		"is_valid":          true,
		"has_payloads":      false,
		"has_structure":     false,
		"payload_count":     0,
		"structure_issues":  []string{},
		"supported_formats": []string{},
	}

	issues := []string{}
	supportedFormats := []string{}

	// Check if repository has any payload files
	filesResult := ps.discoverPayloadFiles(repositoryPath)
	if filesResult.IsErr() {
		validation["is_valid"] = false
		issues = append(issues, fmt.Sprintf("Failed to scan directory: %v", filesResult.Error()))
	} else {
		files := filesResult.Unwrap()
		validation["payload_count"] = len(files)
		validation["has_payloads"] = len(files) > 0

		// Check file formats
		formatMap := make(map[string]int)
		for _, file := range files {
			ext := strings.ToLower(filepath.Ext(file))
			formatMap[ext]++
		}

		for format := range formatMap {
			supportedFormats = append(supportedFormats, format)
		}
	}

	// Check for expected directory structure
	expectedDirs := []string{"model", "data", "interface", "infrastructure", "output", "process"}
	foundDirs := 0

	for _, dir := range expectedDirs {
		dirPath := filepath.Join(repositoryPath, dir)
		if info, err := os.Stat(dirPath); err == nil && info.IsDir() {
			foundDirs++
		}
	}

	validation["has_structure"] = foundDirs > 0
	validation["structure_issues"] = issues
	validation["supported_formats"] = supportedFormats

	return coremodels.Ok(validation)
}

// findExistingPayload finds an existing payload by name within the same file path
func (ps *PayloadSynchronizer) findExistingPayload(ctx context.Context, payloadRepo repositories.PayloadRepository, repositoryID uuid.UUID, payload *coremodels.PayloadDB, filePath string) *coremodels.PayloadDB {
	// Try to find by repository path and name
	payloadsResult := payloadRepo.ListByRepository(ctx, repositoryID)
	if payloadsResult.IsErr() {
		return nil
	}

	payloads := payloadsResult.Unwrap()
	for _, existing := range payloads {
		// Match by repository path and name
		if existing.RepositoryPath == filePath && existing.Name == payload.Name {
			return existing
		}
	}

	return nil
}

// ensureVersion ensures version is not zero
func (ps *PayloadSynchronizer) ensureVersion(version int) int {
	if version <= 0 {
		return 1
	}
	return version
}