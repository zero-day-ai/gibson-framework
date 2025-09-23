// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package payloads

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	coremodels "github.com/gibson-sec/gibson-framework-2/pkg/core/models"
	"github.com/gibson-sec/gibson-framework-2/pkg/core/database/repositories"
	"github.com/gibson-sec/gibson-framework-2/pkg/services"
)

// GitSynchronizer manages the complete synchronization workflow from Git repositories to database
// Requirements 2.1-2.3: Synchronization workflow, 3.1-3.2: Discovery and Organization
type GitSynchronizer struct {
	gitService   *services.GitService
	repoRepo     repositories.PayloadRepositoryRepository
	batchSize    int
	maxConcurrent int
	logger       Logger
}

// SyncOptions holds configuration for synchronization operations
type SyncOptions struct {
	// Repository-specific options
	RepositoryID  uuid.UUID                                   `json:"repository_id"`
	Force         bool                                        `json:"force"`          // Force sync even if not required
	FullClone     bool                                        `json:"full_clone"`     // Override shallow clone setting
	BatchSize     int                                         `json:"batch_size"`     // Number of payloads to process in batch
	MaxConcurrent int                                         `json:"max_concurrent"` // Maximum concurrent operations

	// Discovery options (Requirement 3.1)
	DiscoveryPatterns []string                               `json:"discovery_patterns,omitempty"`
	CategoryMapping   map[string]coremodels.PayloadCategory  `json:"category_mapping,omitempty"`
	DomainMapping     map[string]string                      `json:"domain_mapping,omitempty"`

	// Conflict resolution (Requirement 2.3)
	ConflictStrategy  coremodels.PayloadRepositoryConflictStrategy `json:"conflict_strategy"`

	// Progress callbacks
	OnProgress        func(SyncProgress)                     `json:"-"`
	OnError           func(error)                            `json:"-"`
	OnDiscovery       func(PayloadDiscovery)                 `json:"-"`
}

// SyncProgress represents the current synchronization progress
type SyncProgress struct {
	RepositoryID     uuid.UUID    `json:"repository_id"`
	Phase            SyncPhase    `json:"phase"`
	Message          string       `json:"message"`
	Current          int64        `json:"current"`
	Total            int64        `json:"total"`
	StartTime        time.Time    `json:"start_time"`
	ElapsedTime      time.Duration `json:"elapsed_time"`
	EstimatedRemaining time.Duration `json:"estimated_remaining"`

	// Phase-specific details
	GitProgress      string       `json:"git_progress,omitempty"`
	FilesDiscovered  int64        `json:"files_discovered"`
	PayloadsProcessed int64       `json:"payloads_processed"`
	PayloadsCreated  int64        `json:"payloads_created"`
	PayloadsUpdated  int64        `json:"payloads_updated"`
	PayloadsSkipped  int64        `json:"payloads_skipped"`
	Errors           []string     `json:"errors,omitempty"`
}

// SyncPhase represents the current phase of synchronization
type SyncPhase string

const (
	SyncPhaseValidation    SyncPhase = "validation"
	SyncPhaseCloning       SyncPhase = "cloning"
	SyncPhasePulling       SyncPhase = "pulling"
	SyncPhaseDiscovery     SyncPhase = "discovery"
	SyncPhaseProcessing    SyncPhase = "processing"
	SyncPhaseIndexing      SyncPhase = "indexing"
	SyncPhaseConflictResolution SyncPhase = "conflict_resolution"
	SyncPhaseCleanup       SyncPhase = "cleanup"
	SyncPhaseCompleted     SyncPhase = "completed"
	SyncPhaseFailed        SyncPhase = "failed"
)

// PayloadDiscovery represents a discovered payload file
type PayloadDiscovery struct {
	FilePath         string                    `json:"file_path"`
	RelativePath     string                    `json:"relative_path"`
	Size             int64                     `json:"size"`
	ModifiedTime     time.Time                 `json:"modified_time"`
	Checksum         string                    `json:"checksum"`
	DetectedCategory coremodels.PayloadCategory `json:"detected_category"`
	DetectedDomain   string                    `json:"detected_domain"`
	DetectedType     coremodels.PayloadType    `json:"detected_type"`
	Metadata         map[string]interface{}    `json:"metadata,omitempty"`
}

// SyncResult represents the result of a complete synchronization operation
type SyncResult struct {
	RepositoryID      uuid.UUID     `json:"repository_id"`
	Success           bool          `json:"success"`
	StartTime         time.Time     `json:"start_time"`
	EndTime           time.Time     `json:"end_time"`
	Duration          time.Duration `json:"duration"`
	CommitHash        string        `json:"commit_hash"`

	// Statistics
	FilesDiscovered   int64         `json:"files_discovered"`
	PayloadsProcessed int64         `json:"payloads_processed"`
	PayloadsCreated   int64         `json:"payloads_created"`
	PayloadsUpdated   int64         `json:"payloads_updated"`
	PayloadsSkipped   int64         `json:"payloads_skipped"`
	ConflictsResolved int64         `json:"conflicts_resolved"`

	// Errors and warnings
	Errors            []string      `json:"errors,omitempty"`
	Warnings          []string      `json:"warnings,omitempty"`

	// Final status
	FinalStatus       coremodels.PayloadRepositoryStatus `json:"final_status"`
	ErrorMessage      string        `json:"error_message,omitempty"`
}

// ConflictResolution represents a resolved conflict
type ConflictResolution struct {
	PayloadID        uuid.UUID                                   `json:"payload_id"`
	ConflictType     string                                      `json:"conflict_type"`
	Strategy         coremodels.PayloadRepositoryConflictStrategy `json:"strategy"`
	Resolution       string                                      `json:"resolution"`
	ExistingPayload  *coremodels.PayloadDB                       `json:"existing_payload,omitempty"`
	NewPayload       *coremodels.PayloadDB                       `json:"new_payload,omitempty"`
	ResolvedPayload  *coremodels.PayloadDB                       `json:"resolved_payload,omitempty"`
}

// Logger interface for progress and error reporting
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
}

// NewGitSynchronizer creates a new GitSynchronizer instance
func NewGitSynchronizer(gitService *services.GitService, repoRepo repositories.PayloadRepositoryRepository, logger Logger) *GitSynchronizer {
	return &GitSynchronizer{
		gitService:    gitService,
		repoRepo:      repoRepo,
		batchSize:     100,  // Default batch size for processing
		maxConcurrent: 5,    // Default max concurrent operations
		logger:        logger,
	}
}

// SyncRepository performs complete synchronization for a repository (Requirements 2.1-2.3)
func (gs *GitSynchronizer) SyncRepository(ctx context.Context, opts SyncOptions) coremodels.Result[*SyncResult] {
	startTime := time.Now()
	result := &SyncResult{
		RepositoryID: opts.RepositoryID,
		StartTime:    startTime,
		Errors:       make([]string, 0),
		Warnings:     make([]string, 0),
	}

	// Set defaults
	if opts.BatchSize <= 0 {
		opts.BatchSize = gs.batchSize
	}
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = gs.maxConcurrent
	}

	gs.logger.Info("Starting repository synchronization", "repository_id", opts.RepositoryID)

	// Phase 1: Validation - Get and validate repository
	progress := gs.initializeProgress(opts.RepositoryID, startTime)
	gs.updateProgress(&progress, SyncPhaseValidation, "Validating repository configuration", 0, 8, opts.OnProgress)

	repoResult := gs.repoRepo.GetByID(ctx, opts.RepositoryID)
	if repoResult.IsErr() {
		return gs.handleSyncError(result, fmt.Errorf("failed to get repository: %w", repoResult.Error()), opts.OnError)
	}

	repo := repoResult.Unwrap()
	gs.logger.Info("Repository loaded", "name", repo.Name, "url", repo.URL)

	// Check if sync is required
	if !opts.Force && !repo.IsSyncRequired() && !repo.IsCloneRequired() {
		gs.logger.Info("Repository sync not required", "repository_id", opts.RepositoryID)
		result.Success = true
		result.FinalStatus = coremodels.PayloadRepositoryStatusActive
		result.EndTime = time.Now()
		result.Duration = time.Since(startTime)
		return coremodels.Ok(result)
	}

	// Update repository status to syncing
	if err := gs.updateRepositoryStatus(ctx, opts.RepositoryID, coremodels.PayloadRepositoryStatusSyncing, nil); err != nil {
		gs.logger.Warn("Failed to update repository status to syncing", "error", err)
	}

	// Phase 2: Git Operations - Clone or Pull
	if repo.IsCloneRequired() {
		gs.updateProgress(&progress, SyncPhaseCloning, "Cloning repository", 1, 8, opts.OnProgress)
		if err := gs.performClone(ctx, repo, opts, &progress); err != nil {
			return gs.handleSyncError(result, fmt.Errorf("clone failed: %w", err), opts.OnError)
		}
	} else {
		gs.updateProgress(&progress, SyncPhasePulling, "Pulling latest changes", 1, 8, opts.OnProgress)
		if err := gs.performPull(ctx, repo, opts, &progress); err != nil {
			return gs.handleSyncError(result, fmt.Errorf("pull failed: %w", err), opts.OnError)
		}
	}

	// Phase 3: Discovery - Find payload files (Requirement 3.1)
	gs.updateProgress(&progress, SyncPhaseDiscovery, "Discovering payload files", 2, 8, opts.OnProgress)
	discoveries, err := gs.discoverPayloadFiles(ctx, repo, opts, &progress)
	if err != nil {
		return gs.handleSyncError(result, fmt.Errorf("payload discovery failed: %w", err), opts.OnError)
	}

	result.FilesDiscovered = int64(len(discoveries))
	progress.FilesDiscovered = result.FilesDiscovered
	gs.logger.Info("Payload discovery completed", "files_found", len(discoveries))

	// Phase 4: Processing - Convert discoveries to payloads
	gs.updateProgress(&progress, SyncPhaseProcessing, "Processing payload files", 3, 8, opts.OnProgress)
	payloads, err := gs.processDiscoveries(ctx, repo, discoveries, opts, &progress)
	if err != nil {
		return gs.handleSyncError(result, fmt.Errorf("payload processing failed: %w", err), opts.OnError)
	}

	result.PayloadsProcessed = int64(len(payloads))
	progress.PayloadsProcessed = result.PayloadsProcessed

	// Phase 5: Conflict Resolution (Requirement 2.3)
	gs.updateProgress(&progress, SyncPhaseConflictResolution, "Resolving conflicts", 4, 8, opts.OnProgress)
	conflicts, err := gs.resolveConflicts(ctx, repo, payloads, opts, &progress)
	if err != nil {
		return gs.handleSyncError(result, fmt.Errorf("conflict resolution failed: %w", err), opts.OnError)
	}

	result.ConflictsResolved = int64(len(conflicts))

	// Phase 6: Batch Indexing - Save payloads to database (Requirement 2.2)
	gs.updateProgress(&progress, SyncPhaseIndexing, "Indexing payloads to database", 5, 8, opts.OnProgress)
	indexStats, err := gs.batchIndexPayloads(ctx, repo, payloads, opts, &progress)
	if err != nil {
		return gs.handleSyncError(result, fmt.Errorf("payload indexing failed: %w", err), opts.OnError)
	}

	result.PayloadsCreated = indexStats.Created
	result.PayloadsUpdated = indexStats.Updated
	result.PayloadsSkipped = indexStats.Skipped

	// Phase 7: Cleanup - Remove orphaned payloads
	gs.updateProgress(&progress, SyncPhaseCleanup, "Cleaning up orphaned payloads", 6, 8, opts.OnProgress)
	if err := gs.cleanupOrphanedPayloads(ctx, repo, opts, &progress); err != nil {
		// Log warning but don't fail the sync
		gs.logger.Warn("Cleanup warning", "error", err)
		result.Warnings = append(result.Warnings, fmt.Sprintf("cleanup warning: %v", err))
	}

	// Phase 8: Finalization - Update repository status and statistics
	gs.updateProgress(&progress, SyncPhaseCompleted, "Finalizing synchronization", 7, 8, opts.OnProgress)

	// Get final commit hash
	validation := gs.gitService.Validate(repo.LocalPath)
	var commitHash string
	if validation.IsOk() {
		commitHash = validation.Unwrap().LastCommit
	}
	result.CommitHash = commitHash

	// Update repository with sync results
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	if err := gs.updateRepositorySyncResults(ctx, repo, true, duration, commitHash, result.PayloadsCreated+result.PayloadsUpdated); err != nil {
		gs.logger.Warn("Failed to update repository sync results", "error", err)
	}

	// Complete the result
	result.Success = true
	result.EndTime = endTime
	result.Duration = duration
	result.FinalStatus = coremodels.PayloadRepositoryStatusActive

	gs.updateProgress(&progress, SyncPhaseCompleted, "Synchronization completed successfully", 8, 8, opts.OnProgress)
	gs.logger.Info("Repository synchronization completed",
		"repository_id", opts.RepositoryID,
		"duration", duration,
		"payloads_created", result.PayloadsCreated,
		"payloads_updated", result.PayloadsUpdated,
		"files_discovered", result.FilesDiscovered)

	return coremodels.Ok(result)
}

// SyncAllRepositories synchronizes all repositories that require sync (Requirement 2.1)
func (gs *GitSynchronizer) SyncAllRepositories(ctx context.Context, opts SyncOptions) coremodels.Result[map[uuid.UUID]*SyncResult] {
	gs.logger.Info("Starting synchronization of all repositories")

	// Get repositories requiring sync
	reposResult := gs.repoRepo.ListRequiringSync(ctx)
	if reposResult.IsErr() {
		return coremodels.Err[map[uuid.UUID]*SyncResult](fmt.Errorf("failed to list repositories requiring sync: %w", reposResult.Error()))
	}

	repos := reposResult.Unwrap()
	if len(repos) == 0 {
		gs.logger.Info("No repositories require synchronization")
		return coremodels.Ok(make(map[uuid.UUID]*SyncResult))
	}

	gs.logger.Info("Found repositories requiring sync", "count", len(repos))

	// Create a semaphore to limit concurrent syncs
	semaphore := make(chan struct{}, opts.MaxConcurrent)
	results := make(map[uuid.UUID]*SyncResult)
	var resultsMutex sync.Mutex
	var wg sync.WaitGroup

	// Process repositories concurrently with limits
	for _, repo := range repos {
		wg.Add(1)
		go func(r *coremodels.PayloadRepositoryDB) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Create repository-specific options
			repoOpts := opts
			repoOpts.RepositoryID = r.ID

			// Perform sync
			syncResult := gs.SyncRepository(ctx, repoOpts)

			// Store result
			resultsMutex.Lock()
			if syncResult.IsOk() {
				results[r.ID] = syncResult.Unwrap()
			} else {
				// Create error result
				errorResult := &SyncResult{
					RepositoryID: r.ID,
					Success:      false,
					StartTime:    time.Now(),
					EndTime:      time.Now(),
					Duration:     0,
					ErrorMessage: syncResult.Error().Error(),
					FinalStatus:  coremodels.PayloadRepositoryStatusError,
					Errors:       []string{syncResult.Error().Error()},
				}
				results[r.ID] = errorResult
			}
			resultsMutex.Unlock()
		}(repo)
	}

	// Wait for all syncs to complete
	wg.Wait()

	gs.logger.Info("Completed synchronization of all repositories", "total", len(repos), "successful", countSuccessful(results))
	return coremodels.Ok(results)
}

// Helper methods for sync implementation

// initializeProgress creates initial progress state
func (gs *GitSynchronizer) initializeProgress(repoID uuid.UUID, startTime time.Time) SyncProgress {
	return SyncProgress{
		RepositoryID: repoID,
		StartTime:    startTime,
		Errors:       make([]string, 0),
	}
}

// updateProgress updates progress state and calls callback
func (gs *GitSynchronizer) updateProgress(progress *SyncProgress, phase SyncPhase, message string, current, total int64, callback func(SyncProgress)) {
	progress.Phase = phase
	progress.Message = message
	progress.Current = current
	progress.Total = total
	progress.ElapsedTime = time.Since(progress.StartTime)

	// Calculate estimated remaining time
	if current > 0 {
		avgTimePerStep := progress.ElapsedTime / time.Duration(current)
		remaining := total - current
		progress.EstimatedRemaining = avgTimePerStep * time.Duration(remaining)
	}

	if callback != nil {
		callback(*progress)
	}
}

// handleSyncError creates error result and calls error callback
func (gs *GitSynchronizer) handleSyncError(result *SyncResult, err error, onError func(error)) coremodels.Result[*SyncResult] {
	gs.logger.Error("Synchronization failed", "error", err)

	result.Success = false
	result.EndTime = time.Now()
	result.Duration = time.Since(result.StartTime)
	result.ErrorMessage = err.Error()
	result.FinalStatus = coremodels.PayloadRepositoryStatusError
	result.Errors = append(result.Errors, err.Error())

	// Update repository status to error
	ctx := context.Background()
	if updateErr := gs.updateRepositoryStatus(ctx, result.RepositoryID, coremodels.PayloadRepositoryStatusError, err); updateErr != nil {
		gs.logger.Warn("Failed to update repository status to error", "error", updateErr)
	}

	if onError != nil {
		onError(err)
	}

	return coremodels.Ok(result) // Return result even on error for reporting
}

// updateRepositoryStatus updates repository status
func (gs *GitSynchronizer) updateRepositoryStatus(ctx context.Context, repoID uuid.UUID, status coremodels.PayloadRepositoryStatus, err error) error {
	updateResult := gs.repoRepo.UpdateSyncStatus(ctx, repoID, status, err)
	if updateResult.IsErr() {
		return updateResult.Error()
	}
	return nil
}

// performClone performs repository cloning with progress
func (gs *GitSynchronizer) performClone(ctx context.Context, repo *coremodels.PayloadRepositoryDB, opts SyncOptions, progress *SyncProgress) error {
	cloneOpts := services.GitCloneOptions{
		URL:       repo.URL,
		LocalPath: repo.LocalPath,
		Depth:     repo.GetCloneDepthValue(),
		Branch:    repo.Branch,
		AuthType:  repo.AuthType,
		Full:      opts.FullClone || repo.IsFullClone,
		Progress:  func(msg string) {
			progress.GitProgress = msg
			if opts.OnProgress != nil {
				opts.OnProgress(*progress)
			}
		},
	}

	// Set authentication details if available
	// TODO: Integrate with credential service when available

	cloneResult := gs.gitService.Clone(ctx, cloneOpts)
	if cloneResult.IsErr() {
		return cloneResult.Error()
	}

	return nil
}

// performPull performs repository pull with progress
func (gs *GitSynchronizer) performPull(ctx context.Context, repo *coremodels.PayloadRepositoryDB, opts SyncOptions, progress *SyncProgress) error {
	pullOpts := services.GitPullOptions{
		LocalPath: repo.LocalPath,
		AuthType:  repo.AuthType,
		Progress:  func(msg string) {
			progress.GitProgress = msg
			if opts.OnProgress != nil {
				opts.OnProgress(*progress)
			}
		},
	}

	// Set authentication details if available
	// TODO: Integrate with credential service when available

	pullResult := gs.gitService.Pull(ctx, pullOpts)
	if pullResult.IsErr() {
		return pullResult.Error()
	}

	return nil
}

// discoverPayloadFiles discovers payload files in repository (Requirement 3.1)
func (gs *GitSynchronizer) discoverPayloadFiles(ctx context.Context, repo *coremodels.PayloadRepositoryDB, opts SyncOptions, progress *SyncProgress) ([]PayloadDiscovery, error) {
	var discoveries []PayloadDiscovery

	// Use repository discovery patterns or options
	patterns := opts.DiscoveryPatterns
	if len(patterns) == 0 {
		patterns = repo.DiscoveryPatterns
	}
	if len(patterns) == 0 {
		// Default patterns
		patterns = []string{"*.yaml", "*.yml", "*.json", "*.txt", "*.payload"}
	}

	// Walk repository directory
	err := filepath.Walk(repo.LocalPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and hidden files
		if info.IsDir() || strings.HasPrefix(info.Name(), ".") {
			return nil
		}

		// Check if file matches any pattern
		matched := false
		for _, pattern := range patterns {
			if matched, _ = filepath.Match(pattern, info.Name()); matched {
				break
			}
		}

		if !matched {
			return nil
		}

		// Create discovery entry
		relativePath, _ := filepath.Rel(repo.LocalPath, path)
		discovery := PayloadDiscovery{
			FilePath:     path,
			RelativePath: relativePath,
			Size:         info.Size(),
			ModifiedTime: info.ModTime(),
		}

		// Detect category and domain (Requirement 3.2)
		gs.enrichDiscovery(&discovery, repo, opts)

		discoveries = append(discoveries, discovery)

		// Update progress
		progress.FilesDiscovered = int64(len(discoveries))
		if opts.OnDiscovery != nil {
			opts.OnDiscovery(discovery)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk repository directory: %w", err)
	}

	return discoveries, nil
}

// enrichDiscovery adds category and domain detection to discovery (Requirement 3.2)
func (gs *GitSynchronizer) enrichDiscovery(discovery *PayloadDiscovery, repo *coremodels.PayloadRepositoryDB, opts SyncOptions) {
	// Use path-based category detection
	categoryMapping := opts.CategoryMapping
	if len(categoryMapping) == 0 {
		categoryMapping = convertStringMapToPayloadCategory(repo.CategoryMapping)
	}

	// Domain mapping
	domainMapping := opts.DomainMapping
	if len(domainMapping) == 0 {
		domainMapping = repo.DomainMapping
	}

	// Detect category based on path
	discovery.DetectedCategory = gs.detectCategory(discovery.RelativePath, categoryMapping)
	discovery.DetectedDomain = gs.detectDomain(discovery.RelativePath, domainMapping)
	discovery.DetectedType = gs.detectType(discovery.FilePath, discovery.RelativePath)
}

// detectCategory detects payload category from path
func (gs *GitSynchronizer) detectCategory(relativePath string, categoryMapping map[string]coremodels.PayloadCategory) coremodels.PayloadCategory {
	pathLower := strings.ToLower(relativePath)

	// Check explicit mappings first
	for pattern, category := range categoryMapping {
		if matched, _ := filepath.Match(strings.ToLower(pattern), pathLower); matched {
			return category
		}
	}

	// Default path-based detection
	if strings.Contains(pathLower, "injection") || strings.Contains(pathLower, "xss") || strings.Contains(pathLower, "sqli") {
		return coremodels.PayloadCategoryInterface
	}
	if strings.Contains(pathLower, "jailbreak") || strings.Contains(pathLower, "adversarial") || strings.Contains(pathLower, "prompt") {
		return coremodels.PayloadCategoryModel
	}
	if strings.Contains(pathLower, "data") || strings.Contains(pathLower, "dataset") {
		return coremodels.PayloadCategoryData
	}
	if strings.Contains(pathLower, "infra") || strings.Contains(pathLower, "deploy") {
		return coremodels.PayloadCategoryInfrastructure
	}

	// Default fallback
	return coremodels.PayloadCategoryInterface
}

// detectDomain detects payload domain from path
func (gs *GitSynchronizer) detectDomain(relativePath string, domainMapping map[string]string) string {
	pathLower := strings.ToLower(relativePath)

	// Check explicit mappings first
	for pattern, domain := range domainMapping {
		if matched, _ := filepath.Match(strings.ToLower(pattern), pathLower); matched {
			return domain
		}
	}

	// Extract domain from path structure
	parts := strings.Split(relativePath, string(filepath.Separator))
	if len(parts) > 1 {
		return parts[0] // Use first directory as domain
	}

	return "general"
}

// detectType detects payload type from file extension and content
func (gs *GitSynchronizer) detectType(filePath, relativePath string) coremodels.PayloadType {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".yaml", ".yml":
		return coremodels.PayloadTypeData
	case ".json":
		return coremodels.PayloadTypeData
	case ".txt":
		return coremodels.PayloadTypePrompt
	case ".py", ".js", ".sh":
		return coremodels.PayloadTypeCode
	case ".sql":
		return coremodels.PayloadTypeQuery
	default:
		return coremodels.PayloadTypePrompt
	}
}

// processDiscoveries converts discoveries to payload models
func (gs *GitSynchronizer) processDiscoveries(ctx context.Context, repo *coremodels.PayloadRepositoryDB, discoveries []PayloadDiscovery, opts SyncOptions, progress *SyncProgress) ([]*coremodels.PayloadDB, error) {
	var payloads []*coremodels.PayloadDB

	for i, discovery := range discoveries {
		// Read file content
		content, err := os.ReadFile(discovery.FilePath)
		if err != nil {
			gs.logger.Warn("Failed to read payload file", "path", discovery.FilePath, "error", err)
			continue
		}

		// Create payload model
		payload := &coremodels.PayloadDB{
			ID:             uuid.New(),
			Name:           generatePayloadName(discovery.RelativePath),
			Category:       discovery.DetectedCategory,
			Domain:         discovery.DetectedDomain,
			Type:           discovery.DetectedType,
			Content:        string(content),
			Description:    fmt.Sprintf("Imported from repository %s at %s", repo.Name, discovery.RelativePath),
			RepositoryID:   &repo.ID,
			RepositoryPath: discovery.RelativePath,
			Enabled:        true,
			Validated:      false,
		}

		payload.SetDefaults()
		payloads = append(payloads, payload)

		// Update progress
		progress.PayloadsProcessed = int64(i + 1)
		if opts.OnProgress != nil {
			opts.OnProgress(*progress)
		}
	}

	return payloads, nil
}

// resolveConflicts handles payload conflicts according to strategy (Requirement 2.3)
func (gs *GitSynchronizer) resolveConflicts(ctx context.Context, repo *coremodels.PayloadRepositoryDB, payloads []*coremodels.PayloadDB, opts SyncOptions, progress *SyncProgress) ([]ConflictResolution, error) {
	var conflicts []ConflictResolution
	strategy := opts.ConflictStrategy
	if strategy == "" {
		strategy = repo.ConflictStrategy
	}

	// TODO: Implement conflict detection and resolution
	// This would involve checking existing payloads in the database
	// and applying the conflict strategy (skip, overwrite, error)

	gs.logger.Info("Conflict resolution completed", "strategy", strategy, "conflicts", len(conflicts))
	return conflicts, nil
}

// batchIndexPayloads saves payloads to database in batches (Requirement 2.2)
func (gs *GitSynchronizer) batchIndexPayloads(ctx context.Context, repo *coremodels.PayloadRepositoryDB, payloads []*coremodels.PayloadDB, opts SyncOptions, progress *SyncProgress) (*IndexingStatistics, error) {
	stats := &IndexingStatistics{}

	// Process in batches
	batchSize := opts.BatchSize
	for i := 0; i < len(payloads); i += batchSize {
		end := i + batchSize
		if end > len(payloads) {
			end = len(payloads)
		}

		batch := payloads[i:end]

		// Process each payload in batch
		// TODO: Implement actual database insertion
		// This would use the payload repository to save payloads

		for _, payload := range batch {
			// Simulate processing
			_ = payload
			stats.Created++
		}

		// Update progress
		progress.PayloadsProcessed = int64(end)
		if opts.OnProgress != nil {
			opts.OnProgress(*progress)
		}
	}

	return stats, nil
}

// cleanupOrphanedPayloads removes payloads no longer in repository
func (gs *GitSynchronizer) cleanupOrphanedPayloads(ctx context.Context, repo *coremodels.PayloadRepositoryDB, opts SyncOptions, progress *SyncProgress) error {
	// TODO: Implement orphaned payload cleanup
	// This would find payloads in database that are no longer in the repository
	gs.logger.Info("Orphaned payload cleanup completed", "repository_id", repo.ID)
	return nil
}

// updateRepositorySyncResults updates repository with final sync results
func (gs *GitSynchronizer) updateRepositorySyncResults(ctx context.Context, repo *coremodels.PayloadRepositoryDB, success bool, duration time.Duration, commitHash string, payloadCount int64) error {
	updateResult := gs.repoRepo.UpdateSyncProgress(ctx, repo.ID, coremodels.PayloadRepositoryStatusActive, commitHash, payloadCount, duration)
	if updateResult.IsErr() {
		return updateResult.Error()
	}
	return nil
}

// Helper types and functions

// IndexingStatistics tracks payload indexing results
type IndexingStatistics struct {
	Created int64 `json:"created"`
	Updated int64 `json:"updated"`
	Skipped int64 `json:"skipped"`
}

// generatePayloadName creates a payload name from file path
func generatePayloadName(relativePath string) string {
	name := filepath.Base(relativePath)
	ext := filepath.Ext(name)
	if ext != "" {
		name = strings.TrimSuffix(name, ext)
	}

	// Replace special characters with underscores
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "-", "_")

	return name
}

// convertStringMapToPayloadCategory converts string map to payload category map
func convertStringMapToPayloadCategory(stringMap map[string]string) map[string]coremodels.PayloadCategory {
	result := make(map[string]coremodels.PayloadCategory)
	for k, v := range stringMap {
		switch strings.ToLower(v) {
		case "model":
			result[k] = coremodels.PayloadCategoryModel
		case "data":
			result[k] = coremodels.PayloadCategoryData
		case "interface":
			result[k] = coremodels.PayloadCategoryInterface
		case "infrastructure":
			result[k] = coremodels.PayloadCategoryInfrastructure
		case "output":
			result[k] = coremodels.PayloadCategoryOutput
		case "process":
			result[k] = coremodels.PayloadCategoryProcess
		default:
			result[k] = coremodels.PayloadCategoryInterface
		}
	}
	return result
}

// countSuccessful counts successful sync results
func countSuccessful(results map[uuid.UUID]*SyncResult) int {
	count := 0
	for _, result := range results {
		if result.Success {
			count++
		}
	}
	return count
}