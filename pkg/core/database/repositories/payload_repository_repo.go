// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	coremodels "github.com/gibson-sec/gibson-framework-2/pkg/core/models"
	dbmodels "github.com/gibson-sec/gibson-framework-2/pkg/core/database/models"
)

// PayloadRepositoryRepository defines the interface for payload repository data access
type PayloadRepositoryRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, repo *coremodels.PayloadRepositoryDB) coremodels.Result[*coremodels.PayloadRepositoryDB]
	GetByID(ctx context.Context, id uuid.UUID) coremodels.Result[*coremodels.PayloadRepositoryDB]
	GetByName(ctx context.Context, name string) coremodels.Result[*coremodels.PayloadRepositoryDB]
	GetByURL(ctx context.Context, url string) coremodels.Result[*coremodels.PayloadRepositoryDB]
	List(ctx context.Context) coremodels.Result[[]*coremodels.PayloadRepositoryDB]
	Update(ctx context.Context, repo *coremodels.PayloadRepositoryDB) coremodels.Result[*coremodels.PayloadRepositoryDB]
	Delete(ctx context.Context, id uuid.UUID) coremodels.Result[bool]

	// Sync status management (requirement 1.5)
	UpdateSyncStatus(ctx context.Context, id uuid.UUID, status coremodels.PayloadRepositoryStatus, err error) coremodels.Result[bool]
	UpdateSyncProgress(ctx context.Context, id uuid.UUID, status coremodels.PayloadRepositoryStatus, commitHash string, payloadCount int64, duration time.Duration) coremodels.Result[bool]
	ListWithSyncStatus(ctx context.Context) coremodels.Result[[]*RepositoryWithSyncInfo]

	// Statistics and reporting
	GetStatistics(ctx context.Context) coremodels.Result[*RepositoryStatistics]
	ListByStatus(ctx context.Context, status coremodels.PayloadRepositoryStatus) coremodels.Result[[]*coremodels.PayloadRepositoryDB]
	ListEnabled(ctx context.Context) coremodels.Result[[]*coremodels.PayloadRepositoryDB]
	ListRequiringSync(ctx context.Context) coremodels.Result[[]*coremodels.PayloadRepositoryDB]

	// Utility methods
	ExistsByName(ctx context.Context, name string) coremodels.Result[bool]
	ExistsByURL(ctx context.Context, url string) coremodels.Result[bool]
	CountByStatus(ctx context.Context, status coremodels.PayloadRepositoryStatus) coremodels.Result[int64]
}

// RepositoryWithSyncInfo represents a repository with detailed sync information for requirement 1.5
type RepositoryWithSyncInfo struct {
	*coremodels.PayloadRepositoryDB
	SyncStatusDescription string    `json:"sync_status_description"`
	NextSyncAt           *time.Time `json:"next_sync_at"`
	SyncHealth           string     `json:"sync_health"` // healthy, warning, error
	LastSyncDuration     string     `json:"last_sync_duration_formatted"`
}

// RepositoryStatistics represents aggregate statistics for all repositories
type RepositoryStatistics struct {
	TotalRepositories      int64                                                              `json:"total_repositories"`
	ActiveRepositories     int64                                                              `json:"active_repositories"`
	InactiveRepositories   int64                                                              `json:"inactive_repositories"`
	SyncingRepositories    int64                                                              `json:"syncing_repositories"`
	ErrorRepositories      int64                                                              `json:"error_repositories"`
	TotalPayloads          int64                                                              `json:"total_payloads"`
	AveragePayloadsPerRepo float64                                                            `json:"average_payloads_per_repo"`
	StatusCounts           map[coremodels.PayloadRepositoryStatus]int64                      `json:"status_counts"`
	AuthTypeCounts         map[coremodels.PayloadRepositoryAuthType]int64                    `json:"auth_type_counts"`
	LastSyncTimes          map[uuid.UUID]time.Time                                           `json:"last_sync_times"`
	TotalSize              int64                                                              `json:"total_size"`
}

// payloadRepositoryRepo implements PayloadRepositoryRepository
type payloadRepositoryRepo struct {
	db *sqlx.DB
}

// NewPayloadRepositoryRepository creates a new payload repository repository
func NewPayloadRepositoryRepository(db *sqlx.DB) PayloadRepositoryRepository {
	return &payloadRepositoryRepo{
		db: db,
	}
}

// Create creates a new payload repository (requirement 1.1)
func (r *payloadRepositoryRepo) Create(ctx context.Context, repo *coremodels.PayloadRepositoryDB) coremodels.Result[*coremodels.PayloadRepositoryDB] {
	// Set defaults and validate
	repo.SetDefaults()
	if err := repo.Validate(); err != nil {
		return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("validation failed: %w", err))
	}

	// Convert to database model
	dbRepo := convertToDBModel(repo)

	// SQL insert with RETURNING clause for SQLite
	query := `
		INSERT INTO payload_repositories (
			id, name, url, local_path, clone_depth, is_full_clone, branch,
			auth_type, credential_id, conflict_strategy, status, last_sync_at,
			last_sync_error, last_sync_duration, last_commit_hash, payload_count,
			auto_sync, sync_interval, description, tags, config, discovery_patterns,
			category_mapping, domain_mapping, total_size, last_modified, statistics,
			created_by, created_at, updated_by, updated_at
		) VALUES (
			:id, :name, :url, :local_path, :clone_depth, :is_full_clone, :branch,
			:auth_type, :credential_id, :conflict_strategy, :status, :last_sync_at,
			:last_sync_error, :last_sync_duration, :last_commit_hash, :payload_count,
			:auto_sync, :sync_interval, :description, :tags, :config, :discovery_patterns,
			:category_mapping, :domain_mapping, :total_size, :last_modified, :statistics,
			:created_by, :created_at, :updated_by, :updated_at
		)`

	if _, err := r.db.NamedExecContext(ctx, query, dbRepo); err != nil {
		return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to create repository: %w", err))
	}

	return coremodels.Ok(repo)
}

// GetByID retrieves a repository by ID
func (r *payloadRepositoryRepo) GetByID(ctx context.Context, id uuid.UUID) coremodels.Result[*coremodels.PayloadRepositoryDB] {
	query := `
		SELECT id, name, url, local_path, clone_depth, is_full_clone, branch,
			   auth_type, credential_id, conflict_strategy, status, last_sync_at,
			   last_sync_error, last_sync_duration, last_commit_hash, payload_count,
			   auto_sync, sync_interval, description, tags, config, discovery_patterns,
			   category_mapping, domain_mapping, total_size, last_modified, statistics,
			   created_by, created_at, updated_by, updated_at
		FROM payload_repositories
		WHERE id = ?`

	var dbRepo dbmodels.PayloadRepositoryDB
	if err := r.db.GetContext(ctx, &dbRepo, query, id.String()); err != nil {
		if err == sql.ErrNoRows {
			return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("repository not found with ID: %s", id))
		}
		return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to get repository: %w", err))
	}

	repo := convertFromDBModel(&dbRepo)
	return coremodels.Ok(repo)
}

// GetByName retrieves a repository by name
func (r *payloadRepositoryRepo) GetByName(ctx context.Context, name string) coremodels.Result[*coremodels.PayloadRepositoryDB] {
	query := `
		SELECT id, name, url, local_path, clone_depth, is_full_clone, branch,
			   auth_type, credential_id, conflict_strategy, status, last_sync_at,
			   last_sync_error, last_sync_duration, last_commit_hash, payload_count,
			   auto_sync, sync_interval, description, tags, config, discovery_patterns,
			   category_mapping, domain_mapping, total_size, last_modified, statistics,
			   created_by, created_at, updated_by, updated_at
		FROM payload_repositories
		WHERE name = ?`

	var dbRepo dbmodels.PayloadRepositoryDB
	if err := r.db.GetContext(ctx, &dbRepo, query, name); err != nil {
		if err == sql.ErrNoRows {
			return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("repository not found with name: %s", name))
		}
		return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to get repository: %w", err))
	}

	repo := convertFromDBModel(&dbRepo)
	return coremodels.Ok(repo)
}

// GetByURL retrieves a repository by URL
func (r *payloadRepositoryRepo) GetByURL(ctx context.Context, url string) coremodels.Result[*coremodels.PayloadRepositoryDB] {
	query := `
		SELECT id, name, url, local_path, clone_depth, is_full_clone, branch,
			   auth_type, credential_id, conflict_strategy, status, last_sync_at,
			   last_sync_error, last_sync_duration, last_commit_hash, payload_count,
			   auto_sync, sync_interval, description, tags, config, discovery_patterns,
			   category_mapping, domain_mapping, total_size, last_modified, statistics,
			   created_by, created_at, updated_by, updated_at
		FROM payload_repositories
		WHERE url = ?`

	var dbRepo dbmodels.PayloadRepositoryDB
	if err := r.db.GetContext(ctx, &dbRepo, query, url); err != nil {
		if err == sql.ErrNoRows {
			return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("repository not found with URL: %s", url))
		}
		return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to get repository: %w", err))
	}

	repo := convertFromDBModel(&dbRepo)
	return coremodels.Ok(repo)
}

// List retrieves all repositories
func (r *payloadRepositoryRepo) List(ctx context.Context) coremodels.Result[[]*coremodels.PayloadRepositoryDB] {
	query := `
		SELECT id, name, url, local_path, clone_depth, is_full_clone, branch,
			   auth_type, credential_id, conflict_strategy, status, last_sync_at,
			   last_sync_error, last_sync_duration, last_commit_hash, payload_count,
			   auto_sync, sync_interval, description, tags, config, discovery_patterns,
			   category_mapping, domain_mapping, total_size, last_modified, statistics,
			   created_by, created_at, updated_by, updated_at
		FROM payload_repositories
		ORDER BY created_at DESC`

	var dbRepos []dbmodels.PayloadRepositoryDB
	if err := r.db.SelectContext(ctx, &dbRepos, query); err != nil {
		return coremodels.Err[[]*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to list repositories: %w", err))
	}

	repos := make([]*coremodels.PayloadRepositoryDB, len(dbRepos))
	for i, dbRepo := range dbRepos {
		repos[i] = convertFromDBModel(&dbRepo)
	}

	return coremodels.Ok(repos)
}

// Update updates an existing repository
func (r *payloadRepositoryRepo) Update(ctx context.Context, repo *coremodels.PayloadRepositoryDB) coremodels.Result[*coremodels.PayloadRepositoryDB] {
	// Set updated time and validate
	repo.UpdatedAt = time.Now()
	if err := repo.Validate(); err != nil {
		return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("validation failed: %w", err))
	}

	// Convert to database model
	dbRepo := convertToDBModel(repo)

	query := `
		UPDATE payload_repositories SET
			name = :name, url = :url, local_path = :local_path,
			clone_depth = :clone_depth, is_full_clone = :is_full_clone, branch = :branch,
			auth_type = :auth_type, credential_id = :credential_id, conflict_strategy = :conflict_strategy,
			status = :status, last_sync_at = :last_sync_at, last_sync_error = :last_sync_error,
			last_sync_duration = :last_sync_duration, last_commit_hash = :last_commit_hash,
			payload_count = :payload_count, auto_sync = :auto_sync, sync_interval = :sync_interval,
			description = :description, tags = :tags, config = :config,
			discovery_patterns = :discovery_patterns, category_mapping = :category_mapping,
			domain_mapping = :domain_mapping, total_size = :total_size, last_modified = :last_modified,
			statistics = :statistics, updated_by = :updated_by, updated_at = :updated_at
		WHERE id = :id`

	result, err := r.db.NamedExecContext(ctx, query, dbRepo)
	if err != nil {
		return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to update repository: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to get rows affected: %w", err))
	}

	if rowsAffected == 0 {
		return coremodels.Err[*coremodels.PayloadRepositoryDB](fmt.Errorf("repository not found with ID: %s", repo.ID))
	}

	return coremodels.Ok(repo)
}

// Delete removes a repository
func (r *payloadRepositoryRepo) Delete(ctx context.Context, id uuid.UUID) coremodels.Result[bool] {
	query := `DELETE FROM payload_repositories WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to delete repository: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to get rows affected: %w", err))
	}

	return coremodels.Ok(rowsAffected > 0)
}

// UpdateSyncStatus updates the sync status and error for a repository (requirement 1.5)
func (r *payloadRepositoryRepo) UpdateSyncStatus(ctx context.Context, id uuid.UUID, status coremodels.PayloadRepositoryStatus, syncErr error) coremodels.Result[bool] {
	var errorMsg string
	if syncErr != nil {
		errorMsg = syncErr.Error()
	}

	query := `
		UPDATE payload_repositories SET
			status = ?, last_sync_error = ?, updated_at = ?
		WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, status, errorMsg, time.Now(), id.String())
	if err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to update sync status: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to get rows affected: %w", err))
	}

	return coremodels.Ok(rowsAffected > 0)
}

// UpdateSyncProgress updates sync progress with detailed information (requirement 1.5)
func (r *payloadRepositoryRepo) UpdateSyncProgress(ctx context.Context, id uuid.UUID, status coremodels.PayloadRepositoryStatus, commitHash string, payloadCount int64, duration time.Duration) coremodels.Result[bool] {
	now := time.Now()
	durationNanos := duration.Nanoseconds()

	query := `
		UPDATE payload_repositories SET
			status = ?, last_sync_at = ?, last_commit_hash = ?,
			payload_count = ?, last_sync_duration = ?, last_sync_error = ?, updated_at = ?
		WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, status, now, commitHash, payloadCount, durationNanos, "", time.Now(), id.String())
	if err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to update sync progress: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to get rows affected: %w", err))
	}

	return coremodels.Ok(rowsAffected > 0)
}

// ListWithSyncStatus returns repositories with detailed sync status information (requirement 1.5)
func (r *payloadRepositoryRepo) ListWithSyncStatus(ctx context.Context) coremodels.Result[[]*RepositoryWithSyncInfo] {
	query := `
		SELECT id, name, url, local_path, clone_depth, is_full_clone, branch,
			   auth_type, credential_id, conflict_strategy, status, last_sync_at,
			   last_sync_error, last_sync_duration, last_commit_hash, payload_count,
			   auto_sync, sync_interval, description, tags, config, discovery_patterns,
			   category_mapping, domain_mapping, total_size, last_modified, statistics,
			   created_by, created_at, updated_by, updated_at
		FROM payload_repositories
		ORDER BY created_at DESC`

	var dbRepos []dbmodels.PayloadRepositoryDB
	if err := r.db.SelectContext(ctx, &dbRepos, query); err != nil {
		return coremodels.Err[[]*RepositoryWithSyncInfo](fmt.Errorf("failed to list repositories with sync status: %w", err))
	}

	repos := make([]*RepositoryWithSyncInfo, len(dbRepos))
	for i, dbRepo := range dbRepos {
		repo := convertFromDBModel(&dbRepo)
		syncInfo := &RepositoryWithSyncInfo{
			PayloadRepositoryDB: repo,
		}

		// Add sync status description
		syncInfo.SyncStatusDescription = getSyncStatusDescription(repo)

		// Calculate next sync time if auto-sync is enabled
		if repo.AutoSync && repo.SyncInterval != "" && repo.LastSyncAt != nil {
			if interval, err := time.ParseDuration(repo.SyncInterval); err == nil {
				nextSync := repo.LastSyncAt.Add(interval)
				syncInfo.NextSyncAt = &nextSync
			}
		}

		// Determine sync health
		syncInfo.SyncHealth = getSyncHealth(repo)

		// Format last sync duration
		if repo.LastSyncDuration != nil {
			duration := time.Duration(*repo.LastSyncDuration)
			syncInfo.LastSyncDuration = formatDuration(duration)
		}

		repos[i] = syncInfo
	}

	return coremodels.Ok(repos)
}

// GetStatistics returns aggregate statistics for all repositories
func (r *payloadRepositoryRepo) GetStatistics(ctx context.Context) coremodels.Result[*RepositoryStatistics] {
	// Get basic counts
	countQuery := `
		SELECT
			COUNT(*) as total,
			COUNT(CASE WHEN status = 'active' THEN 1 END) as active,
			COUNT(CASE WHEN status = 'inactive' THEN 1 END) as inactive,
			COUNT(CASE WHEN status = 'syncing' THEN 1 END) as syncing,
			COUNT(CASE WHEN status = 'error' THEN 1 END) as error_count,
			COALESCE(SUM(payload_count), 0) as total_payloads,
			COALESCE(SUM(total_size), 0) as total_size
		FROM payload_repositories`

	var counts struct {
		Total         int64 `db:"total"`
		Active        int64 `db:"active"`
		Inactive      int64 `db:"inactive"`
		Syncing       int64 `db:"syncing"`
		ErrorCount    int64 `db:"error_count"`
		TotalPayloads int64 `db:"total_payloads"`
		TotalSize     int64 `db:"total_size"`
	}

	if err := r.db.GetContext(ctx, &counts, countQuery); err != nil {
		return coremodels.Err[*RepositoryStatistics](fmt.Errorf("failed to get statistics counts: %w", err))
	}

	// Calculate average payloads per repository
	var avgPayloads float64
	if counts.Total > 0 {
		avgPayloads = float64(counts.TotalPayloads) / float64(counts.Total)
	}

	// Get status counts
	statusCounts := make(map[coremodels.PayloadRepositoryStatus]int64)
	statusCounts[coremodels.PayloadRepositoryStatusActive] = counts.Active
	statusCounts[coremodels.PayloadRepositoryStatusInactive] = counts.Inactive
	statusCounts[coremodels.PayloadRepositoryStatusSyncing] = counts.Syncing
	statusCounts[coremodels.PayloadRepositoryStatusError] = counts.ErrorCount

	// Get auth type counts
	authQuery := `
		SELECT auth_type, COUNT(*) as count
		FROM payload_repositories
		GROUP BY auth_type`

	rows, err := r.db.QueryContext(ctx, authQuery)
	if err != nil {
		return coremodels.Err[*RepositoryStatistics](fmt.Errorf("failed to get auth type counts: %w", err))
	}
	defer rows.Close()

	authTypeCounts := make(map[coremodels.PayloadRepositoryAuthType]int64)
	for rows.Next() {
		var authType coremodels.PayloadRepositoryAuthType
		var count int64
		if err := rows.Scan(&authType, &count); err != nil {
			return coremodels.Err[*RepositoryStatistics](fmt.Errorf("failed to scan auth type count: %w", err))
		}
		authTypeCounts[authType] = count
	}

	// Get last sync times
	syncQuery := `
		SELECT id, last_sync_at
		FROM payload_repositories
		WHERE last_sync_at IS NOT NULL`

	syncRows, err := r.db.QueryContext(ctx, syncQuery)
	if err != nil {
		return coremodels.Err[*RepositoryStatistics](fmt.Errorf("failed to get sync times: %w", err))
	}
	defer syncRows.Close()

	lastSyncTimes := make(map[uuid.UUID]time.Time)
	for syncRows.Next() {
		var id uuid.UUID
		var lastSync time.Time
		if err := syncRows.Scan(&id, &lastSync); err != nil {
			return coremodels.Err[*RepositoryStatistics](fmt.Errorf("failed to scan sync time: %w", err))
		}
		lastSyncTimes[id] = lastSync
	}

	stats := &RepositoryStatistics{
		TotalRepositories:      counts.Total,
		ActiveRepositories:     counts.Active,
		InactiveRepositories:   counts.Inactive,
		SyncingRepositories:    counts.Syncing,
		ErrorRepositories:      counts.ErrorCount,
		TotalPayloads:          counts.TotalPayloads,
		AveragePayloadsPerRepo: avgPayloads,
		StatusCounts:           statusCounts,
		AuthTypeCounts:         authTypeCounts,
		LastSyncTimes:          lastSyncTimes,
		TotalSize:              counts.TotalSize,
	}

	return coremodels.Ok(stats)
}

// ListByStatus returns repositories filtered by status
func (r *payloadRepositoryRepo) ListByStatus(ctx context.Context, status coremodels.PayloadRepositoryStatus) coremodels.Result[[]*coremodels.PayloadRepositoryDB] {
	query := `
		SELECT id, name, url, local_path, clone_depth, is_full_clone, branch,
			   auth_type, credential_id, conflict_strategy, status, last_sync_at,
			   last_sync_error, last_sync_duration, last_commit_hash, payload_count,
			   auto_sync, sync_interval, description, tags, config, discovery_patterns,
			   category_mapping, domain_mapping, total_size, last_modified, statistics,
			   created_by, created_at, updated_by, updated_at
		FROM payload_repositories
		WHERE status = ?
		ORDER BY created_at DESC`

	var dbRepos []dbmodels.PayloadRepositoryDB
	if err := r.db.SelectContext(ctx, &dbRepos, query, status); err != nil {
		return coremodels.Err[[]*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to list repositories by status: %w", err))
	}

	repos := make([]*coremodels.PayloadRepositoryDB, len(dbRepos))
	for i, dbRepo := range dbRepos {
		repos[i] = convertFromDBModel(&dbRepo)
	}

	return coremodels.Ok(repos)
}

// ListEnabled returns only enabled repositories
func (r *payloadRepositoryRepo) ListEnabled(ctx context.Context) coremodels.Result[[]*coremodels.PayloadRepositoryDB] {
	query := `
		SELECT id, name, url, local_path, clone_depth, is_full_clone, branch,
			   auth_type, credential_id, conflict_strategy, status, last_sync_at,
			   last_sync_error, last_sync_duration, last_commit_hash, payload_count,
			   auto_sync, sync_interval, description, tags, config, discovery_patterns,
			   category_mapping, domain_mapping, total_size, last_modified, statistics,
			   created_by, created_at, updated_by, updated_at
		FROM payload_repositories
		WHERE status IN ('active', 'syncing')
		ORDER BY created_at DESC`

	var dbRepos []dbmodels.PayloadRepositoryDB
	if err := r.db.SelectContext(ctx, &dbRepos, query); err != nil {
		return coremodels.Err[[]*coremodels.PayloadRepositoryDB](fmt.Errorf("failed to list enabled repositories: %w", err))
	}

	repos := make([]*coremodels.PayloadRepositoryDB, len(dbRepos))
	for i, dbRepo := range dbRepos {
		repos[i] = convertFromDBModel(&dbRepo)
	}

	return coremodels.Ok(repos)
}

// ListRequiringSync returns repositories that need synchronization
func (r *payloadRepositoryRepo) ListRequiringSync(ctx context.Context) coremodels.Result[[]*coremodels.PayloadRepositoryDB] {
	// Get all repositories and filter based on sync requirements
	listResult := r.List(ctx)
	if listResult.IsErr() {
		return coremodels.Err[[]*coremodels.PayloadRepositoryDB](listResult.Error())
	}

	allRepos := listResult.Unwrap()
	var syncRepos []*coremodels.PayloadRepositoryDB

	for _, repo := range allRepos {
		if repo.IsSyncRequired() {
			syncRepos = append(syncRepos, repo)
		}
	}

	return coremodels.Ok(syncRepos)
}

// ExistsByName checks if a repository exists by name
func (r *payloadRepositoryRepo) ExistsByName(ctx context.Context, name string) coremodels.Result[bool] {
	query := `SELECT EXISTS(SELECT 1 FROM payload_repositories WHERE name = ?)`

	var exists bool
	if err := r.db.GetContext(ctx, &exists, query, name); err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to check existence by name: %w", err))
	}

	return coremodels.Ok(exists)
}

// ExistsByURL checks if a repository exists by URL
func (r *payloadRepositoryRepo) ExistsByURL(ctx context.Context, url string) coremodels.Result[bool] {
	query := `SELECT EXISTS(SELECT 1 FROM payload_repositories WHERE url = ?)`

	var exists bool
	if err := r.db.GetContext(ctx, &exists, query, url); err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to check existence by URL: %w", err))
	}

	return coremodels.Ok(exists)
}

// CountByStatus returns count of repositories by status
func (r *payloadRepositoryRepo) CountByStatus(ctx context.Context, status coremodels.PayloadRepositoryStatus) coremodels.Result[int64] {
	query := `SELECT COUNT(*) FROM payload_repositories WHERE status = ?`

	var count int64
	if err := r.db.GetContext(ctx, &count, query, status); err != nil {
		return coremodels.Err[int64](fmt.Errorf("failed to count by status: %w", err))
	}

	return coremodels.Ok(count)
}

// Helper functions for type conversion between core and database models

// convertToDBModel converts a core model to database model
func convertToDBModel(core *coremodels.PayloadRepositoryDB) *dbmodels.PayloadRepositoryDB {
	// Convert time.Duration to nanoseconds for database storage
	var lastSyncDuration *int64
	if core.LastSyncDuration != nil {
		nanos := core.LastSyncDuration.Nanoseconds()
		lastSyncDuration = &nanos
	}

	return &dbmodels.PayloadRepositoryDB{
		ID:               core.ID,
		Name:             core.Name,
		URL:              core.URL,
		LocalPath:        core.LocalPath,
		CloneDepth:       core.CloneDepth,
		IsFullClone:      core.IsFullClone,
		Branch:           core.Branch,
		AuthType:         dbmodels.PayloadRepositoryAuthType(core.AuthType),
		CredentialID:     core.CredentialID,
		ConflictStrategy: dbmodels.PayloadRepositoryConflictStrategy(core.ConflictStrategy),
		Status:           dbmodels.PayloadRepositoryStatus(core.Status),
		LastSyncAt:       core.LastSyncAt,
		LastSyncError:    core.LastSyncError,
		LastSyncDuration: lastSyncDuration,
		LastCommitHash:   core.LastCommitHash,
		PayloadCount:     core.PayloadCount,
		AutoSync:         core.AutoSync,
		SyncInterval:     core.SyncInterval,
		Description:      core.Description,
		Tags:             dbmodels.JSONStringSlice(core.Tags),
		Config:           dbmodels.JSONMap(core.Config),
		DiscoveryPatterns: dbmodels.JSONStringSlice(core.DiscoveryPatterns),
		CategoryMapping:   convertStringMapToJSONMap(core.CategoryMapping),
		DomainMapping:     convertStringMapToJSONMap(core.DomainMapping),
		TotalSize:        core.TotalSize,
		LastModified:     core.LastModified,
		Statistics:       dbmodels.JSONMap(core.Statistics),
		CreatedBy:        core.CreatedBy,
		CreatedAt:        core.CreatedAt,
		UpdatedBy:        core.UpdatedBy,
		UpdatedAt:        core.UpdatedAt,
	}
}

// convertFromDBModel converts a database model to core model
func convertFromDBModel(db *dbmodels.PayloadRepositoryDB) *coremodels.PayloadRepositoryDB {
	// Convert nanoseconds back to time.Duration
	var lastSyncDuration *time.Duration
	if db.LastSyncDuration != nil {
		duration := time.Duration(*db.LastSyncDuration)
		lastSyncDuration = &duration
	}

	return &coremodels.PayloadRepositoryDB{
		ID:               db.ID,
		Name:             db.Name,
		URL:              db.URL,
		LocalPath:        db.LocalPath,
		CloneDepth:       db.CloneDepth,
		IsFullClone:      db.IsFullClone,
		Branch:           db.Branch,
		AuthType:         coremodels.PayloadRepositoryAuthType(db.AuthType),
		CredentialID:     db.CredentialID,
		ConflictStrategy: coremodels.PayloadRepositoryConflictStrategy(db.ConflictStrategy),
		Status:           coremodels.PayloadRepositoryStatus(db.Status),
		LastSyncAt:       db.LastSyncAt,
		LastSyncError:    db.LastSyncError,
		LastSyncDuration: lastSyncDuration,
		LastCommitHash:   db.LastCommitHash,
		PayloadCount:     db.PayloadCount,
		AutoSync:         db.AutoSync,
		SyncInterval:     db.SyncInterval,
		Description:      db.Description,
		Tags:             []string(db.Tags),
		Config:           map[string]interface{}(db.Config),
		DiscoveryPatterns: []string(db.DiscoveryPatterns),
		CategoryMapping:   map[string]string(convertToStringMap(db.CategoryMapping)),
		DomainMapping:     map[string]string(convertToStringMap(db.DomainMapping)),
		TotalSize:        db.TotalSize,
		LastModified:     db.LastModified,
		Statistics:       map[string]interface{}(db.Statistics),
		CreatedBy:        db.CreatedBy,
		CreatedAt:        db.CreatedAt,
		UpdatedBy:        db.UpdatedBy,
		UpdatedAt:        db.UpdatedAt,
	}
}

// Helper function to convert JSONMap to map[string]string
func convertToStringMap(jsonMap dbmodels.JSONMap) map[string]string {
	result := make(map[string]string)
	for k, v := range jsonMap {
		if str, ok := v.(string); ok {
			result[k] = str
		}
	}
	return result
}

// Helper function to convert map[string]string to JSONMap
func convertStringMapToJSONMap(stringMap map[string]string) dbmodels.JSONMap {
	result := make(dbmodels.JSONMap)
	for k, v := range stringMap {
		result[k] = v
	}
	return result
}

// Helper functions for sync status information

// getSyncStatusDescription returns a human-readable description of the sync status
func getSyncStatusDescription(repo *coremodels.PayloadRepositoryDB) string {
	switch repo.Status {
	case coremodels.PayloadRepositoryStatusActive:
		if repo.LastSyncAt != nil {
			return fmt.Sprintf("Last synced %s", formatTimeAgo(*repo.LastSyncAt))
		}
		return "Active, no sync performed yet"
	case coremodels.PayloadRepositoryStatusInactive:
		return "Repository not yet cloned"
	case coremodels.PayloadRepositoryStatusSyncing:
		return "Synchronization in progress"
	case coremodels.PayloadRepositoryStatusError:
		if repo.LastSyncError != "" {
			return fmt.Sprintf("Sync failed: %s", repo.LastSyncError)
		}
		return "Sync failed with unknown error"
	case coremodels.PayloadRepositoryStatusCloning:
		return "Initial clone in progress"
	default:
		return "Unknown status"
	}
}

// getSyncHealth determines the health status of the repository
func getSyncHealth(repo *coremodels.PayloadRepositoryDB) string {
	switch repo.Status {
	case coremodels.PayloadRepositoryStatusActive:
		if repo.AutoSync && repo.LastSyncAt != nil && repo.SyncInterval != "" {
			if interval, err := time.ParseDuration(repo.SyncInterval); err == nil {
				timeSinceSync := time.Since(*repo.LastSyncAt)
				// If more than 2x the sync interval has passed, it's a warning
				if timeSinceSync > interval*2 {
					return "warning"
				}
			}
		}
		return "healthy"
	case coremodels.PayloadRepositoryStatusError:
		return "error"
	case coremodels.PayloadRepositoryStatusSyncing, coremodels.PayloadRepositoryStatusCloning:
		return "healthy"
	case coremodels.PayloadRepositoryStatusInactive:
		return "warning"
	default:
		return "unknown"
	}
}

// formatTimeAgo formats a time as "X minutes ago", "X hours ago", etc.
func formatTimeAgo(t time.Time) string {
	duration := time.Since(t)

	if duration < time.Minute {
		return "just now"
	} else if duration < time.Hour {
		minutes := int(duration.Minutes())
		if minutes == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", minutes)
	} else if duration < 24*time.Hour {
		hours := int(duration.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	} else {
		days := int(duration.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	} else if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else if d < time.Hour {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		if seconds == 0 {
			return fmt.Sprintf("%dm", minutes)
		}
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	} else {
		hours := int(d.Hours())
		minutes := int(d.Minutes()) % 60
		if minutes == 0 {
			return fmt.Sprintf("%dh", hours)
		}
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
}