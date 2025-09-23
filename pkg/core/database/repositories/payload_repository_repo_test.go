// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package repositories

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "github.com/mattn/go-sqlite3"

	coremodels "github.com/gibson-sec/gibson-framework-2/pkg/core/models"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *sqlx.DB {
	db, err := sqlx.Open("sqlite3", ":memory:")
	require.NoError(t, err)

	// Create the payload_repositories table
	schema := `
	CREATE TABLE payload_repositories (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		url TEXT NOT NULL UNIQUE,
		local_path TEXT NOT NULL,
		clone_depth INTEGER NOT NULL DEFAULT 1,
		is_full_clone BOOLEAN NOT NULL DEFAULT FALSE,
		branch TEXT NOT NULL DEFAULT 'main',
		auth_type TEXT NOT NULL DEFAULT 'https',
		credential_id TEXT,
		conflict_strategy TEXT NOT NULL DEFAULT 'skip',
		status TEXT NOT NULL DEFAULT 'inactive',
		last_sync_at DATETIME,
		last_sync_error TEXT,
		last_sync_duration INTEGER,
		last_commit_hash TEXT,
		payload_count INTEGER NOT NULL DEFAULT 0,
		auto_sync BOOLEAN NOT NULL DEFAULT FALSE,
		sync_interval TEXT,
		description TEXT,
		tags TEXT,
		config TEXT,
		discovery_patterns TEXT,
		category_mapping TEXT,
		domain_mapping TEXT,
		total_size INTEGER NOT NULL DEFAULT 0,
		last_modified DATETIME,
		statistics TEXT,
		created_by TEXT,
		created_at DATETIME NOT NULL,
		updated_by TEXT,
		updated_at DATETIME NOT NULL
	);`

	_, err = db.Exec(schema)
	require.NoError(t, err)

	return db
}

// createTestRepository creates a test PayloadRepositoryDB
func createTestRepository() *coremodels.PayloadRepositoryDB {
	return &coremodels.PayloadRepositoryDB{
		ID:               uuid.New(),
		Name:             "test-repo",
		URL:              "https://github.com/test/payloads.git",
		LocalPath:        "/tmp/test-repo",
		CloneDepth:       1,
		IsFullClone:      false,
		Branch:           "main",
		AuthType:         coremodels.PayloadRepositoryAuthTypeHTTPS,
		ConflictStrategy: coremodels.PayloadRepositoryConflictStrategySkip,
		Status:           coremodels.PayloadRepositoryStatusInactive,
		PayloadCount:     0,
		AutoSync:         false,
		Description:      "Test repository",
		Tags:             []string{"test", "security"},
		Config:           map[string]interface{}{"test": "value"},
		DiscoveryPatterns: []string{"*.yaml", "*.json"},
		CategoryMapping:   map[string]string{"injection": "interface"},
		DomainMapping:     map[string]string{"model": "ai"},
		TotalSize:        0,
		CreatedBy:        "test-user",
		CreatedAt:        time.Now(),
		UpdatedBy:        "test-user",
		UpdatedAt:        time.Now(),
	}
}

func TestPayloadRepositoryRepo_Create(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewPayloadRepositoryRepository(db)
	testRepo := createTestRepository()

	// Test successful creation
	result := repo.Create(context.Background(), testRepo)
	require.True(t, result.IsOk(), "Expected successful creation")

	created := result.Unwrap()
	assert.Equal(t, testRepo.Name, created.Name)
	assert.Equal(t, testRepo.URL, created.URL)
	assert.Equal(t, testRepo.CloneDepth, created.CloneDepth)
}

func TestPayloadRepositoryRepo_GetByID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewPayloadRepositoryRepository(db)
	testRepo := createTestRepository()

	// Create repository first
	createResult := repo.Create(context.Background(), testRepo)
	require.True(t, createResult.IsOk())

	// Test retrieval by ID
	getResult := repo.GetByID(context.Background(), testRepo.ID)
	require.True(t, getResult.IsOk(), "Expected successful retrieval")

	retrieved := getResult.Unwrap()
	assert.Equal(t, testRepo.ID, retrieved.ID)
	assert.Equal(t, testRepo.Name, retrieved.Name)
	assert.Equal(t, testRepo.URL, retrieved.URL)
}

func TestPayloadRepositoryRepo_GetByName(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewPayloadRepositoryRepository(db)
	testRepo := createTestRepository()

	// Create repository first
	createResult := repo.Create(context.Background(), testRepo)
	require.True(t, createResult.IsOk())

	// Test retrieval by name
	getResult := repo.GetByName(context.Background(), testRepo.Name)
	require.True(t, getResult.IsOk(), "Expected successful retrieval")

	retrieved := getResult.Unwrap()
	assert.Equal(t, testRepo.Name, retrieved.Name)
	assert.Equal(t, testRepo.URL, retrieved.URL)
}

func TestPayloadRepositoryRepo_UpdateSyncStatus(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewPayloadRepositoryRepository(db)
	testRepo := createTestRepository()

	// Create repository first
	createResult := repo.Create(context.Background(), testRepo)
	require.True(t, createResult.IsOk())

	// Test sync status update
	updateResult := repo.UpdateSyncStatus(context.Background(), testRepo.ID, coremodels.PayloadRepositoryStatusActive, nil)
	require.True(t, updateResult.IsOk(), "Expected successful sync status update")
	assert.True(t, updateResult.Unwrap())

	// Verify the status was updated
	getResult := repo.GetByID(context.Background(), testRepo.ID)
	require.True(t, getResult.IsOk())
	retrieved := getResult.Unwrap()
	assert.Equal(t, coremodels.PayloadRepositoryStatusActive, retrieved.Status)
}

func TestPayloadRepositoryRepo_UpdateSyncProgress(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewPayloadRepositoryRepository(db)
	testRepo := createTestRepository()

	// Create repository first
	createResult := repo.Create(context.Background(), testRepo)
	require.True(t, createResult.IsOk())

	// Test sync progress update
	commitHash := "abc123"
	payloadCount := int64(50)
	duration := 5 * time.Second

	updateResult := repo.UpdateSyncProgress(context.Background(), testRepo.ID, coremodels.PayloadRepositoryStatusActive, commitHash, payloadCount, duration)
	require.True(t, updateResult.IsOk(), "Expected successful sync progress update")
	assert.True(t, updateResult.Unwrap())

	// Verify the progress was updated
	getResult := repo.GetByID(context.Background(), testRepo.ID)
	require.True(t, getResult.IsOk())
	retrieved := getResult.Unwrap()
	assert.Equal(t, coremodels.PayloadRepositoryStatusActive, retrieved.Status)
	assert.Equal(t, commitHash, retrieved.LastCommitHash)
	assert.Equal(t, payloadCount, retrieved.PayloadCount)
	assert.NotNil(t, retrieved.LastSyncAt)
	assert.NotNil(t, retrieved.LastSyncDuration)
}

func TestPayloadRepositoryRepo_ListWithSyncStatus(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewPayloadRepositoryRepository(db)

	// Create multiple test repositories
	testRepo1 := createTestRepository()
	testRepo1.Name = "repo1"
	testRepo1.URL = "https://github.com/test/repo1.git"
	testRepo1.Status = coremodels.PayloadRepositoryStatusActive
	testRepo1.AutoSync = true
	testRepo1.SyncInterval = "1h"
	now := time.Now()
	testRepo1.LastSyncAt = &now

	testRepo2 := createTestRepository()
	testRepo2.Name = "repo2"
	testRepo2.URL = "https://github.com/test/repo2.git"
	testRepo2.Status = coremodels.PayloadRepositoryStatusError
	testRepo2.LastSyncError = "Network timeout"

	// Create both repositories
	createResult1 := repo.Create(context.Background(), testRepo1)
	require.True(t, createResult1.IsOk())

	createResult2 := repo.Create(context.Background(), testRepo2)
	require.True(t, createResult2.IsOk())

	// Test listing with sync status
	listResult := repo.ListWithSyncStatus(context.Background())
	require.True(t, listResult.IsOk(), "Expected successful listing")

	repos := listResult.Unwrap()
	assert.Len(t, repos, 2)

	// Find the repositories in the list
	var repo1, repo2 *RepositoryWithSyncInfo
	for _, r := range repos {
		if r.Name == "repo1" {
			repo1 = r
		} else if r.Name == "repo2" {
			repo2 = r
		}
	}

	require.NotNil(t, repo1, "Expected to find repo1")
	require.NotNil(t, repo2, "Expected to find repo2")

	// Verify sync status information
	assert.Equal(t, "healthy", repo1.SyncHealth)
	assert.NotEmpty(t, repo1.SyncStatusDescription)
	assert.NotNil(t, repo1.NextSyncAt, "Expected next sync time for auto-sync repo")

	assert.Equal(t, "error", repo2.SyncHealth)
	assert.Contains(t, repo2.SyncStatusDescription, "Network timeout")
}

func TestPayloadRepositoryRepo_ExistsByName(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewPayloadRepositoryRepository(db)
	testRepo := createTestRepository()

	// Test non-existence
	existsResult := repo.ExistsByName(context.Background(), testRepo.Name)
	require.True(t, existsResult.IsOk())
	assert.False(t, existsResult.Unwrap())

	// Create repository
	createResult := repo.Create(context.Background(), testRepo)
	require.True(t, createResult.IsOk())

	// Test existence
	existsResult = repo.ExistsByName(context.Background(), testRepo.Name)
	require.True(t, existsResult.IsOk())
	assert.True(t, existsResult.Unwrap())
}

func TestPayloadRepositoryRepo_GetStatistics(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewPayloadRepositoryRepository(db)

	// Create multiple test repositories with different statuses
	repos := []*coremodels.PayloadRepositoryDB{
		{
			ID:           uuid.New(),
			Name:         "active-repo",
			URL:          "https://github.com/test/active.git",
			LocalPath:    "/tmp/active",
			Status:       coremodels.PayloadRepositoryStatusActive,
			AuthType:     coremodels.PayloadRepositoryAuthTypeHTTPS,
			PayloadCount: 10,
			TotalSize:    1024,
		},
		{
			ID:           uuid.New(),
			Name:         "inactive-repo",
			URL:          "https://github.com/test/inactive.git",
			LocalPath:    "/tmp/inactive",
			Status:       coremodels.PayloadRepositoryStatusInactive,
			AuthType:     coremodels.PayloadRepositoryAuthTypeSSH,
			PayloadCount: 5,
			TotalSize:    512,
		},
		{
			ID:           uuid.New(),
			Name:         "error-repo",
			URL:          "https://github.com/test/error.git",
			LocalPath:    "/tmp/error",
			Status:       coremodels.PayloadRepositoryStatusError,
			AuthType:     coremodels.PayloadRepositoryAuthTypeHTTPS,
			PayloadCount: 0,
			TotalSize:    0,
		},
	}

	// Create all repositories
	for _, r := range repos {
		r.SetDefaults()
		createResult := repo.Create(context.Background(), r)
		require.True(t, createResult.IsOk())
	}

	// Get statistics
	statsResult := repo.GetStatistics(context.Background())
	require.True(t, statsResult.IsOk(), "Expected successful statistics retrieval")

	stats := statsResult.Unwrap()
	assert.Equal(t, int64(3), stats.TotalRepositories)
	assert.Equal(t, int64(1), stats.ActiveRepositories)
	assert.Equal(t, int64(1), stats.InactiveRepositories)
	assert.Equal(t, int64(1), stats.ErrorRepositories)
	assert.Equal(t, int64(15), stats.TotalPayloads) // 10 + 5 + 0
	assert.Equal(t, int64(1536), stats.TotalSize)   // 1024 + 512 + 0
	assert.Equal(t, 5.0, stats.AveragePayloadsPerRepo) // 15 / 3

	// Check status counts
	assert.Equal(t, int64(1), stats.StatusCounts[coremodels.PayloadRepositoryStatusActive])
	assert.Equal(t, int64(1), stats.StatusCounts[coremodels.PayloadRepositoryStatusInactive])
	assert.Equal(t, int64(1), stats.StatusCounts[coremodels.PayloadRepositoryStatusError])

	// Check auth type counts
	assert.Equal(t, int64(2), stats.AuthTypeCounts[coremodels.PayloadRepositoryAuthTypeHTTPS])
	assert.Equal(t, int64(1), stats.AuthTypeCounts[coremodels.PayloadRepositoryAuthTypeSSH])
}