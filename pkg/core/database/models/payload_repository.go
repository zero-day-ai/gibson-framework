// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// PayloadRepositoryStatus represents the status of a payload repository
type PayloadRepositoryStatus string

const (
	PayloadRepositoryStatusActive   PayloadRepositoryStatus = "active"
	PayloadRepositoryStatusInactive PayloadRepositoryStatus = "inactive"
	PayloadRepositoryStatusSyncing  PayloadRepositoryStatus = "syncing"
	PayloadRepositoryStatusError    PayloadRepositoryStatus = "error"
	PayloadRepositoryStatusCloning  PayloadRepositoryStatus = "cloning"
)

// PayloadRepositoryAuthType represents the authentication type for a repository
type PayloadRepositoryAuthType string

const (
	PayloadRepositoryAuthTypeNone  PayloadRepositoryAuthType = "none"
	PayloadRepositoryAuthTypeSSH   PayloadRepositoryAuthType = "ssh"
	PayloadRepositoryAuthTypeHTTPS PayloadRepositoryAuthType = "https"
	PayloadRepositoryAuthTypeToken PayloadRepositoryAuthType = "token"
)

// PayloadRepositoryConflictStrategy represents how to handle conflicts during sync
type PayloadRepositoryConflictStrategy string

const (
	PayloadRepositoryConflictStrategySkip      PayloadRepositoryConflictStrategy = "skip"
	PayloadRepositoryConflictStrategyOverwrite PayloadRepositoryConflictStrategy = "overwrite"
	PayloadRepositoryConflictStrategyError     PayloadRepositoryConflictStrategy = "error"
)

// PayloadRepositoryDB represents a Git repository containing security payloads in the database layer
type PayloadRepositoryDB struct {
	// Core identification
	ID        uuid.UUID `db:"id" json:"id"`
	Name      string    `db:"name" json:"name"`
	URL       string    `db:"url" json:"url"`
	LocalPath string    `db:"local_path" json:"local_path"`

	// Repository configuration
	CloneDepth       int                               `db:"clone_depth" json:"clone_depth"`
	IsFullClone      bool                              `db:"is_full_clone" json:"is_full_clone"`
	Branch           string                            `db:"branch" json:"branch"`
	AuthType         PayloadRepositoryAuthType         `db:"auth_type" json:"auth_type"`
	CredentialID     *uuid.UUID                        `db:"credential_id" json:"credential_id,omitempty"`
	ConflictStrategy PayloadRepositoryConflictStrategy `db:"conflict_strategy" json:"conflict_strategy"`

	// Repository status and metadata
	Status           PayloadRepositoryStatus `db:"status" json:"status"`
	LastSyncAt       *time.Time              `db:"last_sync_at" json:"last_sync_at,omitempty"`
	LastSyncError    string                  `db:"last_sync_error" json:"last_sync_error"`
	LastSyncDuration *int64                  `db:"last_sync_duration" json:"last_sync_duration,omitempty"` // Duration in nanoseconds
	LastCommitHash   string                  `db:"last_commit_hash" json:"last_commit_hash"`
	PayloadCount     int64                   `db:"payload_count" json:"payload_count"`
	AutoSync         bool                    `db:"auto_sync" json:"auto_sync"`
	SyncInterval     string                  `db:"sync_interval" json:"sync_interval"`
	Description      string                  `db:"description" json:"description"`
	Tags             JSONStringSlice         `db:"tags" json:"tags,omitempty"`
	Config           JSONMap                 `db:"config" json:"config,omitempty"`

	// Discovery and organization settings
	DiscoveryPatterns JSONStringSlice `db:"discovery_patterns" json:"discovery_patterns,omitempty"`
	CategoryMapping   JSONMap         `db:"category_mapping" json:"category_mapping,omitempty"`
	DomainMapping     JSONMap         `db:"domain_mapping" json:"domain_mapping,omitempty"`

	// Statistics and metadata
	TotalSize    int64      `db:"total_size" json:"total_size"`
	LastModified *time.Time `db:"last_modified" json:"last_modified,omitempty"`
	Statistics   JSONMap    `db:"statistics" json:"statistics,omitempty"`

	// Audit fields
	CreatedBy string    `db:"created_by" json:"created_by"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedBy string    `db:"updated_by" json:"updated_by"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// JSONStringSlice is a wrapper for []string that can be scanned from JSON in database
type JSONStringSlice []string

// Scan implements the Scanner interface for database/sql
func (j *JSONStringSlice) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	var data []byte
	switch v := value.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		*j = nil
		return nil
	}

	return json.Unmarshal(data, j)
}

// Value implements the Valuer interface for database/sql
func (j JSONStringSlice) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// JSONMap is a wrapper for map[string]interface{} that can be scanned from JSON in database
type JSONMap map[string]interface{}

// Scan implements the Scanner interface for database/sql
func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	var data []byte
	switch v := value.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		*j = nil
		return nil
	}

	return json.Unmarshal(data, j)
}

// Value implements the Valuer interface for database/sql
func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// TableName returns the table name for the PayloadRepositoryDB model
func (PayloadRepositoryDB) TableName() string {
	return "payload_repositories"
}

// SetDefaults sets default values for the database model
func (r *PayloadRepositoryDB) SetDefaults() {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}

	if r.CloneDepth == 0 {
		r.CloneDepth = 1 // Default to shallow clone as per requirement 1.3
	}

	if r.Status == "" {
		r.Status = PayloadRepositoryStatusInactive
	}

	if r.AuthType == "" {
		r.AuthType = PayloadRepositoryAuthTypeHTTPS
	}

	if r.ConflictStrategy == "" {
		r.ConflictStrategy = PayloadRepositoryConflictStrategySkip
	}

	if r.Branch == "" {
		r.Branch = "main"
	}

	now := time.Now()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now

	// Initialize discovery patterns with common payload file extensions
	if len(r.DiscoveryPatterns) == 0 {
		r.DiscoveryPatterns = JSONStringSlice{"*.yaml", "*.yml", "*.json", "*.txt", "*.payload"}
	}
}

// IsCloneRequired returns true if the repository needs to be cloned
func (r *PayloadRepositoryDB) IsCloneRequired() bool {
	return r.Status == PayloadRepositoryStatusInactive || r.LocalPath == ""
}

// IsSyncRequired returns true if the repository needs to be synchronized
func (r *PayloadRepositoryDB) IsSyncRequired() bool {
	if !r.AutoSync {
		return false
	}

	if r.LastSyncAt == nil {
		return true
	}

	if r.SyncInterval == "" {
		return false
	}

	interval, err := time.ParseDuration(r.SyncInterval)
	if err != nil {
		return false
	}

	return time.Since(*r.LastSyncAt) >= interval
}

// UpdateSyncStatus updates the sync status and related fields
func (r *PayloadRepositoryDB) UpdateSyncStatus(success bool, duration time.Duration, commitHash string, payloadCount int64, err error) {
	now := time.Now()
	r.LastSyncAt = &now
	durationNanos := duration.Nanoseconds()
	r.LastSyncDuration = &durationNanos
	r.LastCommitHash = commitHash
	r.PayloadCount = payloadCount
	r.UpdatedAt = now

	if success {
		r.Status = PayloadRepositoryStatusActive
		r.LastSyncError = ""
	} else {
		r.Status = PayloadRepositoryStatusError
		if err != nil {
			r.LastSyncError = err.Error()
		}
	}
}

// GetCloneDepthValue returns the clone depth, handling the special case where 0 means full clone
func (r *PayloadRepositoryDB) GetCloneDepthValue() int {
	if r.IsFullClone {
		return 0 // 0 means full clone in git
	}
	if r.CloneDepth <= 0 {
		return 1 // Default to shallow clone
	}
	return r.CloneDepth
}
