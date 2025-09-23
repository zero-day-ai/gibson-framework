// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package models

import (
	"strings"
	"time"

	"github.com/gibson-sec/gibson-framework-2/pkg/core/utils"
	"github.com/google/uuid"
)

// PayloadRepositoryStatus represents the status of a payload repository
type PayloadRepositoryStatus string

const (
	PayloadRepositoryStatusActive    PayloadRepositoryStatus = "active"
	PayloadRepositoryStatusInactive  PayloadRepositoryStatus = "inactive"
	PayloadRepositoryStatusSyncing   PayloadRepositoryStatus = "syncing"
	PayloadRepositoryStatusError     PayloadRepositoryStatus = "error"
	PayloadRepositoryStatusCloning   PayloadRepositoryStatus = "cloning"
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

// PayloadRepositoryDB represents a Git repository containing security payloads
type PayloadRepositoryDB struct {
	// Core identification
	ID        uuid.UUID `json:"id" db:"id" validate:"required"`
	Name      string    `json:"name" db:"name" validate:"required,min=1,max=255"`
	URL       string    `json:"url" db:"url" validate:"required,url"`
	LocalPath string    `json:"local_path" db:"local_path" validate:"required"`

	// Repository configuration
	CloneDepth      int                                    `json:"clone_depth" db:"clone_depth" validate:"min=0"`
	IsFullClone     bool                                   `json:"is_full_clone" db:"is_full_clone"`
	Branch          string                                 `json:"branch" db:"branch"`
	AuthType        PayloadRepositoryAuthType              `json:"auth_type" db:"auth_type" validate:"required"`
	CredentialID    *uuid.UUID                             `json:"credential_id,omitempty" db:"credential_id"`
	ConflictStrategy PayloadRepositoryConflictStrategy     `json:"conflict_strategy" db:"conflict_strategy" validate:"required"`

	// Repository status and metadata
	Status            PayloadRepositoryStatus        `json:"status" db:"status" validate:"required"`
	LastSyncAt        *time.Time                     `json:"last_sync_at,omitempty" db:"last_sync_at"`
	LastSyncError     string                         `json:"last_sync_error,omitempty" db:"last_sync_error"`
	LastSyncDuration  *time.Duration                 `json:"last_sync_duration,omitempty" db:"last_sync_duration"`
	LastCommitHash    string                         `json:"last_commit_hash,omitempty" db:"last_commit_hash"`
	PayloadCount      int64                          `json:"payload_count" db:"payload_count"`
	AutoSync          bool                           `json:"auto_sync" db:"auto_sync"`
	SyncInterval      string                         `json:"sync_interval,omitempty" db:"sync_interval"`
	Description       string                         `json:"description,omitempty" db:"description"`
	Tags              []string                       `json:"tags,omitempty" db:"tags"`
	Config            map[string]interface{}         `json:"config,omitempty" db:"config"`

	// Discovery and organization settings
	DiscoveryPatterns []string                       `json:"discovery_patterns,omitempty" db:"discovery_patterns"`
	CategoryMapping   map[string]string              `json:"category_mapping,omitempty" db:"category_mapping"`
	DomainMapping     map[string]string              `json:"domain_mapping,omitempty" db:"domain_mapping"`

	// Statistics and metadata
	TotalSize         int64                          `json:"total_size" db:"total_size"`
	LastModified      *time.Time                     `json:"last_modified,omitempty" db:"last_modified"`
	Statistics        map[string]interface{}         `json:"statistics,omitempty" db:"statistics"`

	// Audit fields
	CreatedBy    string    `json:"created_by,omitempty" db:"created_by"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedBy    string    `json:"updated_by,omitempty" db:"updated_by"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// PayloadRepositoryCreateRequest represents a request to create a new payload repository
type PayloadRepositoryCreateRequest struct {
	Name             string                                 `json:"name" validate:"required,min=1,max=255"`
	URL              string                                 `json:"url" validate:"required,url"`
	CloneDepth       *int                                   `json:"clone_depth,omitempty" validate:"omitempty,min=0"`
	IsFullClone      bool                                   `json:"is_full_clone,omitempty"`
	Branch           string                                 `json:"branch,omitempty"`
	AuthType         PayloadRepositoryAuthType              `json:"auth_type,omitempty"`
	CredentialID     *uuid.UUID                             `json:"credential_id,omitempty"`
	ConflictStrategy PayloadRepositoryConflictStrategy      `json:"conflict_strategy,omitempty"`
	AutoSync         bool                                   `json:"auto_sync,omitempty"`
	SyncInterval     string                                 `json:"sync_interval,omitempty"`
	Description      string                                 `json:"description,omitempty"`
	Tags             []string                               `json:"tags,omitempty"`
	Config           map[string]interface{}                 `json:"config,omitempty"`
}

// PayloadRepositoryUpdateRequest represents a request to update a payload repository
type PayloadRepositoryUpdateRequest struct {
	Name             *string                                `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	URL              *string                                `json:"url,omitempty" validate:"omitempty,url"`
	CloneDepth       *int                                   `json:"clone_depth,omitempty" validate:"omitempty,min=0"`
	IsFullClone      *bool                                  `json:"is_full_clone,omitempty"`
	Branch           *string                                `json:"branch,omitempty"`
	AuthType         *PayloadRepositoryAuthType             `json:"auth_type,omitempty"`
	CredentialID     *uuid.UUID                             `json:"credential_id,omitempty"`
	ConflictStrategy *PayloadRepositoryConflictStrategy     `json:"conflict_strategy,omitempty"`
	AutoSync         *bool                                  `json:"auto_sync,omitempty"`
	SyncInterval     *string                                `json:"sync_interval,omitempty"`
	Description      *string                                `json:"description,omitempty"`
	Tags             []string                               `json:"tags,omitempty"`
	Config           map[string]interface{}                 `json:"config,omitempty"`
	Status           *PayloadRepositoryStatus               `json:"status,omitempty"`
}

// Result represents a functional result type for error handling
type Result[T any] struct {
	value T
	err   error
}

// Ok creates a successful result
func Ok[T any](value T) Result[T] {
	return Result[T]{value: value, err: nil}
}

// Err creates an error result
func Err[T any](err error) Result[T] {
	var zero T
	return Result[T]{value: zero, err: err}
}

// IsOk returns true if the result contains a value
func (r Result[T]) IsOk() bool {
	return r.err == nil
}

// IsErr returns true if the result contains an error
func (r Result[T]) IsErr() bool {
	return r.err != nil
}

// Unwrap returns the value or panics if there's an error
func (r Result[T]) Unwrap() T {
	if r.err != nil {
		panic(r.err)
	}
	return r.value
}

// UnwrapOr returns the value or the provided default if there's an error
func (r Result[T]) UnwrapOr(defaultValue T) T {
	if r.err != nil {
		return defaultValue
	}
	return r.value
}

// Error returns the error or nil
func (r Result[T]) Error() error {
	return r.err
}

// Value returns the value and error separately
func (r Result[T]) Value() (T, error) {
	return r.value, r.err
}

// SetDefaults sets default values for PayloadRepositoryCreateRequest
func (r *PayloadRepositoryCreateRequest) SetDefaults() {
	// Default clone depth to 1 (shallow clone) as per requirement 1.3
	if r.CloneDepth == nil {
		depth := 1
		r.CloneDepth = &depth
	}

	// Default auth type based on URL scheme
	if r.AuthType == "" {
		if strings.HasPrefix(r.URL, "git@") || strings.HasPrefix(r.URL, "ssh://") {
			r.AuthType = PayloadRepositoryAuthTypeSSH
		} else {
			r.AuthType = PayloadRepositoryAuthTypeHTTPS
		}
	}

	// Default conflict strategy
	if r.ConflictStrategy == "" {
		r.ConflictStrategy = PayloadRepositoryConflictStrategySkip
	}

	// Default branch
	if r.Branch == "" {
		r.Branch = "main"
	}
}

// Validate validates a PayloadRepositoryCreateRequest
func (r *PayloadRepositoryCreateRequest) Validate() error {
	// Set defaults first
	r.SetDefaults()

	// Validate URL format
	if err := utils.ValidateGitURL(r.URL); err != nil {
		return ErrInvalidURL{URL: r.URL, Reason: err.Error()}
	}

	// Validate clone depth is not negative
	if r.CloneDepth != nil && *r.CloneDepth < 0 {
		return ErrInvalidCloneDepth{Depth: *r.CloneDepth}
	}

	// Validate sync interval if provided
	if r.SyncInterval != "" {
		if _, err := time.ParseDuration(r.SyncInterval); err != nil {
			return ErrInvalidSyncInterval{Interval: r.SyncInterval, Reason: err.Error()}
		}
	}

	return nil
}

// SetDefaults sets default values for PayloadRepositoryDB
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
		if strings.HasPrefix(r.URL, "git@") || strings.HasPrefix(r.URL, "ssh://") {
			r.AuthType = PayloadRepositoryAuthTypeSSH
		} else {
			r.AuthType = PayloadRepositoryAuthTypeHTTPS
		}
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
		r.DiscoveryPatterns = []string{
			"*.yaml", "*.yml", "*.json", "*.txt", "*.payload",
		}
	}
}

// Validate validates a PayloadRepositoryDB model
func (r *PayloadRepositoryDB) Validate() error {
	// Set defaults first
	r.SetDefaults()

	// Validate URL format
	if err := utils.ValidateGitURL(r.URL); err != nil {
		return ErrInvalidURL{URL: r.URL, Reason: err.Error()}
	}

	// Validate clone depth is not negative
	if r.CloneDepth < 0 {
		return ErrInvalidCloneDepth{Depth: r.CloneDepth}
	}

	// Validate sync interval if provided
	if r.SyncInterval != "" {
		if _, err := time.ParseDuration(r.SyncInterval); err != nil {
			return ErrInvalidSyncInterval{Interval: r.SyncInterval, Reason: err.Error()}
		}
	}

	return nil
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
	r.LastSyncDuration = &duration
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

// ToCreateRequest converts a PayloadRepositoryDB to a create request
func (r *PayloadRepositoryDB) ToCreateRequest() PayloadRepositoryCreateRequest {
	return PayloadRepositoryCreateRequest{
		Name:             r.Name,
		URL:              r.URL,
		CloneDepth:       &r.CloneDepth,
		IsFullClone:      r.IsFullClone,
		Branch:           r.Branch,
		AuthType:         r.AuthType,
		CredentialID:     r.CredentialID,
		ConflictStrategy: r.ConflictStrategy,
		AutoSync:         r.AutoSync,
		SyncInterval:     r.SyncInterval,
		Description:      r.Description,
		Tags:             r.Tags,
		Config:           r.Config,
	}
}

// Custom error types for payload repository validation
type ErrInvalidURL struct {
	URL    string
	Reason string
}

func (e ErrInvalidURL) Error() string {
	return "invalid repository URL '" + e.URL + "': " + e.Reason
}

type ErrInvalidCloneDepth struct {
	Depth int
}

func (e ErrInvalidCloneDepth) Error() string {
	return "invalid clone depth: depth cannot be negative"
}

type ErrInvalidSyncInterval struct {
	Interval string
	Reason   string
}

func (e ErrInvalidSyncInterval) Error() string {
	return "invalid sync interval '" + e.Interval + "': " + e.Reason
}