// Package models provides core model types for Gibson
package models

import (
	"time"

	"github.com/google/uuid"
)

// ListOptions defines options for listing operations
type ListOptions struct {
	Limit  int
	Offset int
	Filter string
}

// PayloadCategory represents the category of a payload
type PayloadCategory string

const (
	PayloadCategoryModel         PayloadCategory = "model"
	PayloadCategoryData          PayloadCategory = "data"
	PayloadCategoryInterface     PayloadCategory = "interface"
	PayloadCategoryInfrastructure PayloadCategory = "infrastructure"
	PayloadCategoryOutput        PayloadCategory = "output"
	PayloadCategoryProcess       PayloadCategory = "process"
)

// PayloadType represents the type of a payload
type PayloadType string

const (
	PayloadTypePrompt      PayloadType = "prompt"
	PayloadTypeQuery       PayloadType = "query"
	PayloadTypeInput       PayloadType = "input"
	PayloadTypeCode        PayloadType = "code"
	PayloadTypeData        PayloadType = "data"
	PayloadTypeScript      PayloadType = "script"
)

// PayloadDB represents a security testing payload with repository tracking
type PayloadDB struct {
	ID               uuid.UUID               `json:"id" db:"id"`
	Name             string                  `json:"name" db:"name" validate:"required,min=1,max=255"`
	Category         PayloadCategory         `json:"category" db:"category" validate:"required"`
	Domain           string                  `json:"domain" db:"domain" validate:"required"`
	PluginName       string                  `json:"plugin_name,omitempty" db:"plugin_name"`
	Type             PayloadType             `json:"type" db:"type" validate:"required"`
	Version          int                     `json:"version" db:"version"`
	ParentID         *uuid.UUID              `json:"parent_id,omitempty" db:"parent_id"`
	Content          string                  `json:"content" db:"content" validate:"required"`
	Description      string                  `json:"description,omitempty" db:"description"`
	Severity         string                  `json:"severity" db:"severity"`
	Tags             []string                `json:"tags,omitempty" db:"tags"`
	Variables        map[string]interface{}  `json:"variables,omitempty" db:"variables"`
	Config           map[string]interface{}  `json:"config,omitempty" db:"config"`
	Language         string                  `json:"language,omitempty" db:"language"`
	Enabled          bool                    `json:"enabled" db:"enabled"`
	Validated        bool                    `json:"validated" db:"validated"`
	ValidationResult map[string]interface{}  `json:"validation_result,omitempty" db:"validation_result"`
	UsageCount       int64                   `json:"usage_count" db:"usage_count"`
	SuccessRate      float64                 `json:"success_rate" db:"success_rate"`
	LastUsed         *time.Time              `json:"last_used,omitempty" db:"last_used"`
	// Repository tracking fields (Requirement 3.4)
	RepositoryID     *uuid.UUID              `json:"repository_id,omitempty" db:"repository_id"`
	RepositoryPath   string                  `json:"repository_path,omitempty" db:"repository_path"`
	CreatedBy        string                  `json:"created_by,omitempty" db:"created_by"`
	CreatedAt        time.Time               `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time               `json:"updated_at" db:"updated_at"`
}

// SetDefaults sets default values for PayloadDB
func (p *PayloadDB) SetDefaults() {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}

	if p.Version == 0 {
		p.Version = 1
	}

	if p.Severity == "" {
		p.Severity = "medium"
	}

	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now

	// Ensure enabled by default
	if !p.Enabled && p.ID == uuid.Nil {
		p.Enabled = true
	}
}

// Validate validates a PayloadDB model ensuring backward compatibility
func (p *PayloadDB) Validate() error {
	// Set defaults first
	p.SetDefaults()

	// Repository fields are optional for backward compatibility
	// If RepositoryID is provided, RepositoryPath should also be provided
	if p.RepositoryID != nil && p.RepositoryPath == "" {
		return ErrInvalidRepositoryPath{Message: "repository_path is required when repository_id is provided"}
	}

	// Validate that repository path is relative if provided
	if p.RepositoryPath != "" && len(p.RepositoryPath) > 0 {
		// Repository path should not start with / to ensure it's relative
		if p.RepositoryPath[0] == '/' {
			return ErrInvalidRepositoryPath{Message: "repository_path must be relative (not start with /)"}
		}
	}

	return nil
}

// IsRepositoryLinked returns true if the payload is linked to a repository
func (p *PayloadDB) IsRepositoryLinked() bool {
	return p.RepositoryID != nil && p.RepositoryPath != ""
}

// GetRepositoryInfo returns repository information if available
func (p *PayloadDB) GetRepositoryInfo() (repositoryID *uuid.UUID, repositoryPath string) {
	return p.RepositoryID, p.RepositoryPath
}

// SetRepositoryInfo sets repository tracking information
func (p *PayloadDB) SetRepositoryInfo(repositoryID *uuid.UUID, repositoryPath string) {
	p.RepositoryID = repositoryID
	p.RepositoryPath = repositoryPath
	p.UpdatedAt = time.Now()
}

// ClearRepositoryInfo removes repository tracking information
func (p *PayloadDB) ClearRepositoryInfo() {
	p.RepositoryID = nil
	p.RepositoryPath = ""
	p.UpdatedAt = time.Now()
}

// IsVersioned returns true if the payload has a parent (is a version)
func (p *PayloadDB) IsVersioned() bool {
	return p.ParentID != nil
}

// IsActive returns true if the payload is enabled
func (p *PayloadDB) IsActive() bool {
	return p.Enabled
}

// HasTag returns true if the payload has the specified tag
func (p *PayloadDB) HasTag(tag string) bool {
	for _, t := range p.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// Custom error types for payload validation
type ErrInvalidRepositoryPath struct {
	Message string
}

func (e ErrInvalidRepositoryPath) Error() string {
	return "invalid repository path: " + e.Message
}