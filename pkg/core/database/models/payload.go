// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package models

import (
	"database/sql/driver"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// PayloadCategory represents the category of a payload (database enum)
type PayloadCategory string

const (
	PayloadCategoryModel         PayloadCategory = "model"
	PayloadCategoryData          PayloadCategory = "data"
	PayloadCategoryInterface     PayloadCategory = "interface"
	PayloadCategoryInfrastructure PayloadCategory = "infrastructure"
	PayloadCategoryOutput        PayloadCategory = "output"
	PayloadCategoryProcess       PayloadCategory = "process"
)

// PayloadType represents the type of a payload (database enum)
type PayloadType string

const (
	PayloadTypePrompt      PayloadType = "prompt"
	PayloadTypeQuery       PayloadType = "query"
	PayloadTypeInput       PayloadType = "input"
	PayloadTypeCode        PayloadType = "code"
	PayloadTypeData        PayloadType = "data"
	PayloadTypeScript      PayloadType = "script"
)

// Note: JSONStringSlice and JSONMap are defined in payload_repository.go

// PayloadDB represents a security testing payload in the database layer
type PayloadDB struct {
	// Core identification
	ID               uuid.UUID               `db:"id"`
	Name             string                  `db:"name"`
	Category         PayloadCategory         `db:"category"`
	Domain           string                  `db:"domain"`
	PluginName       string                  `db:"plugin_name"`
	Type             PayloadType             `db:"type"`
	Version          int                     `db:"version"`
	ParentID         *uuid.UUID              `db:"parent_id"`

	// Content and metadata
	Content          string                  `db:"content"`
	Description      string                  `db:"description"`
	Severity         string                  `db:"severity"`
	Tags             JSONStringSlice         `db:"tags"`
	Variables        JSONMap                 `db:"variables"`
	Config           JSONMap                 `db:"config"`
	Language         string                  `db:"language"`

	// Status and validation
	Enabled          bool                    `db:"enabled"`
	Validated        bool                    `db:"validated"`
	ValidationResult JSONMap                 `db:"validation_result"`

	// Usage statistics
	UsageCount       int64                   `db:"usage_count"`
	SuccessRate      float64                 `db:"success_rate"`
	LastUsed         *time.Time              `db:"last_used"`

	// Repository tracking fields (from models.go extension)
	RepositoryID     *uuid.UUID              `db:"repository_id"`
	RepositoryPath   string                  `db:"repository_path"`

	// Checksum for change detection (requirement 5.7)
	Checksum         string                  `db:"checksum"`

	// Audit fields
	CreatedBy        string                  `db:"created_by"`
	CreatedAt        time.Time               `db:"created_at"`
	UpdatedAt        time.Time               `db:"updated_at"`
}

// Scan methods for enum types

// Scan implements the sql.Scanner interface for PayloadCategory
func (pc *PayloadCategory) Scan(value interface{}) error {
	if value == nil {
		*pc = PayloadCategoryInterface // Default value
		return nil
	}

	switch s := value.(type) {
	case string:
		*pc = PayloadCategory(s)
	case []byte:
		*pc = PayloadCategory(string(s))
	default:
		return fmt.Errorf("cannot scan %T into PayloadCategory", value)
	}

	return nil
}

// Value implements the driver.Valuer interface for PayloadCategory
func (pc PayloadCategory) Value() (driver.Value, error) {
	return string(pc), nil
}

// Scan implements the sql.Scanner interface for PayloadType
func (pt *PayloadType) Scan(value interface{}) error {
	if value == nil {
		*pt = PayloadTypePrompt // Default value
		return nil
	}

	switch s := value.(type) {
	case string:
		*pt = PayloadType(s)
	case []byte:
		*pt = PayloadType(string(s))
	default:
		return fmt.Errorf("cannot scan %T into PayloadType", value)
	}

	return nil
}

// Value implements the driver.Valuer interface for PayloadType
func (pt PayloadType) Value() (driver.Value, error) {
	return string(pt), nil
}

// UUID scanning for nullable UUIDs

// NullableUUID handles nullable UUID fields
type NullableUUID struct {
	UUID  uuid.UUID
	Valid bool
}

// Scan implements the sql.Scanner interface for NullableUUID
func (nu *NullableUUID) Scan(value interface{}) error {
	if value == nil {
		nu.UUID, nu.Valid = uuid.Nil, false
		return nil
	}

	switch s := value.(type) {
	case string:
		if s == "" {
			nu.UUID, nu.Valid = uuid.Nil, false
			return nil
		}
		u, err := uuid.Parse(s)
		if err != nil {
			return err
		}
		nu.UUID, nu.Valid = u, true
	case []byte:
		if len(s) == 0 {
			nu.UUID, nu.Valid = uuid.Nil, false
			return nil
		}
		u, err := uuid.Parse(string(s))
		if err != nil {
			return err
		}
		nu.UUID, nu.Valid = u, true
	default:
		return fmt.Errorf("cannot scan %T into NullableUUID", value)
	}

	return nil
}

// Value implements the driver.Valuer interface for NullableUUID
func (nu NullableUUID) Value() (driver.Value, error) {
	if !nu.Valid {
		return nil, nil
	}
	return nu.UUID.String(), nil
}

// Helper functions for validation and normalization

// IsValidCategory checks if a category is valid
func IsValidCategory(category string) bool {
	validCategories := []string{
		string(PayloadCategoryModel),
		string(PayloadCategoryData),
		string(PayloadCategoryInterface),
		string(PayloadCategoryInfrastructure),
		string(PayloadCategoryOutput),
		string(PayloadCategoryProcess),
	}

	categoryLower := strings.ToLower(category)
	for _, valid := range validCategories {
		if categoryLower == valid {
			return true
		}
	}
	return false
}

// IsValidType checks if a payload type is valid
func IsValidType(payloadType string) bool {
	validTypes := []string{
		string(PayloadTypePrompt),
		string(PayloadTypeQuery),
		string(PayloadTypeInput),
		string(PayloadTypeCode),
		string(PayloadTypeData),
		string(PayloadTypeScript),
	}

	typeLower := strings.ToLower(payloadType)
	for _, valid := range validTypes {
		if typeLower == valid {
			return true
		}
	}
	return false
}

// NormalizeCategory normalizes a category string to a valid PayloadCategory
func NormalizeCategory(category string) PayloadCategory {
	switch strings.ToLower(category) {
	case "model":
		return PayloadCategoryModel
	case "data":
		return PayloadCategoryData
	case "interface":
		return PayloadCategoryInterface
	case "infrastructure":
		return PayloadCategoryInfrastructure
	case "output":
		return PayloadCategoryOutput
	case "process":
		return PayloadCategoryProcess
	default:
		return PayloadCategoryInterface
	}
}

// NormalizeType normalizes a type string to a valid PayloadType
func NormalizeType(payloadType string) PayloadType {
	switch strings.ToLower(payloadType) {
	case "prompt":
		return PayloadTypePrompt
	case "query":
		return PayloadTypeQuery
	case "input":
		return PayloadTypeInput
	case "code":
		return PayloadTypeCode
	case "data":
		return PayloadTypeData
	case "script":
		return PayloadTypeScript
	default:
		return PayloadTypePrompt
	}
}

// SetDefaults sets default values for database model
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

	if p.Tags == nil {
		p.Tags = JSONStringSlice{}
	}

	if p.Variables == nil {
		p.Variables = make(JSONMap)
	}

	if p.Config == nil {
		p.Config = make(JSONMap)
	}

	if p.ValidationResult == nil {
		p.ValidationResult = make(JSONMap)
	}

	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now

	// Ensure enabled by default for new payloads
	if p.CreatedAt.Equal(p.UpdatedAt) {
		p.Enabled = true
	}
}

// Validate validates the payload database model
func (p *PayloadDB) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}

	if !IsValidCategory(string(p.Category)) {
		return fmt.Errorf("invalid category: %s", p.Category)
	}

	if !IsValidType(string(p.Type)) {
		return fmt.Errorf("invalid type: %s", p.Type)
	}

	if p.Domain == "" {
		return fmt.Errorf("domain is required")
	}

	if p.Content == "" {
		return fmt.Errorf("content is required")
	}

	// Validate repository fields consistency
	if p.RepositoryID != nil && p.RepositoryPath == "" {
		return fmt.Errorf("repository_path is required when repository_id is provided")
	}

	return nil
}