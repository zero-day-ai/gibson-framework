// Package dao provides data access object interfaces and implementations
package dao

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// Payload represents a payload resource accessor.
type Payload struct {
	BaseAccessor
}

// PayloadSearchCriteria defines search parameters for payloads
type PayloadSearchCriteria struct {
	Category   model.PayloadCategory
	Domain     string
	Language   string
	Severity   string
	Enabled    *bool
	Tags       []string
	Query      string // search in name, description, content
	Limit      int
	Offset     int
}

// Init initializes the payload accessor.
func (p *Payload) Init(factory Factory) {
	p.BaseAccessor.Init(factory, "payloads")
}

// TableName returns the table name.
func (p *Payload) TableName() string {
	return "payloads"
}

// payloadDto represents the database record structure
type payloadDto struct {
	ID               string    `db:"id"`
	Name             string    `db:"name"`
	Category         string    `db:"category"`
	Domain           string    `db:"domain"`
	Type             string    `db:"type"`
	Version          int       `db:"version"`
	ParentID         *string   `db:"parent_id"`
	Content          string    `db:"content"`
	Description      *string   `db:"description"`
	Severity         string    `db:"severity"`
	Tags             *string   `db:"tags"`
	Variables        *string   `db:"variables"`
	Config           *string   `db:"config"`
	Language         *string   `db:"language"`
	Enabled          bool      `db:"enabled"`
	Validated        bool      `db:"validated"`
	ValidationResult *string   `db:"validation_result"`
	UsageCount       int64     `db:"usage_count"`
	SuccessRate      float64   `db:"success_rate"`
	LastUsed         *time.Time `db:"last_used"`
	// Repository tracking fields (Requirement 3.4)
	RepositoryID     *string   `db:"repository_id"`
	RepositoryPath   *string   `db:"repository_path"`
	PluginName       *string   `db:"plugin_name"`
	// Checksum field for change detection (Requirement 5.7)
	Checksum         *string   `db:"checksum"`
	CreatedBy        *string   `db:"created_by"`
	CreatedAt        time.Time `db:"created_at"`
	UpdatedAt        time.Time `db:"updated_at"`
}

// Get returns a payload by ID.
func (p *Payload) Get(ctx context.Context, id uuid.UUID) (*model.Payload, error) {
	var dto payloadDto
	query := `SELECT * FROM payloads WHERE id = ?`

	err := p.db.GetContext(ctx, &dto, query, id.String())
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return convertDtoToModel(&dto)
}

// Helper functions for nullable string handling
func getStringFromPointer(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func getPointerFromString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// convertDtoToModel converts database DTO to model
func convertDtoToModel(dto *payloadDto) (*model.Payload, error) {
	id, err := uuid.Parse(dto.ID)
	if err != nil {
		return nil, err
	}

	var parentID *uuid.UUID
	if dto.ParentID != nil {
		parsed, err := uuid.Parse(*dto.ParentID)
		if err != nil {
			return nil, err
		}
		parentID = &parsed
	}

	// Handle repository ID conversion
	var repositoryID *uuid.UUID
	if dto.RepositoryID != nil {
		parsed, err := uuid.Parse(*dto.RepositoryID)
		if err != nil {
			return nil, err
		}
		repositoryID = &parsed
	}

	var tags []string
	if dto.Tags != nil && *dto.Tags != "" {
		if err := json.Unmarshal([]byte(*dto.Tags), &tags); err != nil {
			return nil, err
		}
	}

	var variables map[string]interface{}
	if dto.Variables != nil && *dto.Variables != "" {
		if err := json.Unmarshal([]byte(*dto.Variables), &variables); err != nil {
			return nil, err
		}
	}

	var config map[string]interface{}
	if dto.Config != nil && *dto.Config != "" {
		if err := json.Unmarshal([]byte(*dto.Config), &config); err != nil {
			return nil, err
		}
	}

	var validationResult map[string]interface{}
	if dto.ValidationResult != nil && *dto.ValidationResult != "" {
		if err := json.Unmarshal([]byte(*dto.ValidationResult), &validationResult); err != nil {
			return nil, err
		}
	}

	return &model.Payload{
		ID:               id,
		Name:             dto.Name,
		Category:         model.PayloadCategory(dto.Category),
		Domain:           dto.Domain,
		Type:             model.PayloadType(dto.Type),
		Version:          dto.Version,
		ParentID:         parentID,
		Content:          dto.Content,
		Description:      getStringFromPointer(dto.Description),
		Severity:         dto.Severity,
		Tags:             tags,
		Variables:        variables,
		Config:           config,
		Language:         getStringFromPointer(dto.Language),
		Enabled:          dto.Enabled,
		Validated:        dto.Validated,
		ValidationResult: validationResult,
		UsageCount:       dto.UsageCount,
		SuccessRate:      dto.SuccessRate,
		LastUsed:         dto.LastUsed,
		// Repository tracking fields (Requirement 3.4)
		RepositoryID:     repositoryID,
		RepositoryPath:   getStringFromPointer(dto.RepositoryPath),
		PluginName:       getStringFromPointer(dto.PluginName),
		// Checksum field for change detection (Requirement 5.7)
		Checksum:         getStringFromPointer(dto.Checksum),
		CreatedBy:        getStringFromPointer(dto.CreatedBy),
		CreatedAt:        dto.CreatedAt,
		UpdatedAt:        dto.UpdatedAt,
	}, nil
}

// convertModelToDto converts model to database DTO
func convertModelToDto(payload *model.Payload) (*payloadDto, error) {
	var parentID *string
	if payload.ParentID != nil {
		s := payload.ParentID.String()
		parentID = &s
	}

	// Handle repository ID conversion
	var repositoryID *string
	if payload.RepositoryID != nil {
		s := payload.RepositoryID.String()
		repositoryID = &s
	}

	tagsJSON, err := json.Marshal(payload.Tags)
	if err != nil {
		return nil, err
	}

	variablesJSON, err := json.Marshal(payload.Variables)
	if err != nil {
		return nil, err
	}

	configJSON, err := json.Marshal(payload.Config)
	if err != nil {
		return nil, err
	}

	validationResultJSON, err := json.Marshal(payload.ValidationResult)
	if err != nil {
		return nil, err
	}

	return &payloadDto{
		ID:               payload.ID.String(),
		Name:             payload.Name,
		Category:         string(payload.Category),
		Domain:           payload.Domain,
		Type:             string(payload.Type),
		Version:          payload.Version,
		ParentID:         parentID,
		Content:          payload.Content,
		Description:      getPointerFromString(payload.Description),
		Severity:         payload.Severity,
		Tags:             getPointerFromString(string(tagsJSON)),
		Variables:        getPointerFromString(string(variablesJSON)),
		Config:           getPointerFromString(string(configJSON)),
		Language:         getPointerFromString(payload.Language),
		Enabled:          payload.Enabled,
		Validated:        payload.Validated,
		ValidationResult: getPointerFromString(string(validationResultJSON)),
		UsageCount:       payload.UsageCount,
		SuccessRate:      payload.SuccessRate,
		LastUsed:         payload.LastUsed,
		// Repository tracking fields (Requirement 3.4)
		RepositoryID:     repositoryID,
		RepositoryPath:   getPointerFromString(payload.RepositoryPath),
		PluginName:       getPointerFromString(payload.PluginName),
		// Checksum field for change detection (Requirement 5.7)
		Checksum:         getPointerFromString(payload.Checksum),
		CreatedBy:        getPointerFromString(payload.CreatedBy),
		CreatedAt:        payload.CreatedAt,
		UpdatedAt:        payload.UpdatedAt,
	}, nil
}

// List returns all payloads.
func (p *Payload) List(ctx context.Context) ([]*model.Payload, error) {
	var dtos []payloadDto
	query := `SELECT * FROM payloads ORDER BY created_at DESC`

	err := p.db.SelectContext(ctx, &dtos, query)
	if err != nil {
		return nil, err
	}

	payloads := make([]*model.Payload, len(dtos))
	for i, dto := range dtos {
		payload, err := convertDtoToModel(&dto)
		if err != nil {
			return nil, err
		}
		payloads[i] = payload
	}

	return payloads, nil
}

// Create creates a new payload.
func (p *Payload) Create(ctx context.Context, payload *model.Payload) error {
	if payload.ID == uuid.Nil {
		payload.ID = uuid.New()
	}

	now := time.Now()
	payload.CreatedAt = now
	payload.UpdatedAt = now

	dto, err := convertModelToDto(payload)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO payloads (
			id, name, category, domain, type, version, parent_id, content, description,
			severity, tags, variables, config, language, enabled, validated,
			validation_result, usage_count, success_rate, last_used, repository_id,
			repository_path, checksum, created_by, created_at, updated_at
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		)
	`

	_, err = p.db.ExecContext(ctx, query,
		dto.ID, dto.Name, dto.Category, dto.Domain, dto.Type, dto.Version, dto.ParentID,
		dto.Content, dto.Description, dto.Severity, dto.Tags, dto.Variables, dto.Config,
		dto.Language, dto.Enabled, dto.Validated, dto.ValidationResult, dto.UsageCount,
		dto.SuccessRate, dto.LastUsed, dto.RepositoryID, dto.RepositoryPath, dto.Checksum,
		dto.CreatedBy, dto.CreatedAt, dto.UpdatedAt,
	)
	return err
}

// Update updates an existing payload.
func (p *Payload) Update(ctx context.Context, payload *model.Payload) error {
	payload.UpdatedAt = time.Now()

	dto, err := convertModelToDto(payload)
	if err != nil {
		return err
	}

	query := `
		UPDATE payloads SET
			name = ?, category = ?, domain = ?, type = ?, version = ?, parent_id = ?,
			content = ?, description = ?, severity = ?, tags = ?, variables = ?,
			config = ?, language = ?, enabled = ?, validated = ?, validation_result = ?,
			usage_count = ?, success_rate = ?, last_used = ?, repository_id = ?, repository_path = ?,
			checksum = ?, created_by = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := p.db.ExecContext(ctx, query,
		dto.Name, dto.Category, dto.Domain, dto.Type, dto.Version, dto.ParentID,
		dto.Content, dto.Description, dto.Severity, dto.Tags, dto.Variables, dto.Config,
		dto.Language, dto.Enabled, dto.Validated, dto.ValidationResult, dto.UsageCount,
		dto.SuccessRate, dto.LastUsed, dto.RepositoryID, dto.RepositoryPath, dto.Checksum,
		dto.CreatedBy, dto.UpdatedAt, dto.ID,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("payload with ID %s not found", payload.ID)
	}

	return nil
}

// Delete removes a payload.
func (p *Payload) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM payloads WHERE id = ?`

	result, err := p.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("payload with ID %s not found", id)
	}

	return nil
}

// GetByName returns a payload by name.
func (p *Payload) GetByName(ctx context.Context, name string) (*model.Payload, error) {
	var dto payloadDto
	query := `
		SELECT * FROM payloads
		WHERE name = ?
		ORDER BY version DESC, created_at DESC
		LIMIT 1
	`

	err := p.db.GetContext(ctx, &dto, query, name)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return convertDtoToModel(&dto)
}

// ListByCategory returns payloads filtered by category.
func (p *Payload) ListByCategory(ctx context.Context, category model.PayloadCategory) ([]*model.Payload, error) {
	var dtos []payloadDto
	query := `SELECT * FROM payloads WHERE category = ? ORDER BY name, version DESC`

	err := p.db.SelectContext(ctx, &dtos, query, string(category))
	if err != nil {
		return nil, err
	}

	payloads := make([]*model.Payload, len(dtos))
	for i, dto := range dtos {
		payload, err := convertDtoToModel(&dto)
		if err != nil {
			return nil, err
		}
		payloads[i] = payload
	}

	return payloads, nil
}

// ListByDomain returns payloads filtered by domain.
func (p *Payload) ListByDomain(ctx context.Context, domain string) ([]*model.Payload, error) {
	var dtos []payloadDto
	query := `SELECT * FROM payloads WHERE domain = ? ORDER BY name, version DESC`

	err := p.db.SelectContext(ctx, &dtos, query, domain)
	if err != nil {
		return nil, err
	}

	payloads := make([]*model.Payload, len(dtos))
	for i, dto := range dtos {
		payload, err := convertDtoToModel(&dto)
		if err != nil {
			return nil, err
		}
		payloads[i] = payload
	}

	return payloads, nil
}

// ListEnabled returns only enabled payloads.
func (p *Payload) ListEnabled(ctx context.Context) ([]*model.Payload, error) {
	var dtos []payloadDto
	query := `SELECT * FROM payloads WHERE enabled = true ORDER BY name, version DESC`

	err := p.db.SelectContext(ctx, &dtos, query)
	if err != nil {
		return nil, err
	}

	payloads := make([]*model.Payload, len(dtos))
	for i, dto := range dtos {
		payload, err := convertDtoToModel(&dto)
		if err != nil {
			return nil, err
		}
		payloads[i] = payload
	}

	return payloads, nil
}

// GetVersions returns all versions of a payload.
func (p *Payload) GetVersions(ctx context.Context, parentID uuid.UUID) ([]*model.Payload, error) {
	var dtos []payloadDto
	query := `SELECT * FROM payloads WHERE parent_id = ? ORDER BY version DESC, created_at DESC`

	err := p.db.SelectContext(ctx, &dtos, query, parentID.String())
	if err != nil {
		return nil, err
	}

	payloads := make([]*model.Payload, len(dtos))
	for i, dto := range dtos {
		payload, err := convertDtoToModel(&dto)
		if err != nil {
			return nil, err
		}
		payloads[i] = payload
	}

	return payloads, nil
}

// CreateVersion creates a new version of an existing payload.
func (p *Payload) CreateVersion(ctx context.Context, originalID uuid.UUID, newPayload *model.Payload) error {
	newPayload.ParentID = &originalID
	return p.Create(ctx, newPayload)
}

// UpdateUsageStats updates usage statistics for a payload.
func (p *Payload) UpdateUsageStats(ctx context.Context, id uuid.UUID, successful bool) error {
	now := time.Now()
	var query string

	if successful {
		query = `
			UPDATE payloads SET
				usage_count = usage_count + 1,
				success_rate = (success_rate * usage_count + 1) / (usage_count + 1),
				last_used = ?
			WHERE id = ?
		`
	} else {
		query = `
			UPDATE payloads SET
				usage_count = usage_count + 1,
				success_rate = (success_rate * usage_count) / (usage_count + 1),
				last_used = ?
			WHERE id = ?
		`
	}

	_, err := p.db.ExecContext(ctx, query, now, id.String())
	return err
}

// GetMostUsed returns the most frequently used payloads.
func (p *Payload) GetMostUsed(ctx context.Context, limit int) ([]*model.Payload, error) {
	var dtos []payloadDto
	query := `SELECT * FROM payloads ORDER BY usage_count DESC, success_rate DESC LIMIT ?`

	err := p.db.SelectContext(ctx, &dtos, query, limit)
	if err != nil {
		return nil, err
	}

	payloads := make([]*model.Payload, len(dtos))
	for i, dto := range dtos {
		payload, err := convertDtoToModel(&dto)
		if err != nil {
			return nil, err
		}
		payloads[i] = payload
	}

	return payloads, nil
}

// Search searches payloads based on criteria.
func (p *Payload) Search(ctx context.Context, criteria *PayloadSearchCriteria) ([]*model.Payload, error) {
	var dtos []payloadDto
	var conditions []string
	var args []interface{}

	baseQuery := `SELECT * FROM payloads`

	if criteria.Category != "" {
		conditions = append(conditions, "category = ?")
		args = append(args, string(criteria.Category))
	}

	if criteria.Domain != "" {
		conditions = append(conditions, "domain = ?")
		args = append(args, criteria.Domain)
	}

	if criteria.Language != "" {
		conditions = append(conditions, "language = ?")
		args = append(args, criteria.Language)
	}

	if criteria.Severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, criteria.Severity)
	}

	if criteria.Enabled != nil {
		conditions = append(conditions, "enabled = ?")
		args = append(args, *criteria.Enabled)
	}

	if criteria.Query != "" {
		conditions = append(conditions, "(name LIKE ? OR description LIKE ? OR content LIKE ?)")
		queryParam := "%" + criteria.Query + "%"
		args = append(args, queryParam, queryParam, queryParam)
	}

	// Handle tags search (simplified JSON search)
	for _, tag := range criteria.Tags {
		conditions = append(conditions, "tags LIKE ?")
		args = append(args, "%\""+tag+"\"%")
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	baseQuery += " ORDER BY created_at DESC"

	if criteria.Limit > 0 {
		baseQuery += " LIMIT ?"
		args = append(args, criteria.Limit)

		if criteria.Offset > 0 {
			baseQuery += " OFFSET ?"
			args = append(args, criteria.Offset)
		}
	}

	err := p.db.SelectContext(ctx, &dtos, baseQuery, args...)
	if err != nil {
		return nil, err
	}

	payloads := make([]*model.Payload, len(dtos))
	for i, dto := range dtos {
		payload, err := convertDtoToModel(&dto)
		if err != nil {
			return nil, err
		}
		payloads[i] = payload
	}

	return payloads, nil
}

// GetByPartialID returns a payload by partial UUID match (minimum 8 characters)
func (p *Payload) GetByPartialID(ctx context.Context, partialID string) (*model.Payload, error) {
	// Validate minimum length
	if len(partialID) < 8 {
		return nil, fmt.Errorf("partial ID must be at least 8 characters long")
	}

	// Clean and validate the partial ID
	partialID = strings.ReplaceAll(strings.ToLower(partialID), "-", "")
	if !isHexString(partialID) {
		return nil, fmt.Errorf("invalid UUID format: contains non-hexadecimal characters")
	}

	var dtos []payloadDto
	query := `SELECT * FROM payloads WHERE LOWER(REPLACE(id, '-', '')) LIKE ? ORDER BY created_at DESC`

	err := p.db.SelectContext(ctx, &dtos, query, partialID+"%")
	if err != nil {
		return nil, err
	}

	if len(dtos) == 0 {
		return nil, fmt.Errorf("no payload found with ID prefix '%s'", partialID)
	}

	if len(dtos) > 1 {
		// Multiple matches - return error with list of matching IDs
		var matchingIDs []string
		for _, dto := range dtos {
			matchingIDs = append(matchingIDs, dto.ID)
		}
		return nil, fmt.Errorf("partial ID '%s' matches multiple payloads: %s", partialID, strings.Join(matchingIDs, ", "))
	}

	// Single match found
	return convertDtoToModel(&dtos[0])
}

// ResolveMultipleIDs resolves multiple partial IDs to full UUIDs
func (p *Payload) ResolveMultipleIDs(ctx context.Context, partialIDs []string) ([]*model.Payload, error) {
	var payloads []*model.Payload
	var errors []string

	for _, partialID := range partialIDs {
		payload, err := p.GetByPartialID(ctx, partialID)
		if err != nil {
			errors = append(errors, fmt.Sprintf("ID '%s': %v", partialID, err))
			continue
		}
		payloads = append(payloads, payload)
	}

	if len(errors) > 0 {
		return payloads, fmt.Errorf("errors resolving IDs: %s", strings.Join(errors, "; "))
	}

	return payloads, nil
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// CreatePayloadsTable creates the payloads table
func CreatePayloadsTable(db *sqlx.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS payloads (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		category TEXT NOT NULL,
		domain TEXT NOT NULL,
		type TEXT NOT NULL,
		version INTEGER NOT NULL DEFAULT 1,
		parent_id TEXT,
		content TEXT NOT NULL,
		description TEXT,
		severity TEXT,
		tags TEXT,
		variables TEXT,
		config TEXT,
		language TEXT,
		enabled BOOLEAN NOT NULL DEFAULT true,
		validated BOOLEAN NOT NULL DEFAULT false,
		validation_result TEXT,
		usage_count INTEGER NOT NULL DEFAULT 0,
		success_rate REAL NOT NULL DEFAULT 0.0,
		last_used DATETIME,
		created_by TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (parent_id) REFERENCES payloads(id)
	);

	CREATE INDEX IF NOT EXISTS idx_payloads_name ON payloads(name);
	CREATE INDEX IF NOT EXISTS idx_payloads_category ON payloads(category);
	CREATE INDEX IF NOT EXISTS idx_payloads_domain ON payloads(domain);
	CREATE INDEX IF NOT EXISTS idx_payloads_type ON payloads(type);
	CREATE INDEX IF NOT EXISTS idx_payloads_language ON payloads(language);
	CREATE INDEX IF NOT EXISTS idx_payloads_severity ON payloads(severity);
	CREATE INDEX IF NOT EXISTS idx_payloads_enabled ON payloads(enabled);
	CREATE INDEX IF NOT EXISTS idx_payloads_parent_id ON payloads(parent_id);
	CREATE INDEX IF NOT EXISTS idx_payloads_usage_count ON payloads(usage_count);
	CREATE INDEX IF NOT EXISTS idx_payloads_created_at ON payloads(created_at);
	`

	_, err := db.Exec(schema)
	return err
}