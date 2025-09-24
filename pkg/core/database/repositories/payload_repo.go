// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package repositories

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	coremodels "github.com/zero-day-ai/gibson-framework/pkg/core/models"
	dbmodels "github.com/zero-day-ai/gibson-framework/pkg/core/database/models"
)

// PayloadRepository interface is defined in interfaces.go

// payloadRepo implements PayloadRepository
type payloadRepo struct {
	db *sqlx.DB
}

// NewPayloadRepository creates a new payload repository
func NewPayloadRepository(db *sqlx.DB) PayloadRepository {
	return &payloadRepo{
		db: db,
	}
}

// Create creates a new payload
func (r *payloadRepo) Create(ctx context.Context, payload *coremodels.PayloadDB) coremodels.Result[*coremodels.PayloadDB] {
	// Set defaults and validate
	payload.SetDefaults()
	if err := payload.Validate(); err != nil {
		return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("validation failed: %w", err))
	}

	// Convert to database model
	dbPayload := convertPayloadToDBModel(payload)

	// Calculate content checksum for change detection
	checksum := calculatePayloadChecksum(payload.Content)

	// SQL insert with all required columns
	query := `
		INSERT INTO payloads (
			id, name, category, domain, type, version, parent_id, content, description,
			severity, tags, variables, config, language, enabled, validated,
			validation_result, usage_count, success_rate, last_used, repository_id,
			repository_path, created_by, created_at, updated_at, checksum
		) VALUES (
			:id, :name, :category, :domain, :type, :version, :parent_id, :content, :description,
			:severity, :tags, :variables, :config, :language, :enabled, :validated,
			:validation_result, :usage_count, :success_rate, :last_used, :repository_id,
			:repository_path, :created_by, :created_at, :updated_at, :checksum
		)`

	// Add checksum to the database model
	dbPayload.Checksum = checksum

	if _, err := r.db.NamedExecContext(ctx, query, dbPayload); err != nil {
		return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("failed to create payload: %w", err))
	}

	return coremodels.Ok(payload)
}

// GetByID retrieves a payload by ID
func (r *payloadRepo) GetByID(ctx context.Context, id uuid.UUID) coremodels.Result[*coremodels.PayloadDB] {
	query := `
		SELECT id, name, category, domain, type, version, parent_id, content, description,
			   severity, tags, variables, config, language, enabled, validated,
			   validation_result, usage_count, success_rate, last_used, repository_id,
			   repository_path, created_by, created_at, updated_at, checksum
		FROM payloads
		WHERE id = ?`

	var dbPayload dbmodels.PayloadDB
	if err := r.db.GetContext(ctx, &dbPayload, query, id.String()); err != nil {
		if err == sql.ErrNoRows {
			return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("payload not found with ID: %s", id))
		}
		return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("failed to get payload: %w", err))
	}

	payload := convertPayloadFromDBModel(&dbPayload)
	return coremodels.Ok(payload)
}

// GetByRepositoryPath retrieves a payload by repository ID and path
func (r *payloadRepo) GetByRepositoryPath(ctx context.Context, repositoryID uuid.UUID, repositoryPath string) coremodels.Result[*coremodels.PayloadDB] {
	query := `
		SELECT id, name, category, domain, type, version, parent_id, content, description,
			   severity, tags, variables, config, language, enabled, validated,
			   validation_result, usage_count, success_rate, last_used, repository_id,
			   repository_path, created_by, created_at, updated_at, checksum
		FROM payloads
		WHERE repository_id = ? AND repository_path = ?`

	var dbPayload dbmodels.PayloadDB
	if err := r.db.GetContext(ctx, &dbPayload, query, repositoryID.String(), repositoryPath); err != nil {
		if err == sql.ErrNoRows {
			return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("payload not found for repository %s at path %s", repositoryID, repositoryPath))
		}
		return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("failed to get payload: %w", err))
	}

	payload := convertPayloadFromDBModel(&dbPayload)
	return coremodels.Ok(payload)
}

// Update updates an existing payload
func (r *payloadRepo) Update(ctx context.Context, payload *coremodels.PayloadDB) coremodels.Result[*coremodels.PayloadDB] {
	// Set updated time and validate
	payload.UpdatedAt = time.Now()
	if err := payload.Validate(); err != nil {
		return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("validation failed: %w", err))
	}

	// Convert to database model and update checksum
	dbPayload := convertPayloadToDBModel(payload)
	dbPayload.Checksum = calculatePayloadChecksum(payload.Content)

	query := `
		UPDATE payloads SET
			name = :name, category = :category, domain = :domain, type = :type,
			version = :version, parent_id = :parent_id, content = :content,
			description = :description, severity = :severity, tags = :tags,
			variables = :variables, config = :config, language = :language,
			enabled = :enabled, validated = :validated, validation_result = :validation_result,
			usage_count = :usage_count, success_rate = :success_rate, last_used = :last_used,
			repository_id = :repository_id, repository_path = :repository_path,
			updated_at = :updated_at, checksum = :checksum
		WHERE id = :id`

	result, err := r.db.NamedExecContext(ctx, query, dbPayload)
	if err != nil {
		return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("failed to update payload: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("failed to get rows affected: %w", err))
	}

	if rowsAffected == 0 {
		return coremodels.Err[*coremodels.PayloadDB](fmt.Errorf("payload not found with ID: %s", payload.ID))
	}

	return coremodels.Ok(payload)
}

// Delete removes a payload
func (r *payloadRepo) Delete(ctx context.Context, id uuid.UUID) coremodels.Result[bool] {
	query := `DELETE FROM payloads WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to delete payload: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to get rows affected: %w", err))
	}

	return coremodels.Ok(rowsAffected > 0)
}

// CreateBatch creates multiple payloads in a batch operation
func (r *payloadRepo) CreateBatch(ctx context.Context, payloads []*coremodels.PayloadDB) coremodels.Result[[]*coremodels.PayloadDB] {
	if len(payloads) == 0 {
		return coremodels.Ok([]*coremodels.PayloadDB{})
	}

	// Begin transaction for batch operation
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("failed to begin transaction: %w", err))
	}
	defer tx.Rollback()

	query := `
		INSERT INTO payloads (
			id, name, category, domain, type, version, parent_id, content, description,
			severity, tags, variables, config, language, enabled, validated,
			validation_result, usage_count, success_rate, last_used, repository_id,
			repository_path, created_by, created_at, updated_at, checksum
		) VALUES (
			:id, :name, :category, :domain, :type, :version, :parent_id, :content, :description,
			:severity, :tags, :variables, :config, :language, :enabled, :validated,
			:validation_result, :usage_count, :success_rate, :last_used, :repository_id,
			:repository_path, :created_by, :created_at, :updated_at, :checksum
		)`

	var createdPayloads []*coremodels.PayloadDB

	for _, payload := range payloads {
		// Set defaults and validate
		payload.SetDefaults()
		if err := payload.Validate(); err != nil {
			return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("validation failed for payload %s: %w", payload.Name, err))
		}

		// Convert to database model with checksum
		dbPayload := convertPayloadToDBModel(payload)
		dbPayload.Checksum = calculatePayloadChecksum(payload.Content)

		if _, err := tx.NamedExecContext(ctx, query, dbPayload); err != nil {
			return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("failed to create payload %s: %w", payload.Name, err))
		}

		createdPayloads = append(createdPayloads, payload)
	}

	if err := tx.Commit(); err != nil {
		return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("failed to commit transaction: %w", err))
	}

	return coremodels.Ok(createdPayloads)
}

// UpdateBatch updates multiple payloads in a batch operation
func (r *payloadRepo) UpdateBatch(ctx context.Context, payloads []*coremodels.PayloadDB) coremodels.Result[[]*coremodels.PayloadDB] {
	if len(payloads) == 0 {
		return coremodels.Ok([]*coremodels.PayloadDB{})
	}

	// Begin transaction for batch operation
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("failed to begin transaction: %w", err))
	}
	defer tx.Rollback()

	query := `
		UPDATE payloads SET
			name = :name, category = :category, domain = :domain, type = :type,
			version = :version, parent_id = :parent_id, content = :content,
			description = :description, severity = :severity, tags = :tags,
			variables = :variables, config = :config, language = :language,
			enabled = :enabled, validated = :validated, validation_result = :validation_result,
			usage_count = :usage_count, success_rate = :success_rate, last_used = :last_used,
			repository_id = :repository_id, repository_path = :repository_path,
			updated_at = :updated_at, checksum = :checksum
		WHERE id = :id`

	var updatedPayloads []*coremodels.PayloadDB

	for _, payload := range payloads {
		// Set updated time and validate
		payload.UpdatedAt = time.Now()
		if err := payload.Validate(); err != nil {
			return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("validation failed for payload %s: %w", payload.Name, err))
		}

		// Convert to database model with updated checksum
		dbPayload := convertPayloadToDBModel(payload)
		dbPayload.Checksum = calculatePayloadChecksum(payload.Content)

		result, err := tx.NamedExecContext(ctx, query, dbPayload)
		if err != nil {
			return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("failed to update payload %s: %w", payload.Name, err))
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("failed to get rows affected for payload %s: %w", payload.Name, err))
		}

		if rowsAffected == 0 {
			return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("payload not found with ID: %s", payload.ID))
		}

		updatedPayloads = append(updatedPayloads, payload)
	}

	if err := tx.Commit(); err != nil {
		return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("failed to commit transaction: %w", err))
	}

	return coremodels.Ok(updatedPayloads)
}

// ListByRepository retrieves all payloads for a specific repository
func (r *payloadRepo) ListByRepository(ctx context.Context, repositoryID uuid.UUID) coremodels.Result[[]*coremodels.PayloadDB] {
	query := `
		SELECT id, name, category, domain, type, version, parent_id, content, description,
			   severity, tags, variables, config, language, enabled, validated,
			   validation_result, usage_count, success_rate, last_used, repository_id,
			   repository_path, created_by, created_at, updated_at, checksum
		FROM payloads
		WHERE repository_id = ?
		ORDER BY repository_path, created_at`

	var dbPayloads []dbmodels.PayloadDB
	if err := r.db.SelectContext(ctx, &dbPayloads, query, repositoryID.String()); err != nil {
		return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("failed to list payloads by repository: %w", err))
	}

	payloads := make([]*coremodels.PayloadDB, len(dbPayloads))
	for i, dbPayload := range dbPayloads {
		payloads[i] = convertPayloadFromDBModel(&dbPayload)
	}

	return coremodels.Ok(payloads)
}

// CountByRepository counts all payloads for a specific repository
func (r *payloadRepo) CountByRepository(ctx context.Context, repositoryID uuid.UUID) coremodels.Result[int64] {
	query := `SELECT COUNT(*) FROM payloads WHERE repository_id = ?`

	var count int64
	if err := r.db.GetContext(ctx, &count, query, repositoryID.String()); err != nil {
		return coremodels.Err[int64](fmt.Errorf("failed to count payloads by repository: %w", err))
	}

	return coremodels.Ok(count)
}

// DeleteOrphaned removes payloads that are no longer present in the repository
func (r *payloadRepo) DeleteOrphaned(ctx context.Context, repositoryID uuid.UUID, validPaths []string) coremodels.Result[int64] {
	if len(validPaths) == 0 {
		// If no valid paths, delete all payloads for this repository
		query := `DELETE FROM payloads WHERE repository_id = ?`
		result, err := r.db.ExecContext(ctx, query, repositoryID.String())
		if err != nil {
			return coremodels.Err[int64](fmt.Errorf("failed to delete all orphaned payloads: %w", err))
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return coremodels.Err[int64](fmt.Errorf("failed to get rows affected: %w", err))
		}

		return coremodels.Ok(rowsAffected)
	}

	// Create placeholders for the IN clause
	placeholders := make([]string, len(validPaths))
	args := make([]interface{}, len(validPaths)+1)
	args[0] = repositoryID.String()

	for i, path := range validPaths {
		placeholders[i] = "?"
		args[i+1] = path
	}

	query := fmt.Sprintf(`
		DELETE FROM payloads
		WHERE repository_id = ?
		AND repository_path NOT IN (%s)`,
		strings.Join(placeholders, ","))

	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return coremodels.Err[int64](fmt.Errorf("failed to delete orphaned payloads: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return coremodels.Err[int64](fmt.Errorf("failed to get rows affected: %w", err))
	}

	return coremodels.Ok(rowsAffected)
}

// GetChecksumByPath retrieves the checksum for a payload by repository ID and path
func (r *payloadRepo) GetChecksumByPath(ctx context.Context, repositoryID uuid.UUID, repositoryPath string) coremodels.Result[string] {
	query := `SELECT checksum FROM payloads WHERE repository_id = ? AND repository_path = ?`

	var checksum string
	if err := r.db.GetContext(ctx, &checksum, query, repositoryID.String(), repositoryPath); err != nil {
		if err == sql.ErrNoRows {
			return coremodels.Err[string](fmt.Errorf("checksum not found for repository %s at path %s", repositoryID, repositoryPath))
		}
		return coremodels.Err[string](fmt.Errorf("failed to get checksum: %w", err))
	}

	return coremodels.Ok(checksum)
}

// UpdateChecksum updates the checksum for a payload
func (r *payloadRepo) UpdateChecksum(ctx context.Context, id uuid.UUID, checksum string) coremodels.Result[bool] {
	query := `UPDATE payloads SET checksum = ?, updated_at = ? WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, checksum, time.Now(), id.String())
	if err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to update checksum: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return coremodels.Err[bool](fmt.Errorf("failed to get rows affected: %w", err))
	}

	return coremodels.Ok(rowsAffected > 0)
}

// Helper functions for type conversion and checksums

// calculatePayloadChecksum calculates SHA256 checksum of payload content
func calculatePayloadChecksum(content string) string {
	hasher := sha256.New()
	hasher.Write([]byte(content))
	return hex.EncodeToString(hasher.Sum(nil))
}

// convertPayloadToDBModel converts a core PayloadDB to database model
func convertPayloadToDBModel(core *coremodels.PayloadDB) *dbmodels.PayloadDB {
	return &dbmodels.PayloadDB{
		ID:               core.ID,
		Name:             core.Name,
		Category:         dbmodels.PayloadCategory(core.Category),
		Domain:           core.Domain,
		Type:             dbmodels.PayloadType(core.Type),
		Version:          core.Version,
		ParentID:         core.ParentID,
		Content:          core.Content,
		Description:      core.Description,
		Severity:         core.Severity,
		Tags:             dbmodels.JSONStringSlice(core.Tags),
		Variables:        dbmodels.JSONMap(core.Variables),
		Config:           dbmodels.JSONMap(core.Config),
		Language:         core.Language,
		Enabled:          core.Enabled,
		Validated:        core.Validated,
		ValidationResult: dbmodels.JSONMap(core.ValidationResult),
		UsageCount:       core.UsageCount,
		SuccessRate:      core.SuccessRate,
		LastUsed:         core.LastUsed,
		RepositoryID:     core.RepositoryID,
		RepositoryPath:   core.RepositoryPath,
		Checksum:         calculatePayloadChecksum(core.Content),
		CreatedBy:        core.CreatedBy,
		CreatedAt:        core.CreatedAt,
		UpdatedAt:        core.UpdatedAt,
	}
}

// convertPayloadFromDBModel converts a database PayloadDB to core model
func convertPayloadFromDBModel(db *dbmodels.PayloadDB) *coremodels.PayloadDB {
	return &coremodels.PayloadDB{
		ID:               db.ID,
		Name:             db.Name,
		Category:         coremodels.PayloadCategory(db.Category),
		Domain:           db.Domain,
		Type:             coremodels.PayloadType(db.Type),
		Version:          db.Version,
		ParentID:         db.ParentID,
		Content:          db.Content,
		Description:      db.Description,
		Severity:         db.Severity,
		Tags:             []string(db.Tags),
		Variables:        map[string]interface{}(db.Variables),
		Config:           map[string]interface{}(db.Config),
		Language:         db.Language,
		Enabled:          db.Enabled,
		Validated:        db.Validated,
		ValidationResult: map[string]interface{}(db.ValidationResult),
		UsageCount:       db.UsageCount,
		SuccessRate:      db.SuccessRate,
		LastUsed:         db.LastUsed,
		RepositoryID:     db.RepositoryID,
		RepositoryPath:   db.RepositoryPath,
		CreatedBy:        db.CreatedBy,
		CreatedAt:        db.CreatedAt,
		UpdatedAt:        db.UpdatedAt,
	}
}

// List returns all payloads
func (r *payloadRepo) List(ctx context.Context) coremodels.Result[[]*coremodels.PayloadDB] {
	query := `
		SELECT id, name, category, domain, plugin_name, type, version, parent_id,
		       content, description, severity, tags, variables, config, language,
		       enabled, validated, validation_result, usage_count, success_rate,
		       last_used, repository_id, repository_path, checksum,
		       created_by, created_at, updated_at
		FROM payloads
		ORDER BY created_at DESC
	`

	var dbPayloads []dbmodels.PayloadDB
	err := r.db.SelectContext(ctx, &dbPayloads, query)
	if err != nil {
		return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("failed to list payloads: %w", err))
	}

	// Convert to core models
	var payloads []*coremodels.PayloadDB
	for _, db := range dbPayloads {
		payload := convertPayloadFromDBModel(&db)
		payloads = append(payloads, payload)
	}

	return coremodels.Ok(payloads)
}

// ListByDomain returns all payloads for a specific domain
func (r *payloadRepo) ListByDomain(ctx context.Context, domain string) coremodels.Result[[]*coremodels.PayloadDB] {
	query := `
		SELECT id, name, category, domain, plugin_name, type, version, parent_id,
		       content, description, severity, tags, variables, config, language,
		       enabled, validated, validation_result, usage_count, success_rate,
		       last_used, repository_id, repository_path, checksum,
		       created_by, created_at, updated_at
		FROM payloads
		WHERE domain = ? AND enabled = 1
		ORDER BY created_at DESC
	`

	var dbPayloads []dbmodels.PayloadDB
	err := r.db.SelectContext(ctx, &dbPayloads, query, domain)
	if err != nil {
		return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("failed to list payloads by domain: %w", err))
	}

	// Convert to core models
	var payloads []*coremodels.PayloadDB
	for _, db := range dbPayloads {
		payload := convertPayloadFromDBModel(&db)
		payloads = append(payloads, payload)
	}

	return coremodels.Ok(payloads)
}

// ListByPlugin returns all payloads for a specific plugin
func (r *payloadRepo) ListByPlugin(ctx context.Context, plugin string) coremodels.Result[[]*coremodels.PayloadDB] {
	query := `
		SELECT id, name, category, domain, plugin_name, type, version, parent_id,
		       content, description, severity, tags, variables, config, language,
		       enabled, validated, validation_result, usage_count, success_rate,
		       last_used, repository_id, repository_path, checksum,
		       created_by, created_at, updated_at
		FROM payloads
		WHERE plugin_name = ? AND enabled = 1
		ORDER BY created_at DESC
	`

	var dbPayloads []dbmodels.PayloadDB
	err := r.db.SelectContext(ctx, &dbPayloads, query, plugin)
	if err != nil {
		return coremodels.Err[[]*coremodels.PayloadDB](fmt.Errorf("failed to list payloads by plugin: %w", err))
	}

	// Convert to core models
	var payloads []*coremodels.PayloadDB
	for _, db := range dbPayloads {
		payload := convertPayloadFromDBModel(&db)
		payloads = append(payloads, payload)
	}

	return coremodels.Ok(payloads)
}