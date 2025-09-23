// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package dao

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/model"
	"github.com/google/uuid"
)

// Target represents a target resource accessor.
type Target struct {
	BaseAccessor
}

// Init initializes the target accessor.
func (t *Target) Init(f Factory) {
	t.BaseAccessor.Init(f, "targets")
}

// Get returns a target by ID.
func (t *Target) Get(ctx context.Context, id uuid.UUID) (*model.Target, error) {
	target := &model.Target{}

	query := `
		SELECT id, name, type, provider, url, model, api_version, headers, config,
			   status, description, tags, credential_id, created_at, updated_at
		FROM targets
		WHERE id = ?`

	var (
		headers    []byte
		config     []byte
		tags       []byte
		model_     sql.NullString
		apiVersion sql.NullString
		desc       sql.NullString
		credID     sql.NullString
	)

	err := t.db.QueryRowContext(ctx, query, id.String()).Scan(
		&target.ID, &target.Name, &target.Type, &target.Provider, &target.URL,
		&model_, &apiVersion, &headers, &config, &target.Status,
		&desc, &tags, &credID, &target.CreatedAt, &target.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if model_.Valid {
		target.Model = model_.String
	}
	if apiVersion.Valid {
		target.APIVersion = apiVersion.String
	}
	if desc.Valid {
		target.Description = desc.String
	}
	if credID.Valid {
		credUUID, err := uuid.Parse(credID.String)
		if err == nil {
			target.CredentialID = &credUUID
		}
	}

	// Parse JSON fields
	if len(headers) > 0 {
		if err := json.Unmarshal(headers, &target.Headers); err != nil {
			return nil, err
		}
	}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &target.Config); err != nil {
			return nil, err
		}
	}
	if len(tags) > 0 {
		if err := json.Unmarshal(tags, &target.Tags); err != nil {
			return nil, err
		}
	}

	return target, nil
}

// List returns all targets.
func (t *Target) List(ctx context.Context) ([]*model.Target, error) {
	query := `
		SELECT id, name, type, provider, url, model, api_version, headers, config,
			   status, description, tags, credential_id, created_at, updated_at
		FROM targets
		ORDER BY created_at DESC`

	rows, err := t.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []*model.Target
	for rows.Next() {
		target := &model.Target{}
		var (
			headers    []byte
			config     []byte
			tags       []byte
			model_     sql.NullString
			apiVersion sql.NullString
			desc       sql.NullString
			credID     sql.NullString
		)

		err := rows.Scan(
			&target.ID, &target.Name, &target.Type, &target.Provider, &target.URL,
			&model_, &apiVersion, &headers, &config, &target.Status,
			&desc, &tags, &credID, &target.CreatedAt, &target.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Handle nullable fields
		if model_.Valid {
			target.Model = model_.String
		}
		if apiVersion.Valid {
			target.APIVersion = apiVersion.String
		}
		if desc.Valid {
			target.Description = desc.String
		}
		if credID.Valid {
			credUUID, err := uuid.Parse(credID.String)
			if err == nil {
				target.CredentialID = &credUUID
			}
		}

		// Parse JSON fields
		if len(headers) > 0 {
			json.Unmarshal(headers, &target.Headers)
		}
		if len(config) > 0 {
			json.Unmarshal(config, &target.Config)
		}
		if len(tags) > 0 {
			json.Unmarshal(tags, &target.Tags)
		}

		targets = append(targets, target)
	}

	return targets, rows.Err()
}

// Create creates a new target.
func (t *Target) Create(ctx context.Context, target *model.Target) error {
	if target.ID == uuid.Nil {
		target.ID = uuid.New()
	}

	now := time.Now()
	target.CreatedAt = now
	target.UpdatedAt = now

	query := `
		INSERT INTO targets (
			id, name, type, provider, url, model, api_version, headers, config,
			status, description, tags, credential_id, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var (
		headers []byte
		config  []byte
		tags    []byte
		err     error
	)

	// Marshal JSON fields
	if target.Headers != nil {
		headers, err = json.Marshal(target.Headers)
		if err != nil {
			return err
		}
	}
	if target.Config != nil {
		config, err = json.Marshal(target.Config)
		if err != nil {
			return err
		}
	}
	if target.Tags != nil {
		tags, err = json.Marshal(target.Tags)
		if err != nil {
			return err
		}
	}

	var credID interface{}
	if target.CredentialID != nil {
		credID = target.CredentialID.String()
	}

	var model interface{} = target.Model
	if target.Model == "" {
		model = nil
	}

	var apiVersion interface{} = target.APIVersion
	if target.APIVersion == "" {
		apiVersion = nil
	}

	var description interface{} = target.Description
	if target.Description == "" {
		description = nil
	}

	_, err = t.db.ExecContext(ctx, query,
		target.ID.String(), target.Name, target.Type, target.Provider, target.URL,
		model, apiVersion, headers, config, target.Status,
		description, tags, credID, target.CreatedAt, target.UpdatedAt,
	)

	return err
}

// Update updates an existing target.
func (t *Target) Update(ctx context.Context, target *model.Target) error {
	target.UpdatedAt = time.Now()

	query := `
		UPDATE targets SET
			name = ?, type = ?, provider = ?, url = ?, model = ?, api_version = ?,
			headers = ?, config = ?, status = ?, description = ?, tags = ?,
			credential_id = ?, updated_at = ?
		WHERE id = ?`

	var (
		headers []byte
		config  []byte
		tags    []byte
		err     error
	)

	// Marshal JSON fields
	if target.Headers != nil {
		headers, err = json.Marshal(target.Headers)
		if err != nil {
			return err
		}
	}
	if target.Config != nil {
		config, err = json.Marshal(target.Config)
		if err != nil {
			return err
		}
	}
	if target.Tags != nil {
		tags, err = json.Marshal(target.Tags)
		if err != nil {
			return err
		}
	}

	var credID interface{}
	if target.CredentialID != nil {
		credID = target.CredentialID.String()
	}

	var model interface{} = target.Model
	if target.Model == "" {
		model = nil
	}

	var apiVersion interface{} = target.APIVersion
	if target.APIVersion == "" {
		apiVersion = nil
	}

	var description interface{} = target.Description
	if target.Description == "" {
		description = nil
	}

	_, err = t.db.ExecContext(ctx, query,
		target.Name, target.Type, target.Provider, target.URL,
		model, apiVersion, headers, config, target.Status,
		description, tags, credID, target.UpdatedAt, target.ID.String(),
	)

	return err
}

// Delete removes a target.
func (t *Target) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM targets WHERE id = ?`
	_, err := t.db.ExecContext(ctx, query, id.String())
	return err
}

// UpdateStatus updates only the status of a target.
func (t *Target) UpdateStatus(ctx context.Context, id uuid.UUID, status model.TargetStatus) error {
	query := `UPDATE targets SET status = ?, updated_at = ? WHERE id = ?`
	_, err := t.db.ExecContext(ctx, query, status, time.Now(), id.String())
	return err
}

// ListByProvider returns targets filtered by provider.
func (t *Target) ListByProvider(ctx context.Context, provider model.Provider) ([]*model.Target, error) {
	query := `
		SELECT id, name, type, provider, url, model, api_version, headers, config,
			   status, description, tags, credential_id, created_at, updated_at
		FROM targets
		WHERE provider = ?
		ORDER BY created_at DESC`

	rows, err := t.db.QueryContext(ctx, query, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return t.scanTargets(rows)
}

// ListByStatus returns targets filtered by status.
func (t *Target) ListByStatus(ctx context.Context, status model.TargetStatus) ([]*model.Target, error) {
	query := `
		SELECT id, name, type, provider, url, model, api_version, headers, config,
			   status, description, tags, credential_id, created_at, updated_at
		FROM targets
		WHERE status = ?
		ORDER BY created_at DESC`

	rows, err := t.db.QueryContext(ctx, query, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return t.scanTargets(rows)
}

// GetByName returns a target by name.
func (t *Target) GetByName(ctx context.Context, name string) (*model.Target, error) {
	query := `
		SELECT id, name, type, provider, url, model, api_version, headers, config,
			   status, description, tags, credential_id, created_at, updated_at
		FROM targets
		WHERE name = ?`

	target := &model.Target{}
	var (
		headers    []byte
		config     []byte
		tags       []byte
		model_     sql.NullString
		apiVersion sql.NullString
		desc       sql.NullString
		credID     sql.NullString
	)

	err := t.db.QueryRowContext(ctx, query, name).Scan(
		&target.ID, &target.Name, &target.Type, &target.Provider, &target.URL,
		&model_, &apiVersion, &headers, &config, &target.Status,
		&desc, &tags, &credID, &target.CreatedAt, &target.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Handle nullable fields and JSON parsing (same as Get method)
	if model_.Valid {
		target.Model = model_.String
	}
	if apiVersion.Valid {
		target.APIVersion = apiVersion.String
	}
	if desc.Valid {
		target.Description = desc.String
	}
	if credID.Valid {
		credUUID, err := uuid.Parse(credID.String)
		if err == nil {
			target.CredentialID = &credUUID
		}
	}

	if len(headers) > 0 {
		json.Unmarshal(headers, &target.Headers)
	}
	if len(config) > 0 {
		json.Unmarshal(config, &target.Config)
	}
	if len(tags) > 0 {
		json.Unmarshal(tags, &target.Tags)
	}

	return target, nil
}

// ExistsByName checks if a target exists by name.
func (t *Target) ExistsByName(ctx context.Context, name string) (bool, error) {
	return t.ExistsBy(ctx, "name", name)
}

// CountByProvider returns count of targets by provider.
func (t *Target) CountByProvider(ctx context.Context, provider model.Provider) (int, error) {
	return t.CountBy(ctx, "provider", provider)
}

// ListActiveTargets returns only active targets.
func (t *Target) ListActiveTargets(ctx context.Context) ([]*model.Target, error) {
	return t.ListByStatus(ctx, model.TargetStatusActive)
}

// DeleteByName removes a target by name.
func (t *Target) DeleteByName(ctx context.Context, name string) error {
	query := `DELETE FROM targets WHERE name = ?`
	_, err := t.db.ExecContext(ctx, query, name)
	return err
}

// scanTargets is a helper method to scan multiple target rows.
func (t *Target) scanTargets(rows *sql.Rows) ([]*model.Target, error) {
	var targets []*model.Target

	for rows.Next() {
		target := &model.Target{}
		var (
			headers    []byte
			config     []byte
			tags       []byte
			model_     sql.NullString
			apiVersion sql.NullString
			desc       sql.NullString
			credID     sql.NullString
		)

		err := rows.Scan(
			&target.ID, &target.Name, &target.Type, &target.Provider, &target.URL,
			&model_, &apiVersion, &headers, &config, &target.Status,
			&desc, &tags, &credID, &target.CreatedAt, &target.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Handle nullable fields
		if model_.Valid {
			target.Model = model_.String
		}
		if apiVersion.Valid {
			target.APIVersion = apiVersion.String
		}
		if desc.Valid {
			target.Description = desc.String
		}
		if credID.Valid {
			credUUID, err := uuid.Parse(credID.String)
			if err == nil {
				target.CredentialID = &credUUID
			}
		}

		// Parse JSON fields
		if len(headers) > 0 {
			json.Unmarshal(headers, &target.Headers)
		}
		if len(config) > 0 {
			json.Unmarshal(config, &target.Config)
		}
		if len(tags) > 0 {
			json.Unmarshal(tags, &target.Tags)
		}

		targets = append(targets, target)
	}

	return targets, rows.Err()
}