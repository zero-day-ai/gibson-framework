// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package dao

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/google/uuid"
)

// Credential represents a credential resource accessor.
type Credential struct {
	BaseAccessor
}

// Init initializes the credential accessor.
func (c *Credential) Init(f Factory) {
	c.BaseAccessor.Init(f, "credentials")
}

// Get returns a credential by ID.
func (c *Credential) Get(ctx context.Context, id uuid.UUID) (*model.Credential, error) {
	credential := &model.Credential{}

	query := `
		SELECT id, name, type, provider, status, description, encrypted_value,
			   encryption_iv, key_derivation_salt, tags, rotation_info, usage,
			   created_at, updated_at, last_used
		FROM credentials
		WHERE id = ?`

	var (
		tags        []byte
		rotationInfo []byte
		usage       []byte
		desc        sql.NullString
		lastUsed    sql.NullTime
	)

	err := c.db.QueryRowContext(ctx, query, id.String()).Scan(
		&credential.ID, &credential.Name, &credential.Type, &credential.Provider,
		&credential.Status, &desc, &credential.EncryptedValue,
		&credential.EncryptionIV, &credential.KeyDerivationSalt, &tags,
		&rotationInfo, &usage, &credential.CreatedAt, &credential.UpdatedAt, &lastUsed,
	)

	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if desc.Valid {
		credential.Description = desc.String
	}
	if lastUsed.Valid {
		credential.LastUsed = &lastUsed.Time
	}

	// Parse JSON fields
	if len(tags) > 0 {
		if err := json.Unmarshal(tags, &credential.Tags); err != nil {
			return nil, err
		}
	}
	if len(rotationInfo) > 0 {
		if err := json.Unmarshal(rotationInfo, &credential.RotationInfo); err != nil {
			return nil, err
		}
	}
	if len(usage) > 0 {
		if err := json.Unmarshal(usage, &credential.Usage); err != nil {
			return nil, err
		}
	}

	return credential, nil
}

// List returns all credentials.
func (c *Credential) List(ctx context.Context) ([]*model.Credential, error) {
	query := `
		SELECT id, name, type, provider, status, description, encrypted_value,
			   encryption_iv, key_derivation_salt, tags, rotation_info, usage,
			   created_at, updated_at, last_used
		FROM credentials
		ORDER BY created_at DESC`

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return c.scanCredentials(rows)
}

// Create creates a new credential.
func (c *Credential) Create(ctx context.Context, credential *model.Credential) error {
	if credential.ID == uuid.Nil {
		credential.ID = uuid.New()
	}

	now := time.Now()
	credential.CreatedAt = now
	credential.UpdatedAt = now

	query := `
		INSERT INTO credentials (
			id, name, type, provider, status, description, encrypted_value,
			encryption_iv, key_derivation_salt, tags, rotation_info, usage,
			created_at, updated_at, last_used
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var (
		tags         []byte
		rotationInfo []byte
		usage        []byte
		err          error
	)

	// Marshal JSON fields
	if credential.Tags != nil {
		tags, err = json.Marshal(credential.Tags)
		if err != nil {
			return err
		}
	}
	rotationInfo, err = json.Marshal(credential.RotationInfo)
	if err != nil {
		return err
	}
	usage, err = json.Marshal(credential.Usage)
	if err != nil {
		return err
	}

	var description interface{} = credential.Description
	if credential.Description == "" {
		description = nil
	}

	_, err = c.db.ExecContext(ctx, query,
		credential.ID.String(), credential.Name, credential.Type, credential.Provider,
		credential.Status, description, credential.EncryptedValue,
		credential.EncryptionIV, credential.KeyDerivationSalt, tags,
		rotationInfo, usage, credential.CreatedAt, credential.UpdatedAt, credential.LastUsed,
	)

	return err
}

// Update updates an existing credential.
func (c *Credential) Update(ctx context.Context, credential *model.Credential) error {
	credential.UpdatedAt = time.Now()

	query := `
		UPDATE credentials SET
			name = ?, type = ?, provider = ?, status = ?, description = ?,
			encrypted_value = ?, encryption_iv = ?, key_derivation_salt = ?,
			tags = ?, rotation_info = ?, usage = ?, updated_at = ?, last_used = ?
		WHERE id = ?`

	var (
		tags         []byte
		rotationInfo []byte
		usage        []byte
		err          error
	)

	// Marshal JSON fields
	if credential.Tags != nil {
		tags, err = json.Marshal(credential.Tags)
		if err != nil {
			return err
		}
	}
	rotationInfo, err = json.Marshal(credential.RotationInfo)
	if err != nil {
		return err
	}
	usage, err = json.Marshal(credential.Usage)
	if err != nil {
		return err
	}

	var description interface{} = credential.Description
	if credential.Description == "" {
		description = nil
	}

	_, err = c.db.ExecContext(ctx, query,
		credential.Name, credential.Type, credential.Provider, credential.Status,
		description, credential.EncryptedValue, credential.EncryptionIV,
		credential.KeyDerivationSalt, tags, rotationInfo, usage,
		credential.UpdatedAt, credential.LastUsed, credential.ID.String(),
	)

	return err
}

// Delete removes a credential.
func (c *Credential) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM credentials WHERE id = ?`
	_, err := c.db.ExecContext(ctx, query, id.String())
	return err
}

// GetByName returns a credential by name.
func (c *Credential) GetByName(ctx context.Context, name string) (*model.Credential, error) {
	credential := &model.Credential{}

	query := `
		SELECT id, name, type, provider, status, description, encrypted_value,
			   encryption_iv, key_derivation_salt, tags, rotation_info, usage,
			   created_at, updated_at, last_used
		FROM credentials
		WHERE name = ?`

	var (
		tags         []byte
		rotationInfo []byte
		usage        []byte
		desc         sql.NullString
		lastUsed     sql.NullTime
	)

	err := c.db.QueryRowContext(ctx, query, name).Scan(
		&credential.ID, &credential.Name, &credential.Type, &credential.Provider,
		&credential.Status, &desc, &credential.EncryptedValue,
		&credential.EncryptionIV, &credential.KeyDerivationSalt, &tags,
		&rotationInfo, &usage, &credential.CreatedAt, &credential.UpdatedAt, &lastUsed,
	)

	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if desc.Valid {
		credential.Description = desc.String
	}
	if lastUsed.Valid {
		credential.LastUsed = &lastUsed.Time
	}

	// Parse JSON fields
	if len(tags) > 0 {
		json.Unmarshal(tags, &credential.Tags)
	}
	if len(rotationInfo) > 0 {
		json.Unmarshal(rotationInfo, &credential.RotationInfo)
	}
	if len(usage) > 0 {
		json.Unmarshal(usage, &credential.Usage)
	}

	return credential, nil
}

// ListByProvider returns credentials filtered by provider.
func (c *Credential) ListByProvider(ctx context.Context, provider model.Provider) ([]*model.Credential, error) {
	query := `
		SELECT id, name, type, provider, status, description, encrypted_value,
			   encryption_iv, key_derivation_salt, tags, rotation_info, usage,
			   created_at, updated_at, last_used
		FROM credentials
		WHERE provider = ?
		ORDER BY created_at DESC`

	rows, err := c.db.QueryContext(ctx, query, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return c.scanCredentials(rows)
}

// ListByStatus returns credentials filtered by status.
func (c *Credential) ListByStatus(ctx context.Context, status model.CredentialStatus) ([]*model.Credential, error) {
	query := `
		SELECT id, name, type, provider, status, description, encrypted_value,
			   encryption_iv, key_derivation_salt, tags, rotation_info, usage,
			   created_at, updated_at, last_used
		FROM credentials
		WHERE status = ?
		ORDER BY created_at DESC`

	rows, err := c.db.QueryContext(ctx, query, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return c.scanCredentials(rows)
}

// UpdateLastUsed updates the last used timestamp.
func (c *Credential) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	query := `UPDATE credentials SET last_used = ?, updated_at = ? WHERE id = ?`
	_, err := c.db.ExecContext(ctx, query, now, now, id.String())
	return err
}

// GetActiveCredentials returns only active credentials.
func (c *Credential) GetActiveCredentials(ctx context.Context) ([]*model.Credential, error) {
	return c.ListByStatus(ctx, model.CredentialStatusActive)
}

// RotateCredential updates credential rotation information.
func (c *Credential) RotateCredential(ctx context.Context, id uuid.UUID, rotationInfo model.CredentialRotationInfo) error {
	rotationJSON, err := json.Marshal(rotationInfo)
	if err != nil {
		return err
	}

	query := `UPDATE credentials SET rotation_info = ?, updated_at = ? WHERE id = ?`
	_, err = c.db.ExecContext(ctx, query, rotationJSON, time.Now(), id.String())
	return err
}

// scanCredentials is a helper method to scan multiple credential rows.
func (c *Credential) scanCredentials(rows *sql.Rows) ([]*model.Credential, error) {
	var credentials []*model.Credential

	for rows.Next() {
		credential := &model.Credential{}
		var (
			tags         []byte
			rotationInfo []byte
			usage        []byte
			desc         sql.NullString
			lastUsed     sql.NullTime
		)

		err := rows.Scan(
			&credential.ID, &credential.Name, &credential.Type, &credential.Provider,
			&credential.Status, &desc, &credential.EncryptedValue,
			&credential.EncryptionIV, &credential.KeyDerivationSalt, &tags,
			&rotationInfo, &usage, &credential.CreatedAt, &credential.UpdatedAt, &lastUsed,
		)
		if err != nil {
			return nil, err
		}

		// Handle nullable fields
		if desc.Valid {
			credential.Description = desc.String
		}
		if lastUsed.Valid {
			credential.LastUsed = &lastUsed.Time
		}

		// Parse JSON fields
		if len(tags) > 0 {
			json.Unmarshal(tags, &credential.Tags)
		}
		if len(rotationInfo) > 0 {
			json.Unmarshal(rotationInfo, &credential.RotationInfo)
		}
		if len(usage) > 0 {
			json.Unmarshal(usage, &credential.Usage)
		}

		credentials = append(credentials, credential)
	}

	return credentials, rows.Err()
}