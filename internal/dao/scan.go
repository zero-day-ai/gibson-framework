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

// Scan represents a scan resource accessor.
type Scan struct {
	BaseAccessor
}

// Init initializes the scan accessor.
func (s *Scan) Init(f Factory) {
	s.BaseAccessor.Init(f, "scans")
}

// Get returns a scan by ID.
func (s *Scan) Get(ctx context.Context, id uuid.UUID) (*model.Scan, error) {
	scan := &model.Scan{}

	query := `
		SELECT id, target_id, name, type, status, progress, options, statistics, error,
			   started_by, scheduled_for, started_at, completed_at, created_at, updated_at
		FROM scans
		WHERE id = ?`

	var (
		options    []byte
		statistics []byte
		error_     sql.NullString
		startedBy  sql.NullString
		scheduled  sql.NullTime
		started    sql.NullTime
		completed  sql.NullTime
	)

	err := s.db.QueryRowContext(ctx, query, id.String()).Scan(
		&scan.ID, &scan.TargetID, &scan.Name, &scan.Type, &scan.Status, &scan.Progress,
		&options, &statistics, &error_, &startedBy, &scheduled, &started, &completed,
		&scan.CreatedAt, &scan.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if error_.Valid {
		scan.Error = error_.String
	}
	if startedBy.Valid {
		scan.StartedBy = startedBy.String
	}
	if scheduled.Valid {
		scan.ScheduledFor = &scheduled.Time
	}
	if started.Valid {
		scan.StartedAt = &started.Time
	}
	if completed.Valid {
		scan.CompletedAt = &completed.Time
	}

	// Parse JSON fields
	if len(options) > 0 {
		if err := json.Unmarshal(options, &scan.Options); err != nil {
			return nil, err
		}
	}
	if len(statistics) > 0 {
		if err := json.Unmarshal(statistics, &scan.Statistics); err != nil {
			return nil, err
		}
	}

	return scan, nil
}

// List returns all scans.
func (s *Scan) List(ctx context.Context) ([]*model.Scan, error) {
	query := `
		SELECT id, target_id, name, type, status, progress, options, statistics, error,
			   started_by, scheduled_for, started_at, completed_at, created_at, updated_at
		FROM scans
		ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanScans(rows)
}

// Create creates a new scan.
func (s *Scan) Create(ctx context.Context, scan *model.Scan) error {
	if scan.ID == uuid.Nil {
		scan.ID = uuid.New()
	}

	now := time.Now()
	scan.CreatedAt = now
	scan.UpdatedAt = now

	query := `
		INSERT INTO scans (
			id, target_id, name, type, status, progress, options, statistics, error,
			started_by, scheduled_for, started_at, completed_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var (
		options    []byte
		statistics []byte
		err        error
	)

	// Marshal JSON fields
	options, err = json.Marshal(scan.Options)
	if err != nil {
		return err
	}
	statistics, err = json.Marshal(scan.Statistics)
	if err != nil {
		return err
	}

	var error_ interface{} = scan.Error
	if scan.Error == "" {
		error_ = nil
	}

	var startedBy interface{} = scan.StartedBy
	if scan.StartedBy == "" {
		startedBy = nil
	}

	_, err = s.db.ExecContext(ctx, query,
		scan.ID.String(), scan.TargetID.String(), scan.Name, scan.Type, scan.Status, scan.Progress,
		options, statistics, error_, startedBy, scan.ScheduledFor, scan.StartedAt,
		scan.CompletedAt, scan.CreatedAt, scan.UpdatedAt,
	)

	return err
}

// Update updates an existing scan.
func (s *Scan) Update(ctx context.Context, scan *model.Scan) error {
	scan.UpdatedAt = time.Now()

	query := `
		UPDATE scans SET
			target_id = ?, name = ?, type = ?, status = ?, progress = ?, options = ?,
			statistics = ?, error = ?, started_by = ?, scheduled_for = ?,
			started_at = ?, completed_at = ?, updated_at = ?
		WHERE id = ?`

	var (
		options    []byte
		statistics []byte
		err        error
	)

	// Marshal JSON fields
	options, err = json.Marshal(scan.Options)
	if err != nil {
		return err
	}
	statistics, err = json.Marshal(scan.Statistics)
	if err != nil {
		return err
	}

	var error_ interface{} = scan.Error
	if scan.Error == "" {
		error_ = nil
	}

	var startedBy interface{} = scan.StartedBy
	if scan.StartedBy == "" {
		startedBy = nil
	}

	_, err = s.db.ExecContext(ctx, query,
		scan.TargetID.String(), scan.Name, scan.Type, scan.Status, scan.Progress,
		options, statistics, error_, startedBy, scan.ScheduledFor,
		scan.StartedAt, scan.CompletedAt, scan.UpdatedAt, scan.ID.String(),
	)

	return err
}

// Delete removes a scan.
func (s *Scan) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM scans WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, id.String())
	return err
}

// GetByTargetID returns scans for a specific target.
func (s *Scan) GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Scan, error) {
	query := `
		SELECT id, target_id, name, type, status, progress, options, statistics, error,
			   started_by, scheduled_for, started_at, completed_at, created_at, updated_at
		FROM scans
		WHERE target_id = ?
		ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, targetID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanScans(rows)
}

// ListByStatus returns scans filtered by status.
func (s *Scan) ListByStatus(ctx context.Context, status model.ScanStatus) ([]*model.Scan, error) {
	query := `
		SELECT id, target_id, name, type, status, progress, options, statistics, error,
			   started_by, scheduled_for, started_at, completed_at, created_at, updated_at
		FROM scans
		WHERE status = ?
		ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanScans(rows)
}

// UpdateProgress updates scan progress.
func (s *Scan) UpdateProgress(ctx context.Context, id uuid.UUID, progress float64) error {
	query := `UPDATE scans SET progress = ?, updated_at = ? WHERE id = ?`
	_, err := s.db.ExecContext(ctx, query, progress, time.Now(), id.String())
	return err
}

// UpdateStatus updates scan status.
func (s *Scan) UpdateStatus(ctx context.Context, id uuid.UUID, status model.ScanStatus) error {
	now := time.Now()
	query := `UPDATE scans SET status = ?, updated_at = ? WHERE id = ?`

	// If completing the scan, also set completed_at
	if status == model.ScanStatusCompleted || status == model.ScanStatusFailed || status == model.ScanStatusCancelled {
		query = `UPDATE scans SET status = ?, completed_at = ?, updated_at = ? WHERE id = ?`
		_, err := s.db.ExecContext(ctx, query, status, now, now, id.String())
		return err
	}

	// If starting the scan, set started_at
	if status == model.ScanStatusRunning {
		query = `UPDATE scans SET status = ?, started_at = ?, updated_at = ? WHERE id = ?`
		_, err := s.db.ExecContext(ctx, query, status, now, now, id.String())
		return err
	}

	_, err := s.db.ExecContext(ctx, query, status, now, id.String())
	return err
}

// GetRunningScans returns currently running scans.
func (s *Scan) GetRunningScans(ctx context.Context) ([]*model.Scan, error) {
	return s.ListByStatus(ctx, model.ScanStatusRunning)
}

// scanScans is a helper method to scan multiple scan rows.
func (s *Scan) scanScans(rows *sql.Rows) ([]*model.Scan, error) {
	var scans []*model.Scan

	for rows.Next() {
		scan := &model.Scan{}
		var (
			options    []byte
			statistics []byte
			error_     sql.NullString
			startedBy  sql.NullString
			scheduled  sql.NullTime
			started    sql.NullTime
			completed  sql.NullTime
		)

		err := rows.Scan(
			&scan.ID, &scan.TargetID, &scan.Name, &scan.Type, &scan.Status, &scan.Progress,
			&options, &statistics, &error_, &startedBy, &scheduled, &started, &completed,
			&scan.CreatedAt, &scan.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Handle nullable fields
		if error_.Valid {
			scan.Error = error_.String
		}
		if startedBy.Valid {
			scan.StartedBy = startedBy.String
		}
		if scheduled.Valid {
			scan.ScheduledFor = &scheduled.Time
		}
		if started.Valid {
			scan.StartedAt = &started.Time
		}
		if completed.Valid {
			scan.CompletedAt = &completed.Time
		}

		// Parse JSON fields
		if len(options) > 0 {
			json.Unmarshal(options, &scan.Options)
		}
		if len(statistics) > 0 {
			json.Unmarshal(statistics, &scan.Statistics)
		}

		scans = append(scans, scan)
	}

	return scans, rows.Err()
}