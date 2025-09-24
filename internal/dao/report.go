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
	"github.com/jmoiron/sqlx"
)

// Report represents a report resource accessor.
type Report struct {
	BaseAccessor
}

// Init initializes the report accessor.
func (r *Report) Init(f Factory) {
	r.BaseAccessor.Init(f, "reports")
}

// Get returns a report by ID.
func (r *Report) Get(ctx context.Context, id uuid.UUID) (*model.Report, error) {
	report := &model.Report{}

	query := `
		SELECT id, name, type, status, format, target_id, scan_id, template_id,
			   output_path, generated_by, generated_at, scheduled_for, config,
			   filters, data, error, file_size, created_at, updated_at
		FROM reports
		WHERE id = ?`

	var (
		config      []byte
		filters     []byte
		data        []byte
		targetID    sql.NullString
		scanID      sql.NullString
		templateID  sql.NullString
		outputPath  sql.NullString
		generatedBy sql.NullString
		generatedAt sql.NullTime
		scheduledFor sql.NullTime
		errorMsg    sql.NullString
	)

	err := r.db.QueryRowContext(ctx, query, id.String()).Scan(
		&report.ID, &report.Name, &report.Type, &report.Status, &report.Format,
		&targetID, &scanID, &templateID, &outputPath, &generatedBy,
		&generatedAt, &scheduledFor, &config, &filters, &data, &errorMsg,
		&report.FileSize, &report.CreatedAt, &report.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if targetID.Valid {
		targetUUID, err := uuid.Parse(targetID.String)
		if err != nil {
			return nil, err
		}
		report.TargetID = &targetUUID
	}
	if scanID.Valid {
		scanUUID, err := uuid.Parse(scanID.String)
		if err != nil {
			return nil, err
		}
		report.ScanID = &scanUUID
	}
	if templateID.Valid {
		templateUUID, err := uuid.Parse(templateID.String)
		if err != nil {
			return nil, err
		}
		report.TemplateID = &templateUUID
	}
	if outputPath.Valid {
		report.OutputPath = outputPath.String
	}
	if generatedBy.Valid {
		report.GeneratedBy = generatedBy.String
	}
	if generatedAt.Valid {
		report.GeneratedAt = &generatedAt.Time
	}
	if scheduledFor.Valid {
		report.ScheduledFor = &scheduledFor.Time
	}
	if errorMsg.Valid {
		report.Error = errorMsg.String
	}

	// Parse JSON fields
	if len(config) > 0 {
		if err := json.Unmarshal(config, &report.Config); err != nil {
			return nil, err
		}
	}
	if len(filters) > 0 {
		if err := json.Unmarshal(filters, &report.Filters); err != nil {
			return nil, err
		}
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &report.Data); err != nil {
			return nil, err
		}
	}

	return report, nil
}

// List returns all reports.
func (r *Report) List(ctx context.Context) ([]*model.Report, error) {
	query := `
		SELECT id, name, type, status, format, target_id, scan_id, template_id,
			   output_path, generated_by, generated_at, scheduled_for, config,
			   filters, data, error, file_size, created_at, updated_at
		FROM reports
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanReports(rows)
}

// Create creates a new report.
func (r *Report) Create(ctx context.Context, report *model.Report) error {
	if report.ID == uuid.Nil {
		report.ID = uuid.New()
	}

	now := time.Now()
	report.CreatedAt = now
	report.UpdatedAt = now

	query := `
		INSERT INTO reports (
			id, name, type, status, format, target_id, scan_id, template_id,
			output_path, generated_by, generated_at, scheduled_for, config,
			filters, data, error, file_size, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var (
		config  []byte
		filters []byte
		data    []byte
		err     error
	)

	// Marshal JSON fields
	if report.Config != nil {
		config, err = json.Marshal(report.Config)
		if err != nil {
			return err
		}
	}
	if report.Filters != nil {
		filters, err = json.Marshal(report.Filters)
		if err != nil {
			return err
		}
	}
	if report.Data != nil {
		data, err = json.Marshal(report.Data)
		if err != nil {
			return err
		}
	}

	var targetID, scanID, templateID, outputPath, generatedBy interface{}
	var generatedAt, scheduledFor interface{}
	var errorMsg interface{}

	if report.TargetID != nil {
		targetID = report.TargetID.String()
	}
	if report.ScanID != nil {
		scanID = report.ScanID.String()
	}
	if report.TemplateID != nil {
		templateID = report.TemplateID.String()
	}
	if report.OutputPath != "" {
		outputPath = report.OutputPath
	}
	if report.GeneratedBy != "" {
		generatedBy = report.GeneratedBy
	}
	if report.GeneratedAt != nil {
		generatedAt = report.GeneratedAt
	}
	if report.ScheduledFor != nil {
		scheduledFor = report.ScheduledFor
	}
	if report.Error != "" {
		errorMsg = report.Error
	}

	_, err = r.db.ExecContext(ctx, query,
		report.ID.String(), report.Name, report.Type, report.Status, report.Format,
		targetID, scanID, templateID, outputPath, generatedBy,
		generatedAt, scheduledFor, config, filters, data, errorMsg,
		report.FileSize, report.CreatedAt, report.UpdatedAt,
	)

	return err
}

// Update updates an existing report.
func (r *Report) Update(ctx context.Context, report *model.Report) error {
	report.UpdatedAt = time.Now()

	query := `
		UPDATE reports SET
			name = ?, type = ?, status = ?, format = ?, target_id = ?,
			scan_id = ?, template_id = ?, output_path = ?, generated_by = ?,
			generated_at = ?, scheduled_for = ?, config = ?, filters = ?,
			data = ?, error = ?, file_size = ?, updated_at = ?
		WHERE id = ?`

	var (
		config  []byte
		filters []byte
		data    []byte
		err     error
	)

	// Marshal JSON fields
	if report.Config != nil {
		config, err = json.Marshal(report.Config)
		if err != nil {
			return err
		}
	}
	if report.Filters != nil {
		filters, err = json.Marshal(report.Filters)
		if err != nil {
			return err
		}
	}
	if report.Data != nil {
		data, err = json.Marshal(report.Data)
		if err != nil {
			return err
		}
	}

	var targetID, scanID, templateID, outputPath, generatedBy interface{}
	var generatedAt, scheduledFor interface{}
	var errorMsg interface{}

	if report.TargetID != nil {
		targetID = report.TargetID.String()
	}
	if report.ScanID != nil {
		scanID = report.ScanID.String()
	}
	if report.TemplateID != nil {
		templateID = report.TemplateID.String()
	}
	if report.OutputPath != "" {
		outputPath = report.OutputPath
	}
	if report.GeneratedBy != "" {
		generatedBy = report.GeneratedBy
	}
	if report.GeneratedAt != nil {
		generatedAt = report.GeneratedAt
	}
	if report.ScheduledFor != nil {
		scheduledFor = report.ScheduledFor
	}
	if report.Error != "" {
		errorMsg = report.Error
	}

	_, err = r.db.ExecContext(ctx, query,
		report.Name, report.Type, report.Status, report.Format,
		targetID, scanID, templateID, outputPath, generatedBy,
		generatedAt, scheduledFor, config, filters, data, errorMsg,
		report.FileSize, report.UpdatedAt, report.ID.String(),
	)

	return err
}

// Delete removes a report.
func (r *Report) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM reports WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id.String())
	return err
}

// GetByTargetID returns reports for a specific target.
func (r *Report) GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Report, error) {
	query := `
		SELECT id, name, type, status, format, target_id, scan_id, template_id,
			   output_path, generated_by, generated_at, scheduled_for, config,
			   filters, data, error, file_size, created_at, updated_at
		FROM reports
		WHERE target_id = ?
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, targetID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanReports(rows)
}

// GetByScanID returns reports for a specific scan.
func (r *Report) GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.Report, error) {
	query := `
		SELECT id, name, type, status, format, target_id, scan_id, template_id,
			   output_path, generated_by, generated_at, scheduled_for, config,
			   filters, data, error, file_size, created_at, updated_at
		FROM reports
		WHERE scan_id = ?
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, scanID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanReports(rows)
}

// ListByStatus returns reports filtered by status.
func (r *Report) ListByStatus(ctx context.Context, status model.ReportStatus) ([]*model.Report, error) {
	query := `
		SELECT id, name, type, status, format, target_id, scan_id, template_id,
			   output_path, generated_by, generated_at, scheduled_for, config,
			   filters, data, error, file_size, created_at, updated_at
		FROM reports
		WHERE status = ?
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanReports(rows)
}

// ListByType returns reports filtered by type.
func (r *Report) ListByType(ctx context.Context, reportType model.ReportType) ([]*model.Report, error) {
	query := `
		SELECT id, name, type, status, format, target_id, scan_id, template_id,
			   output_path, generated_by, generated_at, scheduled_for, config,
			   filters, data, error, file_size, created_at, updated_at
		FROM reports
		WHERE type = ?
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, reportType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanReports(rows)
}

// UpdateStatus updates only the status of a report.
func (r *Report) UpdateStatus(ctx context.Context, id uuid.UUID, status model.ReportStatus) error {
	query := `UPDATE reports SET status = ?, updated_at = ? WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, status, time.Now(), id.String())
	return err
}

// GetScheduledReports returns reports that are scheduled for generation.
func (r *Report) GetScheduledReports(ctx context.Context) ([]*model.Report, error) {
	query := `
		SELECT id, name, type, status, format, target_id, scan_id, template_id,
			   output_path, generated_by, generated_at, scheduled_for, config,
			   filters, data, error, file_size, created_at, updated_at
		FROM reports
		WHERE scheduled_for IS NOT NULL AND scheduled_for <= ? AND status = 'pending'
		ORDER BY scheduled_for ASC`

	rows, err := r.db.QueryContext(ctx, query, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanReports(rows)
}

// scanReports is a helper method to scan multiple report rows.
func (r *Report) scanReports(rows *sql.Rows) ([]*model.Report, error) {
	var reports []*model.Report

	for rows.Next() {
		report := &model.Report{}
		var (
			config       []byte
			filters      []byte
			data         []byte
			targetID     sql.NullString
			scanID       sql.NullString
			templateID   sql.NullString
			outputPath   sql.NullString
			generatedBy  sql.NullString
			generatedAt  sql.NullTime
			scheduledFor sql.NullTime
			errorMsg     sql.NullString
		)

		err := rows.Scan(
			&report.ID, &report.Name, &report.Type, &report.Status, &report.Format,
			&targetID, &scanID, &templateID, &outputPath, &generatedBy,
			&generatedAt, &scheduledFor, &config, &filters, &data, &errorMsg,
			&report.FileSize, &report.CreatedAt, &report.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Handle nullable fields
		if targetID.Valid {
			targetUUID, err := uuid.Parse(targetID.String)
			if err != nil {
				return nil, err
			}
			report.TargetID = &targetUUID
		}
		if scanID.Valid {
			scanUUID, err := uuid.Parse(scanID.String)
			if err != nil {
				return nil, err
			}
			report.ScanID = &scanUUID
		}
		if templateID.Valid {
			templateUUID, err := uuid.Parse(templateID.String)
			if err != nil {
				return nil, err
			}
			report.TemplateID = &templateUUID
		}
		if outputPath.Valid {
			report.OutputPath = outputPath.String
		}
		if generatedBy.Valid {
			report.GeneratedBy = generatedBy.String
		}
		if generatedAt.Valid {
			report.GeneratedAt = &generatedAt.Time
		}
		if scheduledFor.Valid {
			report.ScheduledFor = &scheduledFor.Time
		}
		if errorMsg.Valid {
			report.Error = errorMsg.String
		}

		// Parse JSON fields
		if len(config) > 0 {
			json.Unmarshal(config, &report.Config)
		}
		if len(filters) > 0 {
			json.Unmarshal(filters, &report.Filters)
		}
		if len(data) > 0 {
			json.Unmarshal(data, &report.Data)
		}

		reports = append(reports, report)
	}

	return reports, rows.Err()
}

// CreateReportsTable creates the reports table
func CreateReportsTable(db *sqlx.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS reports (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		type TEXT NOT NULL,
		format TEXT NOT NULL DEFAULT 'json',
		status TEXT NOT NULL DEFAULT 'draft',
		target_id TEXT,
		scan_id TEXT,
		config TEXT,
		filters TEXT,
		data TEXT,
		error TEXT,
		scheduled_at DATETIME,
		executed_at DATETIME,
		completed_at DATETIME,
		created_by TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (target_id) REFERENCES targets(id),
		FOREIGN KEY (scan_id) REFERENCES scans(id)
	);

	CREATE INDEX IF NOT EXISTS idx_reports_name ON reports(name);
	CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(type);
	CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
	CREATE INDEX IF NOT EXISTS idx_reports_target_id ON reports(target_id);
	CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);
	CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);
	`

	_, err := db.Exec(schema)
	return err
}