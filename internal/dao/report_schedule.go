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

// ReportSchedule represents a report schedule resource accessor.
type ReportSchedule struct {
	BaseAccessor
}

// Init initializes the report schedule accessor.
func (rs *ReportSchedule) Init(f Factory) {
	rs.BaseAccessor.Init(f, "report_schedules")
}

// Get returns a report schedule by ID.
func (rs *ReportSchedule) Get(ctx context.Context, id uuid.UUID) (*model.ReportSchedule, error) {
	schedule := &model.ReportSchedule{}

	query := `
		SELECT id, name, description, report_type, target_id, scan_type,
			   schedule_expression, format, template_id, enabled, last_run,
			   next_run, config, filters, output_config, notification_config,
			   created_by, created_at, updated_at
		FROM report_schedules
		WHERE id = ?`

	var (
		config             []byte
		filters            []byte
		outputConfig       []byte
		notificationConfig []byte
		description        sql.NullString
		targetID           sql.NullString
		scanType           sql.NullString
		templateID         sql.NullString
		lastRun            sql.NullTime
		nextRun            sql.NullTime
		createdBy          sql.NullString
	)

	err := rs.db.QueryRowContext(ctx, query, id.String()).Scan(
		&schedule.ID, &schedule.Name, &description, &schedule.ReportType,
		&targetID, &scanType, &schedule.ScheduleExpression, &schedule.Format,
		&templateID, &schedule.Enabled, &lastRun, &nextRun, &config,
		&filters, &outputConfig, &notificationConfig, &createdBy,
		&schedule.CreatedAt, &schedule.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if description.Valid {
		schedule.Description = description.String
	}
	if targetID.Valid {
		targetUUID, err := uuid.Parse(targetID.String)
		if err != nil {
			return nil, err
		}
		schedule.TargetID = &targetUUID
	}
	if scanType.Valid {
		schedule.ScanType = scanType.String
	}
	if templateID.Valid {
		templateUUID, err := uuid.Parse(templateID.String)
		if err != nil {
			return nil, err
		}
		schedule.TemplateID = &templateUUID
	}
	if lastRun.Valid {
		schedule.LastRun = &lastRun.Time
	}
	if nextRun.Valid {
		schedule.NextRun = &nextRun.Time
	}
	if createdBy.Valid {
		schedule.CreatedBy = createdBy.String
	}

	// Parse JSON fields
	if len(config) > 0 {
		if err := json.Unmarshal(config, &schedule.Config); err != nil {
			return nil, err
		}
	}
	if len(filters) > 0 {
		if err := json.Unmarshal(filters, &schedule.Filters); err != nil {
			return nil, err
		}
	}
	if len(outputConfig) > 0 {
		if err := json.Unmarshal(outputConfig, &schedule.OutputConfig); err != nil {
			return nil, err
		}
	}
	if len(notificationConfig) > 0 {
		if err := json.Unmarshal(notificationConfig, &schedule.NotificationConfig); err != nil {
			return nil, err
		}
	}

	return schedule, nil
}

// List returns all report schedules.
func (rs *ReportSchedule) List(ctx context.Context) ([]*model.ReportSchedule, error) {
	query := `
		SELECT id, name, description, report_type, target_id, scan_type,
			   schedule_expression, format, template_id, enabled, last_run,
			   next_run, config, filters, output_config, notification_config,
			   created_by, created_at, updated_at
		FROM report_schedules
		ORDER BY created_at DESC`

	rows, err := rs.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return rs.scanReportSchedules(rows)
}

// Create creates a new report schedule.
func (rs *ReportSchedule) Create(ctx context.Context, schedule *model.ReportSchedule) error {
	if schedule.ID == uuid.Nil {
		schedule.ID = uuid.New()
	}

	now := time.Now()
	schedule.CreatedAt = now
	schedule.UpdatedAt = now

	query := `
		INSERT INTO report_schedules (
			id, name, description, report_type, target_id, scan_type,
			schedule_expression, format, template_id, enabled, last_run,
			next_run, config, filters, output_config, notification_config,
			created_by, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var (
		config             []byte
		filters            []byte
		outputConfig       []byte
		notificationConfig []byte
		err                error
	)

	// Marshal JSON fields
	if schedule.Config != nil {
		config, err = json.Marshal(schedule.Config)
		if err != nil {
			return err
		}
	}
	if schedule.Filters != nil {
		filters, err = json.Marshal(schedule.Filters)
		if err != nil {
			return err
		}
	}
	if schedule.OutputConfig != nil {
		outputConfig, err = json.Marshal(schedule.OutputConfig)
		if err != nil {
			return err
		}
	}
	if schedule.NotificationConfig != nil {
		notificationConfig, err = json.Marshal(schedule.NotificationConfig)
		if err != nil {
			return err
		}
	}

	var description, targetID, scanType, templateID, lastRun, nextRun, createdBy interface{}

	if schedule.Description != "" {
		description = schedule.Description
	}
	if schedule.TargetID != nil {
		targetID = schedule.TargetID.String()
	}
	if schedule.ScanType != "" {
		scanType = schedule.ScanType
	}
	if schedule.TemplateID != nil {
		templateID = schedule.TemplateID.String()
	}
	if schedule.LastRun != nil {
		lastRun = schedule.LastRun
	}
	if schedule.NextRun != nil {
		nextRun = schedule.NextRun
	}
	if schedule.CreatedBy != "" {
		createdBy = schedule.CreatedBy
	}

	_, err = rs.db.ExecContext(ctx, query,
		schedule.ID.String(), schedule.Name, description, schedule.ReportType,
		targetID, scanType, schedule.ScheduleExpression, schedule.Format,
		templateID, schedule.Enabled, lastRun, nextRun, config, filters,
		outputConfig, notificationConfig, createdBy, schedule.CreatedAt,
		schedule.UpdatedAt,
	)

	return err
}

// Update updates an existing report schedule.
func (rs *ReportSchedule) Update(ctx context.Context, schedule *model.ReportSchedule) error {
	schedule.UpdatedAt = time.Now()

	query := `
		UPDATE report_schedules SET
			name = ?, description = ?, report_type = ?, target_id = ?,
			scan_type = ?, schedule_expression = ?, format = ?, template_id = ?,
			enabled = ?, last_run = ?, next_run = ?, config = ?, filters = ?,
			output_config = ?, notification_config = ?, created_by = ?, updated_at = ?
		WHERE id = ?`

	var (
		config             []byte
		filters            []byte
		outputConfig       []byte
		notificationConfig []byte
		err                error
	)

	// Marshal JSON fields
	if schedule.Config != nil {
		config, err = json.Marshal(schedule.Config)
		if err != nil {
			return err
		}
	}
	if schedule.Filters != nil {
		filters, err = json.Marshal(schedule.Filters)
		if err != nil {
			return err
		}
	}
	if schedule.OutputConfig != nil {
		outputConfig, err = json.Marshal(schedule.OutputConfig)
		if err != nil {
			return err
		}
	}
	if schedule.NotificationConfig != nil {
		notificationConfig, err = json.Marshal(schedule.NotificationConfig)
		if err != nil {
			return err
		}
	}

	var description, targetID, scanType, templateID, lastRun, nextRun, createdBy interface{}

	if schedule.Description != "" {
		description = schedule.Description
	}
	if schedule.TargetID != nil {
		targetID = schedule.TargetID.String()
	}
	if schedule.ScanType != "" {
		scanType = schedule.ScanType
	}
	if schedule.TemplateID != nil {
		templateID = schedule.TemplateID.String()
	}
	if schedule.LastRun != nil {
		lastRun = schedule.LastRun
	}
	if schedule.NextRun != nil {
		nextRun = schedule.NextRun
	}
	if schedule.CreatedBy != "" {
		createdBy = schedule.CreatedBy
	}

	_, err = rs.db.ExecContext(ctx, query,
		schedule.Name, description, schedule.ReportType, targetID, scanType,
		schedule.ScheduleExpression, schedule.Format, templateID,
		schedule.Enabled, lastRun, nextRun, config, filters, outputConfig,
		notificationConfig, createdBy, schedule.UpdatedAt, schedule.ID.String(),
	)

	return err
}

// Delete removes a report schedule.
func (rs *ReportSchedule) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM report_schedules WHERE id = ?`
	_, err := rs.db.ExecContext(ctx, query, id.String())
	return err
}

// ListEnabled returns only enabled report schedules.
func (rs *ReportSchedule) ListEnabled(ctx context.Context) ([]*model.ReportSchedule, error) {
	query := `
		SELECT id, name, description, report_type, target_id, scan_type,
			   schedule_expression, format, template_id, enabled, last_run,
			   next_run, config, filters, output_config, notification_config,
			   created_by, created_at, updated_at
		FROM report_schedules
		WHERE enabled = 1
		ORDER BY next_run ASC`

	rows, err := rs.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return rs.scanReportSchedules(rows)
}

// GetDueSchedules returns schedules that are due to run.
func (rs *ReportSchedule) GetDueSchedules(ctx context.Context) ([]*model.ReportSchedule, error) {
	query := `
		SELECT id, name, description, report_type, target_id, scan_type,
			   schedule_expression, format, template_id, enabled, last_run,
			   next_run, config, filters, output_config, notification_config,
			   created_by, created_at, updated_at
		FROM report_schedules
		WHERE enabled = 1 AND next_run IS NOT NULL AND next_run <= ?
		ORDER BY next_run ASC`

	rows, err := rs.db.QueryContext(ctx, query, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return rs.scanReportSchedules(rows)
}

// GetByTargetID returns schedules for a specific target.
func (rs *ReportSchedule) GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.ReportSchedule, error) {
	query := `
		SELECT id, name, description, report_type, target_id, scan_type,
			   schedule_expression, format, template_id, enabled, last_run,
			   next_run, config, filters, output_config, notification_config,
			   created_by, created_at, updated_at
		FROM report_schedules
		WHERE target_id = ?
		ORDER BY created_at DESC`

	rows, err := rs.db.QueryContext(ctx, query, targetID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return rs.scanReportSchedules(rows)
}

// UpdateLastRun updates the last run timestamp and calculates next run.
func (rs *ReportSchedule) UpdateLastRun(ctx context.Context, id uuid.UUID, lastRun time.Time, nextRun *time.Time) error {
	query := `UPDATE report_schedules SET last_run = ?, next_run = ?, updated_at = ? WHERE id = ?`

	var nextRunValue interface{}
	if nextRun != nil {
		nextRunValue = *nextRun
	}

	_, err := rs.db.ExecContext(ctx, query, lastRun, nextRunValue, time.Now(), id.String())
	return err
}

// UpdateNextRun updates only the next run timestamp.
func (rs *ReportSchedule) UpdateNextRun(ctx context.Context, id uuid.UUID, nextRun *time.Time) error {
	query := `UPDATE report_schedules SET next_run = ?, updated_at = ? WHERE id = ?`

	var nextRunValue interface{}
	if nextRun != nil {
		nextRunValue = *nextRun
	}

	_, err := rs.db.ExecContext(ctx, query, nextRunValue, time.Now(), id.String())
	return err
}

// EnableSchedule enables a report schedule.
func (rs *ReportSchedule) EnableSchedule(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE report_schedules SET enabled = 1, updated_at = ? WHERE id = ?`
	_, err := rs.db.ExecContext(ctx, query, time.Now(), id.String())
	return err
}

// DisableSchedule disables a report schedule.
func (rs *ReportSchedule) DisableSchedule(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE report_schedules SET enabled = 0, updated_at = ? WHERE id = ?`
	_, err := rs.db.ExecContext(ctx, query, time.Now(), id.String())
	return err
}

// scanReportSchedules is a helper method to scan multiple report schedule rows.
func (rs *ReportSchedule) scanReportSchedules(rows *sql.Rows) ([]*model.ReportSchedule, error) {
	var schedules []*model.ReportSchedule

	for rows.Next() {
		schedule := &model.ReportSchedule{}
		var (
			config             []byte
			filters            []byte
			outputConfig       []byte
			notificationConfig []byte
			description        sql.NullString
			targetID           sql.NullString
			scanType           sql.NullString
			templateID         sql.NullString
			lastRun            sql.NullTime
			nextRun            sql.NullTime
			createdBy          sql.NullString
		)

		err := rows.Scan(
			&schedule.ID, &schedule.Name, &description, &schedule.ReportType,
			&targetID, &scanType, &schedule.ScheduleExpression, &schedule.Format,
			&templateID, &schedule.Enabled, &lastRun, &nextRun, &config,
			&filters, &outputConfig, &notificationConfig, &createdBy,
			&schedule.CreatedAt, &schedule.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Handle nullable fields
		if description.Valid {
			schedule.Description = description.String
		}
		if targetID.Valid {
			targetUUID, err := uuid.Parse(targetID.String)
			if err != nil {
				return nil, err
			}
			schedule.TargetID = &targetUUID
		}
		if scanType.Valid {
			schedule.ScanType = scanType.String
		}
		if templateID.Valid {
			templateUUID, err := uuid.Parse(templateID.String)
			if err != nil {
				return nil, err
			}
			schedule.TemplateID = &templateUUID
		}
		if lastRun.Valid {
			schedule.LastRun = &lastRun.Time
		}
		if nextRun.Valid {
			schedule.NextRun = &nextRun.Time
		}
		if createdBy.Valid {
			schedule.CreatedBy = createdBy.String
		}

		// Parse JSON fields
		if len(config) > 0 {
			json.Unmarshal(config, &schedule.Config)
		}
		if len(filters) > 0 {
			json.Unmarshal(filters, &schedule.Filters)
		}
		if len(outputConfig) > 0 {
			json.Unmarshal(outputConfig, &schedule.OutputConfig)
		}
		if len(notificationConfig) > 0 {
			json.Unmarshal(notificationConfig, &schedule.NotificationConfig)
		}

		schedules = append(schedules, schedule)
	}

	return schedules, rows.Err()
}