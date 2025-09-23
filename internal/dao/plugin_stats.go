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
	"github.com/jmoiron/sqlx"
)

// PluginStats represents a plugin stats resource accessor.
type PluginStats struct {
	BaseAccessor
}

// Init initializes the plugin stats accessor.
func (ps *PluginStats) Init(f Factory) {
	ps.BaseAccessor.Init(f, "plugin_stats")
}

// Get returns plugin stats by ID.
func (ps *PluginStats) Get(ctx context.Context, id uuid.UUID) (*model.PluginStats, error) {
	stats := &model.PluginStats{}

	query := `
		SELECT id, plugin_name, plugin_version, metric_name, metric_type,
			   value, unit, tags, target_id, scan_id, timestamp, created_at
		FROM plugin_stats
		WHERE id = ?`

	var (
		tags     []byte
		unit     sql.NullString
		targetID sql.NullString
		scanID   sql.NullString
	)

	err := ps.db.QueryRowContext(ctx, query, id.String()).Scan(
		&stats.ID, &stats.PluginName, &stats.PluginVersion, &stats.MetricName,
		&stats.MetricType, &stats.Value, &unit, &tags, &targetID, &scanID,
		&stats.Timestamp, &stats.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if unit.Valid {
		stats.Unit = unit.String
	}
	if targetID.Valid {
		targetUUID, err := uuid.Parse(targetID.String)
		if err != nil {
			return nil, err
		}
		stats.TargetID = &targetUUID
	}
	if scanID.Valid {
		scanUUID, err := uuid.Parse(scanID.String)
		if err != nil {
			return nil, err
		}
		stats.ScanID = &scanUUID
	}

	// Parse JSON fields
	if len(tags) > 0 {
		if err := json.Unmarshal(tags, &stats.Tags); err != nil {
			return nil, err
		}
	}

	return stats, nil
}

// List returns all plugin stats.
func (ps *PluginStats) List(ctx context.Context) ([]*model.PluginStats, error) {
	query := `
		SELECT id, plugin_name, plugin_version, metric_name, metric_type,
			   value, unit, tags, target_id, scan_id, timestamp, created_at
		FROM plugin_stats
		ORDER BY timestamp DESC`

	rows, err := ps.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ps.scanPluginStats(rows)
}

// Create creates new plugin stats.
func (ps *PluginStats) Create(ctx context.Context, stats *model.PluginStats) error {
	if stats.ID == uuid.Nil {
		stats.ID = uuid.New()
	}

	now := time.Now()
	stats.CreatedAt = now

	if stats.Timestamp.IsZero() {
		stats.Timestamp = now
	}

	query := `
		INSERT INTO plugin_stats (
			id, plugin_name, plugin_version, metric_name, metric_type,
			value, unit, tags, target_id, scan_id, timestamp, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var (
		tags []byte
		err  error
	)

	// Marshal JSON fields
	if stats.Tags != nil {
		tags, err = json.Marshal(stats.Tags)
		if err != nil {
			return err
		}
	}

	var unit, targetID, scanID interface{}

	if stats.Unit != "" {
		unit = stats.Unit
	}
	if stats.TargetID != nil {
		targetID = stats.TargetID.String()
	}
	if stats.ScanID != nil {
		scanID = stats.ScanID.String()
	}

	_, err = ps.db.ExecContext(ctx, query,
		stats.ID.String(), stats.PluginName, stats.PluginVersion,
		stats.MetricName, stats.MetricType, stats.Value, unit, tags,
		targetID, scanID, stats.Timestamp, stats.CreatedAt,
	)

	return err
}

// Update updates existing plugin stats.
func (ps *PluginStats) Update(ctx context.Context, stats *model.PluginStats) error {
	query := `
		UPDATE plugin_stats SET
			plugin_name = ?, plugin_version = ?, metric_name = ?,
			metric_type = ?, value = ?, unit = ?, tags = ?,
			target_id = ?, scan_id = ?, timestamp = ?
		WHERE id = ?`

	var (
		tags []byte
		err  error
	)

	// Marshal JSON fields
	if stats.Tags != nil {
		tags, err = json.Marshal(stats.Tags)
		if err != nil {
			return err
		}
	}

	var unit, targetID, scanID interface{}

	if stats.Unit != "" {
		unit = stats.Unit
	}
	if stats.TargetID != nil {
		targetID = stats.TargetID.String()
	}
	if stats.ScanID != nil {
		scanID = stats.ScanID.String()
	}

	_, err = ps.db.ExecContext(ctx, query,
		stats.PluginName, stats.PluginVersion, stats.MetricName,
		stats.MetricType, stats.Value, unit, tags, targetID, scanID,
		stats.Timestamp, stats.ID.String(),
	)

	return err
}

// Delete removes plugin stats.
func (ps *PluginStats) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM plugin_stats WHERE id = ?`
	_, err := ps.db.ExecContext(ctx, query, id.String())
	return err
}

// ListByPlugin returns stats for a specific plugin.
func (ps *PluginStats) ListByPlugin(ctx context.Context, pluginName string) ([]*model.PluginStats, error) {
	query := `
		SELECT id, plugin_name, plugin_version, metric_name, metric_type,
			   value, unit, tags, target_id, scan_id, timestamp, created_at
		FROM plugin_stats
		WHERE plugin_name = ?
		ORDER BY timestamp DESC`

	rows, err := ps.db.QueryContext(ctx, query, pluginName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ps.scanPluginStats(rows)
}

// ListByMetric returns stats for a specific metric.
func (ps *PluginStats) ListByMetric(ctx context.Context, pluginName, metricName string) ([]*model.PluginStats, error) {
	query := `
		SELECT id, plugin_name, plugin_version, metric_name, metric_type,
			   value, unit, tags, target_id, scan_id, timestamp, created_at
		FROM plugin_stats
		WHERE plugin_name = ? AND metric_name = ?
		ORDER BY timestamp DESC`

	rows, err := ps.db.QueryContext(ctx, query, pluginName, metricName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ps.scanPluginStats(rows)
}

// ListByTimeRange returns stats within a time range.
func (ps *PluginStats) ListByTimeRange(ctx context.Context, start, end time.Time) ([]*model.PluginStats, error) {
	query := `
		SELECT id, plugin_name, plugin_version, metric_name, metric_type,
			   value, unit, tags, target_id, scan_id, timestamp, created_at
		FROM plugin_stats
		WHERE timestamp BETWEEN ? AND ?
		ORDER BY timestamp DESC`

	rows, err := ps.db.QueryContext(ctx, query, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ps.scanPluginStats(rows)
}

// GetAggregatedStats returns aggregated statistics for a plugin metric.
func (ps *PluginStats) GetAggregatedStats(ctx context.Context, pluginName, metricName string, start, end time.Time) (map[string]float64, error) {
	query := `
		SELECT
			COUNT(*) as count,
			AVG(value) as avg,
			MIN(value) as min,
			MAX(value) as max,
			SUM(value) as sum
		FROM plugin_stats
		WHERE plugin_name = ? AND metric_name = ? AND timestamp BETWEEN ? AND ?`

	var count, avg, min, max, sum float64
	err := ps.db.QueryRowContext(ctx, query, pluginName, metricName, start, end).Scan(
		&count, &avg, &min, &max, &sum,
	)
	if err != nil {
		return nil, err
	}

	return map[string]float64{
		"count": count,
		"avg":   avg,
		"min":   min,
		"max":   max,
		"sum":   sum,
	}, nil
}

// GetTimeSeriesData returns time-series data for a plugin metric.
func (ps *PluginStats) GetTimeSeriesData(ctx context.Context, pluginName, metricName string, start, end time.Time, interval string) ([]*model.PluginStats, error) {
	// SQLite doesn't have native time windowing, so we'll return raw data
	// and let the caller handle aggregation
	query := `
		SELECT id, plugin_name, plugin_version, metric_name, metric_type,
			   value, unit, tags, target_id, scan_id, timestamp, created_at
		FROM plugin_stats
		WHERE plugin_name = ? AND metric_name = ? AND timestamp BETWEEN ? AND ?
		ORDER BY timestamp ASC`

	rows, err := ps.db.QueryContext(ctx, query, pluginName, metricName, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ps.scanPluginStats(rows)
}

// GetTopPluginsByMetric returns plugins ranked by a specific metric.
func (ps *PluginStats) GetTopPluginsByMetric(ctx context.Context, metricName string, metricType model.PluginMetricType, limit int) (map[string]float64, error) {
	var query string

	switch metricType {
	case model.PluginMetricTypeCounter:
		query = `
			SELECT plugin_name, SUM(value) as total
			FROM plugin_stats
			WHERE metric_name = ? AND metric_type = ?
			GROUP BY plugin_name
			ORDER BY total DESC
			LIMIT ?`
	case model.PluginMetricTypeGauge:
		query = `
			SELECT plugin_name, AVG(value) as avg
			FROM plugin_stats
			WHERE metric_name = ? AND metric_type = ?
			GROUP BY plugin_name
			ORDER BY avg DESC
			LIMIT ?`
	case model.PluginMetricTypeTimer:
		query = `
			SELECT plugin_name, AVG(value) as avg
			FROM plugin_stats
			WHERE metric_name = ? AND metric_type = ?
			GROUP BY plugin_name
			ORDER BY avg ASC
			LIMIT ?`
	default:
		query = `
			SELECT plugin_name, AVG(value) as avg
			FROM plugin_stats
			WHERE metric_name = ? AND metric_type = ?
			GROUP BY plugin_name
			ORDER BY avg DESC
			LIMIT ?`
	}

	rows, err := ps.db.QueryContext(ctx, query, metricName, metricType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]float64)
	for rows.Next() {
		var pluginName string
		var value float64
		if err := rows.Scan(&pluginName, &value); err != nil {
			return nil, err
		}
		result[pluginName] = value
	}

	return result, rows.Err()
}

// GetByScanID returns stats for a specific scan.
func (ps *PluginStats) GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.PluginStats, error) {
	query := `
		SELECT id, plugin_name, plugin_version, metric_name, metric_type,
			   value, unit, tags, target_id, scan_id, timestamp, created_at
		FROM plugin_stats
		WHERE scan_id = ?
		ORDER BY timestamp DESC`

	rows, err := ps.db.QueryContext(ctx, query, scanID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ps.scanPluginStats(rows)
}

// GetByTargetID returns stats for a specific target.
func (ps *PluginStats) GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.PluginStats, error) {
	query := `
		SELECT id, plugin_name, plugin_version, metric_name, metric_type,
			   value, unit, tags, target_id, scan_id, timestamp, created_at
		FROM plugin_stats
		WHERE target_id = ?
		ORDER BY timestamp DESC`

	rows, err := ps.db.QueryContext(ctx, query, targetID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ps.scanPluginStats(rows)
}

// DeleteOldStats removes stats older than the specified time.
func (ps *PluginStats) DeleteOldStats(ctx context.Context, before time.Time) (int64, error) {
	query := `DELETE FROM plugin_stats WHERE timestamp < ?`
	result, err := ps.db.ExecContext(ctx, query, before)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// RecordMetric is a convenience method to record a metric.
func (ps *PluginStats) RecordMetric(ctx context.Context, pluginName, pluginVersion, metricName string, metricType model.PluginMetricType, value float64, unit string, tags map[string]interface{}, targetID, scanID *uuid.UUID) error {
	stats := &model.PluginStats{
		PluginName:    pluginName,
		PluginVersion: pluginVersion,
		MetricName:    metricName,
		MetricType:    metricType,
		Value:         value,
		Unit:          unit,
		Tags:          tags,
		TargetID:      targetID,
		ScanID:        scanID,
		Timestamp:     time.Now(),
	}

	return ps.Create(ctx, stats)
}

// scanPluginStats is a helper method to scan multiple plugin stats rows.
func (ps *PluginStats) scanPluginStats(rows *sql.Rows) ([]*model.PluginStats, error) {
	var stats []*model.PluginStats

	for rows.Next() {
		stat := &model.PluginStats{}
		var (
			tags     []byte
			unit     sql.NullString
			targetID sql.NullString
			scanID   sql.NullString
		)

		err := rows.Scan(
			&stat.ID, &stat.PluginName, &stat.PluginVersion, &stat.MetricName,
			&stat.MetricType, &stat.Value, &unit, &tags, &targetID, &scanID,
			&stat.Timestamp, &stat.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Handle nullable fields
		if unit.Valid {
			stat.Unit = unit.String
		}
		if targetID.Valid {
			targetUUID, err := uuid.Parse(targetID.String)
			if err != nil {
				return nil, err
			}
			stat.TargetID = &targetUUID
		}
		if scanID.Valid {
			scanUUID, err := uuid.Parse(scanID.String)
			if err != nil {
				return nil, err
			}
			stat.ScanID = &scanUUID
		}

		// Parse JSON fields
		if len(tags) > 0 {
			json.Unmarshal(tags, &stat.Tags)
		}

		stats = append(stats, stat)
	}

	return stats, rows.Err()
}

// CreatePluginStatsTable creates the plugin_stats table
func CreatePluginStatsTable(db *sqlx.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS plugin_stats (
		id TEXT PRIMARY KEY,
		plugin_id TEXT NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		target_id TEXT,
		scan_id TEXT,
		metric_name TEXT NOT NULL,
		metric_value REAL NOT NULL,
		metric_unit TEXT,
		tags TEXT,
		timestamp DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (target_id) REFERENCES targets(id),
		FOREIGN KEY (scan_id) REFERENCES scans(id)
	);

	CREATE INDEX IF NOT EXISTS idx_plugin_stats_plugin_id ON plugin_stats(plugin_id);
	CREATE INDEX IF NOT EXISTS idx_plugin_stats_target_id ON plugin_stats(target_id);
	CREATE INDEX IF NOT EXISTS idx_plugin_stats_scan_id ON plugin_stats(scan_id);
	CREATE INDEX IF NOT EXISTS idx_plugin_stats_metric_name ON plugin_stats(metric_name);
	CREATE INDEX IF NOT EXISTS idx_plugin_stats_timestamp ON plugin_stats(timestamp);
	CREATE INDEX IF NOT EXISTS idx_plugin_stats_created_at ON plugin_stats(created_at);
	`

	_, err := db.Exec(schema)
	return err
}