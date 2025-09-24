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

// Finding represents a finding resource accessor.
type Finding struct {
	BaseAccessor
}

// Init initializes the finding accessor.
func (f *Finding) Init(factory Factory) {
	f.BaseAccessor.Init(factory, "findings")
}

// Get returns a finding by ID.
func (f *Finding) Get(ctx context.Context, id uuid.UUID) (*model.Finding, error) {
	finding := &model.Finding{}

	query := `
		SELECT id, scan_id, target_id, plugin_id, title, description, severity,
			   status, confidence, risk_score, category, cve, cwe, owasp,
			   location, evidence, remediation, notes, accepted_by, resolved_by,
			   resolved_at, accepted_at, metadata, created_at, updated_at
		FROM findings
		WHERE id = ?`

	var (
		pluginID   sql.NullString
		cve        sql.NullString
		cwe        sql.NullString
		owasp      sql.NullString
		location   sql.NullString
		evidence   []byte
		remediation []byte
		notes      sql.NullString
		acceptedBy sql.NullString
		resolvedBy sql.NullString
		resolvedAt sql.NullTime
		acceptedAt sql.NullTime
		metadata   []byte
	)

	err := f.db.QueryRowContext(ctx, query, id.String()).Scan(
		&finding.ID, &finding.ScanID, &finding.TargetID, &pluginID,
		&finding.Title, &finding.Description, &finding.Severity, &finding.Status,
		&finding.Confidence, &finding.RiskScore, &finding.Category,
		&cve, &cwe, &owasp, &location, &evidence, &remediation, &notes,
		&acceptedBy, &resolvedBy, &resolvedAt, &acceptedAt, &metadata,
		&finding.CreatedAt, &finding.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Handle nullable fields
	if pluginID.Valid {
		pluginUUID, err := uuid.Parse(pluginID.String)
		if err == nil {
			finding.PluginID = &pluginUUID
		}
	}
	if cve.Valid {
		finding.CVE = cve.String
	}
	if cwe.Valid {
		finding.CWE = cwe.String
	}
	if owasp.Valid {
		finding.OWASP = owasp.String
	}
	if location.Valid {
		finding.Location = location.String
	}
	if notes.Valid {
		finding.Notes = notes.String
	}
	if acceptedBy.Valid {
		finding.AcceptedBy = acceptedBy.String
	}
	if resolvedBy.Valid {
		finding.ResolvedBy = resolvedBy.String
	}
	if resolvedAt.Valid {
		finding.ResolvedAt = &resolvedAt.Time
	}
	if acceptedAt.Valid {
		finding.AcceptedAt = &acceptedAt.Time
	}

	// Parse JSON fields
	if len(evidence) > 0 {
		if err := json.Unmarshal(evidence, &finding.Evidence); err != nil {
			return nil, err
		}
	}
	if len(remediation) > 0 {
		if err := json.Unmarshal(remediation, &finding.Remediation); err != nil {
			return nil, err
		}
	}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &finding.Metadata); err != nil {
			return nil, err
		}
	}

	return finding, nil
}

// List returns all findings.
func (f *Finding) List(ctx context.Context) ([]*model.Finding, error) {
	query := `
		SELECT id, scan_id, target_id, plugin_id, title, description, severity,
			   status, confidence, risk_score, category, cve, cwe, owasp,
			   location, evidence, remediation, notes, accepted_by, resolved_by,
			   resolved_at, accepted_at, metadata, created_at, updated_at
		FROM findings
		ORDER BY created_at DESC`

	rows, err := f.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return f.scanFindings(rows)
}

// Create creates a new finding.
func (f *Finding) Create(ctx context.Context, finding *model.Finding) error {
	if finding.ID == uuid.Nil {
		finding.ID = uuid.New()
	}

	now := time.Now()
	finding.CreatedAt = now
	finding.UpdatedAt = now

	query := `
		INSERT INTO findings (
			id, scan_id, target_id, plugin_id, title, description, severity,
			status, confidence, risk_score, category, cve, cwe, owasp,
			location, evidence, remediation, notes, accepted_by, resolved_by,
			resolved_at, accepted_at, metadata, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var (
		evidence    []byte
		remediation []byte
		metadata    []byte
		err         error
	)

	// Marshal JSON fields
	evidence, err = json.Marshal(finding.Evidence)
	if err != nil {
		return err
	}
	remediation, err = json.Marshal(finding.Remediation)
	if err != nil {
		return err
	}
	if finding.Metadata != nil {
		metadata, err = json.Marshal(finding.Metadata)
		if err != nil {
			return err
		}
	}

	var pluginID interface{}
	if finding.PluginID != nil {
		pluginID = finding.PluginID.String()
	}

	var cve interface{} = finding.CVE
	if finding.CVE == "" {
		cve = nil
	}

	var cwe interface{} = finding.CWE
	if finding.CWE == "" {
		cwe = nil
	}

	var owasp interface{} = finding.OWASP
	if finding.OWASP == "" {
		owasp = nil
	}

	var location interface{} = finding.Location
	if finding.Location == "" {
		location = nil
	}

	var notes interface{} = finding.Notes
	if finding.Notes == "" {
		notes = nil
	}

	var acceptedBy interface{} = finding.AcceptedBy
	if finding.AcceptedBy == "" {
		acceptedBy = nil
	}

	var resolvedBy interface{} = finding.ResolvedBy
	if finding.ResolvedBy == "" {
		resolvedBy = nil
	}

	_, err = f.db.ExecContext(ctx, query,
		finding.ID.String(), finding.ScanID.String(), finding.TargetID.String(),
		pluginID, finding.Title, finding.Description, finding.Severity,
		finding.Status, finding.Confidence, finding.RiskScore, finding.Category,
		cve, cwe, owasp, location, evidence, remediation, notes,
		acceptedBy, resolvedBy, finding.ResolvedAt, finding.AcceptedAt,
		metadata, finding.CreatedAt, finding.UpdatedAt,
	)

	return err
}

// Update updates an existing finding.
func (f *Finding) Update(ctx context.Context, finding *model.Finding) error {
	finding.UpdatedAt = time.Now()

	query := `
		UPDATE findings SET
			scan_id = ?, target_id = ?, plugin_id = ?, title = ?, description = ?,
			severity = ?, status = ?, confidence = ?, risk_score = ?, category = ?,
			cve = ?, cwe = ?, owasp = ?, location = ?, evidence = ?, remediation = ?,
			notes = ?, accepted_by = ?, resolved_by = ?, resolved_at = ?,
			accepted_at = ?, metadata = ?, updated_at = ?
		WHERE id = ?`

	var (
		evidence    []byte
		remediation []byte
		metadata    []byte
		err         error
	)

	// Marshal JSON fields
	evidence, err = json.Marshal(finding.Evidence)
	if err != nil {
		return err
	}
	remediation, err = json.Marshal(finding.Remediation)
	if err != nil {
		return err
	}
	if finding.Metadata != nil {
		metadata, err = json.Marshal(finding.Metadata)
		if err != nil {
			return err
		}
	}

	var pluginID interface{}
	if finding.PluginID != nil {
		pluginID = finding.PluginID.String()
	}

	var cve interface{} = finding.CVE
	if finding.CVE == "" {
		cve = nil
	}

	var cwe interface{} = finding.CWE
	if finding.CWE == "" {
		cwe = nil
	}

	var owasp interface{} = finding.OWASP
	if finding.OWASP == "" {
		owasp = nil
	}

	var location interface{} = finding.Location
	if finding.Location == "" {
		location = nil
	}

	var notes interface{} = finding.Notes
	if finding.Notes == "" {
		notes = nil
	}

	var acceptedBy interface{} = finding.AcceptedBy
	if finding.AcceptedBy == "" {
		acceptedBy = nil
	}

	var resolvedBy interface{} = finding.ResolvedBy
	if finding.ResolvedBy == "" {
		resolvedBy = nil
	}

	_, err = f.db.ExecContext(ctx, query,
		finding.ScanID.String(), finding.TargetID.String(), pluginID,
		finding.Title, finding.Description, finding.Severity, finding.Status,
		finding.Confidence, finding.RiskScore, finding.Category,
		cve, cwe, owasp, location, evidence, remediation, notes,
		acceptedBy, resolvedBy, finding.ResolvedAt, finding.AcceptedAt,
		metadata, finding.UpdatedAt, finding.ID.String(),
	)

	return err
}

// Delete removes a finding.
func (f *Finding) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM findings WHERE id = ?`
	_, err := f.db.ExecContext(ctx, query, id.String())
	return err
}

// GetByScanID returns findings for a specific scan.
func (f *Finding) GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.Finding, error) {
	query := `
		SELECT id, scan_id, target_id, plugin_id, title, description, severity,
			   status, confidence, risk_score, category, cve, cwe, owasp,
			   location, evidence, remediation, notes, accepted_by, resolved_by,
			   resolved_at, accepted_at, metadata, created_at, updated_at
		FROM findings
		WHERE scan_id = ?
		ORDER BY severity DESC, created_at DESC`

	rows, err := f.db.QueryContext(ctx, query, scanID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return f.scanFindings(rows)
}

// GetByTargetID returns findings for a specific target.
func (f *Finding) GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Finding, error) {
	query := `
		SELECT id, scan_id, target_id, plugin_id, title, description, severity,
			   status, confidence, risk_score, category, cve, cwe, owasp,
			   location, evidence, remediation, notes, accepted_by, resolved_by,
			   resolved_at, accepted_at, metadata, created_at, updated_at
		FROM findings
		WHERE target_id = ?
		ORDER BY severity DESC, created_at DESC`

	rows, err := f.db.QueryContext(ctx, query, targetID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return f.scanFindings(rows)
}

// ListBySeverity returns findings filtered by severity.
func (f *Finding) ListBySeverity(ctx context.Context, severity model.Severity) ([]*model.Finding, error) {
	query := `
		SELECT id, scan_id, target_id, plugin_id, title, description, severity,
			   status, confidence, risk_score, category, cve, cwe, owasp,
			   location, evidence, remediation, notes, accepted_by, resolved_by,
			   resolved_at, accepted_at, metadata, created_at, updated_at
		FROM findings
		WHERE severity = ?
		ORDER BY created_at DESC`

	rows, err := f.db.QueryContext(ctx, query, severity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return f.scanFindings(rows)
}

// ListByStatus returns findings filtered by status.
func (f *Finding) ListByStatus(ctx context.Context, status model.FindingStatus) ([]*model.Finding, error) {
	query := `
		SELECT id, scan_id, target_id, plugin_id, title, description, severity,
			   status, confidence, risk_score, category, cve, cwe, owasp,
			   location, evidence, remediation, notes, accepted_by, resolved_by,
			   resolved_at, accepted_at, metadata, created_at, updated_at
		FROM findings
		WHERE status = ?
		ORDER BY severity DESC, created_at DESC`

	rows, err := f.db.QueryContext(ctx, query, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return f.scanFindings(rows)
}

// UpdateStatus updates finding status.
func (f *Finding) UpdateStatus(ctx context.Context, id uuid.UUID, status model.FindingStatus) error {
	now := time.Now()
	query := `UPDATE findings SET status = ?, updated_at = ? WHERE id = ?`

	// If resolving the finding, also set resolved_at
	if status == model.FindingStatusResolved {
		query = `UPDATE findings SET status = ?, resolved_at = ?, updated_at = ? WHERE id = ?`
		_, err := f.db.ExecContext(ctx, query, status, now, now, id.String())
		return err
	}

	// If accepting the finding, also set accepted_at
	if status == model.FindingStatusAccepted {
		query = `UPDATE findings SET status = ?, accepted_at = ?, updated_at = ? WHERE id = ?`
		_, err := f.db.ExecContext(ctx, query, status, now, now, id.String())
		return err
	}

	_, err := f.db.ExecContext(ctx, query, status, now, id.String())
	return err
}

// CountBySeverity returns finding counts grouped by severity.
func (f *Finding) CountBySeverity(ctx context.Context) (map[model.Severity]int, error) {
	query := `SELECT severity, COUNT(*) FROM findings GROUP BY severity`

	rows, err := f.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[model.Severity]int)
	for rows.Next() {
		var severity model.Severity
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		counts[severity] = count
	}

	return counts, rows.Err()
}

// GetHighSeverityFindings returns critical and high severity findings.
func (f *Finding) GetHighSeverityFindings(ctx context.Context) ([]*model.Finding, error) {
	query := `
		SELECT id, scan_id, target_id, plugin_id, title, description, severity,
			   status, confidence, risk_score, category, cve, cwe, owasp,
			   location, evidence, remediation, notes, accepted_by, resolved_by,
			   resolved_at, accepted_at, metadata, created_at, updated_at
		FROM findings
		WHERE severity IN (?, ?)
		ORDER BY severity DESC, created_at DESC`

	rows, err := f.db.QueryContext(ctx, query, model.SeverityCritical, model.SeverityHigh)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return f.scanFindings(rows)
}

// scanFindings is a helper method to scan multiple finding rows.
func (f *Finding) scanFindings(rows *sql.Rows) ([]*model.Finding, error) {
	var findings []*model.Finding

	for rows.Next() {
		finding := &model.Finding{}
		var (
			pluginID    sql.NullString
			cve         sql.NullString
			cwe         sql.NullString
			owasp       sql.NullString
			location    sql.NullString
			evidence    []byte
			remediation []byte
			notes       sql.NullString
			acceptedBy  sql.NullString
			resolvedBy  sql.NullString
			resolvedAt  sql.NullTime
			acceptedAt  sql.NullTime
			metadata    []byte
		)

		err := rows.Scan(
			&finding.ID, &finding.ScanID, &finding.TargetID, &pluginID,
			&finding.Title, &finding.Description, &finding.Severity, &finding.Status,
			&finding.Confidence, &finding.RiskScore, &finding.Category,
			&cve, &cwe, &owasp, &location, &evidence, &remediation, &notes,
			&acceptedBy, &resolvedBy, &resolvedAt, &acceptedAt, &metadata,
			&finding.CreatedAt, &finding.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Handle nullable fields
		if pluginID.Valid {
			pluginUUID, err := uuid.Parse(pluginID.String)
			if err == nil {
				finding.PluginID = &pluginUUID
			}
		}
		if cve.Valid {
			finding.CVE = cve.String
		}
		if cwe.Valid {
			finding.CWE = cwe.String
		}
		if owasp.Valid {
			finding.OWASP = owasp.String
		}
		if location.Valid {
			finding.Location = location.String
		}
		if notes.Valid {
			finding.Notes = notes.String
		}
		if acceptedBy.Valid {
			finding.AcceptedBy = acceptedBy.String
		}
		if resolvedBy.Valid {
			finding.ResolvedBy = resolvedBy.String
		}
		if resolvedAt.Valid {
			finding.ResolvedAt = &resolvedAt.Time
		}
		if acceptedAt.Valid {
			finding.AcceptedAt = &acceptedAt.Time
		}

		// Parse JSON fields
		if len(evidence) > 0 {
			json.Unmarshal(evidence, &finding.Evidence)
		}
		if len(remediation) > 0 {
			json.Unmarshal(remediation, &finding.Remediation)
		}
		if len(metadata) > 0 {
			json.Unmarshal(metadata, &finding.Metadata)
		}

		findings = append(findings, finding)
	}

	return findings, rows.Err()
}