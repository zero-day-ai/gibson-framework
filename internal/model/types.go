// Package model provides model interfaces for Gibson
package model

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Component defines the base interface for all components (matches k9s exactly)
type Component interface {
	// Name returns the component name
	Name() string

	// Init initializes the component
	Init() error

	// Start starts the component
	Start() error

	// Stop stops the component
	Stop() error

	// IsActive returns true if component is active
	IsActive() bool
}

// MenuHints represents menu hints for UI components
type MenuHints map[string]string

// Tabular represents tabular data
type Tabular interface {
	// GetData returns the tabular data
	GetData() [][]string

	// GetHeaders returns column headers
	GetHeaders() []string

	// GetRowCount returns number of rows
	GetRowCount() int
}

// ReportType represents the type of report
type ReportType string

const (
	ReportTypeScanSummary    ReportType = "scan_summary"
	ReportTypeDetailedScan   ReportType = "detailed_scan"
	ReportTypeTargetSummary  ReportType = "target_summary"
	ReportTypeVulnerability  ReportType = "vulnerability"
	ReportTypeCompliance     ReportType = "compliance"
	ReportTypeCustom         ReportType = "custom"
)

// ReportStatus represents the status of a report
type ReportStatus string

const (
	ReportStatusPending    ReportStatus = "pending"
	ReportStatusGenerating ReportStatus = "generating"
	ReportStatusCompleted  ReportStatus = "completed"
	ReportStatusFailed     ReportStatus = "failed"
	ReportStatusCancelled  ReportStatus = "cancelled"
)

// ReportFormat represents the output format of a report
type ReportFormat string

const (
	ReportFormatJSON  ReportFormat = "json"
	ReportFormatHTML  ReportFormat = "html"
	ReportFormatPDF   ReportFormat = "pdf"
	ReportFormatCSV   ReportFormat = "csv"
	ReportFormatXML   ReportFormat = "xml"
)

// Report represents a generated security report
type Report struct {
	ID           uuid.UUID               `json:"id" db:"id"`
	Name         string                  `json:"name" db:"name" validate:"required,min=1,max=255"`
	Type         ReportType              `json:"type" db:"type" validate:"required"`
	Status       ReportStatus            `json:"status" db:"status"`
	Format       ReportFormat            `json:"format" db:"format" validate:"required"`
	TargetID     *uuid.UUID              `json:"target_id,omitempty" db:"target_id"`
	ScanID       *uuid.UUID              `json:"scan_id,omitempty" db:"scan_id"`
	TemplateID   *uuid.UUID              `json:"template_id,omitempty" db:"template_id"`
	OutputPath   string                  `json:"output_path,omitempty" db:"output_path"`
	GeneratedBy  string                  `json:"generated_by,omitempty" db:"generated_by"`
	GeneratedAt  *time.Time              `json:"generated_at,omitempty" db:"generated_at"`
	ScheduledFor *time.Time              `json:"scheduled_for,omitempty" db:"scheduled_for"`
	Config       map[string]interface{}  `json:"config,omitempty" db:"config"`
	Filters      map[string]interface{}  `json:"filters,omitempty" db:"filters"`
	Data         map[string]interface{}  `json:"data,omitempty" db:"data"`
	Error        string                  `json:"error,omitempty" db:"error"`
	FileSize     int64                   `json:"file_size" db:"file_size"`
	CreatedAt    time.Time               `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time               `json:"updated_at" db:"updated_at"`
}

// ReportSchedule represents a scheduled report generation
type ReportSchedule struct {
	ID                 uuid.UUID               `json:"id" db:"id"`
	Name               string                  `json:"name" db:"name" validate:"required,min=1,max=255"`
	Description        string                  `json:"description,omitempty" db:"description"`
	ReportType         ReportType              `json:"report_type" db:"report_type" validate:"required"`
	TargetID           *uuid.UUID              `json:"target_id,omitempty" db:"target_id"`
	ScanType           string                  `json:"scan_type,omitempty" db:"scan_type"`
	ScheduleExpression string                  `json:"schedule_expression" db:"schedule_expression" validate:"required"`
	Format             ReportFormat            `json:"format" db:"format" validate:"required"`
	TemplateID         *uuid.UUID              `json:"template_id,omitempty" db:"template_id"`
	Enabled            bool                    `json:"enabled" db:"enabled"`
	LastRun            *time.Time              `json:"last_run,omitempty" db:"last_run"`
	NextRun            *time.Time              `json:"next_run,omitempty" db:"next_run"`
	Config             map[string]interface{}  `json:"config,omitempty" db:"config"`
	Filters            map[string]interface{}  `json:"filters,omitempty" db:"filters"`
	OutputConfig       map[string]interface{}  `json:"output_config,omitempty" db:"output_config"`
	NotificationConfig map[string]interface{}  `json:"notification_config,omitempty" db:"notification_config"`
	CreatedBy          string                  `json:"created_by,omitempty" db:"created_by"`
	CreatedAt          time.Time               `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time               `json:"updated_at" db:"updated_at"`
}

// PayloadCategory represents the category of a payload
type PayloadCategory string

const (
	PayloadCategoryModel         PayloadCategory = "model"
	PayloadCategoryData          PayloadCategory = "data"
	PayloadCategoryInterface     PayloadCategory = "interface"
	PayloadCategoryInfrastructure PayloadCategory = "infrastructure"
	PayloadCategoryOutput        PayloadCategory = "output"
	PayloadCategoryProcess       PayloadCategory = "process"
)

// PayloadType represents the type of a payload
type PayloadType string

const (
	PayloadTypePrompt      PayloadType = "prompt"
	PayloadTypeQuery       PayloadType = "query"
	PayloadTypeInput       PayloadType = "input"
	PayloadTypeCode        PayloadType = "code"
	PayloadTypeData        PayloadType = "data"
	PayloadTypeScript      PayloadType = "script"
)

// Payload represents a security testing payload
type Payload struct {
	ID               uuid.UUID               `json:"id" db:"id"`
	Name             string                  `json:"name" db:"name" validate:"required,min=1,max=255"`
	Category         PayloadCategory         `json:"category" db:"category" validate:"required"`
	Domain           string                  `json:"domain" db:"domain" validate:"required"`
	Type             PayloadType             `json:"type" db:"type" validate:"required"`
	Version          int                     `json:"version" db:"version"`
	ParentID         *uuid.UUID              `json:"parent_id,omitempty" db:"parent_id"`
	Content          string                  `json:"content" db:"content" validate:"required"`
	Description      string                  `json:"description,omitempty" db:"description"`
	Severity         string                  `json:"severity" db:"severity"`
	Tags             []string                `json:"tags,omitempty" db:"tags"`
	Variables        map[string]interface{}  `json:"variables,omitempty" db:"variables"`
	Config           map[string]interface{}  `json:"config,omitempty" db:"config"`
	Language         string                  `json:"language,omitempty" db:"language"`
	Enabled          bool                    `json:"enabled" db:"enabled"`
	Validated        bool                    `json:"validated" db:"validated"`
	ValidationResult map[string]interface{}  `json:"validation_result,omitempty" db:"validation_result"`
	UsageCount       int64                   `json:"usage_count" db:"usage_count"`
	SuccessRate      float64                 `json:"success_rate" db:"success_rate"`
	LastUsed         *time.Time              `json:"last_used,omitempty" db:"last_used"`
	// Repository tracking fields (Requirement 3.4)
	RepositoryID     *uuid.UUID              `json:"repository_id,omitempty" db:"repository_id"`
	RepositoryPath   string                  `json:"repository_path,omitempty" db:"repository_path"`
	PluginName       string                  `json:"plugin_name,omitempty" db:"plugin_name"`
	// Checksum field for change detection (Requirement 5.7)
	Checksum         string                  `json:"checksum,omitempty" db:"checksum"`
	CreatedBy        string                  `json:"created_by,omitempty" db:"created_by"`
	CreatedAt        time.Time               `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time               `json:"updated_at" db:"updated_at"`
}

// PluginMetricType represents the type of plugin metric
type PluginMetricType string

const (
	PluginMetricTypeCounter   PluginMetricType = "counter"
	PluginMetricTypeGauge     PluginMetricType = "gauge"
	PluginMetricTypeHistogram PluginMetricType = "histogram"
	PluginMetricTypeTimer     PluginMetricType = "timer"
)

// PluginStats represents plugin performance and usage statistics
type PluginStats struct {
	ID            uuid.UUID               `json:"id" db:"id"`
	PluginName    string                  `json:"plugin_name" db:"plugin_name" validate:"required"`
	PluginVersion string                  `json:"plugin_version" db:"plugin_version" validate:"required"`
	MetricName    string                  `json:"metric_name" db:"metric_name" validate:"required"`
	MetricType    PluginMetricType        `json:"metric_type" db:"metric_type" validate:"required"`
	Value         float64                 `json:"value" db:"value"`
	Unit          string                  `json:"unit,omitempty" db:"unit"`
	Tags          map[string]interface{}  `json:"tags,omitempty" db:"tags"`
	TargetID      *uuid.UUID              `json:"target_id,omitempty" db:"target_id"`
	ScanID        *uuid.UUID              `json:"scan_id,omitempty" db:"scan_id"`
	Timestamp     time.Time               `json:"timestamp" db:"timestamp"`
	CreatedAt     time.Time               `json:"created_at" db:"created_at"`
}

// IsActive returns true if the report schedule is enabled and next run is set
func (rs *ReportSchedule) IsActive() bool {
	return rs.Enabled && rs.NextRun != nil
}

// IsDue returns true if the report schedule is due to run
func (rs *ReportSchedule) IsDue() bool {
	return rs.Enabled && rs.NextRun != nil && time.Now().After(*rs.NextRun)
}

// IsCompleted returns true if the report generation is completed
func (r *Report) IsCompleted() bool {
	return r.Status == ReportStatusCompleted
}

// IsFailed returns true if the report generation failed
func (r *Report) IsFailed() bool {
	return r.Status == ReportStatusFailed
}

// IsVersioned returns true if the payload has a parent (is a version)
func (p *Payload) IsVersioned() bool {
	return p.ParentID != nil
}

// IsActive returns true if the payload is enabled
func (p *Payload) IsActive() bool {
	return p.Enabled
}

// HasTag returns true if the payload has the specified tag
func (p *Payload) HasTag(tag string) bool {
	for _, t := range p.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// IsFromRepository returns true if the payload is sourced from a repository
func (p *Payload) IsFromRepository() bool {
	return p.RepositoryID != nil
}

// GetRepositoryInfo returns repository source information if available
func (p *Payload) GetRepositoryInfo() (repositoryID *uuid.UUID, repositoryPath string) {
	return p.RepositoryID, p.RepositoryPath
}

// JSON scanning and valuing for complex fields

// JSONStringSlice is a wrapper for []string that can be scanned from JSON
type JSONStringSlice []string

// Scan implements the Scanner interface for database/sql
func (j *JSONStringSlice) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	var data []byte
	switch v := value.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return nil
	}

	return json.Unmarshal(data, j)
}

// Value implements the Valuer interface for database/sql
func (j JSONStringSlice) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// JSONMap is a wrapper for map[string]interface{} that can be scanned from JSON
type JSONMap map[string]interface{}

// Scan implements the Scanner interface for database/sql
func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	var data []byte
	switch v := value.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return nil
	}

	return json.Unmarshal(data, j)
}

// Value implements the Valuer interface for database/sql
func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// ModelCapability represents the capability level of a model
type ModelCapability string

const (
	ModelCapabilityLegacy   ModelCapability = "legacy"
	ModelCapabilityStandard ModelCapability = "standard"
	ModelCapabilityAdvanced ModelCapability = "advanced"
)

// ModelInfo represents information about an AI/ML model
type ModelInfo struct {
	Provider    Provider        `json:"provider" validate:"required"`
	ModelID     string          `json:"model_id" validate:"required"`
	DisplayName string          `json:"display_name"`
	Family      string          `json:"family"`      // e.g., "claude", "gpt", "gemini"
	Version     string          `json:"version"`
	Capability  ModelCapability `json:"capability"`  // e.g., "standard", "advanced", "legacy"
	IsDefault   bool            `json:"is_default"`
	MaxTokens   int             `json:"max_tokens"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// IsAdvanced returns true if the model has advanced capabilities
func (m *ModelInfo) IsAdvanced() bool {
	return m.Capability == ModelCapabilityAdvanced
}

// IsLegacy returns true if the model is legacy
func (m *ModelInfo) IsLegacy() bool {
	return m.Capability == ModelCapabilityLegacy
}

// GetDisplayName returns the display name or model ID if no display name is set
func (m *ModelInfo) GetDisplayName() string {
	if m.DisplayName != "" {
		return m.DisplayName
	}
	return m.ModelID
}