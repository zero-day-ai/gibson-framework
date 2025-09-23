// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package model

import (
	"time"

	"github.com/google/uuid"
)

// TargetStatus represents the status of a target
type TargetStatus string

const (
	TargetStatusActive   TargetStatus = "active"
	TargetStatusInactive TargetStatus = "inactive"
	TargetStatusError    TargetStatus = "error"
)

// ScanStatus represents the status of a scan
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusStopped   ScanStatus = "stopped"
	ScanStatusCancelled ScanStatus = "cancelled"
)

// FindingStatus represents the status of a finding
type FindingStatus string

const (
	FindingStatusNew       FindingStatus = "new"
	FindingStatusReviewed  FindingStatus = "reviewed"
	FindingStatusResolved  FindingStatus = "resolved"
	FindingStatusSuppressed FindingStatus = "suppressed"
	FindingStatusAccepted  FindingStatus = "accepted"
)

// Severity represents finding severity levels
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// TargetType represents the type of target
type TargetType string

const (
	TargetTypeAPI      TargetType = "api"
	TargetTypeModel    TargetType = "model"
	TargetTypeEndpoint TargetType = "endpoint"
)

// Target represents an AI/ML target for security scanning
type Target struct {
	ID           uuid.UUID               `json:"id" db:"id"`
	Name         string                  `json:"name" db:"name" validate:"required,min=1,max=255"`
	Type         TargetType              `json:"type" db:"type"`
	Provider     Provider                `json:"provider" db:"provider" validate:"required"`
	Model        string                  `json:"model" db:"model"`
	URL          string                  `json:"url,omitempty" db:"url"`
	APIVersion   string                  `json:"api_version,omitempty" db:"api_version"`
	CredentialID *uuid.UUID              `json:"credential_id,omitempty" db:"credential_id"`
	Status       TargetStatus            `json:"status" db:"status"`
	Description  string                  `json:"description,omitempty" db:"description"`
	Tags         []string                `json:"tags,omitempty" db:"tags"`
	Headers      map[string]string       `json:"headers,omitempty" db:"headers"`
	Config       map[string]interface{}  `json:"config,omitempty" db:"config"`
	CreatedAt    time.Time               `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time               `json:"updated_at" db:"updated_at"`
}

// ScanType represents the type of scan
type ScanType string

const (
	ScanTypeBasic     ScanType = "basic"
	ScanTypeAdvanced  ScanType = "advanced"
	ScanTypeCustom    ScanType = "custom"
)

// Scan represents a security scan session
type Scan struct {
	ID           uuid.UUID               `json:"id" db:"id"`
	TargetID     uuid.UUID               `json:"target_id" db:"target_id"`
	Name         string                  `json:"name" db:"name" validate:"required,min=1,max=255"`
	Type         ScanType                `json:"type" db:"type"`
	Status       ScanStatus              `json:"status" db:"status"`
	Progress     float64                 `json:"progress" db:"progress"`
	Error        string                  `json:"error,omitempty" db:"error"`
	StartedBy    string                  `json:"started_by,omitempty" db:"started_by"`
	StartedAt    *time.Time              `json:"started_at,omitempty" db:"started_at"`
	CompletedAt  *time.Time              `json:"completed_at,omitempty" db:"completed_at"`
	ScheduledFor *time.Time              `json:"scheduled_for,omitempty" db:"scheduled_for"`
	Options      map[string]interface{}  `json:"options,omitempty" db:"options"`
	Statistics   map[string]interface{}  `json:"statistics,omitempty" db:"statistics"`
	CreatedAt    time.Time               `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time               `json:"updated_at" db:"updated_at"`
}

// Finding represents a security finding from a scan
type Finding struct {
	ID          uuid.UUID               `json:"id" db:"id"`
	ScanID      uuid.UUID               `json:"scan_id" db:"scan_id"`
	TargetID    uuid.UUID               `json:"target_id" db:"target_id"`
	PluginID    *uuid.UUID              `json:"plugin_id,omitempty" db:"plugin_id"`
	Title       string                  `json:"title" db:"title" validate:"required"`
	Description string                  `json:"description" db:"description"`
	Severity    Severity                `json:"severity" db:"severity" validate:"required"`
	Confidence  float64                 `json:"confidence" db:"confidence"`
	RiskScore   float64                 `json:"risk_score" db:"risk_score"`
	Category    string                  `json:"category" db:"category"`
	Status      FindingStatus           `json:"status" db:"status"`
	Evidence    string                  `json:"evidence,omitempty" db:"evidence"`
	Remediation string                  `json:"remediation,omitempty" db:"remediation"`
	CVE         string                  `json:"cve,omitempty" db:"cve"`
	CWE         string                  `json:"cwe,omitempty" db:"cwe"`
	OWASP       string                  `json:"owasp,omitempty" db:"owasp"`
	Location    string                  `json:"location,omitempty" db:"location"`
	Notes       string                  `json:"notes,omitempty" db:"notes"`
	AcceptedBy  string                  `json:"accepted_by,omitempty" db:"accepted_by"`
	ResolvedBy  string                  `json:"resolved_by,omitempty" db:"resolved_by"`
	AcceptedAt  *time.Time              `json:"accepted_at,omitempty" db:"accepted_at"`
	ResolvedAt  *time.Time              `json:"resolved_at,omitempty" db:"resolved_at"`
	Metadata    map[string]interface{}  `json:"metadata,omitempty" db:"metadata"`
	CreatedAt   time.Time               `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time               `json:"updated_at" db:"updated_at"`
}

// Provider represents the AI/ML provider type
type Provider string

const (
	ProviderOpenAI      Provider = "openai"
	ProviderAnthropic   Provider = "anthropic"
	ProviderHuggingFace Provider = "huggingface"
	ProviderCustom      Provider = "custom"
	ProviderAzure       Provider = "azure"
	ProviderGoogle      Provider = "google"
	ProviderCohere      Provider = "cohere"
	ProviderOllama      Provider = "ollama"
)

// CredentialType represents the type of credential
type CredentialType string

const (
	CredentialTypeAPIKey    CredentialType = "api_key"
	CredentialTypeOAuth     CredentialType = "oauth"
	CredentialTypeBearer    CredentialType = "bearer"
	CredentialTypeBasic     CredentialType = "basic"
	CredentialTypeCustom    CredentialType = "custom"
)

// CredentialStatus represents the status of a credential
type CredentialStatus string

const (
	CredentialStatusActive     CredentialStatus = "active"
	CredentialStatusInactive   CredentialStatus = "inactive"
	CredentialStatusExpired    CredentialStatus = "expired"
	CredentialStatusRevoked    CredentialStatus = "revoked"
	CredentialStatusRotating   CredentialStatus = "rotating"
)

// CredentialRotationInfo contains information about credential rotation
type CredentialRotationInfo struct {
	Enabled          bool      `json:"enabled"`
	LastRotated      *time.Time `json:"last_rotated,omitempty"`
	NextRotation     *time.Time `json:"next_rotation,omitempty"`
	RotationInterval string    `json:"rotation_interval,omitempty"` // e.g., "30d", "7d"
	AutoRotate       bool      `json:"auto_rotate"`
	RotationHistory  []CredentialRotationEvent `json:"rotation_history,omitempty"`
}

// CredentialRotationEvent represents a single rotation event
type CredentialRotationEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Reason    string    `json:"reason"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
}

// CredentialUsage tracks credential usage statistics
type CredentialUsage struct {
	TotalUses     int64     `json:"total_uses"`
	LastUsed      *time.Time `json:"last_used,omitempty"`
	UsageCount30d int64     `json:"usage_count_30d"`
	UsageCount7d  int64     `json:"usage_count_7d"`
	UsageCount24h int64     `json:"usage_count_24h"`
	FailureCount  int64     `json:"failure_count"`
	LastFailure   *time.Time `json:"last_failure,omitempty"`
}

// Credential represents a stored credential for AI/ML providers
type Credential struct {
	ID                 uuid.UUID              `json:"id" db:"id"`
	Name               string                 `json:"name" db:"name" validate:"required,min=1,max=255"`
	Type               CredentialType         `json:"type" db:"type" validate:"required"`
	Provider           Provider               `json:"provider" db:"provider" validate:"required"`
	Status             CredentialStatus       `json:"status" db:"status"`
	Description        string                 `json:"description,omitempty" db:"description"`

	// Encrypted credential data
	EncryptedValue     []byte                 `json:"-" db:"encrypted_value"` // Never expose in JSON
	EncryptionIV       []byte                 `json:"-" db:"encryption_iv"`   // Never expose in JSON
	KeyDerivationSalt  []byte                 `json:"-" db:"key_derivation_salt"` // Never expose in JSON

	// Metadata
	Tags               []string               `json:"tags,omitempty" db:"tags"`
	RotationInfo       CredentialRotationInfo `json:"rotation_info" db:"rotation_info"`
	Usage              CredentialUsage        `json:"usage" db:"usage"`

	// Timestamps
	CreatedAt          time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at" db:"updated_at"`
	LastUsed           *time.Time             `json:"last_used,omitempty" db:"last_used"`
}

// CredentialCreateRequest represents a request to create a new credential
type CredentialCreateRequest struct {
	Name         string         `json:"name" validate:"required,min=1,max=255"`
	Type         CredentialType `json:"type" validate:"required"`
	Provider     Provider       `json:"provider" validate:"required"`
	Description  string         `json:"description,omitempty"`
	Value        string         `json:"value" validate:"required"` // Plain text value to be encrypted
	Tags         []string       `json:"tags,omitempty"`
	AutoRotate   bool           `json:"auto_rotate,omitempty"`
	RotationInterval string     `json:"rotation_interval,omitempty"`
}

// CredentialUpdateRequest represents a request to update a credential
type CredentialUpdateRequest struct {
	Name         *string        `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Type         *CredentialType `json:"type,omitempty"`
	Provider     *Provider      `json:"provider,omitempty"`
	Description  *string        `json:"description,omitempty"`
	Value        *string        `json:"value,omitempty"` // Plain text value to be encrypted
	Tags         []string       `json:"tags,omitempty"`
	Status       *CredentialStatus `json:"status,omitempty"`
	AutoRotate   *bool          `json:"auto_rotate,omitempty"`
	RotationInterval *string    `json:"rotation_interval,omitempty"`
}

// CredentialExportData represents credential data for export (without sensitive fields)
type CredentialExportData struct {
	ID           uuid.UUID              `json:"id"`
	Name         string                 `json:"name"`
	Type         CredentialType         `json:"type"`
	Provider     Provider               `json:"provider"`
	Status       CredentialStatus       `json:"status"`
	Description  string                 `json:"description,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
	RotationInfo CredentialRotationInfo `json:"rotation_info"`
	Usage        CredentialUsage        `json:"usage"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	LastUsed     *time.Time             `json:"last_used,omitempty"`
}

// CredentialValidationResult represents the result of credential validation
type CredentialValidationResult struct {
	Valid       bool      `json:"valid"`
	Error       string    `json:"error,omitempty"`
	TestedAt    time.Time `json:"tested_at"`
	ResponseTime time.Duration `json:"response_time"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// ToExportData converts a credential to export data (removes sensitive fields)
func (c *Credential) ToExportData() *CredentialExportData {
	return &CredentialExportData{
		ID:           c.ID,
		Name:         c.Name,
		Type:         c.Type,
		Provider:     c.Provider,
		Status:       c.Status,
		Description:  c.Description,
		Tags:         c.Tags,
		RotationInfo: c.RotationInfo,
		Usage:        c.Usage,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
		LastUsed:     c.LastUsed,
	}
}

// IsActive returns true if the credential is active
func (c *Credential) IsActive() bool {
	return c.Status == CredentialStatusActive
}

// IsExpired returns true if the credential is expired or revoked
func (c *Credential) IsExpired() bool {
	return c.Status == CredentialStatusExpired || c.Status == CredentialStatusRevoked
}

// NeedsRotation returns true if the credential needs rotation
func (c *Credential) NeedsRotation() bool {
	if !c.RotationInfo.Enabled || !c.RotationInfo.AutoRotate {
		return false
	}

	if c.RotationInfo.NextRotation != nil {
		return time.Now().After(*c.RotationInfo.NextRotation)
	}

	return false
}

// HasTag returns true if the credential has the specified tag
func (c *Credential) HasTag(tag string) bool {
	for _, t := range c.Tags {
		if t == tag {
			return true
		}
	}
	return false
}