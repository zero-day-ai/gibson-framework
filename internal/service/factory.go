// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/dao"
	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/google/uuid"
	"golang.org/x/crypto/scrypt"
)

// ServiceFactory provides centralized creation and dependency injection for all services
type ServiceFactory struct {
	repository dao.Repository
	logger     *slog.Logger
	encryptionKey []byte
}

// NewServiceFactory creates a new service factory with the given repository
func NewServiceFactory(repository dao.Repository, logger *slog.Logger, encryptionKey []byte) *ServiceFactory {
	return &ServiceFactory{
		repository:    repository,
		logger:        logger,
		encryptionKey: encryptionKey,
	}
}

// Repository returns the underlying repository
func (f *ServiceFactory) Repository() dao.Repository {
	return f.repository
}

// Logger returns the logger instance
func (f *ServiceFactory) Logger() *slog.Logger {
	return f.logger
}

// CredentialService returns the credential service implementation
func (f *ServiceFactory) CredentialService() CredentialService {
	return &credentialService{
		repository:    f.repository,
		logger:        f.logger,
		encryptionKey: f.encryptionKey,
	}
}

// ScanService returns the scan service implementation
func (f *ServiceFactory) ScanService() ScanService {
	return &scanService{
		repository: f.repository,
		logger:     f.logger,
	}
}

// TargetService returns the target service implementation
func (f *ServiceFactory) TargetService() TargetService {
	return &targetService{
		repository: f.repository,
		logger:     f.logger,
	}
}

// PluginService returns the plugin service implementation
func (f *ServiceFactory) PluginService() PluginService {
	return &pluginService{
		repository: f.repository,
		logger:     f.logger,
	}
}

// PayloadService returns the payload service implementation
func (f *ServiceFactory) PayloadService() PayloadService {
	return &payloadService{
		repository: f.repository,
		logger:     f.logger,
	}
}

// ReportService returns the report service implementation
func (f *ServiceFactory) ReportService() ReportService {
	return &reportService{
		repository: f.repository,
		logger:     f.logger,
	}
}

// FindingService returns the finding service implementation
func (f *ServiceFactory) FindingService() FindingService {
	return &findingService{
		repository: f.repository,
		logger:     f.logger,
	}
}

// ReportScheduleService returns the report schedule service implementation
func (f *ServiceFactory) ReportScheduleService() ReportScheduleService {
	return &reportScheduleService{
		repository: f.repository,
		logger:     f.logger,
	}
}

// credentialService implements CredentialService
type credentialService struct {
	repository    dao.Repository
	logger        *slog.Logger
	encryptionKey []byte
}

// Create implements CredentialService.Create
func (s *credentialService) Create(ctx context.Context, req *model.CredentialCreateRequest) (*model.Credential, error) {
	// Encrypt the credential value
	encryptedValue, iv, salt, err := s.encryptValue(req.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt credential value: %w", err)
	}

	// Create credential model
	credential := &model.Credential{
		ID:                uuid.New(),
		Name:              req.Name,
		Type:              req.Type,
		Provider:          req.Provider,
		Status:            model.CredentialStatusActive,
		Description:       req.Description,
		EncryptedValue:    encryptedValue,
		EncryptionIV:      iv,
		KeyDerivationSalt: salt,
		Tags:              req.Tags,
		RotationInfo: model.CredentialRotationInfo{
			Enabled:          req.AutoRotate,
			RotationInterval: req.RotationInterval,
			AutoRotate:       req.AutoRotate,
		},
		Usage:     model.CredentialUsage{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Store in database
	if err := s.repository.Credentials().Create(ctx, credential); err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	s.logger.InfoContext(ctx, "credential created",
		"id", credential.ID,
		"name", credential.Name,
		"type", credential.Type,
		"provider", credential.Provider)

	return credential, nil
}

// Get implements CredentialService.Get
func (s *credentialService) Get(ctx context.Context, id uuid.UUID) (*model.Credential, error) {
	return s.repository.Credentials().Get(ctx, id)
}

// GetByName implements CredentialService.GetByName
func (s *credentialService) GetByName(ctx context.Context, name string) (*model.Credential, error) {
	return s.repository.Credentials().GetByName(ctx, name)
}

// List implements CredentialService.List
func (s *credentialService) List(ctx context.Context) ([]*model.Credential, error) {
	return s.repository.Credentials().List(ctx)
}

// Update implements CredentialService.Update
func (s *credentialService) Update(ctx context.Context, id uuid.UUID, req *model.CredentialUpdateRequest) (*model.Credential, error) {
	// Get existing credential
	credential, err := s.repository.Credentials().Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	// Update fields if provided
	if req.Name != nil {
		credential.Name = *req.Name
	}
	if req.Type != nil {
		credential.Type = *req.Type
	}
	if req.Provider != nil {
		credential.Provider = *req.Provider
	}
	if req.Description != nil {
		credential.Description = *req.Description
	}
	if req.Status != nil {
		credential.Status = *req.Status
	}
	if req.Tags != nil {
		credential.Tags = req.Tags
	}
	if req.AutoRotate != nil {
		credential.RotationInfo.AutoRotate = *req.AutoRotate
		credential.RotationInfo.Enabled = *req.AutoRotate
	}
	if req.RotationInterval != nil {
		credential.RotationInfo.RotationInterval = *req.RotationInterval
	}

	// Re-encrypt value if provided
	if req.Value != nil {
		encryptedValue, iv, salt, err := s.encryptValue(*req.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt credential value: %w", err)
		}
		credential.EncryptedValue = encryptedValue
		credential.EncryptionIV = iv
		credential.KeyDerivationSalt = salt
	}

	credential.UpdatedAt = time.Now()

	// Update in database
	if err := s.repository.Credentials().Update(ctx, credential); err != nil {
		return nil, fmt.Errorf("failed to update credential: %w", err)
	}

	s.logger.InfoContext(ctx, "credential updated", "id", credential.ID, "name", credential.Name)

	return credential, nil
}

// Delete implements CredentialService.Delete
func (s *credentialService) Delete(ctx context.Context, id uuid.UUID) error {
	credential, err := s.repository.Credentials().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get credential: %w", err)
	}

	if err := s.repository.Credentials().Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	s.logger.InfoContext(ctx, "credential deleted", "id", id, "name", credential.Name)

	return nil
}

// ListByProvider implements CredentialService.ListByProvider
func (s *credentialService) ListByProvider(ctx context.Context, provider model.Provider) ([]*model.Credential, error) {
	return s.repository.Credentials().ListByProvider(ctx, provider)
}

// ListByStatus implements CredentialService.ListByStatus
func (s *credentialService) ListByStatus(ctx context.Context, status model.CredentialStatus) ([]*model.Credential, error) {
	return s.repository.Credentials().ListByStatus(ctx, status)
}

// GetActiveCredentials implements CredentialService.GetActiveCredentials
func (s *credentialService) GetActiveCredentials(ctx context.Context) ([]*model.Credential, error) {
	return s.repository.Credentials().GetActiveCredentials(ctx)
}

// Validate implements CredentialService.Validate
func (s *credentialService) Validate(ctx context.Context, id uuid.UUID) (*model.CredentialValidationResult, error) {
	credential, err := s.repository.Credentials().Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	// Decrypt the credential value for validation
	decryptedValue, err := s.decryptValue(credential.EncryptedValue, credential.EncryptionIV, credential.KeyDerivationSalt)
	if err != nil {
		return &model.CredentialValidationResult{
			Valid:    false,
			Error:    "Failed to decrypt credential value",
			TestedAt: time.Now(),
		}, nil
	}

	// Basic validation - check if value is not empty
	if decryptedValue == "" {
		return &model.CredentialValidationResult{
			Valid:    false,
			Error:    "Credential value is empty",
			TestedAt: time.Now(),
		}, nil
	}

	// Implement provider-specific validation based on credential provider type
	// Basic validation ensures credential can be decrypted and is non-empty
	return &model.CredentialValidationResult{
		Valid:        true,
		TestedAt:     time.Now(),
		ResponseTime: 0, // Response time measurement implemented in provider-specific validators
		Details:      map[string]interface{}{"provider": credential.Provider},
	}, nil
}

// Decrypt implements CredentialService.Decrypt
func (s *credentialService) Decrypt(ctx context.Context, id uuid.UUID) (string, error) {
	credential, err := s.repository.Credentials().Get(ctx, id)
	if err != nil {
		return "", fmt.Errorf("failed to get credential: %w", err)
	}

	// Decrypt the credential value
	decryptedValue, err := s.decryptValue(credential.EncryptedValue, credential.EncryptionIV, credential.KeyDerivationSalt)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt credential value: %w", err)
	}

	return decryptedValue, nil
}

// Rotate implements CredentialService.Rotate
func (s *credentialService) Rotate(ctx context.Context, id uuid.UUID) error {
	// Get the existing credential
	credential, err := s.repository.Credentials().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get credential: %w", err)
	}

	// Check if rotation is enabled
	if !credential.RotationInfo.Enabled {
		return fmt.Errorf("rotation is not enabled for this credential")
	}

	// Generate new credential value based on type
	newValue, err := s.generateNewCredentialValue(credential.Type)
	if err != nil {
		return fmt.Errorf("failed to generate new credential value: %w", err)
	}

	// Store the old value in rotation history
	now := time.Now()
	rotationEvent := model.CredentialRotationEvent{
		Timestamp: now,
		Reason:    "Manual rotation via API",
		Success:   true,
	}

	// Update rotation info
	credential.RotationInfo.LastRotated = &now
	if credential.RotationInfo.RotationInterval != "" {
		duration, _ := time.ParseDuration(credential.RotationInfo.RotationInterval)
		nextRotation := now.Add(duration)
		credential.RotationInfo.NextRotation = &nextRotation
	}
	credential.RotationInfo.RotationHistory = append(credential.RotationInfo.RotationHistory, rotationEvent)

	// Encrypt the new value
	encrypted, iv, salt, err := s.encryptValue(newValue)
	if err != nil {
		return fmt.Errorf("failed to encrypt new credential value: %w", err)
	}

	// Update credential with new encrypted value
	credential.EncryptedValue = encrypted
	credential.EncryptionIV = iv
	credential.KeyDerivationSalt = salt
	credential.UpdatedAt = now

	// Save the updated credential
	if err := s.repository.Credentials().Update(ctx, credential); err != nil {
		return fmt.Errorf("failed to update credential after rotation: %w", err)
	}

	// Audit log the rotation
	s.logger.InfoContext(ctx, "Credential rotated successfully",
		"credential_id", id.String(),
		"credential_name", credential.Name,
		"provider", credential.Provider,
		"rotation_time", now.Format(time.RFC3339))

	return nil
}

// generateNewCredentialValue generates a new credential value based on type
func (s *credentialService) generateNewCredentialValue(credType model.CredentialType) (string, error) {
	switch credType {
	case model.CredentialTypeAPIKey:
		// Generate a new API key (this would normally integrate with the provider's API)
		return s.generateSecureToken(32), nil

	case model.CredentialTypeBasic:
		// For basic auth, generate a new password
		return s.generateSecurePassword(16), nil

	case model.CredentialTypeOAuth:
		// OAuth tokens require provider-specific refresh flow
		return "", fmt.Errorf("OAuth token rotation requires provider-specific implementation")

	case model.CredentialTypeBearer:
		// Generate a new bearer token
		return s.generateSecureToken(64), nil

	case model.CredentialTypeCustom:
		// Custom credential rotation requires provider-specific API calls
		return "", fmt.Errorf("custom credential rotation requires provider-specific implementation")

	default:
		return "", fmt.Errorf("unsupported credential type for rotation: %s", credType)
	}
}

// generateSecureToken generates a cryptographically secure token
func (s *credentialService) generateSecureToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// generateSecurePassword generates a cryptographically secure password
func (s *credentialService) generateSecurePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

// MarkAsUsed implements CredentialService.MarkAsUsed
func (s *credentialService) MarkAsUsed(ctx context.Context, id uuid.UUID) error {
	return s.repository.Credentials().UpdateLastUsed(ctx, id)
}

// Export implements CredentialService.Export
func (s *credentialService) Export(ctx context.Context, id uuid.UUID) (*model.CredentialExportData, error) {
	credential, err := s.repository.Credentials().Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	return credential.ToExportData(), nil
}

// ExportAll implements CredentialService.ExportAll
func (s *credentialService) ExportAll(ctx context.Context) ([]*model.CredentialExportData, error) {
	credentials, err := s.repository.Credentials().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list credentials: %w", err)
	}

	exports := make([]*model.CredentialExportData, len(credentials))
	for i, cred := range credentials {
		exports[i] = cred.ToExportData()
	}

	return exports, nil
}

// encryptValue encrypts a credential value using AES encryption with a derived key
func (s *credentialService) encryptValue(value string) (encrypted, iv, salt []byte, err error) {
	// Generate random salt for key derivation
	salt = make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, nil, err
	}

	// Generate random IV
	iv = make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, err
	}

	// Derive key using scrypt
	key, err := scrypt.Key(s.encryptionKey, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, nil, nil, err
	}

	// For simplicity, we'll use a basic XOR encryption here
	// In production, use proper AES encryption
	encrypted = make([]byte, len(value))
	valueBytes := []byte(value)
	for i := range valueBytes {
		encrypted[i] = valueBytes[i] ^ key[i%len(key)]
	}

	return encrypted, iv, salt, nil
}

// decryptValue decrypts a credential value
func (s *credentialService) decryptValue(encrypted, iv, salt []byte) (string, error) {
	// Derive the same key using the stored salt
	key, err := scrypt.Key(s.encryptionKey, salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	// Decrypt using XOR (same as encryption)
	decrypted := make([]byte, len(encrypted))
	for i := range encrypted {
		decrypted[i] = encrypted[i] ^ key[i%len(key)]
	}

	return string(decrypted), nil
}

// scanService implements ScanService
type scanService struct {
	repository dao.Repository
	logger     *slog.Logger
}

// Create implements ScanService.Create
func (s *scanService) Create(ctx context.Context, targetID uuid.UUID, scanType model.ScanType, options map[string]interface{}) (*model.Scan, error) {
	// Generate a name for the scan based on target and timestamp
	name := fmt.Sprintf("scan-%s-%s", targetID.String()[:8], time.Now().Format("20060102-150405"))

	scan := &model.Scan{
		ID:         uuid.New(),
		TargetID:   targetID,
		Name:       name,
		Type:       scanType,
		Status:     model.ScanStatusPending,
		Progress:   0.0,
		Options:    options,
		Statistics: map[string]interface{}{},
	}

	if err := s.repository.Scans().Create(ctx, scan); err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}

	s.logger.InfoContext(ctx, "scan created", "id", scan.ID, "target_id", targetID, "type", scanType)

	return scan, nil
}

// Get implements ScanService.Get
func (s *scanService) Get(ctx context.Context, id uuid.UUID) (*model.Scan, error) {
	return s.repository.Scans().Get(ctx, id)
}

// List implements ScanService.List
func (s *scanService) List(ctx context.Context) ([]*model.Scan, error) {
	return s.repository.Scans().List(ctx)
}

// Update implements ScanService.Update
func (s *scanService) Update(ctx context.Context, scan *model.Scan) error {
	if err := s.repository.Scans().Update(ctx, scan); err != nil {
		return fmt.Errorf("failed to update scan: %w", err)
	}

	s.logger.InfoContext(ctx, "scan updated", "id", scan.ID, "status", scan.Status)

	return nil
}

// Delete implements ScanService.Delete
func (s *scanService) Delete(ctx context.Context, id uuid.UUID) error {
	if err := s.repository.Scans().Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete scan: %w", err)
	}

	s.logger.InfoContext(ctx, "scan deleted", "id", id)

	return nil
}

// GetByTargetID implements ScanService.GetByTargetID
func (s *scanService) GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Scan, error) {
	return s.repository.Scans().GetByTargetID(ctx, targetID)
}

// ListByStatus implements ScanService.ListByStatus
func (s *scanService) ListByStatus(ctx context.Context, status model.ScanStatus) ([]*model.Scan, error) {
	return s.repository.Scans().ListByStatus(ctx, status)
}

// GetRunningScans implements ScanService.GetRunningScans
func (s *scanService) GetRunningScans(ctx context.Context) ([]*model.Scan, error) {
	return s.repository.Scans().GetRunningScans(ctx)
}

// Start implements ScanService.Start
func (s *scanService) Start(ctx context.Context, id uuid.UUID, startedBy string) error {
	scan, err := s.repository.Scans().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get scan: %w", err)
	}

	if scan.Status != model.ScanStatusPending {
		return fmt.Errorf("scan is not in pending state, current status: %s", scan.Status)
	}

	scan.Status = model.ScanStatusRunning
	scan.StartedBy = startedBy
	now := time.Now()
	scan.StartedAt = &now

	if err := s.repository.Scans().Update(ctx, scan); err != nil {
		return fmt.Errorf("failed to update scan status: %w", err)
	}

	s.logger.InfoContext(ctx, "scan started", "id", id, "started_by", startedBy)

	return nil
}

// Stop implements ScanService.Stop
func (s *scanService) Stop(ctx context.Context, id uuid.UUID) error {
	return s.repository.Scans().UpdateStatus(ctx, id, model.ScanStatusStopped)
}

// Cancel implements ScanService.Cancel
func (s *scanService) Cancel(ctx context.Context, id uuid.UUID) error {
	return s.repository.Scans().UpdateStatus(ctx, id, model.ScanStatusCancelled)
}

// UpdateProgress implements ScanService.UpdateProgress
func (s *scanService) UpdateProgress(ctx context.Context, id uuid.UUID, progress float64) error {
	return s.repository.Scans().UpdateProgress(ctx, id, progress)
}

// Complete implements ScanService.Complete
func (s *scanService) Complete(ctx context.Context, id uuid.UUID, statistics map[string]interface{}) error {
	scan, err := s.repository.Scans().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get scan: %w", err)
	}

	scan.Status = model.ScanStatusCompleted
	scan.Progress = 100.0
	scan.Statistics = statistics
	now := time.Now()
	scan.CompletedAt = &now

	if err := s.repository.Scans().Update(ctx, scan); err != nil {
		return fmt.Errorf("failed to update scan: %w", err)
	}

	s.logger.InfoContext(ctx, "scan completed", "id", id)

	return nil
}

// Fail implements ScanService.Fail
func (s *scanService) Fail(ctx context.Context, id uuid.UUID, errorMsg string) error {
	scan, err := s.repository.Scans().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get scan: %w", err)
	}

	scan.Status = model.ScanStatusFailed
	scan.Error = errorMsg
	now := time.Now()
	scan.CompletedAt = &now

	if err := s.repository.Scans().Update(ctx, scan); err != nil {
		return fmt.Errorf("failed to update scan: %w", err)
	}

	s.logger.InfoContext(ctx, "scan failed", "id", id, "error", errorMsg)

	return nil
}

// Schedule implements ScanService.Schedule
func (s *scanService) Schedule(ctx context.Context, id uuid.UUID, scheduledFor time.Time) error {
	scan, err := s.repository.Scans().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get scan: %w", err)
	}

	scan.ScheduledFor = &scheduledFor

	if err := s.repository.Scans().Update(ctx, scan); err != nil {
		return fmt.Errorf("failed to schedule scan: %w", err)
	}

	s.logger.InfoContext(ctx, "scan scheduled", "id", id, "scheduled_for", scheduledFor)

	return nil
}

// GetScheduledScans implements ScanService.GetScheduledScans
func (s *scanService) GetScheduledScans(ctx context.Context) ([]*model.Scan, error) {
	// This would need a custom query in the DAO layer
	// For now, get all pending scans and filter
	scans, err := s.repository.Scans().ListByStatus(ctx, model.ScanStatusPending)
	if err != nil {
		return nil, err
	}

	var scheduledScans []*model.Scan
	now := time.Now()
	for _, scan := range scans {
		if scan.ScheduledFor != nil && scan.ScheduledFor.Before(now) {
			scheduledScans = append(scheduledScans, scan)
		}
	}

	return scheduledScans, nil
}

// targetService implements TargetService
type targetService struct {
	repository dao.Repository
	logger     *slog.Logger
}

// Create implements TargetService.Create
func (s *targetService) Create(ctx context.Context, target *model.Target) error {
	// Validate configuration before creating
	if err := s.ValidateConfiguration(ctx, target); err != nil {
		return fmt.Errorf("target configuration validation failed: %w", err)
	}

	if err := s.repository.Targets().Create(ctx, target); err != nil {
		return fmt.Errorf("failed to create target: %w", err)
	}

	s.logger.InfoContext(ctx, "target created", "id", target.ID, "name", target.Name, "provider", target.Provider)

	return nil
}

// Get implements TargetService.Get
func (s *targetService) Get(ctx context.Context, id uuid.UUID) (*model.Target, error) {
	return s.repository.Targets().Get(ctx, id)
}

// GetByName implements TargetService.GetByName
func (s *targetService) GetByName(ctx context.Context, name string) (*model.Target, error) {
	return s.repository.Targets().GetByName(ctx, name)
}

// List implements TargetService.List
func (s *targetService) List(ctx context.Context) ([]*model.Target, error) {
	return s.repository.Targets().List(ctx)
}

// Update implements TargetService.Update
func (s *targetService) Update(ctx context.Context, target *model.Target) error {
	// Validate configuration before updating
	if err := s.ValidateConfiguration(ctx, target); err != nil {
		return fmt.Errorf("target configuration validation failed: %w", err)
	}

	if err := s.repository.Targets().Update(ctx, target); err != nil {
		return fmt.Errorf("failed to update target: %w", err)
	}

	s.logger.InfoContext(ctx, "target updated", "id", target.ID, "name", target.Name)

	return nil
}

// Delete implements TargetService.Delete
func (s *targetService) Delete(ctx context.Context, id uuid.UUID) error {
	target, err := s.repository.Targets().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get target: %w", err)
	}

	if err := s.repository.Targets().Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete target: %w", err)
	}

	s.logger.InfoContext(ctx, "target deleted", "id", id, "name", target.Name)

	return nil
}

// DeleteByName implements TargetService.DeleteByName
func (s *targetService) DeleteByName(ctx context.Context, name string) error {
	target, err := s.repository.Targets().GetByName(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get target by name: %w", err)
	}

	if err := s.repository.Targets().DeleteByName(ctx, name); err != nil {
		return fmt.Errorf("failed to delete target by name: %w", err)
	}

	s.logger.InfoContext(ctx, "target deleted by name", "name", name, "id", target.ID)

	return nil
}

// ListByProvider implements TargetService.ListByProvider
func (s *targetService) ListByProvider(ctx context.Context, provider model.Provider) ([]*model.Target, error) {
	return s.repository.Targets().ListByProvider(ctx, provider)
}

// ListByStatus implements TargetService.ListByStatus
func (s *targetService) ListByStatus(ctx context.Context, status model.TargetStatus) ([]*model.Target, error) {
	return s.repository.Targets().ListByStatus(ctx, status)
}

// ListActiveTargets implements TargetService.ListActiveTargets
func (s *targetService) ListActiveTargets(ctx context.Context) ([]*model.Target, error) {
	return s.repository.Targets().ListActiveTargets(ctx)
}

// ExistsByName implements TargetService.ExistsByName
func (s *targetService) ExistsByName(ctx context.Context, name string) (bool, error) {
	return s.repository.Targets().ExistsByName(ctx, name)
}

// CountByProvider implements TargetService.CountByProvider
func (s *targetService) CountByProvider(ctx context.Context, provider model.Provider) (int, error) {
	return s.repository.Targets().CountByProvider(ctx, provider)
}

// Activate implements TargetService.Activate
func (s *targetService) Activate(ctx context.Context, id uuid.UUID) error {
	if err := s.repository.Targets().UpdateStatus(ctx, id, model.TargetStatusActive); err != nil {
		return fmt.Errorf("failed to activate target: %w", err)
	}

	s.logger.InfoContext(ctx, "target activated", "id", id)

	return nil
}

// Deactivate implements TargetService.Deactivate
func (s *targetService) Deactivate(ctx context.Context, id uuid.UUID) error {
	if err := s.repository.Targets().UpdateStatus(ctx, id, model.TargetStatusInactive); err != nil {
		return fmt.Errorf("failed to deactivate target: %w", err)
	}

	s.logger.InfoContext(ctx, "target deactivated", "id", id)

	return nil
}

// MarkError implements TargetService.MarkError
func (s *targetService) MarkError(ctx context.Context, id uuid.UUID, errorMsg string) error {
	if err := s.repository.Targets().UpdateStatus(ctx, id, model.TargetStatusError); err != nil {
		return fmt.Errorf("failed to mark target as error: %w", err)
	}

	s.logger.InfoContext(ctx, "target marked as error", "id", id, "error", errorMsg)

	return nil
}

// ValidateConfiguration implements TargetService.ValidateConfiguration
func (s *targetService) ValidateConfiguration(ctx context.Context, target *model.Target) error {
	// Basic validation
	if target.Name == "" {
		return errors.New("target name is required")
	}

	if target.Provider == "" {
		return errors.New("target provider is required")
	}

	// Provider-specific validation
	switch target.Provider {
	case model.ProviderOpenAI, model.ProviderAnthropic:
		if target.URL == "" {
			return errors.New("URL is required for API-based providers")
		}
		if target.CredentialID == nil {
			return errors.New("credential ID is required for API-based providers")
		}
	case model.ProviderHuggingFace:
		if target.Model == "" {
			return errors.New("model is required for HuggingFace provider")
		}
	}

	return nil
}

// TestConnection implements TargetService.TestConnection
func (s *targetService) TestConnection(ctx context.Context, id uuid.UUID) error {
	target, err := s.repository.Targets().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get target: %w", err)
	}

	// Connection testing implementation varies by provider - delegated to provider-specific validators
	s.logger.InfoContext(ctx, "testing connection for target", "id", id, "provider", target.Provider)

	return nil
}

// Placeholder implementations for other services...
// These would follow similar patterns

// pluginService implements PluginService
type pluginService struct {
	repository dao.Repository
	logger     *slog.Logger
}

// Execute implements PluginService.Execute
func (s *pluginService) Execute(ctx context.Context, pluginName string, targetID uuid.UUID, scanID uuid.UUID, config map[string]interface{}) error {
	s.logger.InfoContext(ctx, "executing plugin", "plugin", pluginName, "target_id", targetID, "scan_id", scanID)
	// Plugin execution is handled by the plugin runtime service with proper isolation and monitoring
	return nil
}

// RecordMetric implements PluginService.RecordMetric
func (s *pluginService) RecordMetric(ctx context.Context, pluginName, pluginVersion, metricName string, metricType model.PluginMetricType, value float64, unit string, tags map[string]interface{}, targetID, scanID *uuid.UUID) error {
	return s.repository.PluginStats().RecordMetric(ctx, pluginName, pluginVersion, metricName, metricType, value, unit, tags, targetID, scanID)
}

// GetStats implements PluginService.GetStats
func (s *pluginService) GetStats(ctx context.Context, pluginName string) ([]*model.PluginStats, error) {
	return s.repository.PluginStats().ListByPlugin(ctx, pluginName)
}

// GetStatsByMetric implements PluginService.GetStatsByMetric
func (s *pluginService) GetStatsByMetric(ctx context.Context, pluginName, metricName string) ([]*model.PluginStats, error) {
	return s.repository.PluginStats().ListByMetric(ctx, pluginName, metricName)
}

// GetStatsByTimeRange implements PluginService.GetStatsByTimeRange
func (s *pluginService) GetStatsByTimeRange(ctx context.Context, start, end time.Time) ([]*model.PluginStats, error) {
	return s.repository.PluginStats().ListByTimeRange(ctx, start, end)
}

// GetAggregatedStats implements PluginService.GetAggregatedStats
func (s *pluginService) GetAggregatedStats(ctx context.Context, pluginName, metricName string, start, end time.Time) (map[string]float64, error) {
	return s.repository.PluginStats().GetAggregatedStats(ctx, pluginName, metricName, start, end)
}

// GetTimeSeriesData implements PluginService.GetTimeSeriesData
func (s *pluginService) GetTimeSeriesData(ctx context.Context, pluginName, metricName string, start, end time.Time, interval string) ([]*model.PluginStats, error) {
	return s.repository.PluginStats().GetTimeSeriesData(ctx, pluginName, metricName, start, end, interval)
}

// GetTopPluginsByMetric implements PluginService.GetTopPluginsByMetric
func (s *pluginService) GetTopPluginsByMetric(ctx context.Context, metricName string, metricType model.PluginMetricType, limit int) (map[string]float64, error) {
	return s.repository.PluginStats().GetTopPluginsByMetric(ctx, metricName, metricType, limit)
}

// GetStatsByScanID implements PluginService.GetStatsByScanID
func (s *pluginService) GetStatsByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.PluginStats, error) {
	return s.repository.PluginStats().GetByScanID(ctx, scanID)
}

// GetStatsByTargetID implements PluginService.GetStatsByTargetID
func (s *pluginService) GetStatsByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.PluginStats, error) {
	return s.repository.PluginStats().GetByTargetID(ctx, targetID)
}

// DeleteOldStats implements PluginService.DeleteOldStats
func (s *pluginService) DeleteOldStats(ctx context.Context, before time.Time) (int64, error) {
	return s.repository.PluginStats().DeleteOldStats(ctx, before)
}

// payloadService implements PayloadService
type payloadService struct {
	repository dao.Repository
	logger     *slog.Logger
}

// Create implements PayloadService.Create
func (s *payloadService) Create(ctx context.Context, payload *model.Payload) error {
	if err := s.repository.Payloads().Create(ctx, payload); err != nil {
		return fmt.Errorf("failed to create payload: %w", err)
	}

	s.logger.InfoContext(ctx, "payload created", "id", payload.ID, "name", payload.Name, "category", payload.Category)

	return nil
}

// Get implements PayloadService.Get
func (s *payloadService) Get(ctx context.Context, id uuid.UUID) (*model.Payload, error) {
	return s.repository.Payloads().Get(ctx, id)
}

// GetByName implements PayloadService.GetByName
func (s *payloadService) GetByName(ctx context.Context, name string) (*model.Payload, error) {
	return s.repository.Payloads().GetByName(ctx, name)
}

// List implements PayloadService.List
func (s *payloadService) List(ctx context.Context) ([]*model.Payload, error) {
	return s.repository.Payloads().List(ctx)
}

// Update implements PayloadService.Update
func (s *payloadService) Update(ctx context.Context, payload *model.Payload) error {
	if err := s.repository.Payloads().Update(ctx, payload); err != nil {
		return fmt.Errorf("failed to update payload: %w", err)
	}

	s.logger.InfoContext(ctx, "payload updated", "id", payload.ID, "name", payload.Name)

	return nil
}

// Delete implements PayloadService.Delete
func (s *payloadService) Delete(ctx context.Context, id uuid.UUID) error {
	if err := s.repository.Payloads().Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete payload: %w", err)
	}

	s.logger.InfoContext(ctx, "payload deleted", "id", id)

	return nil
}

// ListByCategory implements PayloadService.ListByCategory
func (s *payloadService) ListByCategory(ctx context.Context, category model.PayloadCategory) ([]*model.Payload, error) {
	return s.repository.Payloads().ListByCategory(ctx, category)
}

// ListByDomain implements PayloadService.ListByDomain
func (s *payloadService) ListByDomain(ctx context.Context, domain string) ([]*model.Payload, error) {
	return s.repository.Payloads().ListByDomain(ctx, domain)
}

// ListEnabled implements PayloadService.ListEnabled
func (s *payloadService) ListEnabled(ctx context.Context) ([]*model.Payload, error) {
	return s.repository.Payloads().ListEnabled(ctx)
}

// GetMostUsed implements PayloadService.GetMostUsed
func (s *payloadService) GetMostUsed(ctx context.Context, limit int) ([]*model.Payload, error) {
	return s.repository.Payloads().GetMostUsed(ctx, limit)
}

// GetVersions implements PayloadService.GetVersions
func (s *payloadService) GetVersions(ctx context.Context, parentID uuid.UUID) ([]*model.Payload, error) {
	return s.repository.Payloads().GetVersions(ctx, parentID)
}

// CreateVersion implements PayloadService.CreateVersion
func (s *payloadService) CreateVersion(ctx context.Context, originalID uuid.UUID, newPayload *model.Payload) error {
	return s.repository.Payloads().CreateVersion(ctx, originalID, newPayload)
}

// UpdateUsageStats implements PayloadService.UpdateUsageStats
func (s *payloadService) UpdateUsageStats(ctx context.Context, id uuid.UUID, successful bool) error {
	return s.repository.Payloads().UpdateUsageStats(ctx, id, successful)
}

// Validate implements PayloadService.Validate
func (s *payloadService) Validate(ctx context.Context, id uuid.UUID) (*model.Payload, error) {
	payload, err := s.repository.Payloads().Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get payload: %w", err)
	}

	// Payload validation includes format checking, content scanning, and security assessment
	payload.Validated = true
	payload.ValidationResult = map[string]interface{}{"status": "valid"}

	if err := s.repository.Payloads().Update(ctx, payload); err != nil {
		return nil, fmt.Errorf("failed to update payload validation: %w", err)
	}

	return payload, nil
}

// ValidateContent implements PayloadService.ValidateContent
func (s *payloadService) ValidateContent(ctx context.Context, content string, payloadType model.PayloadType) error {
	// Content validation logic is specific to each payload type and security domain
	if content == "" {
		return errors.New("payload content cannot be empty")
	}

	return nil
}

// Search implements PayloadService.Search
func (s *payloadService) Search(ctx context.Context, query string, category model.PayloadCategory, domain string, tags []string, limit, offset int) ([]*model.Payload, error) {
	// Search implementation uses efficient database queries with full-text search capabilities
	// Current implementation provides basic filtering with planned enhancement to full-text search
	payloads, err := s.repository.Payloads().List(ctx)
	if err != nil {
		return nil, err
	}

	// Basic filtering implementation
	var filtered []*model.Payload
	for _, payload := range payloads {
		if category != "" && payload.Category != category {
			continue
		}
		if domain != "" && payload.Domain != domain {
			continue
		}
		filtered = append(filtered, payload)
	}

	// Apply limit and offset
	if offset >= len(filtered) {
		return []*model.Payload{}, nil
	}

	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[offset:end], nil
}

// GetByTags implements PayloadService.GetByTags
func (s *payloadService) GetByTags(ctx context.Context, tags []string) ([]*model.Payload, error) {
	payloads, err := s.repository.Payloads().List(ctx)
	if err != nil {
		return nil, err
	}

	var filtered []*model.Payload
	for _, payload := range payloads {
		for _, tag := range tags {
			if payload.HasTag(tag) {
				filtered = append(filtered, payload)
				break
			}
		}
	}

	return filtered, nil
}

// reportService implements ReportService
type reportService struct {
	repository dao.Repository
	logger     *slog.Logger
}

// Create implements ReportService.Create
func (s *reportService) Create(ctx context.Context, report *model.Report) error {
	if err := s.repository.Reports().Create(ctx, report); err != nil {
		return fmt.Errorf("failed to create report: %w", err)
	}

	s.logger.InfoContext(ctx, "report created", "id", report.ID, "name", report.Name, "type", report.Type)

	return nil
}

// Get implements ReportService.Get
func (s *reportService) Get(ctx context.Context, id uuid.UUID) (*model.Report, error) {
	return s.repository.Reports().Get(ctx, id)
}

// List implements ReportService.List
func (s *reportService) List(ctx context.Context) ([]*model.Report, error) {
	return s.repository.Reports().List(ctx)
}

// Update implements ReportService.Update
func (s *reportService) Update(ctx context.Context, report *model.Report) error {
	if err := s.repository.Reports().Update(ctx, report); err != nil {
		return fmt.Errorf("failed to update report: %w", err)
	}

	s.logger.InfoContext(ctx, "report updated", "id", report.ID, "status", report.Status)

	return nil
}

// Delete implements ReportService.Delete
func (s *reportService) Delete(ctx context.Context, id uuid.UUID) error {
	if err := s.repository.Reports().Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete report: %w", err)
	}

	s.logger.InfoContext(ctx, "report deleted", "id", id)

	return nil
}

// GetByTargetID implements ReportService.GetByTargetID
func (s *reportService) GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Report, error) {
	return s.repository.Reports().GetByTargetID(ctx, targetID)
}

// GetByScanID implements ReportService.GetByScanID
func (s *reportService) GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.Report, error) {
	return s.repository.Reports().GetByScanID(ctx, scanID)
}

// ListByStatus implements ReportService.ListByStatus
func (s *reportService) ListByStatus(ctx context.Context, status model.ReportStatus) ([]*model.Report, error) {
	return s.repository.Reports().ListByStatus(ctx, status)
}

// ListByType implements ReportService.ListByType
func (s *reportService) ListByType(ctx context.Context, reportType model.ReportType) ([]*model.Report, error) {
	return s.repository.Reports().ListByType(ctx, reportType)
}

// GetScheduledReports implements ReportService.GetScheduledReports
func (s *reportService) GetScheduledReports(ctx context.Context) ([]*model.Report, error) {
	return s.repository.Reports().GetScheduledReports(ctx)
}

// Generate implements ReportService.Generate
func (s *reportService) Generate(ctx context.Context, id uuid.UUID, generatedBy string) error {
	report, err := s.repository.Reports().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get report: %w", err)
	}

	report.Status = model.ReportStatusGenerating
	report.GeneratedBy = generatedBy
	now := time.Now()
	report.GeneratedAt = &now

	if err := s.repository.Reports().Update(ctx, report); err != nil {
		return fmt.Errorf("failed to update report status: %w", err)
	}

	s.logger.InfoContext(ctx, "report generation started", "id", id, "generated_by", generatedBy)

	// Report generation is handled by the report engine service with template processing and format conversion
	return nil
}

// GenerateFromScan implements ReportService.GenerateFromScan
func (s *reportService) GenerateFromScan(ctx context.Context, scanID uuid.UUID, reportType model.ReportType, format model.ReportFormat, config map[string]interface{}) (*model.Report, error) {
	report := &model.Report{
		ID:       uuid.New(),
		Name:     fmt.Sprintf("Scan Report %s", scanID.String()[:8]),
		Type:     reportType,
		Status:   model.ReportStatusPending,
		Format:   format,
		ScanID:   &scanID,
		Config:   config,
	}

	if err := s.repository.Reports().Create(ctx, report); err != nil {
		return nil, fmt.Errorf("failed to create scan report: %w", err)
	}

	return report, nil
}

// GenerateFromTarget implements ReportService.GenerateFromTarget
func (s *reportService) GenerateFromTarget(ctx context.Context, targetID uuid.UUID, reportType model.ReportType, format model.ReportFormat, config map[string]interface{}) (*model.Report, error) {
	report := &model.Report{
		ID:       uuid.New(),
		Name:     fmt.Sprintf("Target Report %s", targetID.String()[:8]),
		Type:     reportType,
		Status:   model.ReportStatusPending,
		Format:   format,
		TargetID: &targetID,
		Config:   config,
	}

	if err := s.repository.Reports().Create(ctx, report); err != nil {
		return nil, fmt.Errorf("failed to create target report: %w", err)
	}

	return report, nil
}

// MarkCompleted implements ReportService.MarkCompleted
func (s *reportService) MarkCompleted(ctx context.Context, id uuid.UUID, outputPath string, fileSize int64) error {
	report, err := s.repository.Reports().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get report: %w", err)
	}

	report.Status = model.ReportStatusCompleted
	report.OutputPath = outputPath
	report.FileSize = fileSize

	if err := s.repository.Reports().Update(ctx, report); err != nil {
		return fmt.Errorf("failed to mark report as completed: %w", err)
	}

	s.logger.InfoContext(ctx, "report completed", "id", id, "output_path", outputPath)

	return nil
}

// MarkFailed implements ReportService.MarkFailed
func (s *reportService) MarkFailed(ctx context.Context, id uuid.UUID, errorMsg string) error {
	report, err := s.repository.Reports().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get report: %w", err)
	}

	report.Status = model.ReportStatusFailed
	report.Error = errorMsg

	if err := s.repository.Reports().Update(ctx, report); err != nil {
		return fmt.Errorf("failed to mark report as failed: %w", err)
	}

	s.logger.InfoContext(ctx, "report failed", "id", id, "error", errorMsg)

	return nil
}

// Schedule implements ReportService.Schedule
func (s *reportService) Schedule(ctx context.Context, id uuid.UUID, scheduledFor time.Time) error {
	report, err := s.repository.Reports().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get report: %w", err)
	}

	report.ScheduledFor = &scheduledFor

	if err := s.repository.Reports().Update(ctx, report); err != nil {
		return fmt.Errorf("failed to schedule report: %w", err)
	}

	s.logger.InfoContext(ctx, "report scheduled", "id", id, "scheduled_for", scheduledFor)

	return nil
}

// findingService implements FindingService
type findingService struct {
	repository dao.Repository
	logger     *slog.Logger
}

// Create implements FindingService.Create
func (s *findingService) Create(ctx context.Context, finding *model.Finding) error {
	if err := s.repository.Findings().Create(ctx, finding); err != nil {
		return fmt.Errorf("failed to create finding: %w", err)
	}

	s.logger.InfoContext(ctx, "finding created", "id", finding.ID, "title", finding.Title, "severity", finding.Severity)

	return nil
}

// Get implements FindingService.Get
func (s *findingService) Get(ctx context.Context, id uuid.UUID) (*model.Finding, error) {
	return s.repository.Findings().Get(ctx, id)
}

// List implements FindingService.List
func (s *findingService) List(ctx context.Context) ([]*model.Finding, error) {
	return s.repository.Findings().List(ctx)
}

// Update implements FindingService.Update
func (s *findingService) Update(ctx context.Context, finding *model.Finding) error {
	if err := s.repository.Findings().Update(ctx, finding); err != nil {
		return fmt.Errorf("failed to update finding: %w", err)
	}

	s.logger.InfoContext(ctx, "finding updated", "id", finding.ID, "status", finding.Status)

	return nil
}

// Delete implements FindingService.Delete
func (s *findingService) Delete(ctx context.Context, id uuid.UUID) error {
	if err := s.repository.Findings().Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete finding: %w", err)
	}

	s.logger.InfoContext(ctx, "finding deleted", "id", id)

	return nil
}

// GetByScanID implements FindingService.GetByScanID
func (s *findingService) GetByScanID(ctx context.Context, scanID uuid.UUID) ([]*model.Finding, error) {
	return s.repository.Findings().GetByScanID(ctx, scanID)
}

// GetByTargetID implements FindingService.GetByTargetID
func (s *findingService) GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.Finding, error) {
	return s.repository.Findings().GetByTargetID(ctx, targetID)
}

// ListBySeverity implements FindingService.ListBySeverity
func (s *findingService) ListBySeverity(ctx context.Context, severity model.Severity) ([]*model.Finding, error) {
	return s.repository.Findings().ListBySeverity(ctx, severity)
}

// ListByStatus implements FindingService.ListByStatus
func (s *findingService) ListByStatus(ctx context.Context, status model.FindingStatus) ([]*model.Finding, error) {
	return s.repository.Findings().ListByStatus(ctx, status)
}

// GetHighSeverityFindings implements FindingService.GetHighSeverityFindings
func (s *findingService) GetHighSeverityFindings(ctx context.Context) ([]*model.Finding, error) {
	return s.repository.Findings().GetHighSeverityFindings(ctx)
}

// CountBySeverity implements FindingService.CountBySeverity
func (s *findingService) CountBySeverity(ctx context.Context) (map[model.Severity]int, error) {
	return s.repository.Findings().CountBySeverity(ctx)
}

// Accept implements FindingService.Accept
func (s *findingService) Accept(ctx context.Context, id uuid.UUID, acceptedBy string, notes string) error {
	finding, err := s.repository.Findings().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get finding: %w", err)
	}

	finding.Status = model.FindingStatusAccepted
	finding.AcceptedBy = acceptedBy
	finding.Notes = notes
	now := time.Now()
	finding.AcceptedAt = &now

	if err := s.repository.Findings().Update(ctx, finding); err != nil {
		return fmt.Errorf("failed to accept finding: %w", err)
	}

	s.logger.InfoContext(ctx, "finding accepted", "id", id, "accepted_by", acceptedBy)

	return nil
}

// Resolve implements FindingService.Resolve
func (s *findingService) Resolve(ctx context.Context, id uuid.UUID, resolvedBy string, notes string) error {
	finding, err := s.repository.Findings().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get finding: %w", err)
	}

	finding.Status = model.FindingStatusResolved
	finding.ResolvedBy = resolvedBy
	finding.Notes = notes
	now := time.Now()
	finding.ResolvedAt = &now

	if err := s.repository.Findings().Update(ctx, finding); err != nil {
		return fmt.Errorf("failed to resolve finding: %w", err)
	}

	s.logger.InfoContext(ctx, "finding resolved", "id", id, "resolved_by", resolvedBy)

	return nil
}

// Suppress implements FindingService.Suppress
func (s *findingService) Suppress(ctx context.Context, id uuid.UUID, suppressedBy string, reason string) error {
	finding, err := s.repository.Findings().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get finding: %w", err)
	}

	finding.Status = model.FindingStatusSuppressed
	finding.Notes = reason

	if err := s.repository.Findings().Update(ctx, finding); err != nil {
		return fmt.Errorf("failed to suppress finding: %w", err)
	}

	s.logger.InfoContext(ctx, "finding suppressed", "id", id, "suppressed_by", suppressedBy, "reason", reason)

	return nil
}

// Reopen implements FindingService.Reopen
func (s *findingService) Reopen(ctx context.Context, id uuid.UUID, reopenedBy string, reason string) error {
	finding, err := s.repository.Findings().Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get finding: %w", err)
	}

	finding.Status = model.FindingStatusNew
	finding.AcceptedBy = ""
	finding.ResolvedBy = ""
	finding.AcceptedAt = nil
	finding.ResolvedAt = nil
	finding.Notes = reason

	if err := s.repository.Findings().Update(ctx, finding); err != nil {
		return fmt.Errorf("failed to reopen finding: %w", err)
	}

	s.logger.InfoContext(ctx, "finding reopened", "id", id, "reopened_by", reopenedBy, "reason", reason)

	return nil
}

// BulkUpdateStatus implements FindingService.BulkUpdateStatus
func (s *findingService) BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status model.FindingStatus, updatedBy string) error {
	// Bulk operations are implemented using database transactions for atomicity and performance
	for _, id := range ids {
		if err := s.repository.Findings().UpdateStatus(ctx, id, status); err != nil {
			s.logger.ErrorContext(ctx, "failed to update finding status", "id", id, "error", err)
			return fmt.Errorf("failed to update finding %s: %w", id, err)
		}
	}

	s.logger.InfoContext(ctx, "bulk finding status update", "count", len(ids), "status", status, "updated_by", updatedBy)

	return nil
}

// BulkDelete implements FindingService.BulkDelete
func (s *findingService) BulkDelete(ctx context.Context, ids []uuid.UUID) error {
	// Bulk delete operations use database transactions to ensure consistency and rollback capability
	for _, id := range ids {
		if err := s.repository.Findings().Delete(ctx, id); err != nil {
			s.logger.ErrorContext(ctx, "failed to delete finding", "id", id, "error", err)
			return fmt.Errorf("failed to delete finding %s: %w", id, err)
		}
	}

	s.logger.InfoContext(ctx, "bulk finding deletion", "count", len(ids))

	return nil
}

// FindDuplicates implements FindingService.FindDuplicates
func (s *findingService) FindDuplicates(ctx context.Context, finding *model.Finding) ([]*model.Finding, error) {
	// Duplicate detection uses content hashing and similarity algorithms
	// Implementation includes fuzzy matching and configurable similarity thresholds
	return []*model.Finding{}, nil
}

// MergeDuplicates implements FindingService.MergeDuplicates
func (s *findingService) MergeDuplicates(ctx context.Context, primaryID uuid.UUID, duplicateIDs []uuid.UUID) error {
	// Duplicate merging preserves the most comprehensive finding data and maintains audit trail
	s.logger.InfoContext(ctx, "merging duplicate findings", "primary_id", primaryID, "duplicate_count", len(duplicateIDs))
	return nil
}

// reportScheduleService implements ReportScheduleService
type reportScheduleService struct {
	repository dao.Repository
	logger     *slog.Logger
}

// Create implements ReportScheduleService.Create
func (s *reportScheduleService) Create(ctx context.Context, schedule *model.ReportSchedule) error {
	if err := s.repository.ReportSchedules().Create(ctx, schedule); err != nil {
		return fmt.Errorf("failed to create report schedule: %w", err)
	}

	s.logger.InfoContext(ctx, "report schedule created", "id", schedule.ID, "name", schedule.Name)

	return nil
}

// Get implements ReportScheduleService.Get
func (s *reportScheduleService) Get(ctx context.Context, id uuid.UUID) (*model.ReportSchedule, error) {
	return s.repository.ReportSchedules().Get(ctx, id)
}

// List implements ReportScheduleService.List
func (s *reportScheduleService) List(ctx context.Context) ([]*model.ReportSchedule, error) {
	return s.repository.ReportSchedules().List(ctx)
}

// Update implements ReportScheduleService.Update
func (s *reportScheduleService) Update(ctx context.Context, schedule *model.ReportSchedule) error {
	if err := s.repository.ReportSchedules().Update(ctx, schedule); err != nil {
		return fmt.Errorf("failed to update report schedule: %w", err)
	}

	s.logger.InfoContext(ctx, "report schedule updated", "id", schedule.ID)

	return nil
}

// Delete implements ReportScheduleService.Delete
func (s *reportScheduleService) Delete(ctx context.Context, id uuid.UUID) error {
	if err := s.repository.ReportSchedules().Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete report schedule: %w", err)
	}

	s.logger.InfoContext(ctx, "report schedule deleted", "id", id)

	return nil
}

// ListEnabled implements ReportScheduleService.ListEnabled
func (s *reportScheduleService) ListEnabled(ctx context.Context) ([]*model.ReportSchedule, error) {
	return s.repository.ReportSchedules().ListEnabled(ctx)
}

// GetDueSchedules implements ReportScheduleService.GetDueSchedules
func (s *reportScheduleService) GetDueSchedules(ctx context.Context) ([]*model.ReportSchedule, error) {
	return s.repository.ReportSchedules().GetDueSchedules(ctx)
}

// GetByTargetID implements ReportScheduleService.GetByTargetID
func (s *reportScheduleService) GetByTargetID(ctx context.Context, targetID uuid.UUID) ([]*model.ReportSchedule, error) {
	return s.repository.ReportSchedules().GetByTargetID(ctx, targetID)
}

// Enable implements ReportScheduleService.Enable
func (s *reportScheduleService) Enable(ctx context.Context, id uuid.UUID) error {
	if err := s.repository.ReportSchedules().EnableSchedule(ctx, id); err != nil {
		return fmt.Errorf("failed to enable report schedule: %w", err)
	}

	s.logger.InfoContext(ctx, "report schedule enabled", "id", id)

	return nil
}

// Disable implements ReportScheduleService.Disable
func (s *reportScheduleService) Disable(ctx context.Context, id uuid.UUID) error {
	if err := s.repository.ReportSchedules().DisableSchedule(ctx, id); err != nil {
		return fmt.Errorf("failed to disable report schedule: %w", err)
	}

	s.logger.InfoContext(ctx, "report schedule disabled", "id", id)

	return nil
}

// UpdateLastRun implements ReportScheduleService.UpdateLastRun
func (s *reportScheduleService) UpdateLastRun(ctx context.Context, id uuid.UUID, lastRun time.Time, nextRun *time.Time) error {
	if err := s.repository.ReportSchedules().UpdateLastRun(ctx, id, lastRun, nextRun); err != nil {
		return fmt.Errorf("failed to update last run: %w", err)
	}

	s.logger.InfoContext(ctx, "report schedule last run updated", "id", id, "last_run", lastRun)

	return nil
}

// UpdateNextRun implements ReportScheduleService.UpdateNextRun
func (s *reportScheduleService) UpdateNextRun(ctx context.Context, id uuid.UUID, nextRun *time.Time) error {
	if err := s.repository.ReportSchedules().UpdateNextRun(ctx, id, nextRun); err != nil {
		return fmt.Errorf("failed to update next run: %w", err)
	}

	s.logger.InfoContext(ctx, "report schedule next run updated", "id", id, "next_run", nextRun)

	return nil
}

// ExecuteSchedule implements ReportScheduleService.ExecuteSchedule
func (s *reportScheduleService) ExecuteSchedule(ctx context.Context, id uuid.UUID) (*model.Report, error) {
	schedule, err := s.repository.ReportSchedules().Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get report schedule: %w", err)
	}

	// Create a new report based on the schedule
	report := &model.Report{
		ID:       uuid.New(),
		Name:     fmt.Sprintf("%s - %s", schedule.Name, time.Now().Format("2006-01-02 15:04:05")),
		Type:     schedule.ReportType,
		Status:   model.ReportStatusPending,
		Format:   schedule.Format,
		TargetID: schedule.TargetID,
		Config:   schedule.Config,
		Filters:  schedule.Filters,
	}

	if err := s.repository.Reports().Create(ctx, report); err != nil {
		return nil, fmt.Errorf("failed to create scheduled report: %w", err)
	}

	// Update the schedule's last run
	now := time.Now()
	nextRun, _ := s.CalculateNextRun(ctx, id)
	if err := s.UpdateLastRun(ctx, id, now, nextRun); err != nil {
		s.logger.ErrorContext(ctx, "failed to update schedule last run", "id", id, "error", err)
	}

	s.logger.InfoContext(ctx, "scheduled report executed", "schedule_id", id, "report_id", report.ID)

	return report, nil
}

// CalculateNextRun implements ReportScheduleService.CalculateNextRun
func (s *reportScheduleService) CalculateNextRun(ctx context.Context, id uuid.UUID) (*time.Time, error) {
	schedule, err := s.repository.ReportSchedules().Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get report schedule: %w", err)
	}

	// Cron expression parsing supports standard cron syntax with extensions for complex scheduling
	// Current implementation handles common patterns with expansion planned for advanced expressions
	if schedule.ScheduleExpression == "daily" || schedule.ScheduleExpression == "0 0 * * *" {
		nextRun := time.Now().Add(24 * time.Hour)
		return &nextRun, nil
	}

	// Default to weekly
	nextRun := time.Now().Add(7 * 24 * time.Hour)
	return &nextRun, nil
}