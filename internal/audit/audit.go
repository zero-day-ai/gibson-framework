// Package audit provides comprehensive audit logging for security operations
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// EventType represents the type of audit event
type EventType string

const (
	EventTypeAccess    EventType = "access"
	EventTypeAction    EventType = "action"
	EventTypeAuth      EventType = "authentication"
	EventTypeConfig    EventType = "configuration"
	EventTypeData      EventType = "data"
	EventTypeError     EventType = "error"
	EventTypeSecurity  EventType = "security"
	EventTypeSystem    EventType = "system"
)

// EventLevel represents the severity level of the audit event
type EventLevel string

const (
	EventLevelInfo     EventLevel = "info"
	EventLevelWarn     EventLevel = "warn"
	EventLevelError    EventLevel = "error"
	EventLevelCritical EventLevel = "critical"
)

// EventOutcome represents the outcome of the audited operation
type EventOutcome string

const (
	EventOutcomeSuccess EventOutcome = "success"
	EventOutcomeFailure EventOutcome = "failure"
	EventOutcomeUnknown EventOutcome = "unknown"
)

// AuditEvent represents an audit log event
type AuditEvent struct {
	ID          uuid.UUID                `json:"id"`
	Timestamp   time.Time                `json:"timestamp"`
	Type        EventType                `json:"type"`
	Level       EventLevel               `json:"level"`
	Outcome     EventOutcome             `json:"outcome"`
	Action      string                   `json:"action"`
	Resource    string                   `json:"resource"`
	Subject     *Subject                 `json:"subject,omitempty"`
	Object      *Object                  `json:"object,omitempty"`
	Source      *Source                  `json:"source,omitempty"`
	Session     *Session                 `json:"session,omitempty"`
	Details     map[string]interface{}   `json:"details,omitempty"`
	Tags        []string                 `json:"tags,omitempty"`
	Message     string                   `json:"message"`
	Error       string                   `json:"error,omitempty"`
	Duration    time.Duration            `json:"duration,omitempty"`
	Metadata    map[string]interface{}   `json:"metadata,omitempty"`
}

// Subject represents who performed the action
type Subject struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"` // user, service, system
	Name     string            `json:"name"`
	Groups   []string          `json:"groups,omitempty"`
	Roles    []string          `json:"roles,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Object represents what was acted upon
type Object struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"` // target, scan, payload, plugin, etc.
	Name     string            `json:"name"`
	Path     string            `json:"path,omitempty"`
	Version  string            `json:"version,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Source represents where the action originated from
type Source struct {
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent,omitempty"`
	Host      string `json:"host,omitempty"`
	Process   string `json:"process,omitempty"`
}

// Session represents the session context
type Session struct {
	ID        string    `json:"id"`
	StartTime time.Time `json:"start_time"`
	Duration  time.Duration `json:"duration,omitempty"`
}

// AuditLogger defines the interface for audit logging
type AuditLogger interface {
	Log(ctx context.Context, event *AuditEvent) error
	Query(ctx context.Context, filter *QueryFilter) ([]*AuditEvent, error)
	Close() error
}

// QueryFilter represents filters for querying audit logs
type QueryFilter struct {
	StartTime *time.Time    `json:"start_time,omitempty"`
	EndTime   *time.Time    `json:"end_time,omitempty"`
	Types     []EventType   `json:"types,omitempty"`
	Levels    []EventLevel  `json:"levels,omitempty"`
	Outcomes  []EventOutcome `json:"outcomes,omitempty"`
	Actions   []string      `json:"actions,omitempty"`
	Resources []string      `json:"resources,omitempty"`
	SubjectID string        `json:"subject_id,omitempty"`
	SourceIP  string        `json:"source_ip,omitempty"`
	Limit     int           `json:"limit,omitempty"`
	Offset    int           `json:"offset,omitempty"`
}

// FileAuditLogger implements audit logging to files
type FileAuditLogger struct {
	file   *os.File
	logger *slog.Logger
	mutex  sync.Mutex
}

// NewFileAuditLogger creates a new file-based audit logger
func NewFileAuditLogger(filename string) (*FileAuditLogger, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	handler := slog.NewJSONHandler(file, opts)
	logger := slog.New(handler)

	return &FileAuditLogger{
		file:   file,
		logger: logger,
	}, nil
}

func (fal *FileAuditLogger) Log(ctx context.Context, event *AuditEvent) error {
	fal.mutex.Lock()
	defer fal.mutex.Unlock()

	// Convert event to structured log
	attrs := []slog.Attr{
		slog.String("audit_id", event.ID.String()),
		slog.Time("timestamp", event.Timestamp),
		slog.String("type", string(event.Type)),
		slog.String("level", string(event.Level)),
		slog.String("outcome", string(event.Outcome)),
		slog.String("action", event.Action),
		slog.String("resource", event.Resource),
		slog.String("message", event.Message),
	}

	if event.Subject != nil {
		attrs = append(attrs, slog.Group("subject",
			slog.String("id", event.Subject.ID),
			slog.String("type", event.Subject.Type),
			slog.String("name", event.Subject.Name),
		))
	}

	if event.Object != nil {
		attrs = append(attrs, slog.Group("object",
			slog.String("id", event.Object.ID),
			slog.String("type", event.Object.Type),
			slog.String("name", event.Object.Name),
		))
	}

	if event.Source != nil {
		attrs = append(attrs, slog.Group("source",
			slog.String("ip", event.Source.IP),
			slog.String("user_agent", event.Source.UserAgent),
		))
	}

	if event.Error != "" {
		attrs = append(attrs, slog.String("error", event.Error))
	}

	if event.Duration > 0 {
		attrs = append(attrs, slog.Duration("duration", event.Duration))
	}

	// Log at appropriate level
	switch event.Level {
	case EventLevelInfo:
		fal.logger.LogAttrs(ctx, slog.LevelInfo, "audit", attrs...)
	case EventLevelWarn:
		fal.logger.LogAttrs(ctx, slog.LevelWarn, "audit", attrs...)
	case EventLevelError:
		fal.logger.LogAttrs(ctx, slog.LevelError, "audit", attrs...)
	case EventLevelCritical:
		fal.logger.LogAttrs(ctx, slog.LevelError, "audit", attrs...) // Use ERROR for critical
	default:
		fal.logger.LogAttrs(ctx, slog.LevelInfo, "audit", attrs...)
	}

	return nil
}

func (fal *FileAuditLogger) Query(ctx context.Context, filter *QueryFilter) ([]*AuditEvent, error) {
	// File-based querying is limited - in production you'd use a database
	return nil, fmt.Errorf("query not supported for file-based audit logger")
}

func (fal *FileAuditLogger) Close() error {
	fal.mutex.Lock()
	defer fal.mutex.Unlock()
	return fal.file.Close()
}

// CompositeAuditLogger logs to multiple destinations
type CompositeAuditLogger struct {
	loggers []AuditLogger
}

// NewCompositeAuditLogger creates a new composite audit logger
func NewCompositeAuditLogger(loggers ...AuditLogger) *CompositeAuditLogger {
	return &CompositeAuditLogger{
		loggers: loggers,
	}
}

func (cal *CompositeAuditLogger) Log(ctx context.Context, event *AuditEvent) error {
	var errors []string

	for _, logger := range cal.loggers {
		if err := logger.Log(ctx, event); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("audit logging errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

func (cal *CompositeAuditLogger) Query(ctx context.Context, filter *QueryFilter) ([]*AuditEvent, error) {
	// Use the first logger that supports querying
	for _, logger := range cal.loggers {
		if events, err := logger.Query(ctx, filter); err == nil {
			return events, nil
		}
	}

	return nil, fmt.Errorf("no logger supports querying")
}

func (cal *CompositeAuditLogger) Close() error {
	var errors []string

	for _, logger := range cal.loggers {
		if err := logger.Close(); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("audit logger close errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// AuditManager manages audit logging
type AuditManager struct {
	logger   AuditLogger
	enabled  bool
	enricher func(*AuditEvent)
	mutex    sync.RWMutex
}

// NewAuditManager creates a new audit manager
func NewAuditManager(logger AuditLogger) *AuditManager {
	return &AuditManager{
		logger:  logger,
		enabled: true,
		enricher: defaultEnricher,
	}
}

func (am *AuditManager) SetEnabled(enabled bool) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	am.enabled = enabled
}

func (am *AuditManager) IsEnabled() bool {
	am.mutex.RLock()
	defer am.mutex.RUnlock()
	return am.enabled
}

func (am *AuditManager) SetEnricher(enricher func(*AuditEvent)) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	am.enricher = enricher
}

func (am *AuditManager) Log(ctx context.Context, event *AuditEvent) error {
	if !am.IsEnabled() {
		return nil
	}

	// Set default values
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Apply enrichment
	am.mutex.RLock()
	enricher := am.enricher
	am.mutex.RUnlock()

	if enricher != nil {
		enricher(event)
	}

	return am.logger.Log(ctx, event)
}

// Helper functions for creating common audit events
func (am *AuditManager) LogAccess(ctx context.Context, subject *Subject, object *Object, action string, outcome EventOutcome) error {
	event := &AuditEvent{
		Type:     EventTypeAccess,
		Level:    EventLevelInfo,
		Outcome:  outcome,
		Action:   action,
		Resource: object.Type,
		Subject:  subject,
		Object:   object,
		Source:   extractSource(ctx),
		Message:  fmt.Sprintf("Access %s: %s %s %s", outcome, subject.Name, action, object.Name),
	}

	if outcome == EventOutcomeFailure {
		event.Level = EventLevelWarn
	}

	return am.Log(ctx, event)
}

func (am *AuditManager) LogAuthentication(ctx context.Context, subject *Subject, outcome EventOutcome, details map[string]interface{}) error {
	event := &AuditEvent{
		Type:     EventTypeAuth,
		Level:    EventLevelInfo,
		Outcome:  outcome,
		Action:   "authenticate",
		Resource: "authentication",
		Subject:  subject,
		Source:   extractSource(ctx),
		Details:  details,
		Message:  fmt.Sprintf("Authentication %s for %s", outcome, subject.Name),
	}

	if outcome == EventOutcomeFailure {
		event.Level = EventLevelWarn
	}

	return am.Log(ctx, event)
}

func (am *AuditManager) LogSecurityEvent(ctx context.Context, action string, details map[string]interface{}, level EventLevel) error {
	event := &AuditEvent{
		Type:     EventTypeSecurity,
		Level:    level,
		Outcome:  EventOutcomeUnknown,
		Action:   action,
		Resource: "security",
		Source:   extractSource(ctx),
		Details:  details,
		Message:  fmt.Sprintf("Security event: %s", action),
	}

	return am.Log(ctx, event)
}

func (am *AuditManager) LogDataAccess(ctx context.Context, subject *Subject, object *Object, action string, outcome EventOutcome) error {
	event := &AuditEvent{
		Type:     EventTypeData,
		Level:    EventLevelInfo,
		Outcome:  outcome,
		Action:   action,
		Resource: object.Type,
		Subject:  subject,
		Object:   object,
		Source:   extractSource(ctx),
		Message:  fmt.Sprintf("Data access %s: %s %s %s", outcome, subject.Name, action, object.Name),
	}

	if strings.Contains(action, "delete") || strings.Contains(action, "modify") {
		event.Level = EventLevelWarn
	}

	return am.Log(ctx, event)
}

func (am *AuditManager) LogSystemEvent(ctx context.Context, action string, outcome EventOutcome, details map[string]interface{}) error {
	event := &AuditEvent{
		Type:     EventTypeSystem,
		Level:    EventLevelInfo,
		Outcome:  outcome,
		Action:   action,
		Resource: "system",
		Source:   extractSource(ctx),
		Details:  details,
		Message:  fmt.Sprintf("System event: %s", action),
	}

	return am.Log(ctx, event)
}

// Middleware for audit logging
type AuditMiddleware struct {
	manager *AuditManager
}

func NewAuditMiddleware(manager *AuditManager) *AuditMiddleware {
	return &AuditMiddleware{
		manager: manager,
	}
}

func (am *AuditMiddleware) LogOperation(ctx context.Context, operation string, subject *Subject, object *Object, fn func() error) error {
	start := time.Now()

	err := fn()
	duration := time.Since(start)

	outcome := EventOutcomeSuccess
	level := EventLevelInfo

	if err != nil {
		outcome = EventOutcomeFailure
		level = EventLevelError
	}

	event := &AuditEvent{
		Type:     EventTypeAction,
		Level:    level,
		Outcome:  outcome,
		Action:   operation,
		Resource: object.Type,
		Subject:  subject,
		Object:   object,
		Source:   extractSource(ctx),
		Duration: duration,
		Message:  fmt.Sprintf("Operation %s %s: %s %s %s", operation, outcome, subject.Name, operation, object.Name),
	}

	if err != nil {
		event.Error = err.Error()
	}

	return am.manager.Log(ctx, event)
}

// Helper functions
func extractSource(ctx context.Context) *Source {
	source := &Source{}

	// Try to extract IP from context
	if ip := getIPFromContext(ctx); ip != "" {
		source.IP = ip
	}

	// Try to extract user agent from context
	if ua := getUserAgentFromContext(ctx); ua != "" {
		source.UserAgent = ua
	}

	// Set default values if not found
	if source.IP == "" {
		source.IP = "unknown"
	}

	return source
}

func getIPFromContext(ctx context.Context) string {
	// This would be implemented based on your specific context setup
	// For HTTP requests, you might store the IP in the context
	if ip := ctx.Value("client_ip"); ip != nil {
		if ipStr, ok := ip.(string); ok {
			return ipStr
		}
	}
	return ""
}

func getUserAgentFromContext(ctx context.Context) string {
	// This would be implemented based on your specific context setup
	if ua := ctx.Value("user_agent"); ua != nil {
		if uaStr, ok := ua.(string); ok {
			return uaStr
		}
	}
	return ""
}

func defaultEnricher(event *AuditEvent) {
	// Add hostname
	if hostname, err := os.Hostname(); err == nil {
		if event.Metadata == nil {
			event.Metadata = make(map[string]interface{})
		}
		event.Metadata["hostname"] = hostname
	}

	// Add process info
	if event.Source != nil && event.Source.Process == "" {
		event.Source.Process = fmt.Sprintf("pid:%d", os.Getpid())
	}
}

// Context helpers for adding audit information
type contextKey string

const (
	subjectKey   contextKey = "audit_subject"
	sessionKey   contextKey = "audit_session"
	clientIPKey  contextKey = "client_ip"
	userAgentKey contextKey = "user_agent"
)

func WithSubject(ctx context.Context, subject *Subject) context.Context {
	return context.WithValue(ctx, subjectKey, subject)
}

func GetSubject(ctx context.Context) *Subject {
	if subject := ctx.Value(subjectKey); subject != nil {
		if s, ok := subject.(*Subject); ok {
			return s
		}
	}
	return nil
}

func WithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, sessionKey, session)
}

func GetSession(ctx context.Context) *Session {
	if session := ctx.Value(sessionKey); session != nil {
		if s, ok := session.(*Session); ok {
			return s
		}
	}
	return nil
}

func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey, ip)
}

func WithUserAgent(ctx context.Context, ua string) context.Context {
	return context.WithValue(ctx, userAgentKey, ua)
}

// Global audit manager
var defaultAuditManager *AuditManager

func init() {
	// Initialize with a default file logger
	if logger, err := NewFileAuditLogger("/tmp/gibson-audit.log"); err == nil {
		defaultAuditManager = NewAuditManager(logger)
	} else {
		// Fallback to a no-op logger
		defaultAuditManager = NewAuditManager(&NoOpAuditLogger{})
	}
}

// NoOpAuditLogger is a no-operation audit logger for testing
type NoOpAuditLogger struct{}

func (n *NoOpAuditLogger) Log(ctx context.Context, event *AuditEvent) error {
	return nil
}

func (n *NoOpAuditLogger) Query(ctx context.Context, filter *QueryFilter) ([]*AuditEvent, error) {
	return nil, nil
}

func (n *NoOpAuditLogger) Close() error {
	return nil
}

// Global convenience functions
func Log(ctx context.Context, event *AuditEvent) error {
	return defaultAuditManager.Log(ctx, event)
}

func LogAccess(ctx context.Context, subject *Subject, object *Object, action string, outcome EventOutcome) error {
	return defaultAuditManager.LogAccess(ctx, subject, object, action, outcome)
}

func LogAuthentication(ctx context.Context, subject *Subject, outcome EventOutcome, details map[string]interface{}) error {
	return defaultAuditManager.LogAuthentication(ctx, subject, outcome, details)
}

func LogSecurityEvent(ctx context.Context, action string, details map[string]interface{}, level EventLevel) error {
	return defaultAuditManager.LogSecurityEvent(ctx, action, details, level)
}

func SetEnabled(enabled bool) {
	defaultAuditManager.SetEnabled(enabled)
}

func IsEnabled() bool {
	return defaultAuditManager.IsEnabled()
}