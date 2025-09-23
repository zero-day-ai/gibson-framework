// Package security provides input sanitization and validation utilities
package security

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gibson-sec/gibson-framework-2/internal/audit"
)

// Sanitizer defines the interface for input sanitizers
type Sanitizer interface {
	Sanitize(input string) (string, error)
	Validate(input string) error
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Value   string `json:"value"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// StringSanitizer provides basic string sanitization
type StringSanitizer struct {
	MaxLength       int
	MinLength       int
	AllowedChars    *regexp.Regexp
	ForbiddenChars  *regexp.Regexp
	TrimWhitespace  bool
	HTMLEscape      bool
	RemoveNullBytes bool
}

// NewStringSanitizer creates a new string sanitizer with safe defaults
func NewStringSanitizer() *StringSanitizer {
	return &StringSanitizer{
		MaxLength:       1000,
		MinLength:       0,
		TrimWhitespace:  true,
		HTMLEscape:      true,
		RemoveNullBytes: true,
		// Allow common safe characters
		AllowedChars: regexp.MustCompile(`^[a-zA-Z0-9\s\-_.,!?@#$%^&*()+=\[\]{}|;:'"<>/\\~` + "`" + `]+$`),
	}
}

func (s *StringSanitizer) Sanitize(input string) (string, error) {
	result := input

	// Remove null bytes
	if s.RemoveNullBytes {
		result = strings.ReplaceAll(result, "\x00", "")
	}

	// Trim whitespace
	if s.TrimWhitespace {
		result = strings.TrimSpace(result)
	}

	// HTML escape
	if s.HTMLEscape {
		result = html.EscapeString(result)
	}

	// Remove forbidden characters
	if s.ForbiddenChars != nil {
		result = s.ForbiddenChars.ReplaceAllString(result, "")
	}

	return result, s.Validate(result)
}

func (s *StringSanitizer) Validate(input string) error {
	// Check UTF-8 validity
	if !utf8.ValidString(input) {
		return &ValidationError{
			Message: "invalid UTF-8 encoding",
			Code:    "INVALID_ENCODING",
		}
	}

	// Check length constraints
	if s.MaxLength > 0 && len(input) > s.MaxLength {
		return &ValidationError{
			Message: fmt.Sprintf("exceeds maximum length of %d characters", s.MaxLength),
			Code:    "MAX_LENGTH_EXCEEDED",
		}
	}

	if len(input) < s.MinLength {
		return &ValidationError{
			Message: fmt.Sprintf("below minimum length of %d characters", s.MinLength),
			Code:    "MIN_LENGTH_NOT_MET",
		}
	}

	// Check allowed characters
	if s.AllowedChars != nil && !s.AllowedChars.MatchString(input) {
		return &ValidationError{
			Message: "contains forbidden characters",
			Code:    "FORBIDDEN_CHARACTERS",
		}
	}

	return nil
}

// EmailSanitizer sanitizes email addresses
type EmailSanitizer struct {
	MaxLength int
}

func NewEmailSanitizer() *EmailSanitizer {
	return &EmailSanitizer{
		MaxLength: 320, // RFC 5321 limit
	}
}

func (e *EmailSanitizer) Sanitize(input string) (string, error) {
	result := strings.TrimSpace(strings.ToLower(input))
	return result, e.Validate(result)
}

func (e *EmailSanitizer) Validate(input string) error {
	if len(input) > e.MaxLength {
		return &ValidationError{
			Message: fmt.Sprintf("email exceeds maximum length of %d characters", e.MaxLength),
			Code:    "EMAIL_TOO_LONG",
		}
	}

	// Basic email regex (simplified)
	emailRegex := regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`)
	if !emailRegex.MatchString(input) {
		return &ValidationError{
			Message: "invalid email format",
			Code:    "INVALID_EMAIL_FORMAT",
		}
	}

	return nil
}

// URLSanitizer sanitizes URLs
type URLSanitizer struct {
	AllowedSchemes []string
	MaxLength      int
}

func NewURLSanitizer() *URLSanitizer {
	return &URLSanitizer{
		AllowedSchemes: []string{"http", "https"},
		MaxLength:      2048,
	}
}

func (u *URLSanitizer) Sanitize(input string) (string, error) {
	result := strings.TrimSpace(input)

	// Parse URL
	parsedURL, err := url.Parse(result)
	if err != nil {
		return "", &ValidationError{
			Message: "invalid URL format",
			Code:    "INVALID_URL_FORMAT",
		}
	}

	// Rebuild URL to normalize it
	result = parsedURL.String()

	return result, u.Validate(result)
}

func (u *URLSanitizer) Validate(input string) error {
	if len(input) > u.MaxLength {
		return &ValidationError{
			Message: fmt.Sprintf("URL exceeds maximum length of %d characters", u.MaxLength),
			Code:    "URL_TOO_LONG",
		}
	}

	parsedURL, err := url.Parse(input)
	if err != nil {
		return &ValidationError{
			Message: "invalid URL format",
			Code:    "INVALID_URL_FORMAT",
		}
	}

	// Check allowed schemes
	if len(u.AllowedSchemes) > 0 {
		schemeAllowed := false
		for _, scheme := range u.AllowedSchemes {
			if parsedURL.Scheme == scheme {
				schemeAllowed = true
				break
			}
		}
		if !schemeAllowed {
			return &ValidationError{
				Message: fmt.Sprintf("URL scheme '%s' not allowed", parsedURL.Scheme),
				Code:    "FORBIDDEN_URL_SCHEME",
			}
		}
	}

	return nil
}

// PathSanitizer sanitizes file paths
type PathSanitizer struct {
	MaxLength       int
	AllowAbsolute   bool
	AllowTraversal  bool
	ForbiddenPaths  []string
}

func NewPathSanitizer() *PathSanitizer {
	return &PathSanitizer{
		MaxLength:      1024,
		AllowAbsolute:  false,
		AllowTraversal: false,
		ForbiddenPaths: []string{"/etc", "/proc", "/sys", "/dev"},
	}
}

func (p *PathSanitizer) Sanitize(input string) (string, error) {
	result := strings.TrimSpace(input)

	// Remove null bytes
	result = strings.ReplaceAll(result, "\x00", "")

	// Normalize path separators
	result = strings.ReplaceAll(result, "\\", "/")

	return result, p.Validate(result)
}

func (p *PathSanitizer) Validate(input string) error {
	if len(input) > p.MaxLength {
		return &ValidationError{
			Message: fmt.Sprintf("path exceeds maximum length of %d characters", p.MaxLength),
			Code:    "PATH_TOO_LONG",
		}
	}

	// Check for path traversal if not allowed
	if !p.AllowTraversal && strings.Contains(input, "..") {
		return &ValidationError{
			Message: "path traversal not allowed",
			Code:    "PATH_TRAVERSAL_FORBIDDEN",
		}
	}

	// Check for absolute paths if not allowed
	if !p.AllowAbsolute && strings.HasPrefix(input, "/") {
		return &ValidationError{
			Message: "absolute paths not allowed",
			Code:    "ABSOLUTE_PATH_FORBIDDEN",
		}
	}

	// Check forbidden paths
	for _, forbidden := range p.ForbiddenPaths {
		if strings.HasPrefix(input, forbidden) {
			return &ValidationError{
				Message: fmt.Sprintf("access to path '%s' is forbidden", forbidden),
				Code:    "FORBIDDEN_PATH",
			}
		}
	}

	return nil
}

// SQLSanitizer sanitizes SQL inputs (basic protection)
type SQLSanitizer struct {
	ForbiddenKeywords []string
}

func NewSQLSanitizer() *SQLSanitizer {
	return &SQLSanitizer{
		ForbiddenKeywords: []string{
			"DROP", "DELETE", "INSERT", "UPDATE", "CREATE", "ALTER",
			"EXEC", "EXECUTE", "UNION", "SELECT", "SCRIPT", "JAVASCRIPT",
			"VBSCRIPT", "ONLOAD", "ONERROR", "IFRAME", "OBJECT", "EMBED",
		},
	}
}

func (s *SQLSanitizer) Sanitize(input string) (string, error) {
	result := strings.TrimSpace(input)

	// Escape single quotes
	result = strings.ReplaceAll(result, "'", "''")

	return result, s.Validate(result)
}

func (s *SQLSanitizer) Validate(input string) error {
	upperInput := strings.ToUpper(input)

	for _, keyword := range s.ForbiddenKeywords {
		if strings.Contains(upperInput, keyword) {
			return &ValidationError{
				Message: fmt.Sprintf("contains forbidden SQL keyword: %s", keyword),
				Code:    "FORBIDDEN_SQL_KEYWORD",
			}
		}
	}

	return nil
}

// CommandSanitizer sanitizes shell commands
type CommandSanitizer struct {
	ForbiddenChars    []string
	ForbiddenCommands []string
}

func NewCommandSanitizer() *CommandSanitizer {
	return &CommandSanitizer{
		ForbiddenChars: []string{
			";", "&", "|", "`", "$", "(", ")", "<", ">",
			"*", "?", "[", "]", "{", "}", "\\", "\n", "\r",
		},
		ForbiddenCommands: []string{
			"rm", "del", "format", "fdisk", "mkfs", "dd",
			"sudo", "su", "chmod", "chown", "passwd",
		},
	}
}

func (c *CommandSanitizer) Sanitize(input string) (string, error) {
	result := strings.TrimSpace(input)
	return result, c.Validate(result)
}

func (c *CommandSanitizer) Validate(input string) error {
	// Check for forbidden characters
	for _, char := range c.ForbiddenChars {
		if strings.Contains(input, char) {
			return &ValidationError{
				Message: fmt.Sprintf("contains forbidden character: %s", char),
				Code:    "FORBIDDEN_COMMAND_CHARACTER",
			}
		}
	}

	// Check for forbidden commands
	words := strings.Fields(input)
	if len(words) > 0 {
		command := strings.ToLower(words[0])
		for _, forbidden := range c.ForbiddenCommands {
			if command == forbidden {
				return &ValidationError{
					Message: fmt.Sprintf("forbidden command: %s", forbidden),
					Code:    "FORBIDDEN_COMMAND",
				}
			}
		}
	}

	return nil
}

// CompositeSanitizer combines multiple sanitizers
type CompositeSanitizer struct {
	sanitizers []Sanitizer
}

func NewCompositeSanitizer(sanitizers ...Sanitizer) *CompositeSanitizer {
	return &CompositeSanitizer{
		sanitizers: sanitizers,
	}
}

func (c *CompositeSanitizer) Sanitize(input string) (string, error) {
	result := input

	for _, sanitizer := range c.sanitizers {
		var err error
		result, err = sanitizer.Sanitize(result)
		if err != nil {
			return result, err
		}
	}

	return result, nil
}

func (c *CompositeSanitizer) Validate(input string) error {
	for _, sanitizer := range c.sanitizers {
		if err := sanitizer.Validate(input); err != nil {
			return err
		}
	}
	return nil
}

// SanitizationManager manages sanitization for different field types
type SanitizationManager struct {
	sanitizers map[string]Sanitizer
	auditing   bool
}

func NewSanitizationManager() *SanitizationManager {
	sm := &SanitizationManager{
		sanitizers: make(map[string]Sanitizer),
		auditing:   true,
	}

	// Register default sanitizers
	sm.RegisterSanitizer("string", NewStringSanitizer())
	sm.RegisterSanitizer("email", NewEmailSanitizer())
	sm.RegisterSanitizer("url", NewURLSanitizer())
	sm.RegisterSanitizer("path", NewPathSanitizer())
	sm.RegisterSanitizer("sql", NewSQLSanitizer())
	sm.RegisterSanitizer("command", NewCommandSanitizer())

	return sm
}

func (sm *SanitizationManager) RegisterSanitizer(fieldType string, sanitizer Sanitizer) {
	sm.sanitizers[fieldType] = sanitizer
}

func (sm *SanitizationManager) Sanitize(ctx context.Context, fieldType, fieldName, input string) (string, error) {
	sanitizer, exists := sm.sanitizers[fieldType]
	if !exists {
		// Default to string sanitizer
		sanitizer = sm.sanitizers["string"]
	}

	result, err := sanitizer.Sanitize(input)

	// Audit sanitization if enabled
	if sm.auditing && err != nil {
		sm.auditSanitizationFailure(ctx, fieldType, fieldName, input, err)
	}

	return result, err
}

func (sm *SanitizationManager) Validate(ctx context.Context, fieldType, fieldName, input string) error {
	sanitizer, exists := sm.sanitizers[fieldType]
	if !exists {
		// Default to string sanitizer
		sanitizer = sm.sanitizers["string"]
	}

	err := sanitizer.Validate(input)

	// Audit validation if enabled
	if sm.auditing && err != nil {
		sm.auditValidationFailure(ctx, fieldType, fieldName, input, err)
	}

	return err
}

func (sm *SanitizationManager) auditSanitizationFailure(ctx context.Context, fieldType, fieldName, input string, err error) {
	subject := audit.GetSubject(ctx)
	if subject == nil {
		subject = &audit.Subject{
			ID:   "system",
			Type: "system",
			Name: "sanitization_manager",
		}
	}

	details := map[string]interface{}{
		"field_type": fieldType,
		"field_name": fieldName,
		"input_length": len(input),
		"error": err.Error(),
	}

	audit.LogSecurityEvent(ctx, "input_sanitization_failure", details, audit.EventLevelWarn)
}

func (sm *SanitizationManager) auditValidationFailure(ctx context.Context, fieldType, fieldName, input string, err error) {
	subject := audit.GetSubject(ctx)
	if subject == nil {
		subject = &audit.Subject{
			ID:   "system",
			Type: "system",
			Name: "sanitization_manager",
		}
	}

	details := map[string]interface{}{
		"field_type": fieldType,
		"field_name": fieldName,
		"input_length": len(input),
		"error": err.Error(),
	}

	audit.LogSecurityEvent(ctx, "input_validation_failure", details, audit.EventLevelWarn)
}

// Helper functions for common sanitization tasks
func SanitizeString(input string) (string, error) {
	sanitizer := NewStringSanitizer()
	return sanitizer.Sanitize(input)
}

func ValidateString(input string) error {
	sanitizer := NewStringSanitizer()
	return sanitizer.Validate(input)
}

func SanitizeEmail(input string) (string, error) {
	sanitizer := NewEmailSanitizer()
	return sanitizer.Sanitize(input)
}

func ValidateEmail(input string) error {
	sanitizer := NewEmailSanitizer()
	return sanitizer.Validate(input)
}

func SanitizeURL(input string) (string, error) {
	sanitizer := NewURLSanitizer()
	return sanitizer.Sanitize(input)
}

func ValidateURL(input string) error {
	sanitizer := NewURLSanitizer()
	return sanitizer.Validate(input)
}

func SanitizePath(input string) (string, error) {
	sanitizer := NewPathSanitizer()
	return sanitizer.Sanitize(input)
}

func ValidatePath(input string) error {
	sanitizer := NewPathSanitizer()
	return sanitizer.Validate(input)
}

// Middleware for automatic sanitization
type SanitizationMiddleware struct {
	manager *SanitizationManager
}

func NewSanitizationMiddleware(manager *SanitizationManager) *SanitizationMiddleware {
	return &SanitizationMiddleware{
		manager: manager,
	}
}

func (sm *SanitizationMiddleware) SanitizeMap(ctx context.Context, input map[string]string, fieldTypes map[string]string) (map[string]string, []error) {
	result := make(map[string]string)
	var errors []error

	for field, value := range input {
		fieldType := "string" // default
		if ft, exists := fieldTypes[field]; exists {
			fieldType = ft
		}

		sanitized, err := sm.manager.Sanitize(ctx, fieldType, field, value)
		if err != nil {
			errors = append(errors, err)
		}
		result[field] = sanitized
	}

	return result, errors
}

// Global sanitization manager
var defaultManager = NewSanitizationManager()

// Global convenience functions
func Sanitize(ctx context.Context, fieldType, fieldName, input string) (string, error) {
	return defaultManager.Sanitize(ctx, fieldType, fieldName, input)
}

func Validate(ctx context.Context, fieldType, fieldName, input string) error {
	return defaultManager.Validate(ctx, fieldType, fieldName, input)
}

func RegisterSanitizer(fieldType string, sanitizer Sanitizer) {
	defaultManager.RegisterSanitizer(fieldType, sanitizer)
}

// Character set validation utilities
func IsASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func IsAlphanumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func HasControlCharacters(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return true
		}
	}
	return false
}

func RemoveControlCharacters(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, s)
}