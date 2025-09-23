// Package validation provides comprehensive input validation and sanitization
// for the Gibson security testing framework
package validation

import (
	"encoding/json"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Security constants for input validation
const (
	// Maximum input sizes to prevent DoS attacks
	MaxStringLength       = 65536  // 64KB
	MaxJSONSize          = 1048576 // 1MB
	MaxPathLength        = 4096    // 4KB
	MaxEmailLength       = 320     // RFC 5321 limit
	MaxURLLength         = 2048    // Most browsers support up to 2048
	MaxHeaderLength      = 8192    // 8KB
	MaxCredentialLength  = 4096    // 4KB for encrypted credentials
	MaxDescriptionLength = 10000   // 10KB
	MaxTagLength         = 256     // 256 chars per tag
	MaxTagCount          = 100     // Max number of tags

	// Minimum lengths for security
	MinPasswordLength    = 8
	MinAPIKeyLength     = 16
	MinTokenLength      = 32

	// Common dangerous characters that require special handling
	SQLInjectionChars   = "';\"\\-/*+%<>&|(){}[]`~"
	CommandInjectionChars = ";|&$`(){}[]<>*?\"'~"
	PathTraversalChars  = "../\\./"
	ScriptInjectionChars = "<>\"'&"
)

// ValidationError represents a validation error with context
type ValidationError struct {
	Field     string                 `json:"field"`
	Value     string                 `json:"value,omitempty"`
	Message   string                 `json:"message"`
	Code      string                 `json:"code"`
	Severity  string                 `json:"severity"`
	Context   map[string]interface{} `json:"context,omitempty"`
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation error for '%s': %s", e.Field, e.Message)
	}
	return fmt.Sprintf("validation error: %s", e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}
	if len(e) == 1 {
		return e[0].Error()
	}
	var messages []string
	for _, err := range e {
		messages = append(messages, err.Message)
	}
	return fmt.Sprintf("multiple validation errors: %s", strings.Join(messages, "; "))
}

// HasCritical returns true if any error has critical severity
func (e ValidationErrors) HasCritical() bool {
	for _, err := range e {
		if err.Severity == "critical" {
			return true
		}
	}
	return false
}

// Filter returns only errors matching the specified severity
func (e ValidationErrors) Filter(severity string) ValidationErrors {
	var filtered ValidationErrors
	for _, err := range e {
		if err.Severity == severity {
			filtered = append(filtered, err)
		}
	}
	return filtered
}

// InputValidator provides comprehensive input validation
type InputValidator struct {
	allowHTMLContent bool
	maxStringLength  int
	enableLogging    bool
}

// NewInputValidator creates a new input validator with default settings
func NewInputValidator() *InputValidator {
	return &InputValidator{
		allowHTMLContent: false,
		maxStringLength:  MaxStringLength,
		enableLogging:    true,
	}
}

// WithHTMLAllowed enables HTML content validation (with sanitization)
func (v *InputValidator) WithHTMLAllowed() *InputValidator {
	v.allowHTMLContent = true
	return v
}

// WithMaxLength sets custom maximum string length
func (v *InputValidator) WithMaxLength(length int) *InputValidator {
	v.maxStringLength = length
	return v
}

// ValidateString performs comprehensive string validation
func (v *InputValidator) ValidateString(field, value string, options ...StringOption) ValidationErrors {
	var errors ValidationErrors

	config := &StringConfig{
		MinLength:        0,
		MaxLength:        v.maxStringLength,
		AllowEmpty:       true,
		Pattern:          nil,
		AllowedChars:     "",
		ForbiddenChars:   "",
		CheckSQLInjection: true,
		CheckXSS:         true,
		CheckCommandInjection: true,
		CheckPathTraversal: true,
	}

	for _, option := range options {
		option(config)
	}

	// Length validation
	if !config.AllowEmpty && len(value) == 0 {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    "",
			Message:  "field is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "high",
		})
		return errors
	}

	if len(value) < config.MinLength {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    truncateValue(value, 100),
			Message:  fmt.Sprintf("minimum length is %d characters", config.MinLength),
			Code:     "MIN_LENGTH_NOT_MET",
			Severity: "medium",
		})
	}

	if len(value) > config.MaxLength {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    truncateValue(value, 100),
			Message:  fmt.Sprintf("maximum length is %d characters", config.MaxLength),
			Code:     "MAX_LENGTH_EXCEEDED",
			Severity: "high",
		})
	}

	// UTF-8 validation
	if !utf8.ValidString(value) {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "contains invalid UTF-8 sequences",
			Code:     "INVALID_UTF8",
			Severity: "high",
		})
	}

	// Control character validation
	if hasControlCharacters(value) {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "contains dangerous control characters",
			Code:     "CONTROL_CHARACTERS",
			Severity: "high",
		})
	}

	// Pattern validation
	if config.Pattern != nil && !config.Pattern.MatchString(value) {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    truncateValue(value, 100),
			Message:  "does not match required pattern",
			Code:     "PATTERN_MISMATCH",
			Severity: "medium",
		})
	}

	// Character allowlist/denylist
	if config.AllowedChars != "" && !containsOnlyChars(value, config.AllowedChars) {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "contains forbidden characters",
			Code:     "FORBIDDEN_CHARACTERS",
			Severity: "medium",
		})
	}

	if config.ForbiddenChars != "" && containsAnyChars(value, config.ForbiddenChars) {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "contains forbidden characters",
			Code:     "FORBIDDEN_CHARACTERS",
			Severity: "medium",
		})
	}

	// Security validations
	if config.CheckSQLInjection && hasSQLInjectionPattern(value) {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "potential SQL injection detected",
			Code:     "SQL_INJECTION_DETECTED",
			Severity: "critical",
		})
	}

	if config.CheckXSS && hasXSSPattern(value) {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "potential XSS attack detected",
			Code:     "XSS_DETECTED",
			Severity: "critical",
		})
	}

	if config.CheckCommandInjection && hasCommandInjectionPattern(value) {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "potential command injection detected",
			Code:     "COMMAND_INJECTION_DETECTED",
			Severity: "critical",
		})
	}

	if config.CheckPathTraversal && hasPathTraversalPattern(value) {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "potential path traversal attack detected",
			Code:     "PATH_TRAVERSAL_DETECTED",
			Severity: "critical",
		})
	}

	return errors
}

// ValidateEmail validates email addresses according to RFC 5322
func (v *InputValidator) ValidateEmail(field, value string) ValidationErrors {
	var errors ValidationErrors

	if len(value) == 0 {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "email address is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "high",
		})
		return errors
	}

	if len(value) > MaxEmailLength {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    truncateValue(value, 50),
			Message:  fmt.Sprintf("email address exceeds maximum length of %d characters", MaxEmailLength),
			Code:     "MAX_LENGTH_EXCEEDED",
			Severity: "medium",
		})
	}

	// Use net/mail for RFC 5322 compliance
	addr, err := mail.ParseAddress(value)
	if err != nil {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    truncateValue(value, 50),
			Message:  "invalid email address format",
			Code:     "INVALID_EMAIL_FORMAT",
			Severity: "medium",
		})
		return errors
	}

	// Additional security checks
	emailValue := addr.Address
	if hasSQLInjectionPattern(emailValue) || hasXSSPattern(emailValue) {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "email contains potentially malicious content",
			Code:     "MALICIOUS_EMAIL_CONTENT",
			Severity: "high",
		})
	}

	return errors
}

// ValidateURL validates URLs with comprehensive security checks
func (v *InputValidator) ValidateURL(field, value string, allowedSchemes ...string) ValidationErrors {
	var errors ValidationErrors

	if len(value) == 0 {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "URL is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "high",
		})
		return errors
	}

	if len(value) > MaxURLLength {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    truncateValue(value, 100),
			Message:  fmt.Sprintf("URL exceeds maximum length of %d characters", MaxURLLength),
			Code:     "MAX_LENGTH_EXCEEDED",
			Severity: "medium",
		})
	}

	parsedURL, err := url.Parse(value)
	if err != nil {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    truncateValue(value, 100),
			Message:  "invalid URL format",
			Code:     "INVALID_URL_FORMAT",
			Severity: "medium",
		})
		return errors
	}

	// Scheme validation
	if len(allowedSchemes) > 0 {
		allowed := false
		for _, scheme := range allowedSchemes {
			if parsedURL.Scheme == scheme {
				allowed = true
				break
			}
		}
		if !allowed {
			errors = append(errors, ValidationError{
				Field:    field,
				Value:    parsedURL.Scheme,
				Message:  fmt.Sprintf("URL scheme must be one of: %s", strings.Join(allowedSchemes, ", ")),
				Code:     "INVALID_URL_SCHEME",
				Severity: "medium",
			})
		}
	}

	// Security checks for dangerous schemes
	dangerousSchemes := []string{"javascript", "data", "vbscript", "file"}
	for _, dangerous := range dangerousSchemes {
		if strings.EqualFold(parsedURL.Scheme, dangerous) {
			errors = append(errors, ValidationError{
				Field:    field,
				Value:    parsedURL.Scheme,
				Message:  fmt.Sprintf("dangerous URL scheme '%s' not allowed", parsedURL.Scheme),
				Code:     "DANGEROUS_URL_SCHEME",
				Severity: "critical",
			})
		}
	}

	// Check for localhost/private IP access (potential SSRF)
	if parsedURL.Host != "" {
		host := parsedURL.Host
		if strings.Contains(host, ":") {
			host, _, _ = net.SplitHostPort(host)
		}

		if ip := net.ParseIP(host); ip != nil {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
				errors = append(errors, ValidationError{
					Field:    field,
					Message:  "URLs pointing to private/internal addresses are not allowed",
					Code:     "PRIVATE_IP_ACCESS",
					Severity: "high",
					Context: map[string]interface{}{
						"host": host,
						"ip":   ip.String(),
					},
				})
			}
		}

		// Check for suspicious hostnames
		suspiciousHosts := []string{"localhost", "127.0.0.1", "0.0.0.0", "[::]", "::1"}
		for _, suspicious := range suspiciousHosts {
			if strings.EqualFold(host, suspicious) {
				errors = append(errors, ValidationError{
					Field:    field,
					Message:  "URLs pointing to localhost are not allowed",
					Code:     "LOCALHOST_ACCESS",
					Severity: "high",
				})
			}
		}
	}

	return errors
}

// ValidatePath validates file paths with security checks
func (v *InputValidator) ValidatePath(field, value string, mustExist bool) ValidationErrors {
	var errors ValidationErrors

	if len(value) == 0 {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "path is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "high",
		})
		return errors
	}

	if len(value) > MaxPathLength {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    truncateValue(value, 100),
			Message:  fmt.Sprintf("path exceeds maximum length of %d characters", MaxPathLength),
			Code:     "MAX_LENGTH_EXCEEDED",
			Severity: "medium",
		})
	}

	// Path traversal detection
	if hasPathTraversalPattern(value) {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "path contains traversal patterns",
			Code:     "PATH_TRAVERSAL_DETECTED",
			Severity: "critical",
		})
	}

	// Null byte injection
	if strings.Contains(value, "\x00") {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "path contains null bytes",
			Code:     "NULL_BYTE_INJECTION",
			Severity: "critical",
		})
	}

	// Normalize and validate cleaned path
	cleanPath := filepath.Clean(value)
	if cleanPath != value {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "path contains unnecessary elements",
			Code:     "PATH_NOT_NORMALIZED",
			Severity: "medium",
			Context: map[string]interface{}{
				"normalized": cleanPath,
			},
		})
	}

	return errors
}

// ValidateUUID validates UUID format
func (v *InputValidator) ValidateUUID(field, value string) ValidationErrors {
	var errors ValidationErrors

	if len(value) == 0 {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "UUID is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "high",
		})
		return errors
	}

	if _, err := uuid.Parse(value); err != nil {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    value,
			Message:  "invalid UUID format",
			Code:     "INVALID_UUID_FORMAT",
			Severity: "medium",
		})
	}

	return errors
}

// ValidateJSON validates JSON content and structure
func (v *InputValidator) ValidateJSON(field, value string, maxSize int) ValidationErrors {
	var errors ValidationErrors

	if len(value) == 0 {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "JSON is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "high",
		})
		return errors
	}

	if maxSize == 0 {
		maxSize = MaxJSONSize
	}

	if len(value) > maxSize {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  fmt.Sprintf("JSON exceeds maximum size of %d bytes", maxSize),
			Code:     "MAX_SIZE_EXCEEDED",
			Severity: "high",
		})
	}

	// Parse JSON to validate structure
	var parsed interface{}
	if err := json.Unmarshal([]byte(value), &parsed); err != nil {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  fmt.Sprintf("invalid JSON format: %s", err.Error()),
			Code:     "INVALID_JSON_FORMAT",
			Severity: "medium",
		})
	}

	// Security check for potential payloads
	if hasXSSPattern(value) {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "JSON contains potential XSS payload",
			Code:     "XSS_IN_JSON",
			Severity: "high",
		})
	}

	return errors
}

// ValidateCredential validates credential values with security requirements
func (v *InputValidator) ValidateCredential(field, credentialType, value string) ValidationErrors {
	var errors ValidationErrors

	if len(value) == 0 {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "credential value is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
		return errors
	}

	if len(value) > MaxCredentialLength {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  fmt.Sprintf("credential exceeds maximum length of %d characters", MaxCredentialLength),
			Code:     "MAX_LENGTH_EXCEEDED",
			Severity: "high",
		})
	}

	// Type-specific validation
	switch strings.ToLower(credentialType) {
	case "api_key":
		if len(value) < MinAPIKeyLength {
			errors = append(errors, ValidationError{
				Field:    field,
				Message:  fmt.Sprintf("API key must be at least %d characters", MinAPIKeyLength),
				Code:     "MIN_LENGTH_NOT_MET",
				Severity: "medium",
			})
		}
	case "bearer":
		if len(value) < MinTokenLength {
			errors = append(errors, ValidationError{
				Field:    field,
				Message:  fmt.Sprintf("bearer token must be at least %d characters", MinTokenLength),
				Code:     "MIN_LENGTH_NOT_MET",
				Severity: "medium",
			})
		}
	case "basic":
		// Basic auth should be base64 encoded
		if !isBase64(value) {
			errors = append(errors, ValidationError{
				Field:    field,
				Message:  "basic auth credential must be base64 encoded",
				Code:     "INVALID_ENCODING",
				Severity: "medium",
			})
		}
	}

	// Entropy check for strong credentials
	if entropy := calculateEntropy(value); entropy < 3.0 {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "credential has low entropy and may be weak",
			Code:     "LOW_ENTROPY",
			Severity: "medium",
			Context: map[string]interface{}{
				"entropy": entropy,
			},
		})
	}

	return errors
}

// ValidatePort validates network port numbers
func (v *InputValidator) ValidatePort(field string, port int) ValidationErrors {
	var errors ValidationErrors

	if port < 1 || port > 65535 {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    strconv.Itoa(port),
			Message:  "port must be between 1 and 65535",
			Code:     "PORT_OUT_OF_RANGE",
			Severity: "medium",
		})
	}

	// Warn about well-known system ports
	if port < 1024 {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    strconv.Itoa(port),
			Message:  "using system/privileged port (< 1024)",
			Code:     "SYSTEM_PORT_WARNING",
			Severity: "low",
		})
	}

	return errors
}

// ValidateIPAddress validates IP addresses
func (v *InputValidator) ValidateIPAddress(field, value string, allowedVersions ...string) ValidationErrors {
	var errors ValidationErrors

	if len(value) == 0 {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "IP address is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "high",
		})
		return errors
	}

	ip := net.ParseIP(value)
	if ip == nil {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    value,
			Message:  "invalid IP address format",
			Code:     "INVALID_IP_FORMAT",
			Severity: "medium",
		})
		return errors
	}

	// Version validation
	if len(allowedVersions) > 0 {
		ipVersion := "ipv6"
		if ip.To4() != nil {
			ipVersion = "ipv4"
		}

		allowed := false
		for _, version := range allowedVersions {
			if strings.EqualFold(version, ipVersion) {
				allowed = true
				break
			}
		}

		if !allowed {
			errors = append(errors, ValidationError{
				Field:    field,
				Value:    value,
				Message:  fmt.Sprintf("IP version must be one of: %s", strings.Join(allowedVersions, ", ")),
				Code:     "INVALID_IP_VERSION",
				Severity: "medium",
			})
		}
	}

	// Security checks
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    value,
			Message:  "private/internal IP addresses may pose security risks",
			Code:     "PRIVATE_IP_WARNING",
			Severity: "low",
		})
	}

	return errors
}

// ValidateDuration validates time duration strings
func (v *InputValidator) ValidateDuration(field, value string, min, max time.Duration) ValidationErrors {
	var errors ValidationErrors

	if len(value) == 0 {
		errors = append(errors, ValidationError{
			Field:    field,
			Message:  "duration is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "high",
		})
		return errors
	}

	duration, err := time.ParseDuration(value)
	if err != nil {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    value,
			Message:  "invalid duration format (e.g., '1h30m', '5s')",
			Code:     "INVALID_DURATION_FORMAT",
			Severity: "medium",
		})
		return errors
	}

	if min > 0 && duration < min {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    value,
			Message:  fmt.Sprintf("duration must be at least %s", min),
			Code:     "MIN_DURATION_NOT_MET",
			Severity: "medium",
		})
	}

	if max > 0 && duration > max {
		errors = append(errors, ValidationError{
			Field:    field,
			Value:    value,
			Message:  fmt.Sprintf("duration must not exceed %s", max),
			Code:     "MAX_DURATION_EXCEEDED",
			Severity: "medium",
		})
	}

	return errors
}

// StringConfig holds configuration for string validation
type StringConfig struct {
	MinLength             int
	MaxLength             int
	AllowEmpty            bool
	Pattern               *regexp.Regexp
	AllowedChars          string
	ForbiddenChars        string
	CheckSQLInjection     bool
	CheckXSS              bool
	CheckCommandInjection bool
	CheckPathTraversal    bool
}

// StringOption is a functional option for string validation
type StringOption func(*StringConfig)

// WithMinLength sets minimum string length
func WithMinLength(length int) StringOption {
	return func(c *StringConfig) {
		c.MinLength = length
	}
}

// WithMaxLength sets maximum string length
func WithMaxLength(length int) StringOption {
	return func(c *StringConfig) {
		c.MaxLength = length
	}
}

// WithPattern sets regex pattern requirement
func WithPattern(pattern *regexp.Regexp) StringOption {
	return func(c *StringConfig) {
		c.Pattern = pattern
	}
}

// WithAllowedChars sets character allowlist
func WithAllowedChars(chars string) StringOption {
	return func(c *StringConfig) {
		c.AllowedChars = chars
	}
}

// WithForbiddenChars sets character denylist
func WithForbiddenChars(chars string) StringOption {
	return func(c *StringConfig) {
		c.ForbiddenChars = chars
	}
}

// WithoutSecurityChecks disables injection attack detection
func WithoutSecurityChecks() StringOption {
	return func(c *StringConfig) {
		c.CheckSQLInjection = false
		c.CheckXSS = false
		c.CheckCommandInjection = false
		c.CheckPathTraversal = false
	}
}

// RequiredString marks string as required (not empty)
func RequiredString() StringOption {
	return func(c *StringConfig) {
		c.AllowEmpty = false
	}
}

// Helper functions for security pattern detection

func hasSQLInjectionPattern(value string) bool {
	lowerValue := strings.ToLower(value)

	// Common SQL injection patterns
	sqlPatterns := []string{
		"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_",
		"union", "select", "insert", "update", "delete", "drop",
		"exec", "execute", "script", "declare", "create", "alter",
		"or 1=1", "and 1=1", "' or '1'='1", "\" or \"1\"=\"1",
		"'; drop table", "'; delete from", "'; update",
	}

	for _, pattern := range sqlPatterns {
		if strings.Contains(lowerValue, pattern) {
			return true
		}
	}

	return false
}

func hasXSSPattern(value string) bool {
	lowerValue := strings.ToLower(value)

	// Common XSS patterns
	xssPatterns := []string{
		"<script", "</script>", "javascript:", "vbscript:", "onload=",
		"onerror=", "onclick=", "onmouseover=", "onfocus=", "onblur=",
		"alert(", "confirm(", "prompt(", "document.cookie", "window.location",
		"eval(", "expression(", "url(javascript:", "style=",
		"<iframe", "<object", "<embed", "<form", "src=javascript:",
	}

	for _, pattern := range xssPatterns {
		if strings.Contains(lowerValue, pattern) {
			return true
		}
	}

	return false
}

func hasCommandInjectionPattern(value string) bool {
	// Common command injection patterns
	cmdPatterns := []string{
		";", "|", "&", "$", "`", "$(", "||", "&&",
		"cmd", "sh", "bash", "powershell", "exec", "system",
		"/bin/", "/etc/passwd", "/proc/", "../",
		"nc ", "netcat", "wget", "curl", "ping",
	}

	for _, pattern := range cmdPatterns {
		if strings.Contains(value, pattern) {
			return true
		}
	}

	return false
}

func hasPathTraversalPattern(value string) bool {
	// Path traversal patterns
	traversalPatterns := []string{
		"../", "..\\", "....//", "....\\\\",
		"%2e%2e%2f", "%2e%2e%5c", "..%2f", "..%5c",
		"%252e%252e%252f", "%c0%ae%c0%ae%c0%af",
		"\x00", "%00",
	}

	lowerValue := strings.ToLower(value)
	for _, pattern := range traversalPatterns {
		if strings.Contains(lowerValue, pattern) {
			return true
		}
	}

	return false
}

func hasControlCharacters(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return true
		}
	}
	return false
}

func containsOnlyChars(value, allowedChars string) bool {
	for _, r := range value {
		if !strings.ContainsRune(allowedChars, r) {
			return false
		}
	}
	return true
}

func containsAnyChars(value, forbiddenChars string) bool {
	for _, r := range value {
		if strings.ContainsRune(forbiddenChars, r) {
			return true
		}
	}
	return false
}

func isBase64(s string) bool {
	// Simple check for base64 format
	pattern := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	return pattern.MatchString(s) && len(s)%4 == 0
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	charCount := make(map[rune]int)
	for _, r := range s {
		charCount[r]++
	}

	entropy := 0.0
	length := float64(len(s))

	for _, count := range charCount {
		if count > 0 {
			freq := float64(count) / length
			entropy -= freq * (1.44269504088896 * freq) // log2(freq)
		}
	}

	return entropy
}

func truncateValue(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}
	return value[:maxLen] + "..."
}