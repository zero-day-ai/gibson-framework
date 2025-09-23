// Package config provides configuration validation and management
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string `json:"field"`
	Value   string `json:"value"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("configuration validation error for '%s': %s", e.Field, e.Message)
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
		messages = append(messages, err.Error())
	}
	return fmt.Sprintf("multiple validation errors: %s", strings.Join(messages, "; "))
}

// ConfigValidator validates configuration values
type ConfigValidator struct {
	rules map[string]ValidationRule
}

// ValidationRule defines a validation rule for a configuration field
type ValidationRule struct {
	Required    bool
	Type        string // string, int, bool, duration, url, file, dir, etc.
	MinLength   int
	MaxLength   int
	MinValue    interface{}
	MaxValue    interface{}
	Pattern     *regexp.Regexp
	AllowedValues []string
	Custom      func(value interface{}) error
	Description string
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{
		rules: make(map[string]ValidationRule),
	}
}

// AddRule adds a validation rule for a field
func (cv *ConfigValidator) AddRule(field string, rule ValidationRule) {
	cv.rules[field] = rule
}

// ValidateConfig validates a configuration map
func (cv *ConfigValidator) ValidateConfig(config map[string]interface{}) ValidationErrors {
	var errors ValidationErrors

	// Check required fields and validate existing ones
	for field, rule := range cv.rules {
		value, exists := config[field]

		if !exists || value == nil {
			if rule.Required {
				errors = append(errors, ValidationError{
					Field:   field,
					Message: "required field is missing",
					Code:    "REQUIRED_FIELD_MISSING",
				})
			}
			continue
		}

		if err := cv.validateField(field, value, rule); err != nil {
			if ve, ok := err.(*ValidationError); ok {
				errors = append(errors, *ve)
			} else {
				errors = append(errors, ValidationError{
					Field:   field,
					Value:   fmt.Sprintf("%v", value),
					Message: err.Error(),
					Code:    "VALIDATION_ERROR",
				})
			}
		}
	}

	return errors
}

// validateField validates a single field
func (cv *ConfigValidator) validateField(field string, value interface{}, rule ValidationRule) error {
	// Convert value to string for most validations
	strValue := fmt.Sprintf("%v", value)

	// Type-specific validation
	switch rule.Type {
	case "string":
		return cv.validateString(field, strValue, rule)
	case "int":
		return cv.validateInt(field, value, rule)
	case "bool":
		return cv.validateBool(field, value, rule)
	case "duration":
		return cv.validateDuration(field, strValue, rule)
	case "url":
		return cv.validateURL(field, strValue, rule)
	case "file":
		return cv.validateFile(field, strValue, rule)
	case "dir":
		return cv.validateDir(field, strValue, rule)
	case "ip":
		return cv.validateIP(field, strValue, rule)
	case "port":
		return cv.validatePort(field, value, rule)
	case "email":
		return cv.validateEmail(field, strValue, rule)
	default:
		return cv.validateString(field, strValue, rule)
	}
}

func (cv *ConfigValidator) validateString(field, value string, rule ValidationRule) error {
	// Length validation
	if rule.MinLength > 0 && len(value) < rule.MinLength {
		return &ValidationError{
			Field:   field,
			Value:   value,
			Message: fmt.Sprintf("minimum length is %d characters", rule.MinLength),
			Code:    "MIN_LENGTH_NOT_MET",
		}
	}

	if rule.MaxLength > 0 && len(value) > rule.MaxLength {
		return &ValidationError{
			Field:   field,
			Value:   value,
			Message: fmt.Sprintf("maximum length is %d characters", rule.MaxLength),
			Code:    "MAX_LENGTH_EXCEEDED",
		}
	}

	// Pattern validation
	if rule.Pattern != nil && !rule.Pattern.MatchString(value) {
		return &ValidationError{
			Field:   field,
			Value:   value,
			Message: "does not match required pattern",
			Code:    "PATTERN_MISMATCH",
		}
	}

	// Allowed values validation
	if len(rule.AllowedValues) > 0 {
		allowed := false
		for _, allowedValue := range rule.AllowedValues {
			if value == allowedValue {
				allowed = true
				break
			}
		}
		if !allowed {
			return &ValidationError{
				Field:   field,
				Value:   value,
				Message: fmt.Sprintf("must be one of: %s", strings.Join(rule.AllowedValues, ", ")),
				Code:    "INVALID_VALUE",
			}
		}
	}

	// Custom validation
	if rule.Custom != nil {
		return rule.Custom(value)
	}

	return nil
}

func (cv *ConfigValidator) validateInt(field string, value interface{}, rule ValidationRule) error {
	var intValue int64
	var err error

	switch v := value.(type) {
	case int:
		intValue = int64(v)
	case int64:
		intValue = v
	case string:
		intValue, err = strconv.ParseInt(v, 10, 64)
		if err != nil {
			return &ValidationError{
				Field:   field,
				Value:   v,
				Message: "must be a valid integer",
				Code:    "INVALID_INTEGER",
			}
		}
	default:
		return &ValidationError{
			Field:   field,
			Value:   fmt.Sprintf("%v", value),
			Message: "must be an integer",
			Code:    "TYPE_MISMATCH",
		}
	}

	// Range validation
	if rule.MinValue != nil {
		if minVal, ok := rule.MinValue.(int64); ok && intValue < minVal {
			return &ValidationError{
				Field:   field,
				Value:   fmt.Sprintf("%d", intValue),
				Message: fmt.Sprintf("minimum value is %d", minVal),
				Code:    "MIN_VALUE_NOT_MET",
			}
		}
	}

	if rule.MaxValue != nil {
		if maxVal, ok := rule.MaxValue.(int64); ok && intValue > maxVal {
			return &ValidationError{
				Field:   field,
				Value:   fmt.Sprintf("%d", intValue),
				Message: fmt.Sprintf("maximum value is %d", maxVal),
				Code:    "MAX_VALUE_EXCEEDED",
			}
		}
	}

	return nil
}

func (cv *ConfigValidator) validateBool(field string, value interface{}, rule ValidationRule) error {
	switch value.(type) {
	case bool:
		return nil
	case string:
		strValue := value.(string)
		if _, err := strconv.ParseBool(strValue); err != nil {
			return &ValidationError{
				Field:   field,
				Value:   strValue,
				Message: "must be a valid boolean (true/false)",
				Code:    "INVALID_BOOLEAN",
			}
		}
		return nil
	default:
		return &ValidationError{
			Field:   field,
			Value:   fmt.Sprintf("%v", value),
			Message: "must be a boolean",
			Code:    "TYPE_MISMATCH",
		}
	}
}

func (cv *ConfigValidator) validateDuration(field, value string, rule ValidationRule) error {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return &ValidationError{
			Field:   field,
			Value:   value,
			Message: "must be a valid duration (e.g., '1h30m', '5s')",
			Code:    "INVALID_DURATION",
		}
	}

	// Range validation
	if rule.MinValue != nil {
		if minDur, ok := rule.MinValue.(time.Duration); ok && duration < minDur {
			return &ValidationError{
				Field:   field,
				Value:   value,
				Message: fmt.Sprintf("minimum duration is %s", minDur),
				Code:    "MIN_DURATION_NOT_MET",
			}
		}
	}

	if rule.MaxValue != nil {
		if maxDur, ok := rule.MaxValue.(time.Duration); ok && duration > maxDur {
			return &ValidationError{
				Field:   field,
				Value:   value,
				Message: fmt.Sprintf("maximum duration is %s", maxDur),
				Code:    "MAX_DURATION_EXCEEDED",
			}
		}
	}

	return nil
}

func (cv *ConfigValidator) validateURL(field, value string, rule ValidationRule) error {
	parsedURL, err := url.Parse(value)
	if err != nil {
		return &ValidationError{
			Field:   field,
			Value:   value,
			Message: "must be a valid URL",
			Code:    "INVALID_URL",
		}
	}

	// Check scheme if specified in allowed values
	if len(rule.AllowedValues) > 0 {
		schemeAllowed := false
		for _, allowedScheme := range rule.AllowedValues {
			if parsedURL.Scheme == allowedScheme {
				schemeAllowed = true
				break
			}
		}
		if !schemeAllowed {
			return &ValidationError{
				Field:   field,
				Value:   value,
				Message: fmt.Sprintf("URL scheme must be one of: %s", strings.Join(rule.AllowedValues, ", ")),
				Code:    "INVALID_URL_SCHEME",
			}
		}
	}

	return nil
}

func (cv *ConfigValidator) validateFile(field, value string, rule ValidationRule) error {
	// Check if file exists
	if _, err := os.Stat(value); err != nil {
		if os.IsNotExist(err) {
			return &ValidationError{
				Field:   field,
				Value:   value,
				Message: "file does not exist",
				Code:    "FILE_NOT_FOUND",
			}
		}
		return &ValidationError{
			Field:   field,
			Value:   value,
			Message: fmt.Sprintf("cannot access file: %s", err.Error()),
			Code:    "FILE_ACCESS_ERROR",
		}
	}

	// Check if it's actually a file
	fileInfo, err := os.Stat(value)
	if err != nil {
		return &ValidationError{
			Field:   field,
			Value:   value,
			Message: fmt.Sprintf("cannot stat file: %s", err.Error()),
			Code:    "FILE_STAT_ERROR",
		}
	}

	if fileInfo.IsDir() {
		return &ValidationError{
			Field:   field,
			Value:   value,
			Message: "path is a directory, not a file",
			Code:    "PATH_IS_DIRECTORY",
		}
	}

	return nil
}

func (cv *ConfigValidator) validateDir(field, value string, rule ValidationRule) error {
	// Check if directory exists
	if _, err := os.Stat(value); err != nil {
		if os.IsNotExist(err) {
			return &ValidationError{
				Field:   field,
				Value:   value,
				Message: "directory does not exist",
				Code:    "DIRECTORY_NOT_FOUND",
			}
		}
		return &ValidationError{
			Field:   field,
			Value:   value,
			Message: fmt.Sprintf("cannot access directory: %s", err.Error()),
			Code:    "DIRECTORY_ACCESS_ERROR",
		}
	}

	// Check if it's actually a directory
	fileInfo, err := os.Stat(value)
	if err != nil {
		return &ValidationError{
			Field:   field,
			Value:   value,
			Message: fmt.Sprintf("cannot stat directory: %s", err.Error()),
			Code:    "DIRECTORY_STAT_ERROR",
		}
	}

	if !fileInfo.IsDir() {
		return &ValidationError{
			Field:   field,
			Value:   value,
			Message: "path is a file, not a directory",
			Code:    "PATH_IS_FILE",
		}
	}

	return nil
}

func (cv *ConfigValidator) validateIP(field, value string, rule ValidationRule) error {
	ip := net.ParseIP(value)
	if ip == nil {
		return &ValidationError{
			Field:   field,
			Value:   value,
			Message: "must be a valid IP address",
			Code:    "INVALID_IP_ADDRESS",
		}
	}

	// Check IP version if specified in allowed values
	if len(rule.AllowedValues) > 0 {
		ipVersion := "ipv6"
		if ip.To4() != nil {
			ipVersion = "ipv4"
		}

		versionAllowed := false
		for _, allowedVersion := range rule.AllowedValues {
			if ipVersion == allowedVersion {
				versionAllowed = true
				break
			}
		}
		if !versionAllowed {
			return &ValidationError{
				Field:   field,
				Value:   value,
				Message: fmt.Sprintf("IP version must be one of: %s", strings.Join(rule.AllowedValues, ", ")),
				Code:    "INVALID_IP_VERSION",
			}
		}
	}

	return nil
}

func (cv *ConfigValidator) validatePort(field string, value interface{}, rule ValidationRule) error {
	var port int64
	var err error

	switch v := value.(type) {
	case int:
		port = int64(v)
	case int64:
		port = v
	case string:
		port, err = strconv.ParseInt(v, 10, 64)
		if err != nil {
			return &ValidationError{
				Field:   field,
				Value:   v,
				Message: "must be a valid port number",
				Code:    "INVALID_PORT",
			}
		}
	default:
		return &ValidationError{
			Field:   field,
			Value:   fmt.Sprintf("%v", value),
			Message: "must be a port number",
			Code:    "TYPE_MISMATCH",
		}
	}

	if port < 1 || port > 65535 {
		return &ValidationError{
			Field:   field,
			Value:   fmt.Sprintf("%d", port),
			Message: "port must be between 1 and 65535",
			Code:    "PORT_OUT_OF_RANGE",
		}
	}

	return nil
}

func (cv *ConfigValidator) validateEmail(field, value string, rule ValidationRule) error {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(value) {
		return &ValidationError{
			Field:   field,
			Value:   value,
			Message: "must be a valid email address",
			Code:    "INVALID_EMAIL",
		}
	}

	return nil
}

// GibsonConfigValidator creates a validator with Gibson-specific rules
func NewGibsonConfigValidator() *ConfigValidator {
	validator := NewConfigValidator()

	// Database configuration
	validator.AddRule("database.driver", ValidationRule{
		Required:      true,
		Type:         "string",
		AllowedValues: []string{"sqlite", "postgres", "mysql"},
		Description:  "Database driver to use",
	})

	validator.AddRule("database.dsn", ValidationRule{
		Required:    true,
		Type:       "string",
		MinLength:  1,
		Description: "Database connection string",
	})

	validator.AddRule("database.max_connections", ValidationRule{
		Type:        "int",
		MinValue:    int64(1),
		MaxValue:    int64(1000),
		Description: "Maximum number of database connections",
	})

	validator.AddRule("database.connection_timeout", ValidationRule{
		Type:        "duration",
		MinValue:    time.Second,
		MaxValue:    time.Minute * 5,
		Description: "Database connection timeout",
	})

	// Server configuration
	validator.AddRule("server.host", ValidationRule{
		Type:        "string",
		Description: "Server host address",
	})

	validator.AddRule("server.port", ValidationRule{
		Required:    true,
		Type:       "port",
		Description: "Server port number",
	})

	validator.AddRule("server.tls.enabled", ValidationRule{
		Type:        "bool",
		Description: "Enable TLS/HTTPS",
	})

	validator.AddRule("server.tls.cert_file", ValidationRule{
		Type:        "file",
		Description: "TLS certificate file path",
	})

	validator.AddRule("server.tls.key_file", ValidationRule{
		Type:        "file",
		Description: "TLS private key file path",
	})

	// Logging configuration
	validator.AddRule("logging.level", ValidationRule{
		Required:      true,
		Type:         "string",
		AllowedValues: []string{"debug", "info", "warn", "error"},
		Description:  "Logging level",
	})

	validator.AddRule("logging.format", ValidationRule{
		Type:         "string",
		AllowedValues: []string{"text", "json"},
		Description:  "Log output format",
	})

	validator.AddRule("logging.file", ValidationRule{
		Type:        "string",
		Description: "Log file path (optional)",
	})

	// Security configuration
	validator.AddRule("security.rate_limit.enabled", ValidationRule{
		Type:        "bool",
		Description: "Enable rate limiting",
	})

	validator.AddRule("security.rate_limit.requests_per_minute", ValidationRule{
		Type:        "int",
		MinValue:    int64(1),
		MaxValue:    int64(10000),
		Description: "Maximum requests per minute",
	})

	validator.AddRule("security.audit_log.enabled", ValidationRule{
		Type:        "bool",
		Description: "Enable audit logging",
	})

	validator.AddRule("security.audit_log.file", ValidationRule{
		Type:        "string",
		Description: "Audit log file path",
	})

	// Plugin configuration
	validator.AddRule("plugins.directory", ValidationRule{
		Type:        "dir",
		Description: "Plugin directory path",
	})

	validator.AddRule("plugins.timeout", ValidationRule{
		Type:        "duration",
		MinValue:    time.Second,
		MaxValue:    time.Hour,
		Description: "Plugin execution timeout",
	})

	validator.AddRule("plugins.max_concurrent", ValidationRule{
		Type:        "int",
		MinValue:    int64(1),
		MaxValue:    int64(100),
		Description: "Maximum concurrent plugin executions",
	})

	// Metrics configuration
	validator.AddRule("metrics.enabled", ValidationRule{
		Type:        "bool",
		Description: "Enable metrics collection",
	})

	validator.AddRule("metrics.endpoint", ValidationRule{
		Type:        "string",
		Description: "Metrics endpoint path",
	})

	validator.AddRule("metrics.interval", ValidationRule{
		Type:        "duration",
		MinValue:    time.Second,
		MaxValue:    time.Hour,
		Description: "Metrics collection interval",
	})

	return validator
}

// ConfigValidationResult represents the result of configuration validation
type ConfigValidationResult struct {
	Valid   bool              `json:"valid"`
	Errors  ValidationErrors  `json:"errors,omitempty"`
	Warnings []string         `json:"warnings,omitempty"`
}

// ValidateGibsonConfig validates a Gibson configuration
func ValidateGibsonConfig(config map[string]interface{}) *ConfigValidationResult {
	validator := NewGibsonConfigValidator()
	errors := validator.ValidateConfig(config)

	result := &ConfigValidationResult{
		Valid:  len(errors) == 0,
		Errors: errors,
	}

	// Add warnings for common configuration issues
	result.Warnings = generateConfigWarnings(config)

	return result
}

func generateConfigWarnings(config map[string]interface{}) []string {
	var warnings []string

	// Check for potential security issues
	if tlsEnabled, ok := config["server.tls.enabled"].(bool); ok && !tlsEnabled {
		warnings = append(warnings, "TLS is disabled - consider enabling HTTPS for production")
	}

	if auditEnabled, ok := config["security.audit_log.enabled"].(bool); ok && !auditEnabled {
		warnings = append(warnings, "Audit logging is disabled - consider enabling for security compliance")
	}

	if rateLimitEnabled, ok := config["security.rate_limit.enabled"].(bool); ok && !rateLimitEnabled {
		warnings = append(warnings, "Rate limiting is disabled - consider enabling for production")
	}

	// Check for development vs production settings
	if logLevel, ok := config["logging.level"].(string); ok && logLevel == "debug" {
		warnings = append(warnings, "Debug logging is enabled - consider using 'info' or 'warn' in production")
	}

	return warnings
}

// Helper function to validate configuration from environment variables
func ValidateEnvConfig(envPrefix string) *ConfigValidationResult {
	config := make(map[string]interface{})

	// Convert environment variables to config map
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, envPrefix) {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimPrefix(parts[0], envPrefix)
				key = strings.ToLower(strings.ReplaceAll(key, "_", "."))
				config[key] = parts[1]
			}
		}
	}

	return ValidateGibsonConfig(config)
}

// Helper function to validate configuration from file
func ValidateConfigFile(filename string) (*ConfigValidationResult, error) {
	// This would typically use a config file parser like Viper
	// For now, return a simple implementation
	if _, err := os.Stat(filename); err != nil {
		return nil, fmt.Errorf("config file not found: %s", filename)
	}

	// In a real implementation, you would parse the file format
	// (YAML, JSON, TOML, etc.) and convert to a map
	config := make(map[string]interface{})

	return ValidateGibsonConfig(config), nil
}

// Security-focused validation helpers
func ValidateSecureConfig(config map[string]interface{}) []string {
	var issues []string

	// Check for insecure defaults
	if host, ok := config["server.host"].(string); ok && host == "0.0.0.0" {
		issues = append(issues, "Server is bound to all interfaces (0.0.0.0) - consider using 127.0.0.1 for localhost only")
	}

	// Check for weak configurations
	if maxConn, ok := config["database.max_connections"].(int); ok && maxConn > 100 {
		issues = append(issues, "High number of database connections may impact performance")
	}

	// Check for missing security configurations
	if _, ok := config["security.rate_limit.enabled"]; !ok {
		issues = append(issues, "Rate limiting configuration is missing")
	}

	if _, ok := config["security.audit_log.enabled"]; !ok {
		issues = append(issues, "Audit logging configuration is missing")
	}

	return issues
}