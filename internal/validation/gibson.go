// Package validation provides Gibson-specific validation functions
package validation

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Gibson-specific validation patterns and constants
var (
	// Model name patterns for different providers
	OpenAIModelPattern     = regexp.MustCompile(`^(gpt-[34](\.\d+)?(-turbo)?(-\d{4})?|text-davinci-\d+|code-davinci-\d+)$`)
	AnthropicModelPattern  = regexp.MustCompile(`^claude-(instant-|sonnet-|opus-)?[\w\-\.]+$`)
	HuggingFaceModelPattern = regexp.MustCompile(`^[\w\-\.]+/[\w\-\.]+$`)
	CustomModelPattern     = regexp.MustCompile(`^[\w\-\.]+$`)

	// API version patterns
	APIVersionPattern = regexp.MustCompile(`^v?\d+(\.\d+)*(-[\w\-]+)?$`)

	// Provider endpoint patterns
	OpenAIEndpointPattern     = regexp.MustCompile(`^https://api\.openai\.com/v\d+/`)
	AnthropicEndpointPattern  = regexp.MustCompile(`^https://api\.anthropic\.com/v\d+/`)
	AzureEndpointPattern      = regexp.MustCompile(`^https://[\w\-]+\.openai\.azure\.com/`)
	GoogleEndpointPattern     = regexp.MustCompile(`^https://[\w\-]+\.googleapis\.com/`)
	OllamaEndpointPattern     = regexp.MustCompile(`^https?://[\w\-\.:]+(:\d+)?/api/`)

	// Security-related patterns
	PayloadContentPattern = regexp.MustCompile(`^[\x20-\x7E\s]*$`) // Printable ASCII + whitespace
	TagPattern           = regexp.MustCompile(`^[\w\-\.]+$`)
	ScheduleExpressionPattern = regexp.MustCompile(`^(\*|[0-5]?\d)\s+(\*|[01]?\d|2[0-3])\s+(\*|[0-2]?\d|3[01])\s+(\*|[0-2]?\d|1[0-2])\s+(\*|[0-6])$`) // Cron format
)

// GibsonValidator provides Gibson-specific validation functions
type GibsonValidator struct {
	inputValidator *InputValidator
	sanitizer      *Sanitizer
}

// NewGibsonValidator creates a new Gibson-specific validator
func NewGibsonValidator() *GibsonValidator {
	return &GibsonValidator{
		inputValidator: NewInputValidator(),
		sanitizer:      NewSanitizer(),
	}
}

// ValidateTarget validates a Gibson Target configuration
func (gv *GibsonValidator) ValidateTarget(target interface{}) ValidationErrors {
	var errors ValidationErrors

	// Use type assertion or reflection to extract fields
	// This is a simplified version - in practice, you'd extract from the actual Target struct
	name, nameOk := extractStringField(target, "name")
	targetType, typeOk := extractStringField(target, "type")
	provider, providerOk := extractStringField(target, "provider")
	model, _ := extractStringField(target, "model")
	url, _ := extractStringField(target, "url")
	apiVersion, _ := extractStringField(target, "api_version")
	description, _ := extractStringField(target, "description")
	tags, _ := extractStringSliceField(target, "tags")

	// Validate required fields
	if !nameOk || name == "" {
		errors = append(errors, ValidationError{
			Field:    "name",
			Message:  "target name is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.inputValidator.ValidateString("name", name,
			WithMinLength(1),
			WithMaxLength(255),
			RequiredString(),
			WithForbiddenChars(SQLInjectionChars+ScriptInjectionChars))...)
	}

	if !typeOk || targetType == "" {
		errors = append(errors, ValidationError{
			Field:    "type",
			Message:  "target type is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.ValidateTargetType(targetType)...)
	}

	if !providerOk || provider == "" {
		errors = append(errors, ValidationError{
			Field:    "provider",
			Message:  "provider is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.ValidateProvider(provider)...)
	}

	// Validate optional fields
	if model != "" {
		errors = append(errors, gv.ValidateModelName(provider, model)...)
	}

	if url != "" {
		errors = append(errors, gv.ValidateProviderURL(provider, url)...)
	}

	if apiVersion != "" {
		errors = append(errors, gv.ValidateAPIVersion(apiVersion)...)
	}

	if description != "" {
		errors = append(errors, gv.inputValidator.ValidateString("description", description,
			WithMaxLength(MaxDescriptionLength))...)
	}

	if len(tags) > 0 {
		errors = append(errors, gv.ValidateTags(tags)...)
	}

	return errors
}

// ValidateCredential validates a Gibson Credential configuration
func (gv *GibsonValidator) ValidateCredential(credential interface{}) ValidationErrors {
	var errors ValidationErrors

	name, nameOk := extractStringField(credential, "name")
	credType, typeOk := extractStringField(credential, "type")
	provider, providerOk := extractStringField(credential, "provider")
	value, valueOk := extractStringField(credential, "value")
	description, _ := extractStringField(credential, "description")
	tags, _ := extractStringSliceField(credential, "tags")
	rotationInterval, _ := extractStringField(credential, "rotation_interval")

	// Validate required fields
	if !nameOk || name == "" {
		errors = append(errors, ValidationError{
			Field:    "name",
			Message:  "credential name is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.inputValidator.ValidateString("name", name,
			WithMinLength(1),
			WithMaxLength(255),
			RequiredString())...)
	}

	if !typeOk || credType == "" {
		errors = append(errors, ValidationError{
			Field:    "type",
			Message:  "credential type is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.ValidateCredentialType(credType)...)
	}

	if !providerOk || provider == "" {
		errors = append(errors, ValidationError{
			Field:    "provider",
			Message:  "provider is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.ValidateProvider(provider)...)
	}

	if !valueOk || value == "" {
		errors = append(errors, ValidationError{
			Field:    "value",
			Message:  "credential value is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.inputValidator.ValidateCredential("value", credType, value)...)
	}

	// Validate optional fields
	if description != "" {
		errors = append(errors, gv.inputValidator.ValidateString("description", description,
			WithMaxLength(MaxDescriptionLength))...)
	}

	if len(tags) > 0 {
		errors = append(errors, gv.ValidateTags(tags)...)
	}

	if rotationInterval != "" {
		errors = append(errors, gv.ValidateRotationInterval(rotationInterval)...)
	}

	return errors
}

// ValidatePayload validates a Gibson Payload configuration
func (gv *GibsonValidator) ValidatePayload(payload interface{}) ValidationErrors {
	var errors ValidationErrors

	name, nameOk := extractStringField(payload, "name")
	category, categoryOk := extractStringField(payload, "category")
	domain, domainOk := extractStringField(payload, "domain")
	payloadType, typeOk := extractStringField(payload, "type")
	content, contentOk := extractStringField(payload, "content")
	description, _ := extractStringField(payload, "description")
	severity, _ := extractStringField(payload, "severity")
	language, _ := extractStringField(payload, "language")
	tags, _ := extractStringSliceField(payload, "tags")

	// Validate required fields
	if !nameOk || name == "" {
		errors = append(errors, ValidationError{
			Field:    "name",
			Message:  "payload name is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.inputValidator.ValidateString("name", name,
			WithMinLength(1),
			WithMaxLength(255),
			RequiredString())...)
	}

	if !categoryOk || category == "" {
		errors = append(errors, ValidationError{
			Field:    "category",
			Message:  "payload category is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.ValidatePayloadCategory(category)...)
	}

	if !domainOk || domain == "" {
		errors = append(errors, ValidationError{
			Field:    "domain",
			Message:  "payload domain is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.inputValidator.ValidateString("domain", domain,
			WithMinLength(1),
			WithMaxLength(255),
			RequiredString(),
			WithPattern(regexp.MustCompile(`^[\w\-\.]+$`)))...)
	}

	if !typeOk || payloadType == "" {
		errors = append(errors, ValidationError{
			Field:    "type",
			Message:  "payload type is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.ValidatePayloadType(payloadType)...)
	}

	if !contentOk || content == "" {
		errors = append(errors, ValidationError{
			Field:    "content",
			Message:  "payload content is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.ValidatePayloadContent(content)...)
	}

	// Validate optional fields
	if description != "" {
		errors = append(errors, gv.inputValidator.ValidateString("description", description,
			WithMaxLength(MaxDescriptionLength))...)
	}

	if severity != "" {
		errors = append(errors, gv.ValidateSeverity(severity)...)
	}

	if language != "" {
		errors = append(errors, gv.ValidateLanguage(language)...)
	}

	if len(tags) > 0 {
		errors = append(errors, gv.ValidateTags(tags)...)
	}

	return errors
}

// ValidateReportSchedule validates a Gibson ReportSchedule configuration
func (gv *GibsonValidator) ValidateReportSchedule(schedule interface{}) ValidationErrors {
	var errors ValidationErrors

	name, nameOk := extractStringField(schedule, "name")
	reportType, typeOk := extractStringField(schedule, "report_type")
	scheduleExpression, exprOk := extractStringField(schedule, "schedule_expression")
	format, formatOk := extractStringField(schedule, "format")
	description, _ := extractStringField(schedule, "description")

	// Validate required fields
	if !nameOk || name == "" {
		errors = append(errors, ValidationError{
			Field:    "name",
			Message:  "schedule name is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.inputValidator.ValidateString("name", name,
			WithMinLength(1),
			WithMaxLength(255),
			RequiredString())...)
	}

	if !typeOk || reportType == "" {
		errors = append(errors, ValidationError{
			Field:    "report_type",
			Message:  "report type is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.ValidateReportType(reportType)...)
	}

	if !exprOk || scheduleExpression == "" {
		errors = append(errors, ValidationError{
			Field:    "schedule_expression",
			Message:  "schedule expression is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.ValidateScheduleExpression(scheduleExpression)...)
	}

	if !formatOk || format == "" {
		errors = append(errors, ValidationError{
			Field:    "format",
			Message:  "report format is required",
			Code:     "REQUIRED_FIELD_MISSING",
			Severity: "critical",
		})
	} else {
		errors = append(errors, gv.ValidateReportFormat(format)...)
	}

	// Validate optional fields
	if description != "" {
		errors = append(errors, gv.inputValidator.ValidateString("description", description,
			WithMaxLength(MaxDescriptionLength))...)
	}

	return errors
}

// Specific validation functions

// ValidateTargetType validates Gibson target types
func (gv *GibsonValidator) ValidateTargetType(targetType string) ValidationErrors {
	var errors ValidationErrors

	validTypes := []string{"api", "model", "endpoint"}
	found := false
	for _, valid := range validTypes {
		if strings.EqualFold(targetType, valid) {
			found = true
			break
		}
	}

	if !found {
		errors = append(errors, ValidationError{
			Field:    "type",
			Value:    targetType,
			Message:  fmt.Sprintf("target type must be one of: %s", strings.Join(validTypes, ", ")),
			Code:     "INVALID_TARGET_TYPE",
			Severity: "medium",
		})
	}

	return errors
}

// ValidateProvider validates AI/ML provider names
func (gv *GibsonValidator) ValidateProvider(provider string) ValidationErrors {
	var errors ValidationErrors

	validProviders := []string{"openai", "anthropic", "huggingface", "custom", "azure", "google", "ollama"}
	found := false
	for _, valid := range validProviders {
		if strings.EqualFold(provider, valid) {
			found = true
			break
		}
	}

	if !found {
		errors = append(errors, ValidationError{
			Field:    "provider",
			Value:    provider,
			Message:  fmt.Sprintf("provider must be one of: %s", strings.Join(validProviders, ", ")),
			Code:     "INVALID_PROVIDER",
			Severity: "medium",
		})
	}

	return errors
}

// ValidateModelName validates model names for specific providers
func (gv *GibsonValidator) ValidateModelName(provider, model string) ValidationErrors {
	var errors ValidationErrors

	switch strings.ToLower(provider) {
	case "openai":
		if !OpenAIModelPattern.MatchString(model) {
			errors = append(errors, ValidationError{
				Field:    "model",
				Value:    model,
				Message:  "invalid OpenAI model name format",
				Code:     "INVALID_MODEL_NAME",
				Severity: "medium",
			})
		}
	case "anthropic":
		if !AnthropicModelPattern.MatchString(model) {
			errors = append(errors, ValidationError{
				Field:    "model",
				Value:    model,
				Message:  "invalid Anthropic model name format",
				Code:     "INVALID_MODEL_NAME",
				Severity: "medium",
			})
		}
	case "huggingface":
		if !HuggingFaceModelPattern.MatchString(model) {
			errors = append(errors, ValidationError{
				Field:    "model",
				Value:    model,
				Message:  "invalid HuggingFace model name format (should be org/model)",
				Code:     "INVALID_MODEL_NAME",
				Severity: "medium",
			})
		}
	case "custom", "azure", "google", "ollama":
		if !CustomModelPattern.MatchString(model) {
			errors = append(errors, ValidationError{
				Field:    "model",
				Value:    model,
				Message:  "invalid model name format",
				Code:     "INVALID_MODEL_NAME",
				Severity: "medium",
			})
		}
	}

	return errors
}

// ValidateProviderURL validates URLs for specific providers
func (gv *GibsonValidator) ValidateProviderURL(provider, url string) ValidationErrors {
	var errors ValidationErrors

	// First do general URL validation
	errors = append(errors, gv.inputValidator.ValidateURL("url", url, "https", "http")...)

	// Provider-specific URL validation
	switch strings.ToLower(provider) {
	case "openai":
		if !OpenAIEndpointPattern.MatchString(url) {
			errors = append(errors, ValidationError{
				Field:    "url",
				Value:    url,
				Message:  "URL does not match OpenAI API endpoint pattern",
				Code:     "INVALID_PROVIDER_URL",
				Severity: "medium",
			})
		}
	case "anthropic":
		if !AnthropicEndpointPattern.MatchString(url) {
			errors = append(errors, ValidationError{
				Field:    "url",
				Value:    url,
				Message:  "URL does not match Anthropic API endpoint pattern",
				Code:     "INVALID_PROVIDER_URL",
				Severity: "medium",
			})
		}
	case "azure":
		if !AzureEndpointPattern.MatchString(url) {
			errors = append(errors, ValidationError{
				Field:    "url",
				Value:    url,
				Message:  "URL does not match Azure OpenAI endpoint pattern",
				Code:     "INVALID_PROVIDER_URL",
				Severity: "medium",
			})
		}
	case "google":
		if !GoogleEndpointPattern.MatchString(url) {
			errors = append(errors, ValidationError{
				Field:    "url",
				Value:    url,
				Message:  "URL does not match Google API endpoint pattern",
				Code:     "INVALID_PROVIDER_URL",
				Severity: "medium",
			})
		}
	case "ollama":
		if !OllamaEndpointPattern.MatchString(url) {
			errors = append(errors, ValidationError{
				Field:    "url",
				Value:    url,
				Message:  "URL does not match Ollama API endpoint pattern",
				Code:     "INVALID_PROVIDER_URL",
				Severity: "medium",
			})
		}
	}

	return errors
}

// ValidateAPIVersion validates API version strings
func (gv *GibsonValidator) ValidateAPIVersion(version string) ValidationErrors {
	var errors ValidationErrors

	if !APIVersionPattern.MatchString(version) {
		errors = append(errors, ValidationError{
			Field:    "api_version",
			Value:    version,
			Message:  "invalid API version format (expected: v1, v1.0, v2.1, etc.)",
			Code:     "INVALID_API_VERSION",
			Severity: "medium",
		})
	}

	return errors
}

// ValidateCredentialType validates credential types
func (gv *GibsonValidator) ValidateCredentialType(credType string) ValidationErrors {
	var errors ValidationErrors

	validTypes := []string{"api_key", "oauth", "bearer", "basic", "custom"}
	found := false
	for _, valid := range validTypes {
		if strings.EqualFold(credType, valid) {
			found = true
			break
		}
	}

	if !found {
		errors = append(errors, ValidationError{
			Field:    "type",
			Value:    credType,
			Message:  fmt.Sprintf("credential type must be one of: %s", strings.Join(validTypes, ", ")),
			Code:     "INVALID_CREDENTIAL_TYPE",
			Severity: "medium",
		})
	}

	return errors
}

// ValidatePayloadCategory validates payload categories
func (gv *GibsonValidator) ValidatePayloadCategory(category string) ValidationErrors {
	var errors ValidationErrors

	validCategories := []string{"model", "data", "interface", "infrastructure", "output", "process"}
	found := false
	for _, valid := range validCategories {
		if strings.EqualFold(category, valid) {
			found = true
			break
		}
	}

	if !found {
		errors = append(errors, ValidationError{
			Field:    "category",
			Value:    category,
			Message:  fmt.Sprintf("payload category must be one of: %s", strings.Join(validCategories, ", ")),
			Code:     "INVALID_PAYLOAD_CATEGORY",
			Severity: "medium",
		})
	}

	return errors
}

// ValidatePayloadType validates payload types
func (gv *GibsonValidator) ValidatePayloadType(payloadType string) ValidationErrors {
	var errors ValidationErrors

	validTypes := []string{"prompt", "query", "input", "code", "data", "script"}
	found := false
	for _, valid := range validTypes {
		if strings.EqualFold(payloadType, valid) {
			found = true
			break
		}
	}

	if !found {
		errors = append(errors, ValidationError{
			Field:    "type",
			Value:    payloadType,
			Message:  fmt.Sprintf("payload type must be one of: %s", strings.Join(validTypes, ", ")),
			Code:     "INVALID_PAYLOAD_TYPE",
			Severity: "medium",
		})
	}

	return errors
}

// ValidatePayloadContent validates payload content for security
func (gv *GibsonValidator) ValidatePayloadContent(content string) ValidationErrors {
	var errors ValidationErrors

	// Basic validation
	errors = append(errors, gv.inputValidator.ValidateString("content", content,
		WithMinLength(1),
		WithMaxLength(100000), // Large payloads allowed for testing
		RequiredString())...)

	// Security checks - payloads are intentionally dangerous, but we still check for format
	if !utf8.ValidString(content) {
		errors = append(errors, ValidationError{
			Field:    "content",
			Message:  "payload content contains invalid UTF-8 sequences",
			Code:     "INVALID_UTF8",
			Severity: "high",
		})
	}

	// Check for null bytes
	if strings.Contains(content, "\x00") {
		errors = append(errors, ValidationError{
			Field:    "content",
			Message:  "payload content contains null bytes",
			Code:     "NULL_BYTES_DETECTED",
			Severity: "medium",
		})
	}

	return errors
}

// ValidateSeverity validates severity levels
func (gv *GibsonValidator) ValidateSeverity(severity string) ValidationErrors {
	var errors ValidationErrors

	validSeverities := []string{"critical", "high", "medium", "low", "info"}
	found := false
	for _, valid := range validSeverities {
		if strings.EqualFold(severity, valid) {
			found = true
			break
		}
	}

	if !found {
		errors = append(errors, ValidationError{
			Field:    "severity",
			Value:    severity,
			Message:  fmt.Sprintf("severity must be one of: %s", strings.Join(validSeverities, ", ")),
			Code:     "INVALID_SEVERITY",
			Severity: "medium",
		})
	}

	return errors
}

// ValidateReportType validates report types
func (gv *GibsonValidator) ValidateReportType(reportType string) ValidationErrors {
	var errors ValidationErrors

	validTypes := []string{"scan_summary", "detailed_scan", "target_summary", "vulnerability", "compliance", "custom"}
	found := false
	for _, valid := range validTypes {
		if strings.EqualFold(reportType, valid) {
			found = true
			break
		}
	}

	if !found {
		errors = append(errors, ValidationError{
			Field:    "report_type",
			Value:    reportType,
			Message:  fmt.Sprintf("report type must be one of: %s", strings.Join(validTypes, ", ")),
			Code:     "INVALID_REPORT_TYPE",
			Severity: "medium",
		})
	}

	return errors
}

// ValidateReportFormat validates report formats
func (gv *GibsonValidator) ValidateReportFormat(format string) ValidationErrors {
	var errors ValidationErrors

	validFormats := []string{"json", "html", "pdf", "csv", "xml"}
	found := false
	for _, valid := range validFormats {
		if strings.EqualFold(format, valid) {
			found = true
			break
		}
	}

	if !found {
		errors = append(errors, ValidationError{
			Field:    "format",
			Value:    format,
			Message:  fmt.Sprintf("report format must be one of: %s", strings.Join(validFormats, ", ")),
			Code:     "INVALID_REPORT_FORMAT",
			Severity: "medium",
		})
	}

	return errors
}

// ValidateScheduleExpression validates cron-like schedule expressions
func (gv *GibsonValidator) ValidateScheduleExpression(expression string) ValidationErrors {
	var errors ValidationErrors

	if !ScheduleExpressionPattern.MatchString(expression) {
		errors = append(errors, ValidationError{
			Field:    "schedule_expression",
			Value:    expression,
			Message:  "invalid cron schedule format (expected: minute hour day month weekday)",
			Code:     "INVALID_SCHEDULE_EXPRESSION",
			Severity: "medium",
		})
	}

	return errors
}

// ValidateLanguage validates programming/markup language names
func (gv *GibsonValidator) ValidateLanguage(language string) ValidationErrors {
	var errors ValidationErrors

	// Common languages for AI/ML security testing
	validLanguages := []string{
		"python", "javascript", "java", "c", "cpp", "csharp", "go", "rust",
		"ruby", "php", "sql", "html", "css", "json", "yaml", "xml",
		"bash", "powershell", "markdown", "plaintext",
	}

	found := false
	for _, valid := range validLanguages {
		if strings.EqualFold(language, valid) {
			found = true
			break
		}
	}

	if !found {
		errors = append(errors, ValidationError{
			Field:    "language",
			Value:    language,
			Message:  "unsupported language",
			Code:     "UNSUPPORTED_LANGUAGE",
			Severity: "low",
		})
	}

	return errors
}

// ValidateTags validates tag arrays
func (gv *GibsonValidator) ValidateTags(tags []string) ValidationErrors {
	var errors ValidationErrors

	if len(tags) > MaxTagCount {
		errors = append(errors, ValidationError{
			Field:    "tags",
			Message:  fmt.Sprintf("maximum of %d tags allowed", MaxTagCount),
			Code:     "MAX_TAGS_EXCEEDED",
			Severity: "medium",
		})
	}

	seenTags := make(map[string]bool)
	for i, tag := range tags {
		fieldName := fmt.Sprintf("tags[%d]", i)

		// Length validation
		if len(tag) == 0 {
			errors = append(errors, ValidationError{
				Field:    fieldName,
				Message:  "tag cannot be empty",
				Code:     "EMPTY_TAG",
				Severity: "medium",
			})
			continue
		}

		if len(tag) > MaxTagLength {
			errors = append(errors, ValidationError{
				Field:    fieldName,
				Value:    truncateValue(tag, 50),
				Message:  fmt.Sprintf("tag exceeds maximum length of %d characters", MaxTagLength),
				Code:     "TAG_TOO_LONG",
				Severity: "medium",
			})
		}

		// Format validation
		if !TagPattern.MatchString(tag) {
			errors = append(errors, ValidationError{
				Field:    fieldName,
				Value:    tag,
				Message:  "tag contains invalid characters (use only letters, numbers, hyphens, dots)",
				Code:     "INVALID_TAG_FORMAT",
				Severity: "medium",
			})
		}

		// Duplicate detection
		lowerTag := strings.ToLower(tag)
		if seenTags[lowerTag] {
			errors = append(errors, ValidationError{
				Field:    fieldName,
				Value:    tag,
				Message:  "duplicate tag",
				Code:     "DUPLICATE_TAG",
				Severity: "medium",
			})
		}
		seenTags[lowerTag] = true

		// Security validation
		if hasSQLInjectionPattern(tag) || hasXSSPattern(tag) {
			errors = append(errors, ValidationError{
				Field:    fieldName,
				Value:    tag,
				Message:  "tag contains potentially malicious content",
				Code:     "MALICIOUS_TAG_CONTENT",
				Severity: "high",
			})
		}
	}

	return errors
}

// ValidateRotationInterval validates credential rotation intervals
func (gv *GibsonValidator) ValidateRotationInterval(interval string) ValidationErrors {
	var errors ValidationErrors

	// Parse as duration
	duration, err := time.ParseDuration(interval)
	if err != nil {
		errors = append(errors, ValidationError{
			Field:    "rotation_interval",
			Value:    interval,
			Message:  "invalid rotation interval format (e.g., '30d', '7d', '24h')",
			Code:     "INVALID_ROTATION_INTERVAL",
			Severity: "medium",
		})
		return errors
	}

	// Minimum rotation interval (1 hour)
	if duration < time.Hour {
		errors = append(errors, ValidationError{
			Field:    "rotation_interval",
			Value:    interval,
			Message:  "rotation interval must be at least 1 hour",
			Code:     "ROTATION_INTERVAL_TOO_SHORT",
			Severity: "medium",
		})
	}

	// Maximum rotation interval (1 year)
	if duration > 365*24*time.Hour {
		errors = append(errors, ValidationError{
			Field:    "rotation_interval",
			Value:    interval,
			Message:  "rotation interval must not exceed 1 year",
			Code:     "ROTATION_INTERVAL_TOO_LONG",
			Severity: "medium",
		})
	}

	return errors
}

// Helper functions for field extraction (simplified - in practice you'd use reflection or type assertions)

func extractStringField(data interface{}, fieldName string) (string, bool) {
	// This is a simplified implementation
	// In practice, you'd use reflection or type assertions to extract fields from structs
	if m, ok := data.(map[string]interface{}); ok {
		if value, exists := m[fieldName]; exists {
			if str, ok := value.(string); ok {
				return str, true
			}
		}
	}
	return "", false
}

func extractStringSliceField(data interface{}, fieldName string) ([]string, bool) {
	// Simplified implementation
	if m, ok := data.(map[string]interface{}); ok {
		if value, exists := m[fieldName]; exists {
			if slice, ok := value.([]string); ok {
				return slice, true
			}
			// Handle []interface{} case
			if interfaceSlice, ok := value.([]interface{}); ok {
				var stringSlice []string
				for _, item := range interfaceSlice {
					if str, ok := item.(string); ok {
						stringSlice = append(stringSlice, str)
					}
				}
				return stringSlice, true
			}
		}
	}
	return nil, false
}

// SanitizeGibsonInput provides Gibson-specific input sanitization
func (gv *GibsonValidator) SanitizeGibsonInput(input string, inputType string) string {
	switch inputType {
	case "credential_value":
		return gv.sanitizer.SanitizeCredential(input)
	case "payload_content":
		// Payloads are intentionally dangerous, so minimal sanitization
		return gv.sanitizer.SanitizeString(input, &SanitizationConfig{
			StripControlChars:   true,
			NormalizeWhitespace: false,
			TrimWhitespace:     false,
			MaxLength:          100000,
			PreserveNewlines:   true,
			ConvertToLowerCase: false,
			RemoveNonPrintable: false,
		})
	case "target_name", "credential_name", "payload_name":
		return gv.sanitizer.SanitizeString(input, &SanitizationConfig{
			StripControlChars:   true,
			NormalizeWhitespace: true,
			TrimWhitespace:     true,
			MaxLength:          255,
			PreserveNewlines:   false,
			ConvertToLowerCase: false,
			RemoveNonPrintable: true,
		})
	case "description":
		return gv.sanitizer.SanitizeString(input, DefaultSanitizationConfig())
	case "url":
		sanitized, err := gv.sanitizer.SanitizeURL(input)
		if err != nil {
			return ""
		}
		return sanitized
	case "email":
		return gv.sanitizer.SanitizeEmail(input)
	default:
		return gv.sanitizer.SanitizeString(input, DefaultSanitizationConfig())
	}
}