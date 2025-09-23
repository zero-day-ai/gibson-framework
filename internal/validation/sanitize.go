// Package validation provides sanitization functions for secure input handling
package validation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SanitizationConfig holds configuration for sanitization operations
type SanitizationConfig struct {
	StripControlChars     bool
	NormalizeWhitespace   bool
	TrimWhitespace       bool
	MaxLength            int
	PreserveNewlines     bool
	ConvertToLowerCase   bool
	RemoveNonPrintable   bool
}

// DefaultSanitizationConfig returns a default configuration for general sanitization
func DefaultSanitizationConfig() *SanitizationConfig {
	return &SanitizationConfig{
		StripControlChars:   true,
		NormalizeWhitespace: true,
		TrimWhitespace:     true,
		MaxLength:          MaxStringLength,
		PreserveNewlines:   true,
		ConvertToLowerCase: false,
		RemoveNonPrintable: true,
	}
}

// StrictSanitizationConfig returns a strict configuration for high-security contexts
func StrictSanitizationConfig() *SanitizationConfig {
	return &SanitizationConfig{
		StripControlChars:   true,
		NormalizeWhitespace: true,
		TrimWhitespace:     true,
		MaxLength:          1000,
		PreserveNewlines:   false,
		ConvertToLowerCase: false,
		RemoveNonPrintable: true,
	}
}

// Sanitizer provides comprehensive input sanitization capabilities
type Sanitizer struct {
	htmlEscaper    *strings.Replacer
	jsEscaper      *strings.Replacer
	sqlEscaper     *strings.Replacer
	cmdEscaper     *strings.Replacer
	pathCleaner    *regexp.Regexp
	xssPatterns    []*regexp.Regexp
	sqlPatterns    []*regexp.Regexp
	cmdPatterns    []*regexp.Regexp
}

// NewSanitizer creates a new sanitizer with optimized pattern matching
func NewSanitizer() *Sanitizer {
	// HTML/XML character escaper
	htmlEscaper := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
		"/", "&#47;",
	)

	// JavaScript string escaper
	jsEscaper := strings.NewReplacer(
		"\\", "\\\\",
		"\"", "\\\"",
		"'", "\\'",
		"\n", "\\n",
		"\r", "\\r",
		"\t", "\\t",
		"\x00", "\\x00",
		"\x08", "\\x08",
		"\x0c", "\\x0c",
	)

	// SQL escaper (basic - parameterized queries are still preferred)
	sqlEscaper := strings.NewReplacer(
		"'", "''",
		"\\", "\\\\",
		"\x00", "\\0",
		"\n", "\\n",
		"\r", "\\r",
		"\x1a", "\\Z",
	)

	// Command injection escaper
	cmdEscaper := strings.NewReplacer(
		";", "\\;",
		"|", "\\|",
		"&", "\\&",
		"$", "\\$",
		"`", "\\`",
		"(", "\\(",
		")", "\\)",
		"{", "\\{",
		"}", "\\}",
		"[", "\\[",
		"]", "\\]",
		"<", "\\<",
		">", "\\>",
		"*", "\\*",
		"?", "\\?",
		"\"", "\\\"",
		"'", "\\'",
		"~", "\\~",
	)

	// Path traversal cleaner
	pathCleaner := regexp.MustCompile(`\.\.[\\/]|[\\/]\.\.[\\/]?|[\\/]\.\.?$`)

	// Precompiled XSS patterns for performance
	xssPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<\s*script[^>]*>.*?</\s*script\s*>`),
		regexp.MustCompile(`(?i)<\s*iframe[^>]*>.*?</\s*iframe\s*>`),
		regexp.MustCompile(`(?i)<\s*object[^>]*>.*?</\s*object\s*>`),
		regexp.MustCompile(`(?i)<\s*embed[^>]*>`),
		regexp.MustCompile(`(?i)javascript\s*:`),
		regexp.MustCompile(`(?i)vbscript\s*:`),
		regexp.MustCompile(`(?i)on\w+\s*=`),
		regexp.MustCompile(`(?i)expression\s*\(`),
		regexp.MustCompile(`(?i)url\s*\(\s*javascript:`),
	}

	// Precompiled SQL injection patterns
	sqlPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(\bor\b|\band\b)\s+\d+\s*=\s*\d+`),
		regexp.MustCompile(`(?i)'\s*(or|and)\s+'[^']*'\s*=\s*'[^']*'`),
		regexp.MustCompile(`(?i);\s*(drop|delete|update|insert|create|alter)\b`),
		regexp.MustCompile(`(?i)union\s+select`),
		regexp.MustCompile(`(?i)exec\s*\(`),
		regexp.MustCompile(`(?i)xp_\w+`),
		regexp.MustCompile(`(?i)sp_\w+`),
	}

	// Precompiled command injection patterns
	cmdPatterns := []*regexp.Regexp{
		regexp.MustCompile(`[;&|]\s*\w+`),
		regexp.MustCompile(`\$\(\w+\)`),
		regexp.MustCompile("`\\w+`"),
		regexp.MustCompile(`\|\s*(nc|netcat|wget|curl|ping|sh|bash|cmd|powershell)\b`),
	}

	return &Sanitizer{
		htmlEscaper:  htmlEscaper,
		jsEscaper:    jsEscaper,
		sqlEscaper:   sqlEscaper,
		cmdEscaper:   cmdEscaper,
		pathCleaner:  pathCleaner,
		xssPatterns:  xssPatterns,
		sqlPatterns:  sqlPatterns,
		cmdPatterns:  cmdPatterns,
	}
}

// SanitizeString performs comprehensive string sanitization
func (s *Sanitizer) SanitizeString(input string, config *SanitizationConfig) string {
	if config == nil {
		config = DefaultSanitizationConfig()
	}

	result := input

	// Remove or replace invalid UTF-8 sequences
	if !utf8.ValidString(result) {
		result = strings.ToValidUTF8(result, "")
	}

	// Remove null bytes
	result = strings.ReplaceAll(result, "\x00", "")

	// Strip control characters
	if config.StripControlChars {
		result = s.stripControlCharacters(result, config.PreserveNewlines)
	}

	// Remove non-printable characters
	if config.RemoveNonPrintable {
		result = s.removeNonPrintable(result)
	}

	// Normalize whitespace
	if config.NormalizeWhitespace {
		result = s.normalizeWhitespace(result)
	}

	// Trim whitespace
	if config.TrimWhitespace {
		result = strings.TrimSpace(result)
	}

	// Convert case
	if config.ConvertToLowerCase {
		result = strings.ToLower(result)
	}

	// Truncate to max length
	if config.MaxLength > 0 && len(result) > config.MaxLength {
		result = result[:config.MaxLength]
		// Ensure we don't break UTF-8 sequences
		result = strings.ToValidUTF8(result, "")
	}

	return result
}

// SanitizeHTML sanitizes HTML content by escaping dangerous characters
func (s *Sanitizer) SanitizeHTML(input string) string {
	return s.htmlEscaper.Replace(input)
}

// SanitizeHTMLStrict removes all HTML tags and escapes remaining content
func (s *Sanitizer) SanitizeHTMLStrict(input string) string {
	// Remove all HTML tags
	htmlTagRegex := regexp.MustCompile(`<[^>]*>`)
	result := htmlTagRegex.ReplaceAllString(input, "")

	// Escape remaining HTML entities
	result = s.htmlEscaper.Replace(result)

	// Remove any remaining XSS patterns
	result = s.RemoveXSSPatterns(result)

	return result
}

// SanitizeXML sanitizes XML content by escaping special characters
func (s *Sanitizer) SanitizeXML(input string) string {
	// XML uses same escaping as HTML for these characters
	return s.htmlEscaper.Replace(input)
}

// SanitizeJavaScript escapes JavaScript string content
func (s *Sanitizer) SanitizeJavaScript(input string) string {
	return s.jsEscaper.Replace(input)
}

// SanitizeSQL performs basic SQL escaping (parameterized queries preferred)
func (s *Sanitizer) SanitizeSQL(input string) string {
	return s.sqlEscaper.Replace(input)
}

// SanitizeShellCommand escapes shell command arguments
func (s *Sanitizer) SanitizeShellCommand(input string) string {
	return s.cmdEscaper.Replace(input)
}

// SanitizeShellCommandStrict removes dangerous command injection patterns
func (s *Sanitizer) SanitizeShellCommandStrict(input string) string {
	result := input

	// Remove command injection patterns
	for _, pattern := range s.cmdPatterns {
		result = pattern.ReplaceAllString(result, "")
	}

	// Escape remaining dangerous characters
	result = s.cmdEscaper.Replace(result)

	return result
}

// SanitizePath normalizes and secures file paths
func (s *Sanitizer) SanitizePath(input string) string {
	// Remove null bytes
	result := strings.ReplaceAll(input, "\x00", "")

	// Remove path traversal patterns
	result = s.pathCleaner.ReplaceAllString(result, "")

	// Normalize path separators
	result = strings.ReplaceAll(result, "\\", "/")

	// Clean the path
	result = filepath.Clean(result)

	// Ensure path doesn't start with ../
	if strings.HasPrefix(result, "../") {
		result = strings.TrimPrefix(result, "../")
	}

	return result
}

// SanitizeURL validates and sanitizes URLs
func (s *Sanitizer) SanitizeURL(input string) (string, error) {
	// Parse the URL
	parsedURL, err := url.Parse(input)
	if err != nil {
		return "", err
	}

	// Check for dangerous schemes
	dangerousSchemes := []string{"javascript", "data", "vbscript", "file"}
	for _, scheme := range dangerousSchemes {
		if strings.EqualFold(parsedURL.Scheme, scheme) {
			return "", fmt.Errorf("dangerous URL scheme: %s", parsedURL.Scheme)
		}
	}

	// Sanitize components
	if parsedURL.User != nil {
		// Remove user info for security
		parsedURL.User = nil
	}

	// Sanitize query parameters
	if parsedURL.RawQuery != "" {
		query := parsedURL.Query()
		sanitizedQuery := url.Values{}

		for key, values := range query {
			sanitizedKey := s.SanitizeString(key, DefaultSanitizationConfig())
			for _, value := range values {
				sanitizedValue := s.SanitizeString(value, DefaultSanitizationConfig())
				sanitizedQuery.Add(sanitizedKey, sanitizedValue)
			}
		}

		parsedURL.RawQuery = sanitizedQuery.Encode()
	}

	// Sanitize fragment
	if parsedURL.Fragment != "" {
		parsedURL.Fragment = s.SanitizeString(parsedURL.Fragment, DefaultSanitizationConfig())
	}

	return parsedURL.String(), nil
}

// SanitizeJSON sanitizes JSON content while preserving structure
func (s *Sanitizer) SanitizeJSON(input string) (string, error) {
	var data interface{}
	if err := json.Unmarshal([]byte(input), &data); err != nil {
		return "", err
	}

	sanitized := s.sanitizeJSONValue(data)

	result, err := json.Marshal(sanitized)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

// SanitizeEmail sanitizes email addresses
func (s *Sanitizer) SanitizeEmail(input string) string {
	// Basic sanitization - remove dangerous characters
	result := s.SanitizeString(input, &SanitizationConfig{
		StripControlChars:   true,
		NormalizeWhitespace: true,
		TrimWhitespace:     true,
		MaxLength:          MaxEmailLength,
		PreserveNewlines:   false,
		ConvertToLowerCase: true,
		RemoveNonPrintable: true,
	})

	// Remove XSS patterns that might be in email
	result = s.RemoveXSSPatterns(result)

	return result
}

// SanitizeCredential sanitizes credential values (preserves structure but removes injections)
func (s *Sanitizer) SanitizeCredential(input string) string {
	config := &SanitizationConfig{
		StripControlChars:   true,
		NormalizeWhitespace: false, // Preserve exact credential format
		TrimWhitespace:     false,  // Don't modify credential structure
		MaxLength:          MaxCredentialLength,
		PreserveNewlines:   false,
		ConvertToLowerCase: false, // Preserve case sensitivity
		RemoveNonPrintable: true,
	}

	result := s.SanitizeString(input, config)

	// Remove obvious injection attempts while preserving legitimate content
	result = s.RemoveXSSPatterns(result)
	result = s.RemoveSQLInjectionPatterns(result)

	return result
}

// RemoveXSSPatterns removes cross-site scripting patterns
func (s *Sanitizer) RemoveXSSPatterns(input string) string {
	result := input

	for _, pattern := range s.xssPatterns {
		result = pattern.ReplaceAllString(result, "")
	}

	return result
}

// RemoveSQLInjectionPatterns removes SQL injection patterns
func (s *Sanitizer) RemoveSQLInjectionPatterns(input string) string {
	result := input

	for _, pattern := range s.sqlPatterns {
		result = pattern.ReplaceAllString(result, "")
	}

	return result
}

// RemoveCommandInjectionPatterns removes command injection patterns
func (s *Sanitizer) RemoveCommandInjectionPatterns(input string) string {
	result := input

	for _, pattern := range s.cmdPatterns {
		result = pattern.ReplaceAllString(result, "")
	}

	return result
}

// EncodeForURL URL-encodes string for safe use in URLs
func (s *Sanitizer) EncodeForURL(input string) string {
	return url.QueryEscape(input)
}

// EncodeForHTML HTML-encodes string for safe use in HTML content
func (s *Sanitizer) EncodeForHTML(input string) string {
	return html.EscapeString(input)
}

// EncodeForHTMLAttribute HTML-encodes string for safe use in HTML attributes
func (s *Sanitizer) EncodeForHTMLAttribute(input string) string {
	// More aggressive escaping for attributes
	result := html.EscapeString(input)
	result = strings.ReplaceAll(result, " ", "&#32;")
	result = strings.ReplaceAll(result, "\t", "&#9;")
	result = strings.ReplaceAll(result, "\n", "&#10;")
	result = strings.ReplaceAll(result, "\r", "&#13;")
	return result
}

// EncodeForBase64 encodes string as base64
func (s *Sanitizer) EncodeForBase64(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

// DecodeFromBase64 safely decodes base64 string
func (s *Sanitizer) DecodeFromBase64(input string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", err
	}

	// Sanitize decoded content
	result := s.SanitizeString(string(decoded), DefaultSanitizationConfig())
	return result, nil
}

// Helper functions

func (s *Sanitizer) stripControlCharacters(input string, preserveNewlines bool) string {
	var result strings.Builder
	result.Grow(len(input))

	for _, r := range input {
		if unicode.IsControl(r) {
			if preserveNewlines && (r == '\n' || r == '\r' || r == '\t') {
				result.WriteRune(r)
			}
			// Skip other control characters
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}

func (s *Sanitizer) removeNonPrintable(input string) string {
	var result strings.Builder
	result.Grow(len(input))

	for _, r := range input {
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			result.WriteRune(r)
		}
		// Skip non-printable characters
	}

	return result.String()
}

func (s *Sanitizer) normalizeWhitespace(input string) string {
	// Replace multiple whitespace with single space
	whitespaceRegex := regexp.MustCompile(`\s+`)
	return whitespaceRegex.ReplaceAllString(input, " ")
}

func (s *Sanitizer) sanitizeJSONValue(value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		return s.SanitizeString(v, DefaultSanitizationConfig())
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, val := range v {
			sanitizedKey := s.SanitizeString(key, DefaultSanitizationConfig())
			result[sanitizedKey] = s.sanitizeJSONValue(val)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, val := range v {
			result[i] = s.sanitizeJSONValue(val)
		}
		return result
	case float64, int, bool, nil:
		return v // Numbers, booleans, and null are safe
	default:
		// Convert unknown types to sanitized strings
		return s.SanitizeString(fmt.Sprintf("%v", v), DefaultSanitizationConfig())
	}
}

// Escape utilities for specific contexts

// EscapeForCSV escapes string for safe use in CSV files
func (s *Sanitizer) EscapeForCSV(input string) string {
	// CSV escaping: quote field if it contains comma, quote, or newline
	if strings.ContainsAny(input, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(input, "\"", "\"\"") + "\""
	}
	return input
}

// EscapeForRegex escapes string for safe use in regex patterns
func (s *Sanitizer) EscapeForRegex(input string) string {
	// Escape regex special characters
	specialChars := []string{"\\", "^", "$", ".", "[", "]", "|", "(", ")", "?", "*", "+", "{", "}"}
	result := input
	for _, char := range specialChars {
		result = strings.ReplaceAll(result, char, "\\"+char)
	}
	return result
}

// EscapeForLDAP escapes string for safe use in LDAP queries
func (s *Sanitizer) EscapeForLDAP(input string) string {
	// LDAP special characters that need escaping
	ldapEscaper := strings.NewReplacer(
		"\\", "\\5c",
		"*", "\\2a",
		"(", "\\28",
		")", "\\29",
		"\x00", "\\00",
	)
	return ldapEscaper.Replace(input)
}

// Validate sanitization effectiveness

// IsSanitized checks if a string appears to be properly sanitized
func (s *Sanitizer) IsSanitized(input string) bool {
	// Check for common injection patterns
	if hasSQLInjectionPattern(input) {
		return false
	}

	if hasXSSPattern(input) {
		return false
	}

	if hasCommandInjectionPattern(input) {
		return false
	}

	if hasPathTraversalPattern(input) {
		return false
	}

	// Check for control characters
	if hasControlCharacters(input) {
		return false
	}

	return true
}

// GetSanitizationReport provides detailed analysis of what was sanitized
func (s *Sanitizer) GetSanitizationReport(original, sanitized string) map[string]interface{} {
	report := map[string]interface{}{
		"original_length":   len(original),
		"sanitized_length":  len(sanitized),
		"length_changed":    len(original) != len(sanitized),
		"content_changed":   original != sanitized,
		"had_control_chars": hasControlCharacters(original),
		"had_xss_patterns":  hasXSSPattern(original),
		"had_sql_patterns":  hasSQLInjectionPattern(original),
		"had_cmd_patterns":  hasCommandInjectionPattern(original),
		"had_path_patterns": hasPathTraversalPattern(original),
		"is_safe":          s.IsSanitized(sanitized),
	}

	if original != sanitized {
		// Calculate percentage of content changed
		changes := 0.0
		if len(original) > 0 {
			changes = float64(len(original)-len(sanitized)) / float64(len(original)) * 100
		}
		report["percent_changed"] = changes
	}

	return report
}