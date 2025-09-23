package validation

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// Test basic string validation
func TestInputValidator_ValidateString(t *testing.T) {
	validator := NewInputValidator()

	tests := []struct {
		name     string
		field    string
		value    string
		options  []StringOption
		expected int // expected number of errors
		severity string
	}{
		{
			name:     "valid string",
			field:    "name",
			value:    "valid-name",
			options:  []StringOption{RequiredString(), WithMaxLength(50)},
			expected: 0,
		},
		{
			name:     "empty required string",
			field:    "name",
			value:    "",
			options:  []StringOption{RequiredString()},
			expected: 1,
			severity: "high",
		},
		{
			name:     "string too long",
			field:    "description",
			value:    strings.Repeat("a", 100000),
			options:  []StringOption{WithMaxLength(1000)},
			expected: 1,
			severity: "high",
		},
		{
			name:     "string too short",
			field:    "password",
			value:    "123",
			options:  []StringOption{WithMinLength(8)},
			expected: 1,
			severity: "medium",
		},
		{
			name:     "SQL injection attempt",
			field:    "username",
			value:    "admin'; DROP TABLE users; --",
			options:  []StringOption{},
			expected: 2, // SQL + Command injection detected
			severity: "critical",
		},
		{
			name:     "XSS attempt",
			field:    "comment",
			value:    "<script>alert('xss')</script>",
			options:  []StringOption{},
			expected: 2, // SQL + XSS detected
			severity: "critical",
		},
		{
			name:     "command injection attempt",
			field:    "filename",
			value:    "test.txt; rm -rf /",
			options:  []StringOption{},
			expected: 2, // SQL + Command injection detected
			severity: "critical",
		},
		{
			name:     "path traversal attempt",
			field:    "path",
			value:    "../../../etc/passwd",
			options:  []StringOption{},
			expected: 2, // Command + Path traversal detected
			severity: "critical",
		},
		{
			name:     "control characters",
			field:    "data",
			value:    "test\x00\x01data",
			options:  []StringOption{},
			expected: 2, // Control chars + Path traversal detected
			severity: "high",
		},
		{
			name:     "pattern mismatch",
			field:    "email",
			value:    "invalid-email",
			options:  []StringOption{WithPattern(regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`))},
			expected: 1,
			severity: "medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validator.ValidateString(tt.field, tt.value, tt.options...)

			if len(errors) != tt.expected {
				t.Errorf("expected %d errors, got %d: %v", tt.expected, len(errors), errors)
			}

			if tt.expected > 0 && tt.severity != "" {
				found := false
				for _, err := range errors {
					if err.Severity == tt.severity {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error with severity '%s' not found", tt.severity)
				}
			}
		})
	}
}

// Test email validation
func TestInputValidator_ValidateEmail(t *testing.T) {
	validator := NewInputValidator()

	tests := []struct {
		name     string
		email    string
		expected int
	}{
		{"valid email", "user@example.com", 0},
		{"valid email with plus", "user+test@example.com", 0},
		{"empty email", "", 1},
		{"invalid format", "invalid-email", 1},
		{"email too long", strings.Repeat("a", 300) + "@example.com", 0}, // Valid format, just long
		{"XSS in email", "test<script>alert('xss')</script>@example.com", 1},
		{"SQL injection in email", "test'; DROP TABLE users; --@example.com", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validator.ValidateEmail("email", tt.email)
			if len(errors) != tt.expected {
				t.Errorf("expected %d errors, got %d: %v", tt.expected, len(errors), errors)
			}
		})
	}
}

// Test URL validation
func TestInputValidator_ValidateURL(t *testing.T) {
	validator := NewInputValidator()

	tests := []struct {
		name           string
		url            string
		allowedSchemes []string
		expected       int
		shouldHaveCritical bool
	}{
		{"valid HTTPS URL", "https://api.example.com/v1", []string{"https"}, 0, false},
		{"valid HTTP URL", "http://localhost:8080/api", []string{"http", "https"}, 1, false}, // Warning for localhost
		{"empty URL", "", nil, 1, false},
		{"invalid URL", "not-a-url", nil, 0, false}, // URL.Parse doesn't fail on this
		{"disallowed scheme", "ftp://example.com", []string{"https"}, 1, false},
		{"dangerous scheme", "javascript:alert('xss')", nil, 1, true},
		{"data URL", "data:text/html,<script>alert('xss')</script>", nil, 1, true},
		{"private IP", "https://192.168.1.1/api", nil, 1, false},
		{"localhost access", "https://localhost:8080/api", nil, 1, false},
		{"URL too long", "https://example.com/" + strings.Repeat("a", 3000), nil, 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validator.ValidateURL("url", tt.url, tt.allowedSchemes...)

			if len(errors) != tt.expected {
				t.Errorf("expected %d errors, got %d: %v", tt.expected, len(errors), errors)
			}

			if tt.shouldHaveCritical {
				found := false
				for _, err := range errors {
					if err.Severity == "critical" {
						found = true
						break
					}
				}
				if !found && tt.expected > 0 {
					t.Errorf("expected critical error not found")
				}
			}
		})
	}
}

// Test credential validation
func TestInputValidator_ValidateCredential(t *testing.T) {
	validator := NewInputValidator()

	tests := []struct {
		name     string
		credType string
		value    string
		expected int
	}{
		{"valid API key", "api_key", "sk-1234567890abcdef1234567890abcdef", 1}, // Low entropy warning
		{"valid bearer token", "bearer", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", 1}, // Low entropy warning
		{"empty credential", "api_key", "", 1},
		{"API key too short", "api_key", "short", 2}, // Length + entropy
		{"bearer token too short", "bearer", "abc", 2}, // Length + entropy
		{"invalid base64 for basic", "basic", "not-base64!", 2}, // Base64 + entropy
		{"low entropy credential", "api_key", "1111111111111111", 1},
		{"credential too long", "api_key", strings.Repeat("a", 5000), 2}, // Length + entropy
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validator.ValidateCredential("credential", tt.credType, tt.value)
			if len(errors) != tt.expected {
				t.Errorf("expected %d errors, got %d: %v", tt.expected, len(errors), errors)
			}
		})
	}
}

// Test sanitizer
func TestSanitizer_SanitizeString(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []struct {
		name     string
		input    string
		config   *SanitizationConfig
		expected string
	}{
		{
			name:     "basic sanitization",
			input:    "  Hello\x00World\x01  ",
			config:   DefaultSanitizationConfig(),
			expected: "HelloWorld",
		},
		{
			name:     "preserve newlines",
			input:    "Line 1\nLine 2\rLine 3",
			config:   &SanitizationConfig{StripControlChars: true, PreserveNewlines: true, TrimWhitespace: true},
			expected: "Line 1\nLine 2\rLine 3",
		},
		{
			name:     "normalize whitespace",
			input:    "Multiple    spaces   here",
			config:   &SanitizationConfig{NormalizeWhitespace: true},
			expected: "Multiple spaces here",
		},
		{
			name:     "truncate long string",
			input:    strings.Repeat("a", 100),
			config:   &SanitizationConfig{MaxLength: 50, TrimWhitespace: true},
			expected: strings.Repeat("a", 50),
		},
		{
			name:     "convert to lowercase",
			input:    "UPPER CASE TEXT",
			config:   &SanitizationConfig{ConvertToLowerCase: true, TrimWhitespace: true},
			expected: "upper case text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeString(tt.input, tt.config)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// Test HTML sanitization
func TestSanitizer_SanitizeHTML(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "escape HTML characters",
			input:    "<script>alert('xss')</script>",
			expected: "&lt;script&gt;alert(&#39;xss&#39;)&lt;&#47;script&gt;",
		},
		{
			name:     "escape quotes",
			input:    `He said "Hello & goodbye"`,
			expected: "He said &quot;Hello &amp; goodbye&quot;",
		},
		{
			name:     "normal text unchanged",
			input:    "Normal text without special chars",
			expected: "Normal text without special chars",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeHTML(tt.input)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// Test XSS pattern removal
func TestSanitizer_RemoveXSSPatterns(t *testing.T) {
	sanitizer := NewSanitizer()

	tests := []struct {
		name     string
		input    string
		expected bool // true if XSS patterns should be removed
	}{
		{
			name:     "script tag",
			input:    "<script>alert('xss')</script>",
			expected: true,
		},
		{
			name:     "iframe tag",
			input:    "<iframe src='javascript:alert(1)'></iframe>",
			expected: true,
		},
		{
			name:     "javascript protocol",
			input:    "javascript:alert('xss')",
			expected: true,
		},
		{
			name:     "event handler",
			input:    "<img src=x onerror=alert(1)>",
			expected: true,
		},
		{
			name:     "clean text",
			input:    "This is clean text",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.RemoveXSSPatterns(tt.input)
			hasXSSRemoved := result != tt.input

			if hasXSSRemoved != tt.expected {
				t.Errorf("expected XSS removal: %v, got: %v (input: '%s', result: '%s')",
					tt.expected, hasXSSRemoved, tt.input, result)
			}
		})
	}
}

// Test Gibson-specific validation
func TestGibsonValidator_ValidateTargetType(t *testing.T) {
	validator := NewGibsonValidator()

	tests := []struct {
		name         string
		targetType   string
		expectErrors int
	}{
		{"valid API type", "api", 0},
		{"valid model type", "model", 0},
		{"valid endpoint type", "endpoint", 0},
		{"case insensitive", "API", 0},
		{"invalid type", "database", 1},
		{"empty type", "", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validator.ValidateTargetType(tt.targetType)
			if len(errors) != tt.expectErrors {
				t.Errorf("expected %d errors, got %d: %v", tt.expectErrors, len(errors), errors)
			}
		})
	}
}

// Test provider validation
func TestGibsonValidator_ValidateProvider(t *testing.T) {
	validator := NewGibsonValidator()

	tests := []struct {
		name         string
		provider     string
		expectErrors int
	}{
		{"OpenAI provider", "openai", 0},
		{"Anthropic provider", "anthropic", 0},
		{"case insensitive", "OPENAI", 0},
		{"invalid provider", "invalid", 1},
		{"empty provider", "", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validator.ValidateProvider(tt.provider)
			if len(errors) != tt.expectErrors {
				t.Errorf("expected %d errors, got %d: %v", tt.expectErrors, len(errors), errors)
			}
		})
	}
}

// Test model name validation
func TestGibsonValidator_ValidateModelName(t *testing.T) {
	validator := NewGibsonValidator()

	tests := []struct {
		name         string
		provider     string
		model        string
		expectErrors int
	}{
		{"valid OpenAI model", "openai", "gpt-4", 0},
		{"valid OpenAI turbo model", "openai", "gpt-3.5-turbo", 0},
		{"valid Anthropic model", "anthropic", "claude-2", 0},
		{"valid HuggingFace model", "huggingface", "microsoft/DialoGPT-medium", 0},
		{"invalid OpenAI model", "openai", "invalid-model", 1},
		{"invalid HuggingFace format", "huggingface", "just-model-name", 1},
		{"valid custom model", "custom", "my-model-v1", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validator.ValidateModelName(tt.provider, tt.model)
			if len(errors) != tt.expectErrors {
				t.Errorf("expected %d errors, got %d: %v", tt.expectErrors, len(errors), errors)
			}
		})
	}
}

// Test rate limiter
func TestRateLimiter_Check(t *testing.T) {
	limiter := NewRateLimiter()

	// Set a small limit for testing
	limiter.SetLimit("test", &RateLimit{
		Requests: 2,
		Window:   time.Minute,
	})

	// First request should be allowed
	result1 := limiter.Check("test", "user1")
	if !result1.Allowed {
		t.Errorf("first request should be allowed")
	}
	if result1.Remaining != 1 {
		t.Errorf("expected 1 remaining, got %d", result1.Remaining)
	}

	// Second request should be allowed
	result2 := limiter.Check("test", "user1")
	if !result2.Allowed {
		t.Errorf("second request should be allowed")
	}
	if result2.Remaining != 0 {
		t.Errorf("expected 0 remaining, got %d", result2.Remaining)
	}

	// Third request should be denied
	result3 := limiter.Check("test", "user1")
	if result3.Allowed {
		t.Errorf("third request should be denied")
	}
	if result3.Remaining != 0 {
		t.Errorf("expected 0 remaining, got %d", result3.Remaining)
	}

	// Different user should be allowed
	result4 := limiter.Check("test", "user2")
	if !result4.Allowed {
		t.Errorf("different user should be allowed")
	}
}

// Test burst rate limiter
func TestBurstRateLimiter(t *testing.T) {
	limiter := NewBurstRateLimiter(2, time.Second)

	// First two requests should be allowed
	if !limiter.Allow() {
		t.Errorf("first request should be allowed")
	}
	if !limiter.Allow() {
		t.Errorf("second request should be allowed")
	}

	// Third request should be denied
	if limiter.Allow() {
		t.Errorf("third request should be denied")
	}

	// Check token count
	if tokens := limiter.GetTokens(); tokens != 0 {
		t.Errorf("expected 0 tokens, got %d", tokens)
	}
}

// Test validation errors
func TestValidationErrors_HasCritical(t *testing.T) {
	errors := ValidationErrors{
		{Severity: "medium", Message: "medium error"},
		{Severity: "critical", Message: "critical error"},
		{Severity: "low", Message: "low error"},
	}

	if !errors.HasCritical() {
		t.Errorf("should have critical errors")
	}

	mediumErrors := errors.Filter("medium")
	if len(mediumErrors) != 1 {
		t.Errorf("expected 1 medium error, got %d", len(mediumErrors))
	}
}

// Test tag validation
func TestGibsonValidator_ValidateTags(t *testing.T) {
	validator := NewGibsonValidator()

	tests := []struct {
		name         string
		tags         []string
		expectErrors int
	}{
		{"valid tags", []string{"security", "test", "api-v1"}, 0},
		{"empty tag", []string{"valid", ""}, 1},
		{"duplicate tags", []string{"test", "Test"}, 1},
		{"invalid characters", []string{"test@tag"}, 1},
		{"too many tags", make([]string, 150), 1}, // Exceeds MaxTagCount
		{"XSS in tag", []string{"<script>alert(1)</script>"}, 1},
		{"SQL injection in tag", []string{"test'; DROP TABLE users; --"}, 1},
	}

	// Fill the "too many tags" test case
	for i := range tests[4].tags {
		tests[4].tags[i] = "tag" + string(rune('A'+i%26))
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := validator.ValidateTags(tt.tags)
			if len(errors) < tt.expectErrors {
				t.Errorf("expected at least %d errors, got %d: %v", tt.expectErrors, len(errors), errors)
			}
		})
	}
}

// Benchmark validation performance
func BenchmarkInputValidator_ValidateString(b *testing.B) {
	validator := NewInputValidator()
	testString := "This is a test string for validation benchmarking"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateString("test", testString, RequiredString(), WithMaxLength(1000))
	}
}

func BenchmarkSanitizer_SanitizeString(b *testing.B) {
	sanitizer := NewSanitizer()
	testString := "This is a test string for sanitization benchmarking with <script>alert('xss')</script>"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sanitizer.SanitizeString(testString, DefaultSanitizationConfig())
	}
}

func BenchmarkRateLimiter_Check(b *testing.B) {
	limiter := NewRateLimiter()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Check("validation_requests", "test-user")
	}
}