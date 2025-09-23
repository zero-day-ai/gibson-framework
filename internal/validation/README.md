# Gibson Framework - Input Validation and Sanitization

This package provides comprehensive input validation and sanitization for the Gibson AI/ML security testing framework, implementing security controls to prevent all OWASP Top 10 injection vulnerabilities.

## Features

### ✅ Complete Security Coverage

- **SQL Injection Prevention**: Parameterized query validation and content filtering
- **XSS Attack Prevention**: HTML/JavaScript sanitization and validation
- **Command Injection Prevention**: Shell command escaping and pattern detection
- **Path Traversal Prevention**: File path normalization and validation
- **SSRF Prevention**: URL validation with private IP filtering
- **Rate Limiting**: DoS protection with adaptive throttling
- **Input Size Limits**: Memory exhaustion prevention
- **Character Encoding Validation**: UTF-8 validation and control character filtering

### 🚀 Performance Optimized

- **Pre-compiled Regex Patterns**: Optimized pattern matching for security checks
- **Efficient Rate Limiting**: Token bucket and sliding window algorithms
- **Minimal Allocations**: Memory-efficient validation with object pooling
- **Benchmark Results**:
  - String validation: ~2μs per operation
  - Sanitization: ~6μs per operation
  - Rate limiting: ~373ns per check

### 🎯 Gibson-Specific Features

- **AI/ML Provider Validation**: OpenAI, Anthropic, HuggingFace, etc.
- **Model Name Patterns**: Provider-specific model validation
- **Credential Security**: Entropy analysis and type-specific validation
- **Payload Content Validation**: Security testing payload validation
- **Report Generation Validation**: Comprehensive report parameter validation

## Package Structure

```
internal/validation/
├── input.go          # Core input validation functions
├── sanitize.go       # Comprehensive sanitization utilities
├── gibson.go         # Gibson-specific validation logic
├── ratelimit.go      # Rate limiting and DoS protection
├── validation_test.go # Comprehensive test suite
└── README.md         # This documentation
```

## Quick Start

### Basic Input Validation

```go
import "github.com/gibson-sec/gibson/internal/validation"

// Create validator
validator := validation.NewInputValidator()

// Validate string with security checks
errors := validator.ValidateString("username", userInput,
    validation.RequiredString(),
    validation.WithMaxLength(255),
    validation.WithPattern(regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)))

// Check for critical security issues
if errors.HasCritical() {
    log.Error("Critical security validation failed", "errors", errors)
    return fmt.Errorf("invalid input")
}
```

### Input Sanitization

```go
// Create sanitizer
sanitizer := validation.NewSanitizer()

// Basic sanitization
clean := sanitizer.SanitizeString(userInput, validation.DefaultSanitizationConfig())

// HTML sanitization
safeHTML := sanitizer.SanitizeHTML(htmlContent)

// URL sanitization
safeURL, err := sanitizer.SanitizeURL(urlInput)

// Credential sanitization (preserves structure)
cleanCred := sanitizer.SanitizeCredential(credentialValue)
```

### Gibson-Specific Validation

```go
// Create Gibson validator
gibsonValidator := validation.NewGibsonValidator()

// Validate AI/ML target
targetData := map[string]interface{}{
    "name":     "My OpenAI Target",
    "provider": "openai",
    "model":    "gpt-4",
    "type":     "api",
}
errors := gibsonValidator.ValidateTarget(targetData)

// Validate credential
credData := map[string]interface{}{
    "name":     "OpenAI API Key",
    "type":     "api_key",
    "provider": "openai",
    "value":    apiKey,
}
errors = gibsonValidator.ValidateCredential(credData)
```

### Rate Limiting

```go
// Create rate limiter
rateLimiter := validation.NewValidationRateLimiter()

// Check rate limits
result := rateLimiter.CheckValidationRequest(clientIP, userID)
if !result.Allowed {
    log.Warn("Rate limit exceeded",
        "client", clientIP,
        "retry_after", result.RetryAfter)
    return errors.New("rate limit exceeded")
}

// Specific operation rate limiting
result = rateLimiter.CheckCredentialOperation(clientIP, userID)
```

## Security Configuration

### Validation Options

```go
// String validation with security options
errors := validator.ValidateString("field", value,
    validation.RequiredString(),                    // Cannot be empty
    validation.WithMinLength(8),                   // Minimum length
    validation.WithMaxLength(255),                 // Maximum length
    validation.WithAllowedChars("a-zA-Z0-9_-"),   // Character allowlist
    validation.WithForbiddenChars("<>&\"'"),       // Character denylist
    validation.WithPattern(customRegex),           // Custom pattern
    validation.WithoutSecurityChecks(),            // Disable injection checks
)
```

### Sanitization Configuration

```go
config := &validation.SanitizationConfig{
    StripControlChars:   true,     // Remove control characters
    NormalizeWhitespace: true,     // Normalize spaces/tabs
    TrimWhitespace:     true,      // Trim leading/trailing spaces
    MaxLength:          1000,      // Truncate long strings
    PreserveNewlines:   false,     // Remove newlines
    ConvertToLowerCase: false,     // Case conversion
    RemoveNonPrintable: true,      // Remove non-printable chars
}

clean := sanitizer.SanitizeString(input, config)
```

### Rate Limit Configuration

```go
// Custom rate limits
rateLimiter.SetLimit("custom_operation", &validation.RateLimit{
    Requests: 100,                    // Max requests
    Window:   time.Minute,           // Time window
})

// Burst protection
burstLimiter := validation.NewBurstRateLimiter(10, time.Second)
if !burstLimiter.Allow() {
    return errors.New("burst limit exceeded")
}
```

## Validation Rules

### String Validation

| Check Type | Description | Error Severity |
|------------|-------------|----------------|
| Length | Min/max character limits | Medium |
| UTF-8 | Valid Unicode encoding | High |
| Control Chars | Dangerous control characters | High |
| Pattern Match | Regex pattern compliance | Medium |
| Character Sets | Allowed/forbidden characters | Medium |
| SQL Injection | SQL injection patterns | Critical |
| XSS | Cross-site scripting patterns | Critical |
| Command Injection | Shell command patterns | Critical |
| Path Traversal | Directory traversal patterns | Critical |

### URL Validation

| Check Type | Description | Error Severity |
|------------|-------------|----------------|
| Format | Valid URL structure | Medium |
| Scheme | Allowed protocols (http/https) | Medium |
| Dangerous Schemes | javascript/data/vbscript | Critical |
| Private IPs | SSRF prevention | High |
| Length | URL length limits | Medium |

### Credential Validation

| Check Type | Description | Error Severity |
|------------|-------------|----------------|
| Length | Type-specific length requirements | Medium |
| Entropy | Randomness analysis | Medium |
| Format | Type-specific format validation | Medium |
| Encoding | Base64/hex validation | Medium |

### Gibson-Specific Validation

| Component | Validation Rules |
|-----------|------------------|
| **Providers** | openai, anthropic, huggingface, azure, google, ollama, custom |
| **Target Types** | api, model, endpoint |
| **Credential Types** | api_key, oauth, bearer, basic, custom |
| **Model Names** | Provider-specific naming patterns |
| **Payload Categories** | model, data, interface, infrastructure, output, process |
| **Report Types** | scan_summary, detailed_scan, vulnerability, compliance |
| **Severities** | critical, high, medium, low, info |

## Rate Limiting

### Default Limits

| Operation Type | Requests | Window |
|----------------|----------|--------|
| Validation Requests | 1,000 | 1 minute |
| Credential Operations | 100 | 1 minute |
| Target Operations | 200 | 1 minute |
| Scan Operations | 50 | 1 minute |
| Payload Operations | 500 | 1 minute |
| Report Generation | 10 | 1 minute |
| Authentication | 5 | 1 minute |
| API per IP | 1,000 | 1 hour |
| API per User | 5,000 | 1 hour |

### Adaptive Rate Limiting

The system includes adaptive rate limiting that automatically adjusts limits based on system load:

- **Low Load (< 30%)**: Full rate limits
- **Medium Load (30-70%)**: 70% of normal limits
- **High Load (70-90%)**: 30% of normal limits
- **Critical Load (> 90%)**: 10% of limits + probabilistic denial

## Error Handling

### Validation Errors

```go
type ValidationError struct {
    Field     string                 `json:"field"`
    Value     string                 `json:"value,omitempty"`
    Message   string                 `json:"message"`
    Code      string                 `json:"code"`
    Severity  string                 `json:"severity"`
    Context   map[string]interface{} `json:"context,omitempty"`
}
```

### Error Severity Levels

- **Critical**: Security vulnerabilities (SQL injection, XSS, etc.)
- **High**: Data integrity issues (invalid encoding, dangerous content)
- **Medium**: Format violations (length, pattern mismatches)
- **Low**: Warnings (using system ports, deprecated formats)

### Error Codes

| Code | Description |
|------|-------------|
| `REQUIRED_FIELD_MISSING` | Required field is empty |
| `MAX_LENGTH_EXCEEDED` | Input exceeds size limit |
| `MIN_LENGTH_NOT_MET` | Input below minimum size |
| `PATTERN_MISMATCH` | Regex pattern validation failed |
| `SQL_INJECTION_DETECTED` | SQL injection attempt detected |
| `XSS_DETECTED` | XSS attack attempt detected |
| `COMMAND_INJECTION_DETECTED` | Command injection detected |
| `PATH_TRAVERSAL_DETECTED` | Path traversal attempt detected |
| `INVALID_UTF8` | Invalid UTF-8 encoding |
| `CONTROL_CHARACTERS` | Dangerous control characters |
| `DANGEROUS_URL_SCHEME` | Dangerous URL protocol |
| `PRIVATE_IP_ACCESS` | SSRF attempt detected |

## Testing

### Running Tests

```bash
# Run all tests
go test ./internal/validation -v

# Run with coverage
go test ./internal/validation -coverprofile=coverage.out
go tool cover -html=coverage.out

# Run benchmarks
go test ./internal/validation -bench=. -benchmem

# Run specific test categories
go test ./internal/validation -run TestInputValidator
go test ./internal/validation -run TestSanitizer
go test ./internal/validation -run TestGibsonValidator
go test ./internal/validation -run TestRateLimiter
```

### Test Coverage

The test suite provides comprehensive coverage:

- ✅ All validation functions
- ✅ All sanitization functions
- ✅ All Gibson-specific validators
- ✅ Rate limiting scenarios
- ✅ Error handling paths
- ✅ Performance benchmarks
- ✅ Security attack simulations

## Integration Examples

### HTTP Middleware Integration

```go
func ValidationMiddleware(rateLimiter *validation.ValidationRateLimiter) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            clientIP := validation.GetClientIP(getHeaders(r))

            result := rateLimiter.CheckValidationRequest(clientIP, getUserID(r))
            if !result.Allowed {
                http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

### Gibson CLI Integration

```go
func ValidateTargetCommand(cmd *cobra.Command, args []string) error {
    validator := validation.NewGibsonValidator()

    targetData := map[string]interface{}{
        "name":     cmd.Flag("name").Value.String(),
        "provider": cmd.Flag("provider").Value.String(),
        "model":    cmd.Flag("model").Value.String(),
    }

    if errors := validator.ValidateTarget(targetData); len(errors) > 0 {
        for _, err := range errors {
            if err.Severity == "critical" {
                return fmt.Errorf("critical validation error: %s", err.Message)
            }
            cmd.PrintErrf("Warning: %s\n", err.Message)
        }
    }

    return nil
}
```

### Database Layer Integration

```go
func (r *TargetRepository) Create(target *models.Target) error {
    // Validate before database operation
    validator := validation.NewGibsonValidator()

    targetData := map[string]interface{}{
        "name":     target.Name,
        "provider": string(target.Provider),
        "model":    target.Model,
        "type":     string(target.Type),
        "url":      target.URL,
    }

    if errors := validator.ValidateTarget(targetData); len(errors) > 0 {
        if errors.HasCritical() {
            return fmt.Errorf("validation failed: %w", errors)
        }
    }

    // Sanitize input before storage
    sanitizer := validation.NewSanitizer()
    target.Name = sanitizer.SanitizeGibsonInput(target.Name, "target_name")
    target.Description = sanitizer.SanitizeGibsonInput(target.Description, "description")

    return r.db.Create(target)
}
```

## Security Best Practices

### Defense in Depth

1. **Input Validation**: Validate all inputs at entry points
2. **Sanitization**: Clean data before processing/storage
3. **Output Encoding**: Encode data for specific contexts
4. **Rate Limiting**: Prevent abuse and DoS attacks
5. **Parameterized Queries**: Always use prepared statements
6. **Principle of Least Privilege**: Validate against allowlists

### Validation Strategy

```go
// 1. Rate limiting first
if !rateLimiter.Allow("operation", clientIP) {
    return ErrRateLimited
}

// 2. Input validation
if errors := validator.ValidateInput(input); errors.HasCritical() {
    return ErrInvalidInput
}

// 3. Sanitization before use
clean := sanitizer.Sanitize(input)

// 4. Context-specific encoding
encoded := sanitizer.EncodeForContext(clean, "html")
```

## Performance Considerations

### Benchmarks

```
BenchmarkInputValidator_ValidateString-8    600126   1923 ns/op   272 B/op   4 allocs/op
BenchmarkSanitizer_SanitizeString-8         211126   5796 ns/op  1483 B/op  21 allocs/op
BenchmarkRateLimiter_Check-8               3309526   373.0 ns/op  128 B/op   4 allocs/op
```

### Optimization Tips

1. **Reuse Validators**: Create validators once, use many times
2. **Pre-compile Patterns**: Use package-level regex compilation
3. **Batch Validation**: Validate related fields together
4. **Cache Results**: Cache validation results for repeated inputs
5. **Profile Performance**: Use `go test -bench` to identify bottlenecks

## Contributing

### Adding New Validators

1. Add validation function to appropriate file
2. Include comprehensive error handling
3. Add security-focused test cases
4. Update documentation and examples
5. Run full test suite and benchmarks

### Security Considerations

- Always use allowlists over denylists when possible
- Test with real attack payloads
- Consider Unicode normalization attacks
- Validate encoding at input boundaries
- Log security validation failures for monitoring

## License

This validation package is part of the Gibson Framework and subject to the same Apache 2.0 license.