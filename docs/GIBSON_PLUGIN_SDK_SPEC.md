# Gibson Framework Plugin SDK and Developer Tools Specification

## Executive Summary

This specification outlines the extraction of Gibson Framework's shared plugin code into a standalone SDK module (`gibson-plugin-sdk`) and the creation of comprehensive developer tools (`gibson-cli`). The approach follows Gibson's existing architectural patterns including Result types, dual model system, repository patterns, and Cobra CLI structure.

## Table of Contents

1. [SDK Module Extraction](#sdk-module-extraction)
2. [Developer Tools (CLI)](#developer-tools-cli)
3. [Implementation Phases](#implementation-phases)
4. [Compatibility Strategy](#compatibility-strategy)
5. [Migration Guide](#migration-guide)
6. [Testing Framework](#testing-framework)
7. [Documentation Structure](#documentation-structure)
8. [Success Metrics](#success-metrics)

---

## SDK Module Extraction

### 1. Module Structure and Organization

#### Repository Structure
```
github.com/gibson-sec/gibson-plugin-sdk/
├── go.mod                          # Module definition
├── go.sum                          # Dependency checksums
├── LICENSE                         # Apache 2.0 license
├── README.md                       # SDK documentation
├── COMPATIBILITY.md                # Framework compatibility matrix
├── MIGRATION.md                    # Migration guide for existing plugins
├── Makefile                        # Build and test automation
│
├── plugin/                         # Core plugin interfaces
│   ├── interfaces.go               # SecurityPlugin interface
│   ├── types.go                    # Shared type definitions
│   ├── domains.go                  # Security domain definitions
│   └── doc.go                      # Package documentation
│
├── grpc/                           # gRPC implementation
│   ├── client.go                   # gRPC client implementation
│   ├── server.go                   # gRPC server implementation
│   ├── handshake.go                # HashiCorp plugin handshake config
│   └── proto/                      # Protocol buffer definitions
│       ├── plugin.proto
│       └── generated/
│           └── plugin.pb.go
│
├── models/                         # Core models following Gibson patterns
│   ├── result.go                   # Result[T] type implementation
│   ├── finding.go                  # Finding model with validation
│   ├── target.go                   # Target model
│   ├── request.go                  # AssessRequest model
│   ├── response.go                 # AssessResponse model
│   └── resource.go                 # ResourceUsage tracking
│
├── validation/                     # Validation utilities
│   ├── plugin.go                   # Plugin validation logic
│   ├── config.go                   # Configuration validation
│   ├── finding.go                  # Finding validation
│   └── sanitize.go                 # Input sanitization
│
├── testing/                        # Testing utilities
│   ├── harness.go                  # Plugin test harness
│   ├── mocks.go                    # Mock implementations
│   ├── fixtures.go                 # Test fixtures
│   ├── integration.go              # Integration test helpers
│   └── benchmarks.go               # Benchmark utilities
│
├── helpers/                        # Helper utilities
│   ├── config.go                   # Configuration helpers
│   ├── logging.go                  # Logging adapters
│   ├── metrics.go                  # Metrics collection
│   └── retry.go                    # Retry logic utilities
│
├── examples/                       # Example plugins
│   ├── minimal/                    # Minimal plugin example
│   │   ├── main.go
│   │   ├── plugin.yaml
│   │   └── README.md
│   ├── sql-injection/              # SQL injection scanner
│   │   ├── main.go
│   │   ├── plugin.yaml
│   │   └── tests/
│   ├── prompt-injection/           # Prompt injection tester
│   │   ├── main.go
│   │   ├── plugin.yaml
│   │   └── payloads/
│   └── knowledge-graph/            # Knowledge graph integration
│       ├── main.go
│       ├── plugin.yaml
│       └── streaming/
│
└── internal/                       # Internal packages (not exported)
    ├── version/                    # Version management
    └── utils/                      # Internal utilities
```

### 2. Core SDK Components

#### 2.1 Plugin Interface (plugin/interfaces.go)
```go
package plugin

import (
    "context"
    "github.com/gibson-sec/gibson-plugin-sdk/models"
)

// SecurityPlugin is the core interface all Gibson plugins must implement
type SecurityPlugin interface {
    // GetInfo returns plugin metadata and capabilities
    GetInfo(ctx context.Context) models.Result[*PluginInfo]

    // Execute performs security assessment on the target
    Execute(ctx context.Context, request *AssessRequest) models.Result[*AssessResponse]

    // Validate checks plugin configuration and target validity
    Validate(ctx context.Context, request *AssessRequest) models.Result[bool]

    // Health performs plugin health check
    Health(ctx context.Context) models.Result[*HealthStatus]

    // Configure updates plugin configuration
    Configure(ctx context.Context, config map[string]interface{}) models.Result[bool]

    // GetCapabilities returns detailed plugin capabilities
    GetCapabilities(ctx context.Context) models.Result[*Capabilities]
}

// StreamingPlugin extends SecurityPlugin with streaming capabilities
type StreamingPlugin interface {
    SecurityPlugin

    // Stream enables real-time streaming of findings
    Stream(ctx context.Context, request *AssessRequest) (<-chan models.Result[*Finding], error)
}

// BatchPlugin extends SecurityPlugin with batch processing
type BatchPlugin interface {
    SecurityPlugin

    // ExecuteBatch processes multiple targets concurrently
    ExecuteBatch(ctx context.Context, requests []*AssessRequest) models.Result[*BatchResponse]
}
```

#### 2.2 Result Type Pattern (models/result.go)
```go
package models

// Result implements Gibson's functional error handling pattern
type Result[T any] struct {
    value T
    err   error
}

// Ok creates a successful Result
func Ok[T any](value T) Result[T] {
    return Result[T]{value: value}
}

// Err creates an error Result
func Err[T any](err error) Result[T] {
    return Result[T]{err: err}
}

// IsOk returns true if the Result is successful
func (r Result[T]) IsOk() bool {
    return r.err == nil
}

// IsErr returns true if the Result contains an error
func (r Result[T]) IsErr() bool {
    return r.err != nil
}

// Unwrap returns the value, panics if error
func (r Result[T]) Unwrap() T {
    if r.err != nil {
        panic(r.err)
    }
    return r.value
}

// UnwrapOr returns the value or a default if error
func (r Result[T]) UnwrapOr(defaultValue T) T {
    if r.err != nil {
        return defaultValue
    }
    return r.value
}

// Map transforms the Result value if successful
func (r Result[T]) Map(fn func(T) T) Result[T] {
    if r.IsOk() {
        return Ok(fn(r.value))
    }
    return r
}

// AndThen chains Result operations
func (r Result[T]) AndThen(fn func(T) Result[T]) Result[T] {
    if r.IsOk() {
        return fn(r.value)
    }
    return r
}
```

#### 2.3 Type Definitions (plugin/types.go)
```go
package plugin

import (
    "time"
    "github.com/google/uuid"
)

// PluginInfo contains plugin metadata
type PluginInfo struct {
    ID          uuid.UUID              `json:"id" validate:"required"`
    Name        string                 `json:"name" validate:"required,min=1,max=255"`
    Version     string                 `json:"version" validate:"required,semver"`
    Description string                 `json:"description"`
    Author      string                 `json:"author"`
    License     string                 `json:"license"`
    Domains     []SecurityDomain       `json:"domains" validate:"required,min=1"`
    Capabilities []string              `json:"capabilities"`
    Config      ConfigSchema           `json:"config"`
    Runtime     RuntimeRequirements    `json:"runtime"`
}

// ConfigSchema defines plugin configuration structure
type ConfigSchema struct {
    Required []ConfigField `json:"required"`
    Optional []ConfigField `json:"optional"`
}

// ConfigField represents a configuration field
type ConfigField struct {
    Name        string      `json:"name" validate:"required"`
    Type        string      `json:"type" validate:"required,oneof=string int bool float"`
    Description string      `json:"description"`
    Default     interface{} `json:"default,omitempty"`
    Validation  string      `json:"validation,omitempty"`
    Secret      bool        `json:"secret,omitempty"`
}

// RuntimeRequirements specifies plugin resource requirements
type RuntimeRequirements struct {
    MinMemory      int64         `json:"min_memory_bytes"`
    MaxMemory      int64         `json:"max_memory_bytes"`
    Timeout        time.Duration `json:"timeout"`
    CPUCores       int           `json:"cpu_cores"`
    NetworkAccess  bool          `json:"network_access"`
    FileAccess     []string      `json:"file_access,omitempty"`
}

// Capabilities describes detailed plugin capabilities
type Capabilities struct {
    SupportedTargetTypes []string          `json:"supported_target_types"`
    SupportedProtocols   []string          `json:"supported_protocols"`
    PayloadCategories    []PayloadCategory `json:"payload_categories"`
    DetectionMethods     []string          `json:"detection_methods"`
    OutputFormats        []string          `json:"output_formats"`
    Concurrency          int               `json:"max_concurrency"`
    RateLimiting         *RateLimitConfig  `json:"rate_limiting,omitempty"`
}
```

#### 2.4 Security Domains (plugin/domains.go)
```go
package plugin

// SecurityDomain represents Gibson's six security domain categories
type SecurityDomain string

const (
    DomainModel          SecurityDomain = "model"          // AI/ML model attacks
    DomainData           SecurityDomain = "data"           // Data poisoning/extraction
    DomainInterface      SecurityDomain = "interface"      // Prompt/UI attacks
    DomainInfrastructure SecurityDomain = "infrastructure" // Infrastructure attacks
    DomainOutput         SecurityDomain = "output"         // Output manipulation
    DomainProcess        SecurityDomain = "process"        // Process/workflow attacks
)

// PayloadCategory represents specific attack categories
type PayloadCategory string

const (
    PayloadCategoryInjection        PayloadCategory = "injection"
    PayloadCategoryJailbreak        PayloadCategory = "jailbreak"
    PayloadCategoryDataExtraction   PayloadCategory = "data_extraction"
    PayloadCategoryModelExtraction  PayloadCategory = "model_extraction"
    PayloadCategoryAdversarial      PayloadCategory = "adversarial"
    PayloadCategoryPrivacyViolation PayloadCategory = "privacy_violation"
    PayloadCategoryBiasExploitation PayloadCategory = "bias_exploitation"
)
```

### 3. gRPC Implementation

#### 3.1 Protocol Buffer Definition (grpc/proto/plugin.proto)
```protobuf
syntax = "proto3";

package gibson.plugin.v1;
option go_package = "github.com/gibson-sec/gibson-plugin-sdk/grpc/generated;generated";

service SecurityPlugin {
    rpc GetInfo(GetInfoRequest) returns (GetInfoResponse);
    rpc Execute(AssessRequest) returns (AssessResponse);
    rpc ExecuteStream(AssessRequest) returns (stream Finding);
    rpc Validate(AssessRequest) returns (ValidateResponse);
    rpc Health(HealthRequest) returns (HealthResponse);
    rpc Configure(ConfigureRequest) returns (ConfigureResponse);
}

message GetInfoRequest {
    string context_id = 1;
}

message GetInfoResponse {
    PluginInfo info = 1;
    string error = 2;
}

message AssessRequest {
    Target target = 1;
    map<string, string> config = 2;
    string scan_id = 3;
    int64 timeout_ms = 4;
    map<string, string> metadata = 5;
}

message AssessResponse {
    bool success = 1;
    string error = 2;
    repeated Finding findings = 3;
    int64 start_time = 4;
    int64 end_time = 5;
    ResourceUsage resource_usage = 6;
}

// Additional message definitions...
```

#### 3.2 HashiCorp Plugin Integration (grpc/handshake.go)
```go
package grpc

import (
    "github.com/hashicorp/go-plugin"
)

// HandshakeConfig is the Gibson plugin handshake configuration
var HandshakeConfig = plugin.HandshakeConfig{
    ProtocolVersion:  2,
    MagicCookieKey:   "GIBSON_PLUGIN_MAGIC_COOKIE",
    MagicCookieValue: "gibson-security-framework-v2",
}

// PluginMap is the map of plugins for serving
var PluginMap = map[string]plugin.Plugin{
    "security": &SecurityPluginPlugin{},
}

// SecurityPluginPlugin is the implementation of plugin.Plugin
type SecurityPluginPlugin struct {
    plugin.Plugin
    Impl SecurityPlugin
}

func (p *SecurityPluginPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
    generated.RegisterSecurityPluginServer(s, &grpcServer{
        Impl:   p.Impl,
        broker: broker,
    })
    return nil
}

func (p *SecurityPluginPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
    return &grpcClient{
        client: generated.NewSecurityPluginClient(c),
        broker: broker,
    }, nil
}
```

### 4. Testing Framework

#### 4.1 Test Harness (testing/harness.go)
```go
package testing

import (
    "context"
    "testing"
    "github.com/gibson-sec/gibson-plugin-sdk/plugin"
    "github.com/gibson-sec/gibson-plugin-sdk/models"
)

// PluginTestHarness provides comprehensive plugin testing
type PluginTestHarness struct {
    Plugin plugin.SecurityPlugin
    Config map[string]interface{}
}

// TestCompliance runs standard compliance tests
func (h *PluginTestHarness) TestCompliance(t *testing.T) {
    t.Run("GetInfo", h.testGetInfo)
    t.Run("Validate", h.testValidate)
    t.Run("Health", h.testHealth)
    t.Run("Execute", h.testExecute)
    t.Run("ErrorHandling", h.testErrorHandling)
    t.Run("Timeouts", h.testTimeouts)
    t.Run("ResourceLimits", h.testResourceLimits)
}

// TestPerformance runs performance benchmarks
func (h *PluginTestHarness) TestPerformance(b *testing.B) {
    b.Run("ExecuteLatency", h.benchmarkExecuteLatency)
    b.Run("MemoryUsage", h.benchmarkMemoryUsage)
    b.Run("Concurrency", h.benchmarkConcurrency)
}

// TestSecurity runs security validation tests
func (h *PluginTestHarness) TestSecurity(t *testing.T) {
    t.Run("InputValidation", h.testInputValidation)
    t.Run("OutputSanitization", h.testOutputSanitization)
    t.Run("SecretHandling", h.testSecretHandling)
}
```

### 5. Version Management

#### 5.1 Semantic Versioning Strategy
```go
package version

// Version represents SDK version following semver
type Version struct {
    Major int
    Minor int
    Patch int
    Pre   string
    Build string
}

const (
    // Current SDK version
    Major = 1
    Minor = 0
    Patch = 0

    // Minimum supported framework version
    MinFrameworkVersion = "2.0.0"

    // Maximum supported framework version
    MaxFrameworkVersion = "3.0.0"
)

// IsCompatible checks framework compatibility
func IsCompatible(frameworkVersion string) bool {
    // Implementation
}
```

#### 5.2 Compatibility Matrix
```yaml
# COMPATIBILITY.md
compatibility:
  sdk_version: "1.0.x"
  framework_versions:
    min: "2.0.0"
    max: "2.5.x"
  breaking_changes: []

  sdk_version: "1.1.x"
  framework_versions:
    min: "2.2.0"
    max: "3.0.x"
  breaking_changes:
    - version: "1.1.0"
      description: "Added ResourceUsage to AssessResponse"
      migration: "Set ResourceUsage to nil for backwards compatibility"
```

---

## Developer Tools (CLI)

### 1. CLI Structure

#### 1.1 Command Hierarchy
```
gibson
├── plugin
│   ├── scaffold       # Create new plugin from template
│   ├── validate       # Validate plugin implementation
│   ├── test          # Run plugin tests
│   ├── benchmark     # Run performance benchmarks
│   ├── package       # Package plugin for distribution
│   ├── publish       # Publish to plugin registry
│   ├── install       # Install plugin locally
│   ├── list          # List installed plugins
│   └── info          # Show plugin information
│
├── sdk
│   ├── version       # Show SDK version info
│   ├── compatibility # Check compatibility
│   ├── update        # Update SDK version
│   └── migrate       # Migrate to new SDK version
│
├── dev
│   ├── server        # Start development server
│   ├── watch         # Watch and rebuild
│   ├── debug         # Debug plugin execution
│   └── profile       # Profile plugin performance
│
└── registry
    ├── search        # Search plugin registry
    ├── download      # Download from registry
    └── submit        # Submit to registry
```

### 2. Plugin Scaffold Command

#### 2.1 Implementation (cmd/plugin_scaffold.go)
```go
package cmd

import (
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
    "github.com/gibson-sec/gibson-cli/internal/scaffold"
)

func pluginScaffoldCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:     "scaffold NAME",
        Aliases: []string{"create", "new", "init"},
        Short:   "Create a new plugin from template",
        Long:    "Scaffold a new Gibson security plugin with best practices and boilerplate code",
        Args:    cobra.ExactArgs(1),
        RunE:    runPluginScaffold,
        Example: `  # Create a basic plugin
  gibson plugin scaffold my-scanner

  # Create with specific domain
  gibson plugin scaffold my-scanner --domain interface

  # Create with multiple capabilities
  gibson plugin scaffold my-scanner \
    --domain interface \
    --capabilities "sql-injection,xss,command-injection"

  # Create from specific template
  gibson plugin scaffold my-scanner --template advanced

  # Create with custom SDK version
  gibson plugin scaffold my-scanner --sdk-version v1.2.0`,
    }

    // Flags following Gibson patterns
    cmd.Flags().StringP("domain", "d", "interface", "Security domain (model|data|interface|infrastructure|output|process)")
    cmd.Flags().StringSliceP("capabilities", "c", []string{}, "Plugin capabilities")
    cmd.Flags().StringP("template", "t", "basic", "Template to use (basic|advanced|streaming|batch)")
    cmd.Flags().String("sdk-version", "latest", "Gibson SDK version to use")
    cmd.Flags().StringP("output", "o", ".", "Output directory")
    cmd.Flags().String("author", "", "Plugin author name")
    cmd.Flags().String("license", "Apache-2.0", "Plugin license")
    cmd.Flags().Bool("git", true, "Initialize git repository")
    cmd.Flags().Bool("tests", true, "Include test files")
    cmd.Flags().Bool("ci", true, "Include CI/CD configuration")

    return cmd
}

func runPluginScaffold(cmd *cobra.Command, args []string) error {
    pluginName := args[0]

    // Get configuration from flags
    config := scaffold.Config{
        Name:         pluginName,
        Domain:       viper.GetString("domain"),
        Capabilities: viper.GetStringSlice("capabilities"),
        Template:     viper.GetString("template"),
        SDKVersion:   viper.GetString("sdk-version"),
        OutputDir:    viper.GetString("output"),
        Author:       viper.GetString("author"),
        License:      viper.GetString("license"),
        InitGit:      viper.GetBool("git"),
        IncludeTests: viper.GetBool("tests"),
        IncludeCI:    viper.GetBool("ci"),
    }

    // Create scaffolder
    s := scaffold.New(config)

    // Generate plugin structure
    result := s.Generate()
    if result.IsErr() {
        return result.Unwrap()
    }

    // Output success message
    cmd.Printf("✓ Plugin '%s' created successfully at %s\n", pluginName, config.OutputDir)
    cmd.Printf("\nNext steps:\n")
    cmd.Printf("  cd %s\n", pluginName)
    cmd.Printf("  go mod tidy\n")
    cmd.Printf("  gibson plugin validate\n")
    cmd.Printf("  gibson plugin test\n")

    return nil
}
```

#### 2.2 Template Structure
```go
// internal/scaffold/templates.go
package scaffold

const BasicPluginTemplate = `package main

import (
    "context"
    "fmt"

    "github.com/hashicorp/go-plugin"
    sdk "github.com/gibson-sec/gibson-plugin-sdk"
    "github.com/gibson-sec/gibson-plugin-sdk/models"
    "github.com/gibson-sec/gibson-plugin-sdk/plugin"
)

type {{.Name}}Plugin struct {
    config map[string]interface{}
}

func (p *{{.Name}}Plugin) GetInfo(ctx context.Context) models.Result[*plugin.PluginInfo] {
    return models.Ok(&plugin.PluginInfo{
        Name:        "{{.Name}}",
        Version:     "1.0.0",
        Description: "{{.Description}}",
        Author:      "{{.Author}}",
        License:     "{{.License}}",
        Domains:     []plugin.SecurityDomain{plugin.Domain{{.Domain}}},
        Capabilities: {{.Capabilities}},
        Config: plugin.ConfigSchema{
            Required: []plugin.ConfigField{
                {
                    Name:        "target_url",
                    Type:        "string",
                    Description: "Target URL to scan",
                    Validation:  "url",
                },
            },
            Optional: []plugin.ConfigField{
                {
                    Name:        "timeout",
                    Type:        "int",
                    Description: "Scan timeout in seconds",
                    Default:     30,
                },
            },
        },
    })
}

func (p *{{.Name}}Plugin) Execute(ctx context.Context, req *plugin.AssessRequest) models.Result[*plugin.AssessResponse] {
    // TODO: Implement security assessment logic

    findings := []*plugin.Finding{}

    // Example finding
    finding := &plugin.Finding{
        Title:       "Example Security Issue",
        Description: "This is an example finding",
        Severity:    plugin.SeverityMedium,
        Confidence:  plugin.ConfidenceHigh,
        Domain:      plugin.Domain{{.Domain}},
        Category:    "{{.Category}}",
    }

    findings = append(findings, finding)

    return models.Ok(&plugin.AssessResponse{
        Success:  true,
        Findings: findings,
    })
}

func (p *{{.Name}}Plugin) Validate(ctx context.Context, req *plugin.AssessRequest) models.Result[bool] {
    // Validate configuration and target
    if req.Target == nil {
        return models.Err[bool](fmt.Errorf("target is required"))
    }

    if req.Target.URL == "" && req.Target.Type == "api" {
        return models.Err[bool](fmt.Errorf("URL is required for API targets"))
    }

    return models.Ok(true)
}

func (p *{{.Name}}Plugin) Health(ctx context.Context) models.Result[*plugin.HealthStatus] {
    return models.Ok(&plugin.HealthStatus{
        Healthy: true,
        Message: "Plugin is operational",
    })
}

func (p *{{.Name}}Plugin) Configure(ctx context.Context, config map[string]interface{}) models.Result[bool] {
    p.config = config
    return models.Ok(true)
}

func (p *{{.Name}}Plugin) GetCapabilities(ctx context.Context) models.Result[*plugin.Capabilities] {
    return models.Ok(&plugin.Capabilities{
        SupportedTargetTypes: []string{"api", "website"},
        SupportedProtocols:   []string{"http", "https"},
        PayloadCategories:    []plugin.PayloadCategory{plugin.PayloadCategory{{.PayloadCategory}}},
        DetectionMethods:     []string{"pattern-matching", "response-analysis"},
        OutputFormats:        []string{"json", "sarif"},
        Concurrency:          10,
    })
}

func main() {
    plugin.Serve(&plugin.ServeConfig{
        HandshakeConfig: sdk.HandshakeConfig,
        Plugins: map[string]plugin.Plugin{
            "security": &sdk.SecurityPluginPlugin{
                Impl: &{{.Name}}Plugin{},
            },
        },
        GRPCServer: plugin.DefaultGRPCServer,
    })
}
`
```

### 3. Plugin Validation

#### 3.1 Validation Command (cmd/plugin_validate.go)
```go
package cmd

import (
    "github.com/spf13/cobra"
    "github.com/gibson-sec/gibson-cli/internal/validate"
)

func pluginValidateCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "validate [PATH]",
        Short: "Validate plugin implementation",
        Long:  "Validate that a plugin correctly implements the Gibson SecurityPlugin interface",
        Args:  cobra.MaximumNArgs(1),
        RunE:  runPluginValidate,
        Example: `  # Validate current directory
  gibson plugin validate

  # Validate specific plugin
  gibson plugin validate ./my-plugin

  # Validate with verbose output
  gibson plugin validate -v

  # Validate and run compliance tests
  gibson plugin validate --compliance

  # Validate against specific SDK version
  gibson plugin validate --sdk-version v1.2.0`,
    }

    cmd.Flags().BoolP("verbose", "v", false, "Verbose output")
    cmd.Flags().Bool("compliance", false, "Run compliance tests")
    cmd.Flags().Bool("security", false, "Run security validation")
    cmd.Flags().Bool("performance", false, "Run performance benchmarks")
    cmd.Flags().String("sdk-version", "", "Validate against specific SDK version")
    cmd.Flags().StringP("output", "o", "table", "Output format (table|json|yaml)")

    return cmd
}

func runPluginValidate(cmd *cobra.Command, args []string) error {
    path := "."
    if len(args) > 0 {
        path = args[0]
    }

    validator := validate.New(validate.Config{
        Path:           path,
        Verbose:        viper.GetBool("verbose"),
        RunCompliance:  viper.GetBool("compliance"),
        RunSecurity:    viper.GetBool("security"),
        RunPerformance: viper.GetBool("performance"),
        SDKVersion:     viper.GetString("sdk-version"),
    })

    results := validator.Validate()

    // Output results
    switch viper.GetString("output") {
    case "json":
        return outputJSON(cmd, results)
    case "yaml":
        return outputYAML(cmd, results)
    default:
        return outputTable(cmd, results)
    }
}
```

#### 3.2 Validation Implementation
```go
package validate

import (
    "context"
    "fmt"
    "os/exec"
    "time"

    "github.com/gibson-sec/gibson-plugin-sdk/plugin"
    "github.com/gibson-sec/gibson-plugin-sdk/testing"
)

type Validator struct {
    config Config
}

func (v *Validator) Validate() models.Result[*ValidationResults] {
    results := &ValidationResults{
        Timestamp: time.Now(),
        Path:      v.config.Path,
    }

    // Step 1: Build plugin
    buildResult := v.buildPlugin()
    results.BuildCheck = buildResult
    if buildResult.IsErr() {
        return models.Ok(results)
    }

    // Step 2: Load plugin
    loadResult := v.loadPlugin()
    results.LoadCheck = loadResult
    if loadResult.IsErr() {
        return models.Ok(results)
    }

    // Step 3: Interface compliance
    complianceResult := v.checkCompliance(loadResult.Unwrap())
    results.ComplianceCheck = complianceResult

    // Step 4: Configuration validation
    configResult := v.validateConfig(loadResult.Unwrap())
    results.ConfigCheck = configResult

    // Step 5: Security checks (optional)
    if v.config.RunSecurity {
        securityResult := v.runSecurityChecks(loadResult.Unwrap())
        results.SecurityCheck = securityResult
    }

    // Step 6: Performance benchmarks (optional)
    if v.config.RunPerformance {
        perfResult := v.runPerformanceBenchmarks(loadResult.Unwrap())
        results.PerformanceCheck = perfResult
    }

    // Calculate overall status
    results.Valid = results.AllChecksPassed()

    return models.Ok(results)
}

func (v *Validator) checkCompliance(p plugin.SecurityPlugin) models.Result[*ComplianceResults] {
    harness := testing.PluginTestHarness{
        Plugin: p,
    }

    results := &ComplianceResults{
        InterfaceImplemented: true,
        RequiredMethods:      []MethodCheck{},
    }

    // Check each required method
    methods := []string{"GetInfo", "Execute", "Validate", "Health", "Configure", "GetCapabilities"}

    for _, method := range methods {
        check := v.checkMethod(p, method)
        results.RequiredMethods = append(results.RequiredMethods, check)
    }

    // Run compliance tests if requested
    if v.config.RunCompliance {
        testResults := harness.RunComplianceTests()
        results.ComplianceTests = testResults
    }

    return models.Ok(results)
}
```

### 4. Plugin Testing Framework

#### 4.1 Test Command
```go
package cmd

func pluginTestCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "test [PATH]",
        Short: "Run plugin tests",
        Long:  "Run unit tests, integration tests, and compliance tests for a plugin",
        Args:  cobra.MaximumNArgs(1),
        RunE:  runPluginTest,
        Example: `  # Run all tests
  gibson plugin test

  # Run specific test suites
  gibson plugin test --suite unit,integration

  # Run with coverage
  gibson plugin test --coverage

  # Run with race detection
  gibson plugin test --race`,
    }

    cmd.Flags().StringSlice("suite", []string{"all"}, "Test suites to run (unit|integration|compliance|security)")
    cmd.Flags().Bool("coverage", false, "Generate coverage report")
    cmd.Flags().Bool("race", false, "Enable race detection")
    cmd.Flags().Bool("verbose", false, "Verbose test output")
    cmd.Flags().Duration("timeout", 10*time.Minute, "Test timeout")

    return cmd
}
```

### 5. Development Server

#### 5.1 Development Server Implementation
```go
package dev

import (
    "context"
    "net/http"

    "github.com/gibson-sec/gibson-cli/internal/server"
)

type DevServer struct {
    config ServerConfig
    plugin plugin.SecurityPlugin
}

func (s *DevServer) Start(ctx context.Context) error {
    // Start plugin in development mode
    mux := http.NewServeMux()

    // Health endpoint
    mux.HandleFunc("/health", s.handleHealth)

    // Plugin info endpoint
    mux.HandleFunc("/info", s.handleInfo)

    // Test execution endpoint
    mux.HandleFunc("/execute", s.handleExecute)

    // WebSocket for live reload
    mux.HandleFunc("/ws", s.handleWebSocket)

    // Metrics endpoint
    mux.HandleFunc("/metrics", s.handleMetrics)

    // Debug endpoints
    mux.HandleFunc("/debug/pprof/", pprof.Index)
    mux.HandleFunc("/debug/config", s.handleConfig)

    server := &http.Server{
        Addr:    s.config.Address,
        Handler: mux,
    }

    return server.ListenAndServe()
}
```

---

## Implementation Phases

### Phase 1: SDK Extraction (Weeks 1-2)

#### Week 1: Core SDK
- [ ] Create gibson-plugin-sdk repository
- [ ] Extract shared code from gibson-framework/shared
- [ ] Implement Result[T] type pattern
- [ ] Define plugin interfaces and types
- [ ] Set up go.mod with proper versioning

#### Week 2: gRPC and Testing
- [ ] Implement gRPC server/client
- [ ] Create protocol buffer definitions
- [ ] Build testing harness
- [ ] Add validation utilities
- [ ] Create basic examples

### Phase 2: Developer Tools (Weeks 3-5)

#### Week 3: CLI Foundation
- [ ] Create gibson-cli repository
- [ ] Implement Cobra command structure
- [ ] Add plugin scaffold command
- [ ] Add plugin validate command

#### Week 4: Testing and Validation
- [ ] Implement plugin test command
- [ ] Add compliance testing
- [ ] Add security validation
- [ ] Add performance benchmarking

#### Week 5: Advanced Tools
- [ ] Implement development server
- [ ] Add plugin packaging
- [ ] Add watch mode
- [ ] Add debugging support

### Phase 3: Documentation and Examples (Week 6)

- [ ] Write comprehensive SDK documentation
- [ ] Create plugin development guide
- [ ] Build example plugins for each domain
- [ ] Create video tutorials
- [ ] Set up documentation site

### Phase 4: Migration and Rollout (Week 7-8)

#### Week 7: Migration
- [ ] Migrate knowledge-graph plugin
- [ ] Update existing plugins
- [ ] Create migration guide
- [ ] Test backward compatibility

#### Week 8: Release
- [ ] Publish SDK v1.0.0
- [ ] Release CLI tools
- [ ] Announce to community
- [ ] Monitor adoption

---

## Compatibility Strategy

### Version Compatibility Rules

1. **SDK Versioning**
   - MAJOR: Breaking changes to SecurityPlugin interface
   - MINOR: New optional fields, new helper functions
   - PATCH: Bug fixes, documentation updates

2. **Framework Compatibility**
   - Each SDK version supports 2 major framework versions
   - 6-month deprecation notice for breaking changes
   - Automated compatibility testing in CI

3. **Plugin Compatibility**
   - Plugins specify minimum SDK version
   - Framework checks plugin SDK version on load
   - Clear error messages for incompatible versions

### Compatibility Testing Matrix

```yaml
test_matrix:
  sdk_versions: [1.0.0, 1.1.0, 1.2.0]
  framework_versions: [2.0.0, 2.1.0, 2.2.0, 3.0.0]
  plugin_examples: [minimal, sql-injection, prompt-injection]

  expected_results:
    - sdk: 1.0.0
      framework: [2.0.0, 2.1.0]
      result: compatible
    - sdk: 1.0.0
      framework: [2.2.0, 3.0.0]
      result: incompatible
```

---

## Migration Guide

### For Existing Plugin Developers

#### Step 1: Update go.mod
```go
// Before (using local shared)
replace github.com/gibson-sec/gibson-framework-2/shared => ../../gibson-framework/shared

// After (using SDK)
require github.com/gibson-sec/gibson-plugin-sdk v1.0.0
```

#### Step 2: Update Imports
```go
// Before
import (
    "github.com/gibson-sec/gibson-framework-2/shared"
)

// After
import (
    sdk "github.com/gibson-sec/gibson-plugin-sdk"
    "github.com/gibson-sec/gibson-plugin-sdk/plugin"
    "github.com/gibson-sec/gibson-plugin-sdk/models"
)
```

#### Step 3: Update Interface Implementation
```go
// Before - returning raw values
func (p *MyPlugin) GetInfo(ctx context.Context) (*shared.PluginInfo, error)

// After - using Result[T] pattern
func (p *MyPlugin) GetInfo(ctx context.Context) models.Result[*plugin.PluginInfo]
```

#### Step 4: Update Main Function
```go
// After
func main() {
    plugin.Serve(&plugin.ServeConfig{
        HandshakeConfig: sdk.HandshakeConfig,
        Plugins: map[string]plugin.Plugin{
            "security": &sdk.SecurityPluginPlugin{
                Impl: &MyPlugin{},
            },
        },
    })
}
```

### Migration Tool

```bash
# Automated migration tool
gibson sdk migrate --from local --to v1.0.0

# What it does:
# 1. Updates go.mod dependencies
# 2. Rewrites import statements
# 3. Updates interface signatures
# 4. Adds Result[T] wrapping
# 5. Updates plugin.yaml if needed
```

---

## Testing Framework

### 1. Unit Testing

```go
// plugin_test.go
package main

import (
    "testing"
    "github.com/gibson-sec/gibson-plugin-sdk/testing"
)

func TestPluginCompliance(t *testing.T) {
    plugin := &MyPlugin{}
    harness := testing.PluginTestHarness{
        Plugin: plugin,
        Config: map[string]interface{}{
            "timeout": 30,
        },
    }

    harness.TestCompliance(t)
}

func BenchmarkPluginExecution(b *testing.B) {
    plugin := &MyPlugin{}
    harness := testing.PluginTestHarness{
        Plugin: plugin,
    }

    harness.TestPerformance(b)
}
```

### 2. Integration Testing

```go
func TestPluginIntegration(t *testing.T) {
    // Start test server
    server := testing.NewTestServer()
    defer server.Close()

    // Create plugin with test configuration
    plugin := &MyPlugin{
        config: map[string]interface{}{
            "target_url": server.URL,
        },
    }

    // Run integration tests
    harness := testing.IntegrationHarness{
        Plugin: plugin,
        Server: server,
    }

    harness.RunIntegrationTests(t)
}
```

### 3. CI/CD Pipeline

```yaml
# .github/workflows/plugin-ci.yml
name: Plugin CI

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Install Gibson CLI
        run: |
          go install github.com/gibson-sec/gibson-cli@latest

      - name: Validate Plugin
        run: |
          gibson plugin validate
          gibson plugin validate --compliance
          gibson plugin validate --security

      - name: Run Tests
        run: |
          gibson plugin test --coverage --race

      - name: Build Plugin
        run: |
          gibson plugin package

      - name: Upload Artifacts
        uses: actions/upload-artifact@v3
        with:
          name: plugin-package
          path: dist/
```

---

## Documentation Structure

### 1. SDK Documentation

```
docs.gibson-sec.com/sdk/
├── getting-started/
│   ├── installation.md
│   ├── your-first-plugin.md
│   ├── plugin-anatomy.md
│   └── testing-guide.md
│
├── concepts/
│   ├── security-domains.md
│   ├── result-pattern.md
│   ├── plugin-lifecycle.md
│   └── resource-management.md
│
├── guides/
│   ├── sql-injection-scanner.md
│   ├── prompt-injection-tester.md
│   ├── model-adversarial.md
│   └── streaming-plugins.md
│
├── reference/
│   ├── interfaces/
│   │   ├── SecurityPlugin.md
│   │   ├── StreamingPlugin.md
│   │   └── BatchPlugin.md
│   ├── types/
│   │   ├── PluginInfo.md
│   │   ├── Finding.md
│   │   └── Target.md
│   └── helpers/
│       ├── validation.md
│       └── testing.md
│
├── cli/
│   ├── commands/
│   │   ├── plugin-scaffold.md
│   │   ├── plugin-validate.md
│   │   └── plugin-test.md
│   └── configuration.md
│
└── migration/
    ├── from-shared.md
    ├── version-upgrade.md
    └── troubleshooting.md
```

### 2. Plugin Development Guide

```markdown
# Gibson Plugin Development Guide

## Quick Start

### 1. Install Gibson CLI
```bash
go install github.com/gibson-sec/gibson-cli@latest
```

### 2. Create Your Plugin
```bash
gibson plugin scaffold my-scanner --domain interface
cd my-scanner
```

### 3. Implement Security Logic
Edit `main.go` to implement your security assessment logic.

### 4. Test Your Plugin
```bash
gibson plugin test
gibson plugin validate --compliance
```

### 5. Package and Distribute
```bash
gibson plugin package
gibson registry submit
```

## Plugin Architecture

Plugins follow Gibson's domain-based security model...

## Best Practices

1. **Error Handling**: Always use Result[T] pattern
2. **Resource Management**: Track and limit resource usage
3. **Security**: Validate all inputs, sanitize outputs
4. **Performance**: Implement timeouts, use concurrency wisely
5. **Testing**: Write comprehensive tests, use the test harness
```

---

## Success Metrics

### Adoption Metrics
- Number of external plugins created
- SDK downloads per month
- CLI tool usage statistics
- Community contributions

### Quality Metrics
- Plugin validation pass rate
- Average plugin test coverage
- Security vulnerability reports
- Performance benchmark results

### Developer Experience Metrics
- Time to create first plugin
- Documentation effectiveness (support tickets)
- Tool satisfaction survey results
- Migration success rate

### Technical Metrics
- SDK version adoption rate
- Backward compatibility success
- CI/CD pipeline success rate
- Registry availability

---

## Risk Mitigation

### Technical Risks

1. **Breaking Changes**
   - Mitigation: Comprehensive versioning strategy
   - Mitigation: Extensive compatibility testing
   - Mitigation: Clear migration guides

2. **Performance Degradation**
   - Mitigation: Benchmark suite in CI/CD
   - Mitigation: Resource usage monitoring
   - Mitigation: Performance regression tests

3. **Security Vulnerabilities**
   - Mitigation: Security validation in CLI
   - Mitigation: Automated security scanning
   - Mitigation: Regular security audits

### Adoption Risks

1. **Low Adoption Rate**
   - Mitigation: Comprehensive documentation
   - Mitigation: Video tutorials and workshops
   - Mitigation: Active community support

2. **Migration Difficulties**
   - Mitigation: Automated migration tool
   - Mitigation: Backward compatibility period
   - Mitigation: Direct support for early adopters

---

## Appendices

### A. Example Plugin Implementations

[Full implementations of example plugins in each security domain]

### B. API Reference

[Complete API documentation with examples]

### C. Troubleshooting Guide

[Common issues and solutions]

### D. Performance Optimization Guide

[Best practices for high-performance plugins]

### E. Security Hardening Guide

[Security best practices for plugin development]

---

## Approval and Sign-off

**Specification Version:** 1.0.0
**Date:** 2024-01-19
**Author:** Gibson Framework Team
**Status:** PENDING APPROVAL

### Review Checklist
- [ ] Technical feasibility validated
- [ ] Resource requirements estimated
- [ ] Timeline realistic and achievable
- [ ] Risk mitigation adequate
- [ ] Documentation plan comprehensive
- [ ] Testing strategy complete
- [ ] Migration path clear
- [ ] Success metrics defined

### Approval Required From:
- [ ] Engineering Lead
- [ ] Security Team
- [ ] DevOps Team
- [ ] Product Management
- [ ] Developer Relations

---

END OF SPECIFICATION