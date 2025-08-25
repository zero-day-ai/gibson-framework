# CLI Models and Validation Architecture

## Overview

Gibson's CLI models provide comprehensive type safety and validation for all command-line interactions. Built on Pydantic v2, these models ensure data integrity, provide clear error messages, and enable consistent API contracts across all CLI commands.

## Model Architecture

### Base Model Hierarchy

```
GibsonBaseModel (from gibson.models.base)
├── CommandRequest (base for all CLI inputs)
│   ├── ScanRequest (scan command parameters)
│   ├── PayloadRequest (payload operations)
│   ├── TargetRequest (target management)
│   ├── ModuleRequest (module operations)
│   ├── ConfigRequest (configuration management)
│   ├── BatchRequest (batch operations)
│   └── [Other command-specific requests]
├── CommandResponse (base for all CLI outputs)
│   ├── ScanResponse (scan results)
│   ├── PayloadResponse (payload operation results)
│   ├── ErrorResponse (error reporting)
│   ├── PaginatedResponse (paginated results)
│   ├── BatchResponse (batch operation results)
│   └── [Other command-specific responses]
└── ProgressUpdate (real-time progress tracking)
```

### Core Model Categories

#### Request Models
All CLI commands use request models that inherit from `CommandRequest`:

```python
class CommandRequest(GibsonBaseModel):
    # Output control
    verbose: bool = False
    quiet: bool = False
    output_format: OutputFormat = OutputFormat.TABLE
    
    # Configuration
    config_override: Optional[Dict[str, Any]] = None
    config_file: Optional[str] = None
    
    # Execution control
    dry_run: bool = False
    force: bool = False
    timeout: Optional[float] = None
```

**Key Features**:
- Mutually exclusive verbose/quiet flags with validation
- Security validation prevents sensitive configuration overrides
- Consistent timeout and execution control across all commands

#### Response Models
All CLI commands return response models that inherit from `CommandResponse`:

```python
class CommandResponse(GibsonBaseModel):
    success: bool
    message: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    errors: Optional[List[ErrorModel]] = None
    warnings: Optional[List[str]] = None
    duration: Optional[float] = None
    command: Optional[str] = None
```

**Key Features**:
- Consistent success/failure indication
- Structured error reporting with machine-readable codes
- Multiple output format support (table, JSON, YAML, etc.)
- Execution metadata tracking

## Command-Specific Models

### Scan Models (`scan.py`)

**ScanRequest**: Comprehensive scan configuration
```python
class ScanRequest(CommandRequest):
    # Target configuration
    target: HttpUrl  # Validated URL or endpoint
    target_name: Optional[str]  # Human-readable name
    
    # Scan parameters
    scan_type: ScanType  # QUICK, FULL, CUSTOM, etc.
    domains: List[AttackDomain]  # Attack domains to test
    modules: Optional[List[str]]  # Specific modules to run
    depth: AnalysisDepth  # SURFACE, DEEP, COMPREHENSIVE
    
    # Execution parameters
    parallel: bool = True
    max_workers: int = 5
    timeout_per_module: int = 300
```

**Key Validation**:
- URL validation for targets with protocol checking
- Domain validation against available attack domains
- Module existence validation
- Resource limit validation (workers, timeouts)

**ScanResponse**: Structured scan results
```python
class ScanResponse(CommandResponse):
    scan_id: UUID
    target_info: TargetInfo
    findings: List[Finding]
    coverage: ScanCoverage
    performance: ScanPerformance
    recommendations: List[str]
```

### Payload Models (`payload.py`)

**PayloadRequest**: Payload operation parameters
```python
class PayloadRequest(CommandRequest):
    operation: PayloadOperation  # SYNC, LIST, VALIDATE, SEARCH
    source: Optional[str]  # Git URL or source name
    category: Optional[str]  # Payload category filter
    tags: Optional[List[str]]  # Tag-based filtering
    force_update: bool = False
```

**PayloadResponse**: Payload operation results
```python
class PayloadResponse(CommandResponse):
    payloads_processed: int
    payloads_updated: int
    payloads_added: int
    sync_duration: float
    source_info: List[SourceInfo]
```

### Target Models (`target.py`)

**TargetRequest**: Target management operations
```python
class TargetRequest(CommandRequest):
    operation: TargetOperation  # ADD, LIST, TEST, REMOVE
    name: Optional[str]  # Target identifier
    url: Optional[HttpUrl]  # Target URL
    auth_type: Optional[AuthType]  # Authentication method
    credentials: Optional[Dict[str, str]]  # Secure credential storage
```

**Key Security Features**:
- Credential validation without logging sensitive data
- Authentication type validation
- Secure credential storage integration

### Module Models (`module.py`)

**ModuleRequest**: Module management operations
```python
class ModuleRequest(CommandRequest):
    operation: ModuleOperation  # INSTALL, LIST, REMOVE, SEARCH
    module_name: Optional[str]  # Module identifier
    source: Optional[str]  # Installation source
    version: Optional[str]  # Version specification
    upgrade: bool = False
```

**ModuleResponse**: Module operation results with dependency information
```python
class ModuleResponse(CommandResponse):
    modules: List[ModuleInfo]
    dependencies: Dict[str, List[str]]
    conflicts: List[ConflictInfo]
    installation_summary: InstallationSummary
```

## Enumeration Types

### Output Formats (`OutputFormat`)
```python
class OutputFormat(str, Enum):
    TABLE = "table"      # Rich-formatted tables
    JSON = "json"        # Machine-readable JSON
    YAML = "yaml"        # Human-readable YAML
    CSV = "csv"          # Data analysis format
    MARKDOWN = "markdown" # Documentation format
    SARIF = "sarif"      # Security tool integration
    HTML = "html"        # Web-friendly format
    XML = "xml"          # Structured data format
```

### Scan Types (`ScanType`)
```python
class ScanType(str, Enum):
    QUICK = "quick"              # Essential modules only
    FULL = "full"                # Comprehensive testing
    CUSTOM = "custom"            # User-defined modules
    TARGETED = "targeted"        # Specific vulnerability focus
    COMPREHENSIVE = "comprehensive"  # All available tests
    MINIMAL = "minimal"          # Basic safety checks
    BASELINE = "baseline"        # Establishment scan
```

### Analysis Depth (`AnalysisDepth`)
```python
class AnalysisDepth(str, Enum):
    SURFACE = "surface"      # Quick surface-level checks
    DEEP = "deep"            # Thorough analysis
    COMPREHENSIVE = "comprehensive"  # Exhaustive testing
```

### Attack Domains (`AttackDomain`)
```python
class AttackDomain(str, Enum):
    PROMPT = "prompt"        # LLM01 - Prompt Injection
    DATA = "data"            # LLM03 - Training Data Poisoning
    MODEL = "model"          # LLM10 - Model Theft
    OUTPUT = "output"        # LLM02 - Insecure Output Handling
    SYSTEM = "system"        # System-level attacks
```

## Validation Patterns

### Field-Level Validation

**URL Validation**:
```python
@field_validator('target')
@classmethod
def validate_target_url(cls, v: HttpUrl) -> HttpUrl:
    """Validate target URL format and accessibility."""
    if not str(v).startswith(('http://', 'https://')):
        raise ValueError("Target must be HTTP or HTTPS URL")
    return v
```

**Domain Validation**:
```python
@field_validator('domains')
@classmethod
def validate_attack_domains(cls, v: List[AttackDomain]) -> List[AttackDomain]:
    """Validate attack domain selection."""
    if not v:
        raise ValueError("At least one attack domain must be specified")
    return list(set(v))  # Remove duplicates
```

**Resource Limit Validation**:
```python
@field_validator('max_workers')
@classmethod
def validate_worker_count(cls, v: int) -> int:
    """Validate worker count within reasonable limits."""
    if not 1 <= v <= 50:
        raise ValueError("Worker count must be between 1 and 50")
    return v
```

### Model-Level Validation

**Cross-Field Validation**:
```python
@model_validator(mode='after')
def validate_scan_parameters(self) -> 'ScanRequest':
    """Validate scan parameter combinations."""
    if self.scan_type == ScanType.CUSTOM and not self.modules:
        raise ValueError("Custom scan requires module specification")
    
    if self.parallel and self.max_workers == 1:
        self.parallel = False  # Auto-correct inconsistency
    
    return self
```

**Security Validation**:
```python
@model_validator(mode='after')
def validate_security_constraints(self) -> 'CommandRequest':
    """Ensure security constraints are met."""
    if self.config_override:
        dangerous_keys = ['api_key', 'secret', 'password', 'token']
        for key in self.config_override.keys():
            if any(danger in key.lower() for danger in dangerous_keys):
                raise ValueError(f"Cannot override sensitive config: {key}")
    return self
```

## Validation Utilities

### CLI Validation Functions (`utils/validation.py`)

**Domain Validation**:
```python
def validate_domains(domains: Optional[str]) -> List[AttackDomain]:
    """Parse and validate comma-separated domain list."""
    if not domains:
        return list(AttackDomain)
    
    domain_names = [d.strip().lower() for d in domains.split(",")]
    valid_domains = []
    invalid_domains = []
    
    # Validation logic with helpful error messages
    # ...
    
    if invalid_domains:
        valid_options = ", ".join(sorted(valid_domain_names))
        raise typer.BadParameter(
            f"Invalid domain(s): {', '.join(invalid_domains)}. "
            f"Valid options: {valid_options}"
        )
```

**Output Format Validation**:
```python
def validate_output_format(format: str) -> OutputFormat:
    """Validate and convert output format string."""
    try:
        return OutputFormat(format.lower())
    except ValueError:
        valid_formats = [f.value for f in OutputFormat]
        raise typer.BadParameter(
            f"Invalid format '{format}'. Valid options: {', '.join(valid_formats)}"
        )
```

**File Path Validation**:
```python
def validate_file_path(path: str, must_exist: bool = False) -> Path:
    """Validate file path with existence checking."""
    file_path = Path(path).expanduser().resolve()
    
    if must_exist and not file_path.exists():
        raise typer.BadParameter(f"File does not exist: {file_path}")
    
    if must_exist and not file_path.is_file():
        raise typer.BadParameter(f"Path is not a file: {file_path}")
    
    return file_path
```

## Error Handling and User Experience

### Error Response Models

**ErrorResponse**: Comprehensive error reporting
```python
class ErrorResponse(CommandResponse):
    success: Literal[False] = False
    error_code: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    traceback: Optional[str] = None
    suggestions: Optional[List[str]] = None
```

**Error Creation from Exceptions**:
```python
@classmethod
def from_exception(cls, exception: Exception, 
                  command: Optional[str] = None,
                  include_traceback: bool = False) -> 'ErrorResponse':
    """Create user-friendly error response from exception."""
    error_response = cls(
        message=str(exception),
        error_code=exception.__class__.__name__,
        command=command
    )
    
    # Add type-specific suggestions
    if isinstance(exception, ValueError):
        error_response.suggestions = [
            "Check input parameters",
            "Use --help to see valid options"
        ]
    elif isinstance(exception, FileNotFoundError):
        error_response.suggestions = [
            "Verify file path is correct",
            "Check file permissions"
        ]
```

### Progress Tracking Models

**ProgressUpdate**: Real-time operation feedback
```python
class ProgressUpdate(BaseModel):
    operation: str  # Current operation description
    current: int    # Current progress value
    total: Optional[int] = None  # Total items/steps
    percentage: Optional[float] = None  # Auto-calculated percentage
    message: Optional[str] = None  # Progress message
    eta: Optional[float] = None  # Estimated time remaining
```

## Integration Patterns

### Command Integration

**Request Building**:
```python
# In CLI command functions
def build_scan_request(
    target: str,
    scan_type: str = "quick",
    verbose: bool = False
) -> ScanRequest:
    """Build validated scan request from CLI arguments."""
    return ScanRequest(
        target=HttpUrl(target),
        scan_type=ScanType(scan_type),
        verbose=verbose
    )
```

**Response Processing**:
```python
# In CLI command functions
def process_scan_response(response: ScanResponse, 
                        format: OutputFormat) -> None:
    """Process and display scan response."""
    output = response.to_cli_output(format)
    console.print(output)
```

### Core System Integration

**Context Integration**:
```python
# Models integrate with Gibson's Context system
async def execute_with_context(request: CommandRequest) -> CommandResponse:
    """Execute command with proper context."""
    context = Context(
        config_file=request.config_file,
        config_override=request.config_override
    )
    
    # Execute core operation
    result = await core_operation(context, request)
    
    return CommandResponse(
        success=True,
        data=result.model_dump()
    )
```

## Technical Debt and Improvements

### Current Technical Debt

1. **Model Size**: Some models (especially ScanRequest) are becoming large and could benefit from composition
2. **Validation Duplication**: Some validation logic is repeated across different models
3. **Error Message Consistency**: Error messages could be more standardized across different validation failures

### Improvement Recommendations

#### High Priority
1. **Model Composition**: Break large models into smaller, composed models
   ```python
   class ScanRequest(CommandRequest):
       target_config: TargetConfig
       scan_config: ScanConfiguration  
       execution_config: ExecutionParameters
   ```

2. **Validation Consolidation**: Create shared validation utilities
   ```python
   class CommonValidators:
       @staticmethod
       def validate_url(url: str) -> HttpUrl: ...
       
       @staticmethod
       def validate_timeout(timeout: float) -> float: ...
   ```

#### Medium Priority
1. **Custom Field Types**: Create custom Pydantic types for common patterns
2. **Validation Error Localization**: Support for multiple languages in error messages
3. **Schema Documentation**: Auto-generate schema documentation from models

### Performance Optimizations

1. **Lazy Validation**: Defer expensive validation until actually needed
2. **Validation Caching**: Cache validation results for repeated operations
3. **Model Serialization**: Optimize JSON serialization for large responses

## Testing and Validation

### Model Testing Patterns

```python
# Example model tests
def test_scan_request_validation():
    """Test scan request validation."""
    # Valid request
    valid_request = ScanRequest(
        target="https://api.example.com",
        scan_type=ScanType.QUICK
    )
    assert valid_request.target == "https://api.example.com"
    
    # Invalid URL should raise validation error
    with pytest.raises(ValidationError):
        ScanRequest(
            target="invalid-url",
            scan_type=ScanType.QUICK
        )
```

### Integration Testing

```python
def test_request_response_cycle():
    """Test complete request/response cycle."""
    request = ScanRequest(target="https://test.com")
    
    # Execute command (mocked)
    response = execute_scan_command(request)
    
    # Validate response structure
    assert isinstance(response, ScanResponse)
    assert response.success in [True, False]
    
    # Test output formatting
    output = response.to_cli_output(OutputFormat.JSON)
    assert json.loads(output)  # Should be valid JSON
```

## Future Enhancements

### Planned Features

1. **Schema Versioning**: Support for model evolution and backward compatibility
2. **Custom Serializers**: Specialized serialization for different output formats
3. **Validation Plugins**: Extensible validation system for custom requirements
4. **Interactive Validation**: Real-time validation feedback in interactive mode
5. **Model Documentation**: Automatic help generation from model definitions
6. **Configuration Profiles**: Pre-defined model configurations for common use cases

This comprehensive model architecture ensures type safety, provides excellent user experience through clear validation messages, and maintains consistency across all CLI operations while remaining extensible for future enhancements.