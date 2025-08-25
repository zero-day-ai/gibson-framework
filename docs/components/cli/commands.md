# CLI Commands Architecture

## Overview

Gibson's CLI commands are organized into domain-specific modules, each implementing a coherent set of operations. All commands follow consistent patterns for argument parsing, validation, execution, and output formatting.

## Command Organization

### Command Categories

#### Core Security Operations
- **`scan.py`** - Primary security scanning operations
  - Quick scan for rapid assessment
  - Full scan for comprehensive testing
  - Custom scan with user-defined modules
  - Target resolution and authentication handling

- **`module.py`** - Security module management
  - Module discovery and installation
  - Dependency resolution and validation
  - Module lifecycle management
  - Module repository operations

#### Data Management
- **`payloads.py`** - Attack payload synchronization
  - Git-based payload synchronization
  - Payload database management
  - Source repository configuration
  - Payload validation and organization

- **`target.py`** - Target system management
  - Target registration and validation
  - Authentication credential management
  - Target testing and health checks
  - Target configuration updates

#### System Operations
- **`config.py`** - Configuration management
  - Configuration viewing and editing
  - Environment-specific settings
  - Configuration validation
  - Setting reset and defaults

- **`database.py`** - Database operations
  - Database initialization and migration
  - Data backup and restore
  - Database health checks
  - Schema synchronization

#### Reporting and Analysis
- **`report.py`** - Report generation
  - Scan result formatting
  - Multiple output formats (PDF, HTML, JSON, SARIF)
  - Executive summary generation
  - Compliance report creation

- **`chain.py`** - Attack chain operations
  - Attack sequence planning
  - Chain execution and monitoring
  - Result correlation and analysis
  - Chain template management

#### Authentication and Security
- **`auth.py`** - Authentication operations
  - User authentication and session management
  - API key management
  - Permission validation
  - Audit log access

- **`credentials.py`** - Credential management
  - Secure credential storage
  - Credential validation and testing
  - Credential rotation workflows
  - Integration with external vaults

#### Development and Integration
- **`console.py`** - Interactive console mode
  - REPL-style interaction
  - Command history and autocomplete
  - Multi-line command support
  - Interactive debugging

- **`schema.py`** - Schema synchronization
  - Database schema updates
  - API schema validation
  - Schema versioning
  - Migration generation

- **`llm.py`** - LLM provider management
  - Provider configuration
  - API key management
  - Rate limit monitoring
  - Usage tracking and reporting

## Command Architecture Patterns

### Standard Command Structure

```python
# Standard command file structure
import asyncio
from typing import Optional, List
import typer
from rich.console import Console

from gibson.core.context import Context
from gibson.cli.models.base import CommandRequest, CommandResponse
from gibson.cli.models.specific import SpecificRequest, SpecificResponse

app = typer.Typer(help="Command category description")
console = Console()

@app.command()
async def operation_name(
    # Required arguments
    required_param: str = typer.Argument(..., help="Required parameter"),
    
    # Optional arguments with defaults
    optional_param: Optional[str] = typer.Option(None, help="Optional parameter"),
    
    # Common CLI flags
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    output_format: str = typer.Option("table", help="Output format"),
):
    \"\"\"Command description and help text.\"\"\"
    
    # 1. Build request model
    request = SpecificRequest(
        required_param=required_param,
        optional_param=optional_param,
        verbose=verbose,
        output_format=output_format
    )
    
    # 2. Execute core operation
    try:
        context = Context()
        result = await core_operation(context, request)
        
        # 3. Build response
        response = CommandResponse(
            success=True,
            data=result.model_dump(),
            duration=execution_time
        )
        
    except Exception as e:
        # 4. Handle errors
        response = ErrorResponse.from_exception(
            e, 
            command=f"operation_name {required_param}",
            include_traceback=verbose
        )
    
    # 5. Output results
    console.print(response.to_cli_output(output_format))
```

### Async Operation Patterns

Commands use consistent async patterns for non-blocking operations:

```python
# Long-running operations with progress tracking
async def long_running_operation(request: OperationRequest) -> CommandResponse:
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("Processing...", total=100)
        
        # Execute operation with progress updates
        for step in operation_steps:
            await process_step(step)
            progress.update(task, advance=10)
        
        return CommandResponse(success=True)
```

### Error Handling Patterns

All commands follow standardized error handling:

```python
# Standardized error handling
try:
    result = await risky_operation()
except SpecificError as e:
    # Handle specific error types with user-friendly messages
    return ErrorResponse(
        message="Operation failed due to configuration issue",
        error_code="CONFIG_INVALID",
        suggestions=["Check configuration file", "Run 'gibson config validate'"]
    )
except ValidationError as e:
    # Handle validation errors with field-specific guidance
    return ErrorResponse(
        message="Invalid input parameters",
        error_details={"field_errors": e.errors()},
        suggestions=["Use --help to see valid options"]
    )
except Exception as e:
    # Handle unexpected errors gracefully
    return ErrorResponse.from_exception(
        e,
        command=current_command,
        include_traceback=request.verbose
    )
```

## Command Implementation Details

### Scan Commands (scan.py)

**Key Functions**:
- `quick_scan()` - Rapid assessment with essential modules
- `full_scan()` - Comprehensive testing with all applicable modules
- `custom_scan()` - User-defined module selection and configuration

**Architecture Highlights**:
- Dynamic target resolution (URL, named target, or file path)
- Credential integration with automatic authentication
- Module filtering based on target compatibility
- Result aggregation and formatting

**Technical Debt**:
- Large file (200+ lines) could be split into scan type modules
- Some duplicate target resolution logic
- Error handling could be more granular

### Payload Commands (payloads.py)

**Key Functions**:
- `sync()` - Synchronize payloads from Git repositories
- `list()` - Display available payloads with filtering
- `source()` - Manage payload sources and repositories
- `validate()` - Validate payload format and content

**Architecture Highlights**:
- Git integration with authentication escalation
- Database-backed payload storage and indexing
- Multi-source payload aggregation
- Payload validation and metadata extraction

**Technical Debt**:
- File is becoming large with multiple responsibilities
- Git authentication logic could be abstracted
- Payload validation logic scattered across multiple functions

### Target Commands (target.py)

**Key Functions**:
- `add()` - Register new targets with validation
- `list()` - Display configured targets
- `test()` - Validate target connectivity and authentication
- `remove()` - Remove targets with confirmation

**Architecture Highlights**:
- Secure credential storage integration
- Target validation and health checking
- Support for multiple target types (API, file, model)
- Authentication testing and validation

### Module Commands (module.py)

**Key Functions**:
- `list()` - Display available and installed modules
- `install()` - Install modules from various sources
- `remove()` - Uninstall modules with dependency checking
- `search()` - Search module repositories

**Architecture Highlights**:
- Multi-source module fetching (Git, registry, local)
- Dependency resolution and conflict detection
- Module validation and security checking
- Installation progress tracking

## Configuration and Context Management

### Configuration Resolution

Commands resolve configuration from multiple sources in priority order:
1. Command-line options (`--config-override`)
2. Environment variables
3. Configuration files (`--config-file` or default locations)
4. System defaults

```python
# Configuration resolution in commands
context = Context(
    config_file=request.config_file,
    config_override=request.config_override
)
config = await context.get_config()
```

### Context Object Usage

The Context object provides unified access to system resources:

```python
# Context usage patterns
async with Context() as ctx:
    # Database access
    db = await ctx.get_database()
    
    # Configuration access
    config = ctx.config
    
    # Service access
    module_manager = ctx.get_module_manager()
    payload_manager = ctx.get_payload_manager()
```

## Output Formatting

### Supported Output Formats

Commands support multiple output formats through the base response system:

- **TABLE**: Rich-formatted tables with colors and styling
- **JSON**: Machine-readable JSON with proper indentation
- **YAML**: Human-readable YAML format
- **CSV**: Comma-separated values for data analysis
- **MARKDOWN**: Markdown tables for documentation
- **SARIF**: SARIF format for security tooling integration
- **HTML**: HTML tables with styling for web display

### Output Formatting Implementation

```python
# Output formatting in command responses
class CommandResponse:
    def to_cli_output(self, format: OutputFormat) -> str:
        if format == OutputFormat.TABLE:
            return self._format_as_rich_table()
        elif format == OutputFormat.JSON:
            return self.model_dump_json(indent=2)
        elif format == OutputFormat.SARIF:
            return self._format_as_sarif()
        # ... other formats
```

## Integration Patterns

### Core System Integration

Commands integrate with core Gibson systems through well-defined interfaces:

```python
# Service integration pattern
from gibson.core.orchestrator import ScanExecutor
from gibson.core.module_management import ModuleManager
from gibson.core.targets import TargetManager

async def execute_scan(request: ScanRequest) -> CommandResponse:
    # Use core services through Context
    ctx = Context()
    executor = ScanExecutor(ctx)
    target_manager = TargetManager(ctx)
    
    # Resolve target and execute scan
    target = await target_manager.resolve_target(request.target)
    result = await executor.execute_scan(target, request.modules)
    
    return CommandResponse(success=True, data=result)
```

### Database Integration

Commands access the database layer through the database manager:

```python
# Database integration pattern
from gibson.db.manager import DatabaseManager

async def database_operation(request: DBRequest) -> CommandResponse:
    db_manager = DatabaseManager()
    async with db_manager.get_session() as session:
        result = await session.execute(query)
        return CommandResponse(success=True, data=result.fetchall())
```

## Testing and Validation

### Command Testing Patterns

Commands are tested at multiple levels:

1. **Unit Tests**: Test individual command functions with mocked dependencies
2. **Integration Tests**: Test command execution with real dependencies
3. **CLI Tests**: Test complete command-line invocation and output

```python
# Command testing example
@pytest.mark.asyncio
async def test_scan_command():
    # Setup
    mock_context = MockContext()
    request = ScanRequest(target="test-target", scan_type=ScanType.QUICK)
    
    # Execute
    response = await execute_scan_command(request, mock_context)
    
    # Assert
    assert response.success is True
    assert "findings" in response.data
```

### Input Validation

All commands use Pydantic models for comprehensive input validation:

```python
# Input validation with Pydantic
class ScanRequest(CommandRequest):
    target: str = Field(..., min_length=1, description="Target to scan")
    scan_type: ScanType = Field(default=ScanType.QUICK)
    
    @field_validator('target')
    @classmethod
    def validate_target(cls, v: str) -> str:
        if not (v.startswith('http') or v.startswith('file://') or '/' in v):
            raise ValueError("Target must be URL, file path, or named target")
        return v
```

## Future Improvements

### Planned Enhancements

1. **Command Decomposition**: Break large command files into focused modules
2. **Plugin System**: Allow third-party command extensions
3. **Enhanced Autocomplete**: Better shell completion for all parameters
4. **Interactive Wizards**: Guided setup for complex operations
5. **Command Templates**: Reusable command configurations
6. **Batch Operations**: Enhanced support for bulk operations
7. **Command Chaining**: Ability to chain commands together
8. **Performance Monitoring**: Built-in performance tracking for commands

### Technical Debt Reduction

1. **Standardize Error Handling**: Consistent error patterns across all commands
2. **Consolidate Validation**: Shared validation utilities to reduce duplication
3. **Service Layer Migration**: Move commands to use service layer instead of direct database access
4. **Configuration Consistency**: Standardize configuration patterns across commands
5. **Output Format Standardization**: Ensure all commands support all output formats consistently

This architecture provides a solid foundation for Gibson's CLI system while identifying clear paths for future improvements and technical debt reduction.