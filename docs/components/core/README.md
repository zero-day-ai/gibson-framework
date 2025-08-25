# Component: Core System Architecture

## Overview

**Purpose**: Gibson's core system provides the foundational orchestration layer that coordinates all security testing operations. It manages the lifecycle of scans, coordinates between different attack domains, handles service initialization, and provides the central hub for all system operations.

**Location**: `gibson/core/`

**Key Design Decisions**: 
- **Central Orchestration Pattern**: Single Base class coordinates all system operations and services
- **Attack Domain Architecture**: Modular design where each security domain (prompt, data, model, etc.) is independently manageable
- **Async-First Design**: Built on asyncio for non-blocking operations and concurrent execution
- **Dependency Injection**: Context-based service resolution and configuration management
- **Graceful Degradation**: System continues to function with reduced capability when services are unavailable

## Architecture

### Component Structure
```
gibson/core/
├── __init__.py                 # Core module exports
├── base.py                     # Central Base orchestrator class
├── config.py                   # Configuration management
├── context.py                  # Global context and dependency injection
├── ai.py                       # AI service integration layer
├── auth/                       # Authentication and security services
│   ├── __init__.py            # Authentication module exports
│   ├── audit.py               # Security audit logging
│   ├── audit_logger.py        # Audit event tracking
│   ├── auth_service.py        # Main authentication service
│   ├── benchmarks.py          # Security performance benchmarks
│   ├── config.py              # Authentication configuration
│   ├── credential_manager.py  # Secure credential storage
│   ├── crypto.py              # Cryptographic utilities
│   ├── env_injection.py       # Environment variable injection
│   ├── env_injector.py        # Dynamic environment setup
│   ├── error_handler.py       # Authentication error handling
│   ├── error_handling.py      # Error handling utilities
│   ├── hardening.py           # Security hardening measures
│   ├── migration.py           # Authentication migration utilities
│   ├── migration_utils.py     # Migration helper functions
│   ├── monitoring.py          # Security monitoring
│   ├── performance.py         # Authentication performance tracking
│   ├── providers.py           # Authentication provider implementations
│   ├── request_auth.py        # Request-level authentication
│   └── validation.py          # Authentication validation
├── llm/                        # LLM service integration
│   ├── __init__.py            # LLM module exports
│   ├── client_factory.py      # LLM client factory pattern
│   ├── completion.py          # Text completion services
│   ├── environment.py         # LLM environment configuration
│   ├── error_handling.py      # LLM-specific error handling
│   ├── fallback.py            # Fallback mechanisms
│   ├── module_adapter.py      # Module integration adapter
│   ├── rate_limiting.py       # API rate limiting
│   ├── table_registry.py      # LLM provider registry
│   ├── types.py               # LLM-specific type definitions
│   └── usage_tracking.py      # API usage and cost tracking
├── migrations/                 # System migration management
│   ├── __init__.py            # Migration module exports
│   ├── manager.py             # Migration orchestration
│   └── safety.py              # Migration safety checks
├── module_management/          # Security module lifecycle
│   └── [extensive module management system]
├── modules/                    # Security testing modules
│   ├── __init__.py            # Module exports
│   ├── base.py                # Base module interface
│   └── prompts/               # Prompt-based security modules
├── orchestrator/              # Execution orchestration
│   ├── __init__.py            # Orchestrator exports
│   ├── llm_integration.py     # LLM service orchestration
│   └── scan_executor.py       # Scan execution coordination
├── payloads/                  # Attack payload management
│   └── [extensive payload management system]
├── schema_sync/               # Schema synchronization
│   └── [schema management system]
└── targets/                   # Target management
    └── [target configuration system]
```

### Key Classes and Interfaces

#### Base Orchestrator (`base.py`)
- **Base**: Central orchestration class coordinating all Gibson operations
  - Service initialization and lifecycle management
  - Attack domain registration and coordination  
  - Module discovery and execution orchestration
  - Database and authentication service integration

- **BaseAttack**: Abstract base class for attack domain implementations
  - Domain-specific module discovery
  - Module execution interface
  - Capability reporting and metadata

- **AttackDomain**: Enumeration of security attack categories
  - PROMPT: LLM prompt injection attacks
  - DATA: Training data poisoning attacks  
  - MODEL: Model theft and extraction attacks
  - SYSTEM: System-level security tests
  - OUTPUT: Output handling vulnerabilities

#### Context Management (`context.py`)
- **Context**: Global state and dependency injection container
  - Configuration management and override handling
  - Console and output formatting coordination
  - Directory structure initialization
  - Service registry and resolution

#### Configuration System (`config.py`)
- **Config**: Centralized configuration object
- **ConfigManager**: Configuration loading and validation
- **Environment Integration**: Environment variable resolution and override

### Design Patterns Used

#### 1. **Central Orchestrator Pattern**
The Base class serves as the single coordination point for all system operations:

```python
class Base:
    """Central orchestration framework for Gibson security scanning."""
    
    def __init__(self, config: Optional[Config] = None, context: Optional[Context] = None):
        self.config = config or ConfigManager().config
        self.context = context
        self.attack_domains: Dict[AttackDomain, BaseAttack] = {}
        self.available_modules: Dict[str, AttackDomain] = {}
        
    async def initialize(self) -> None:
        """Initialize all services in proper dependency order."""
        await self._initialize_database()
        await self._initialize_authentication_services()
        await self._initialize_shared_services()
        await self._initialize_module_manager()
        await self._initialize_attack_domains()
```

#### 2. **Plugin Architecture for Attack Domains**
Each attack domain implements the BaseAttack interface for consistent integration:

```python
class BaseAttack:
    """Base class for attack domain implementations."""
    
    async def discover_modules(self) -> List[str]:
        """Discover available modules for this domain."""
        
    async def execute_module(self, module_name: str, target: str) -> Optional[Finding]:
        """Execute a specific module against target."""
        
    async def get_capabilities(self) -> Dict[str, Any]:
        """Get domain-specific capabilities and metadata."""
```

#### 3. **Service Factory Pattern**
Services are created and configured through factory methods with proper dependency injection:

```python
# Example service initialization pattern
async def _initialize_authentication_services(self) -> None:
    """Initialize authentication services for secure credential management."""
    from gibson.core.auth.credential_manager import CredentialManager
    from gibson.core.auth.auth_service import AuthService
    
    self.credential_manager = CredentialManager(config=self.config.auth)
    self.auth_service = AuthService(
        credential_manager=self.credential_manager,
        config=self.config.auth
    )
```

#### 4. **Async Context Manager Pattern**
Services support async context management for proper resource cleanup:

```python
# Usage pattern for Base orchestrator
async def execute_scan(scan_config: ScanConfig) -> ScanResult:
    base = Base()
    async with base:
        await base.initialize()
        return await base.execute_scan(scan_config)
```

## Data Flow

### Input Data
- **Scan Configurations**: Complete scan parameters including targets, modules, and execution settings
- **Target Information**: Target URLs, authentication credentials, and connection parameters
- **Module Selection**: Specific security modules to execute or domain-based filtering
- **Context Parameters**: CLI flags, configuration overrides, and execution context

### Data Transformations
1. **Configuration Resolution**: CLI parameters → Context object → Resolved configuration
2. **Target Resolution**: Target identifier → Validated target object → Connection parameters
3. **Module Selection**: Domain filters → Available modules → Selected module instances
4. **Execution Coordination**: Module instances → Concurrent execution → Aggregated results
5. **Result Processing**: Raw findings → Validated findings → Formatted scan results

### Integration with Other Components

#### CLI Integration
- **Context Creation**: CLI commands create Context objects with user parameters
- **Configuration Override**: CLI flags override default configuration values
- **Progress Reporting**: Real-time progress updates back to CLI for user feedback

#### Database Integration
- **Connection Management**: Base orchestrator manages singleton database connection
- **Result Persistence**: Scan results and findings automatically persisted
- **Configuration Storage**: Target and credential information stored securely

#### Module System Integration
- **Module Discovery**: Base orchestrator discovers available modules across domains
- **Execution Coordination**: Manages concurrent module execution with resource limits
- **Result Aggregation**: Collects and validates results from multiple modules

## Technical Analysis

### Code Quality Assessment

**Strengths**:
- **Clear Separation of Concerns**: Each service has well-defined responsibilities
- **Comprehensive Error Handling**: Graceful degradation when services are unavailable
- **Async-First Architecture**: Efficient concurrent execution and non-blocking operations
- **Extensive Configuration Support**: Flexible configuration with multiple override mechanisms
- **Security-First Design**: Built-in authentication, audit logging, and secure credential management

**Areas for Improvement**:
- **Large Base Class**: The Base orchestrator class is becoming large and could benefit from decomposition
- **Service Dependencies**: Complex dependency graph between services needs better documentation
- **Error Recovery**: Some error scenarios could have better recovery mechanisms
- **Resource Management**: Memory and connection pool management could be more explicit

**Complexity**: High - This is the central coordination point requiring deep domain knowledge

### Performance Characteristics
- **Initialization Time**: ~2-5 seconds depending on available services and database connection
- **Concurrent Execution**: Efficiently manages multiple modules running in parallel
- **Memory Usage**: Base orchestrator maintains minimal state, delegates to specialized services
- **Resource Pooling**: Database connections and HTTP clients are pooled and reused

### Identified Technical Debt

#### Legacy Code Patterns
- **Module Manager Comments**: Disabled imports suggest incomplete module management integration
- **Test Mode Detection**: Ad-hoc test mode detection logic scattered throughout initialization
- **Service Initialization**: Some services use delayed initialization patterns that could be simplified

#### Unused/Underutilized Components
- **Git Service**: Referenced but not fully implemented in current codebase
- **Data Service**: Placeholder service not yet integrated
- **AI Service**: Basic integration present but could be more comprehensive

#### Areas for Modernization
- **Type Hints**: Some methods could benefit from more specific type hints
- **Context Managers**: More services could implement async context management
- **Configuration Validation**: Runtime configuration validation could be more comprehensive

## Integration Points

### Dependencies on Other Components
- **gibson.core.config**: Configuration loading and management
- **gibson.core.context**: Global state and dependency injection
- **gibson.db.manager**: Database connection and operations
- **gibson.core.auth**: Authentication and credential management
- **gibson.core.llm**: LLM service integration and API management
- **gibson.models**: Shared data models for scans, targets, and findings

### External System Integrations
- **Database Systems**: SQLite (primary), PostgreSQL (future support)
- **LLM Providers**: OpenAI, Anthropic, Azure OpenAI, and other LiteLLM-supported providers
- **Authentication Systems**: API keys, OAuth, JWT tokens
- **Git Repositories**: For payload and module source management

### Extension Mechanisms
- **Attack Domain Registration**: New attack domains can be registered with the Base orchestrator
- **Service Plugin System**: New services can be integrated through the initialization system
- **Module Discovery**: Automatic discovery of new security modules
- **Configuration Extension**: New configuration sections can be added seamlessly

## Improvement Recommendations

### High Priority

1. **Base Class Decomposition**: Break the Base class into smaller, focused orchestrators
   - **ScanOrchestrator**: Handles scan execution coordination
   - **ServiceOrchestrator**: Manages service initialization and lifecycle
   - **ModuleOrchestrator**: Coordinates module discovery and execution

2. **Service Dependency Management**: Implement explicit dependency injection container
   ```python
   class ServiceContainer:
       def __init__(self):
           self.services = {}
           self.dependencies = {}
       
       def register(self, service_name: str, factory: Callable, dependencies: List[str] = None):
           """Register service with dependency specifications."""
           
       async def resolve(self, service_name: str) -> Any:
           """Resolve service with automatic dependency injection."""
   ```

3. **Error Recovery Framework**: Implement comprehensive error recovery strategies
   - **Service Fallbacks**: Define fallback services when primary services fail
   - **Retry Mechanisms**: Configurable retry logic for transient failures
   - **Circuit Breakers**: Prevent cascade failures in service dependencies

### Medium Priority

1. **Resource Management**: Implement explicit resource management
   - **Connection Pooling**: Centralized connection pool management
   - **Memory Monitoring**: Track memory usage and implement cleanup strategies
   - **Timeout Management**: Consistent timeout handling across all services

2. **Configuration Validation**: Enhanced configuration validation and error reporting
   - **Schema Validation**: JSON schema validation for configuration files
   - **Runtime Validation**: Validate configuration consistency at runtime
   - **Configuration Migration**: Handle configuration format changes gracefully

3. **Service Health Monitoring**: Implement comprehensive health checking
   ```python
   class ServiceHealthMonitor:
       async def check_service_health(self, service_name: str) -> HealthStatus:
           """Check health of individual service."""
           
       async def check_system_health(self) -> SystemHealthReport:
           """Check overall system health."""
   ```

### Low Priority

1. **Performance Optimization**: Optimize initialization and execution performance
2. **Advanced Logging**: Structured logging with correlation IDs and distributed tracing
3. **Configuration Hot Reload**: Runtime configuration updates without restart

### Performance Optimizations

1. **Lazy Service Initialization**: Initialize services only when actually needed
2. **Concurrent Service Startup**: Initialize independent services in parallel
3. **Module Preloading**: Cache frequently used modules for faster execution
4. **Result Streaming**: Stream scan results instead of batching for large scans

## Usage Examples

### Basic Orchestration Usage
```python
# Initialize and use the Base orchestrator
from gibson.core.base import Base, ScanType
from gibson.models.scan import ScanConfig
from gibson.models.target import Target

async def execute_security_scan():
    # Create scan configuration
    scan_config = ScanConfig(
        scan_type=ScanType.QUICK,
        target=Target(url="https://api.example.com"),
        domains=[AttackDomain.PROMPT, AttackDomain.OUTPUT]
    )
    
    # Initialize orchestrator
    base = Base()
    await base.initialize()
    
    try:
        # Execute scan
        result = await base.execute_scan(scan_config)
        
        print(f"Scan completed with {len(result.findings)} findings")
        return result
        
    finally:
        await base.cleanup()
```

### Service Integration Pattern
```python
# Integrate custom service with Base orchestrator
class CustomSecurityService:
    def __init__(self, config: Config):
        self.config = config
        
    async def initialize(self) -> None:
        """Initialize custom service."""
        
    async def analyze_target(self, target: Target) -> List[Finding]:
        """Perform custom security analysis."""
        
# Integration in Base class
async def _initialize_custom_services(self) -> None:
    """Initialize custom services."""
    self.custom_service = CustomSecurityService(self.config)
    await self.custom_service.initialize()
```

### Configuration Management
```python
# Advanced configuration management
from gibson.core.config import ConfigManager, Config

# Load configuration with overrides
config_manager = ConfigManager()
config = config_manager.load_config(
    config_file="custom-config.yaml",
    overrides={
        "scan.timeout": 300,
        "llm.provider": "anthropic"
    }
)

# Use with Base orchestrator
base = Base(config=config)
```

## Files Overview

### Core Implementation Files
- **base.py**: Central Base orchestrator class with service coordination and attack domain management
- **context.py**: Global context management and dependency injection container
- **config.py**: Configuration loading, validation, and management system
- **ai.py**: AI service integration layer for LLM operations

### Service Directories
- **auth/**: Complete authentication and security service suite
- **llm/**: LLM integration services with rate limiting and usage tracking
- **orchestrator/**: Execution coordination services for scan management
- **migrations/**: System migration management and safety checks

### Supporting Files
- **__init__.py**: Module exports and public interface definition
- **migrations/**: Database and system migration utilities

### Test Coverage
- **Unit Tests**: Core orchestration logic and service initialization
- **Integration Tests**: Service integration and end-to-end workflows
- **Missing Tests**: Some error recovery paths and edge cases need additional coverage

## Related Documentation
- [Authentication System](../auth/) - Security and credential management services
- [LLM Integration](../llm/) - AI service integration and management
- [Module Management](../module-management/) - Security module lifecycle
- [Configuration Guide](config.md) - Configuration system documentation
- [Context Management](context.md) - Global context and dependency injection