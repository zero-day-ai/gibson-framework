# Configuration Management System

## Overview

The Gibson configuration system (`gibson/core/config.py`) implements hierarchical configuration management with environment variable support, type safety through Pydantic models, and flexible override mechanisms. It provides centralized configuration for all Gibson components while supporting multiple deployment environments and user customization patterns.

## Configuration Architecture

### Core Configuration Models

#### Main Configuration Class
```python
class Config(BaseSettings):
    """Main configuration model with environment variable support."""
    
    model_config = SettingsConfigDict(
        env_prefix="GIBSON_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )
    
    version: str = Field(default="1.0", description="Config version")
    profile: str = Field(default="default", description="Active profile")
    
    api: APIConfig = Field(default_factory=APIConfig)
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    prompt_registry: PromptRegistryConfig = Field(default_factory=PromptRegistryConfig)
    research: ResearchConfig = Field(default_factory=ResearchConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
```

**Key Features**:
- **Environment Variable Integration**: Automatic mapping of `GIBSON_*` environment variables
- **Nested Configuration**: Support for complex nested configuration structures
- **Type Safety**: Full Pydantic validation for all configuration values
- **Default Values**: Comprehensive default configuration for immediate usability

#### Configuration Sub-Models

##### API Configuration
```python
class APIConfig(BaseModel):
    """API configuration settings."""
    
    timeout: int = Field(default=30, description="Request timeout in seconds")
    retry: int = Field(default=3, description="Number of retries")
    rate_limit: int = Field(default=100, description="Requests per minute")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
```

**Purpose**: Centralized HTTP client and API interaction settings for all Gibson services

##### Database Configuration
```python
class DatabaseConfig(BaseModel):
    """Database configuration."""
    
    url: str = Field(
        default="sqlite+aiosqlite:///~/.gibson/gibson.db",
        description="Database URL",
    )
    pool_size: int = Field(default=5, description="Connection pool size")
    max_overflow: int = Field(default=10, description="Max overflow connections")
    validate_on_init: bool = Field(default=True, description="Validate schema on initialization")
    auto_create_tables: bool = Field(default=True, description="Automatically create missing tables")
    backup_on_migration: bool = Field(default=True, description="Backup database before migrations")
```

**Features**:
- **Connection Pooling**: Configurable database connection pool management
- **Schema Management**: Automatic table creation and migration handling
- **Backup Safety**: Automatic backup before destructive operations

##### Safety Controls
```python
class SafetyConfig(BaseModel):
    """Safety controls configuration."""
    
    dry_run: bool = Field(default=False, description="Dry run mode")
    rate_limit: bool = Field(default=True, description="Enable rate limiting")
    max_parallel: int = Field(default=10, description="Max parallel operations")
    require_confirmation: bool = Field(default=False, description="Require user confirmation")
    max_scan_duration: int = Field(default=3600, description="Max scan duration in seconds")
```

**Security Features**:
- **Rate Limiting Protection**: Prevent API abuse and resource exhaustion
- **Concurrency Limits**: Control parallel operation execution
- **Safety Confirmations**: Require explicit confirmation for destructive operations
- **Timeout Protection**: Maximum execution time limits for long-running operations

##### Registry Configuration
```python
class RegistryConfig(BaseModel):
    """Module registry configuration."""
    
    sources: list[str] = Field(
        default_factory=lambda: ["github.com/zero-day-ai/gibson-modules"],
        description="Module registry sources",
    )
    auto_update: bool = Field(default=True, description="Auto-update modules")
    cache_dir: Optional[Path] = Field(default=None, description="Module cache directory")
```

**Module Management Features**:
- **Multi-Source Support**: Support for multiple module repositories
- **Automatic Updates**: Configurable automatic module updating
- **Caching**: Local caching of downloaded modules

### Hierarchical Configuration Loading

#### Configuration Precedence
The configuration system implements a clear precedence hierarchy:

```mermaid
graph TD
    A[Environment Variables] --> B[Explicit Config File]
    B --> C[Project Config .gibson/config.yaml]
    C --> D[User Config ~/.config/gibson/config.yaml]
    D --> E[System Config /etc/gibson/config.yaml]
    E --> F[Default Values]
    
    A -.-> G[Final Configuration]
    B -.-> G
    C -.-> G
    D -.-> G
    E -.-> G
    F -.-> G
```

**Precedence Order** (highest to lowest):
1. **Environment Variables**: `GIBSON_*` variables with nested delimiter support
2. **Explicit Config File**: File specified via `--config` CLI flag
3. **Project Config**: `.gibson/config.yaml` in current working directory
4. **User Config**: `~/.config/gibson/config.yaml` user-specific settings
5. **System Config**: `/etc/gibson/config.yaml` system-wide settings
6. **Default Values**: Built-in defaults from Pydantic Field definitions

#### Configuration Merging Strategy
```python
def _merge_configs(self, base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge configuration dictionaries."""
    result = base.copy()
    
    for key, value in update.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = self._merge_configs(result[key], value)
        else:
            result[key] = value
    
    return result
```

**Features**:
- **Deep Merging**: Nested dictionary structures are merged recursively
- **Value Override**: Higher precedence values completely replace lower precedence values
- **Structure Preservation**: Dictionary structures are preserved during merging

### Directory Management

#### Automatic Directory Setup
```python
def _setup_directories(self) -> None:
    """Setup required directories."""
    # Ensure ~/.gibson directory exists first
    gibson_dir = Path.home() / ".gibson"
    gibson_dir.mkdir(parents=True, exist_ok=True)
    
    # Set default directories if not configured
    if not self.config.data_dir:
        self.config.data_dir = gibson_dir / "data"
    if not self.config.cache_dir:
        self.config.cache_dir = gibson_dir / "cache"
    if not self.config.module_dir:
        self.config.module_dir = gibson_dir / "modules"
```

**Directory Structure**:
```
~/.gibson/
├── config.yaml          # User configuration
├── gibson.db            # Main database file
├── data/                 # Application data
├── cache/                # Temporary cache files
└── modules/              # Installed security modules
```

#### Database Path Management
```python
# BULLETPROOF: Force database to always use ~/.gibson/gibson.db
canonical_db_path = gibson_dir / "gibson.db"
canonical_url = f"sqlite+aiosqlite:///{canonical_db_path}"

if self.config.database.url != canonical_url:
    logger.info(f"Forcing database path from '{self.config.database.url}' to canonical location: '{canonical_url}'")
    self.config.database.url = canonical_url
```

**Features**:
- **Canonical Database Location**: All installations use `~/.gibson/gibson.db`
- **Path Normalization**: Automatic resolution of `~` and relative paths
- **Directory Creation**: Automatic creation of all required directories

### Environment Variable Support

#### Mapping Pattern
Gibson supports comprehensive environment variable configuration using these patterns:

```bash
# Basic configuration
export GIBSON_PROFILE="production"
export GIBSON_VERSION="2.0"

# Nested configuration using double underscores
export GIBSON_DATABASE__URL="postgresql://user:pass@localhost/gibson"
export GIBSON_DATABASE__POOL_SIZE=20

# API configuration
export GIBSON_API__TIMEOUT=60
export GIBSON_API__RETRY=5
export GIBSON_API__RATE_LIMIT=200

# Safety configuration
export GIBSON_SAFETY__DRY_RUN=true
export GIBSON_SAFETY__MAX_PARALLEL=5
export GIBSON_SAFETY__REQUIRE_CONFIRMATION=true
```

#### Type Conversion
Pydantic automatically handles type conversion for environment variables:
- **Booleans**: `"true"`, `"false"`, `"1"`, `"0"` (case-insensitive)
- **Numbers**: Automatic conversion to `int` and `float` types
- **Lists**: JSON array format or comma-separated values
- **Paths**: Automatic conversion to `Path` objects with home directory expansion

### Configuration Manager

#### Initialization and Loading
```python
class ConfigManager:
    """Hierarchical configuration manager."""
    
    def __init__(self, config_file: Optional[Path] = None) -> None:
        self.config_file = config_file
        self.config = self._load_config()
        self._setup_directories()
```

**Lifecycle Management**:
1. **Configuration Loading**: Hierarchical loading with proper precedence
2. **Validation**: Full Pydantic validation with error handling
3. **Directory Setup**: Automatic creation of required directories
4. **Path Resolution**: Canonical path resolution for consistency

#### Configuration Persistence
```python
def save(self, path: Optional[Path] = None) -> None:
    """Save current configuration to file."""
    save_path = path or self.config_file or Path.home() / ".config" / "gibson" / "config.yaml"
    
    # Convert config to serializable format
    config_data = self.config.model_dump()
    serializable_config = convert_paths(config_data)
    
    with open(save_path, "w") as f:
        yaml.dump(serializable_config, f, default_flow_style=False)
```

**Features**:
- **Path Serialization**: Automatic conversion of `Path` objects to strings
- **YAML Format**: Human-readable YAML output with proper formatting
- **Flexible Location**: Save to custom location or default user config

### Integration Patterns

#### Global Configuration Access
```python
# Global config manager instance
_config_manager: Optional[ConfigManager] = None

def get_config(config_file: Optional[Path] = None) -> Config:
    """Get global configuration instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_file=config_file)
    return _config_manager.config
```

**Usage Pattern**:
```python
from gibson.core.config import get_config

# Get global configuration
config = get_config()

# Use configuration values
timeout = config.api.timeout
db_url = config.database.url
max_parallel = config.safety.max_parallel
```

#### Component-Specific Configuration
Different Gibson components access configuration through specific sub-models:

```python
# Database component
db_config = config.database
connection = create_engine(
    db_config.url,
    pool_size=db_config.pool_size,
    max_overflow=db_config.max_overflow
)

# API client component
api_config = config.api
session = aiohttp.ClientSession(
    timeout=aiohttp.ClientTimeout(total=api_config.timeout),
    connector=aiohttp.TCPConnector(verify_ssl=api_config.verify_ssl)
)
```

## Error Handling and Validation

### Configuration Validation
```python
try:
    config = Config(**config_data)
    logger.debug(f"Loaded configuration: database_url={config.database.url}")
    return config
except ValidationError as e:
    logger.error(f"Configuration validation failed: {e}")
    # Return default config on validation error
    return Config()
```

**Validation Features**:
- **Pydantic Validation**: Comprehensive type and constraint validation
- **Graceful Fallback**: Default configuration used on validation errors
- **Error Logging**: Detailed error messages for debugging configuration issues

### File Loading Error Handling
```python
def _load_yaml(self, path: Path) -> Dict[str, Any]:
    """Load YAML configuration file."""
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning(f"Failed to load config from {path}: {e}")
        return {}
```

**Robustness Features**:
- **Non-Fatal Errors**: Missing or invalid config files don't crash initialization
- **Empty File Handling**: Empty files return empty dictionary instead of None
- **Exception Isolation**: File loading errors are isolated and logged

## Configuration Examples

### Basic Configuration File
```yaml
# ~/.config/gibson/config.yaml
version: "1.0"
profile: "development"

api:
  timeout: 60
  retry: 5
  rate_limit: 150

database:
  url: "sqlite+aiosqlite:///~/.gibson/gibson.db"
  pool_size: 10

safety:
  dry_run: false
  max_parallel: 15
  require_confirmation: false

output:
  format: "human"
  color: true
  verbose: true
  log_level: "DEBUG"
```

### Production Configuration
```yaml
# /etc/gibson/config.yaml
version: "1.0"
profile: "production"

api:
  timeout: 30
  retry: 3
  rate_limit: 100
  verify_ssl: true

database:
  url: "postgresql+asyncpg://gibson:secret@localhost/gibson_prod"
  pool_size: 20
  max_overflow: 30
  validate_on_init: true
  backup_on_migration: true

safety:
  dry_run: false
  rate_limit: true
  max_parallel: 5
  require_confirmation: true
  max_scan_duration: 7200

output:
  format: "json"
  color: false
  verbose: false
  log_level: "INFO"
```

### Environment Variable Configuration
```bash
#!/bin/bash
# production-env.sh

# Basic settings
export GIBSON_PROFILE="production"
export GIBSON_VERSION="2.0"

# Database configuration
export GIBSON_DATABASE__URL="postgresql+asyncpg://user:pass@db.example.com/gibson"
export GIBSON_DATABASE__POOL_SIZE=25
export GIBSON_DATABASE__MAX_OVERFLOW=50

# API settings
export GIBSON_API__TIMEOUT=45
export GIBSON_API__RETRY=3
export GIBSON_API__RATE_LIMIT=200

# Safety controls
export GIBSON_SAFETY__DRY_RUN=false
export GIBSON_SAFETY__MAX_PARALLEL=8
export GIBSON_SAFETY__REQUIRE_CONFIRMATION=true
export GIBSON_SAFETY__MAX_SCAN_DURATION=10800

# Registry configuration
export GIBSON_REGISTRY__AUTO_UPDATE=false
export GIBSON_REGISTRY__SOURCES='["github.com/enterprise/security-modules"]'

# Output configuration
export GIBSON_OUTPUT__FORMAT="json"
export GIBSON_OUTPUT__COLOR=false
export GIBSON_OUTPUT__VERBOSE=false
export GIBSON_OUTPUT__LOG_LEVEL="WARNING"
```

### Project-Specific Configuration
```yaml
# .gibson/config.yaml (project directory)
version: "1.0"
profile: "project"

# Project-specific module registry
registry:
  sources:
    - "github.com/enterprise/custom-modules"
    - "github.com/zero-day-ai/gibson-modules"
  auto_update: false
  cache_dir: "./.gibson/module-cache"

# Custom prompt registry for this project
prompt_registry:
  sources:
    - url: "github.com/enterprise/custom-prompts"
      name: "enterprise"
      priority: 200
      branch: "main"
      enabled: true
    - url: "github.com/zero-day-ai/gibson-prompts"
      name: "official"
      priority: 100
      branch: "main"
      enabled: true

# Project-specific safety settings
safety:
  dry_run: true
  max_parallel: 3
  require_confirmation: true

# Custom data directories for this project
data_dir: "./.gibson/data"
cache_dir: "./.gibson/cache"
module_dir: "./.gibson/modules"
```

## Technical Debt and Improvements

### Current Technical Debt

#### 1. Configuration Schema Evolution
- **Version Compatibility**: Limited support for configuration version migration
- **Schema Changes**: No automatic handling of deprecated configuration options
- **Backward Compatibility**: Manual handling required for breaking changes

#### 2. Validation Error Handling
- **Silent Fallback**: Validation errors fall back to defaults without user awareness
- **Error Context**: Limited context about which configuration file caused validation errors
- **Partial Validation**: No support for validating only parts of configuration

#### 3. Runtime Configuration Updates
- **Static Configuration**: No support for runtime configuration reloading
- **Hot Reload**: Cannot update configuration without restart
- **Dynamic Overrides**: Limited support for temporary configuration changes

### Improvement Recommendations

#### High Priority

1. **Configuration Version Management**
   ```python
   class ConfigMigration:
       """Handle configuration version migrations."""
       
       @staticmethod
       def migrate_v1_to_v2(config_data: Dict) -> Dict:
           """Migrate v1.0 config format to v2.0."""
           
       def migrate_config(self, config_data: Dict, target_version: str) -> Dict:
           """Migrate configuration to target version."""
   ```

2. **Enhanced Validation Feedback**
   ```python
   class ConfigValidationError(Exception):
       """Enhanced configuration validation error."""
       
       def __init__(self, source_file: Path, validation_error: ValidationError):
           self.source_file = source_file
           self.validation_error = validation_error
           super().__init__(self._format_error())
   ```

3. **Configuration Hot Reload**
   ```python
   class ConfigWatcher:
       """Watch configuration files for changes."""
       
       async def start_watching(self, callback: Callable[[Config], None]):
           """Start watching config files for changes."""
           
       async def reload_config(self) -> Config:
           """Reload configuration from all sources."""
   ```

#### Medium Priority

1. **Configuration Schema Validation**
   - Add JSON Schema validation for configuration files
   - Implement configuration linting and validation tools
   - Add support for configuration templates and examples

2. **Environment-Specific Profiles**
   - Enhanced profile support with inheritance
   - Environment-specific configuration overlays
   - Configuration composition patterns

3. **Configuration Documentation**
   - Auto-generated configuration reference documentation
   - Configuration option discovery and help system
   - Interactive configuration wizards

#### Low Priority

1. **Advanced Configuration Sources**
   - Support for remote configuration sources (HTTP, S3, etc.)
   - Configuration encryption and secrets management
   - Database-backed configuration storage

2. **Configuration Analytics**
   - Track configuration option usage and patterns
   - Configuration optimization recommendations
   - Performance impact analysis of configuration choices

This configuration system provides robust, flexible, and type-safe configuration management for the entire Gibson framework while maintaining simplicity for basic use cases and power for advanced deployment scenarios.