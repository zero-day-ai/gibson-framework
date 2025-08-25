"""Configuration management with hierarchical loading."""

import os
from pathlib import Path
from typing import Any, Dict, Optional, List

import yaml
from platformdirs import user_config_dir, site_config_dir
from pydantic import BaseModel, Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict
from loguru import logger


class APIConfig(BaseModel):
    """API configuration settings."""
    
    timeout: int = Field(default=30, description="Request timeout in seconds")
    retry: int = Field(default=3, description="Number of retries")
    rate_limit: int = Field(default=100, description="Requests per minute")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")


class RegistryConfig(BaseModel):
    """Module registry configuration."""
    
    sources: list[str] = Field(
        default_factory=lambda: ["github.com/zero-day-ai/gibson-modules"],
        description="Module registry sources",
    )
    auto_update: bool = Field(default=True, description="Auto-update modules")
    cache_dir: Optional[Path] = Field(default=None, description="Module cache directory")


class PromptRegistryConfig(BaseModel):
    """Prompt registry configuration."""
    
    sources: list[Dict[str, Any]] = Field(
        default_factory=lambda: [
            {
                "url": "github.com/zero-day-ai/gibson-prompts",
                "name": "official",
                "priority": 100,
                "branch": "main",
                "enabled": True
            }
        ],
        description="Prompt registry sources",
    )
    cache_dir: Optional[Path] = Field(
        default=None,
        description="Prompt cache directory"
    )
    auto_update: bool = Field(
        default=True,
        description="Auto-update prompt collections"
    )
    update_interval: int = Field(
        default=86400,
        description="Update interval in seconds (24 hours default)"
    )
    max_prompts_per_module: int = Field(
        default=100,
        description="Maximum prompts to load per module"
    )
    verify_sources: bool = Field(
        default=True,
        description="Verify prompt source authenticity"
    )


class ResearchConfig(BaseModel):
    """AI research assistant configuration."""
    
    model: str = Field(default="gpt-4", description="AI model to use")
    temperature: float = Field(default=0.7, description="Model temperature")
    max_tokens: int = Field(default=2000, description="Max response tokens")
    human_in_loop: bool = Field(default=True, description="Require human approval")
    cache_responses: bool = Field(default=True, description="Cache AI responses")


class OutputConfig(BaseModel):
    """Output configuration."""
    
    format: str = Field(default="human", description="Default output format")
    color: bool = Field(default=True, description="Enable colored output")
    verbose: bool = Field(default=False, description="Verbose output")
    log_level: str = Field(default="INFO", description="Logging level")


class SafetyConfig(BaseModel):
    """Safety controls configuration."""
    
    dry_run: bool = Field(default=False, description="Dry run mode")
    rate_limit: bool = Field(default=True, description="Enable rate limiting")
    max_parallel: int = Field(default=10, description="Max parallel operations")
    require_confirmation: bool = Field(default=False, description="Require user confirmation")
    max_scan_duration: int = Field(default=3600, description="Max scan duration in seconds")


class DatabaseConfig(BaseModel):
    """Database configuration."""
    
    url: str = Field(
        default="sqlite+aiosqlite:///~/.gibson/gibson.db",
        description="Database URL",
    )
    pool_size: int = Field(default=5, description="Connection pool size")
    max_overflow: int = Field(default=10, description="Max overflow connections")


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
    
    # Paths
    data_dir: Optional[Path] = Field(default=None, description="Data directory")
    cache_dir: Optional[Path] = Field(default=None, description="Cache directory")
    module_dir: Optional[Path] = Field(default=None, description="Module directory")


class ConfigManager:
    """Hierarchical configuration manager."""
    
    def __init__(self, config_file: Optional[Path] = None) -> None:
        """
        Initialize configuration manager.
        
        Args:
            config_file: Optional explicit config file path
        """
        self.config_file = config_file
        self.config = self._load_config()
        self._setup_directories()
    
    def _load_config(self) -> Config:
        """
        Load configuration with hierarchical precedence.
        
        Precedence (highest to lowest):
        1. Environment variables (GIBSON_*)
        2. Explicit config file (--config flag)
        3. Project config (.gibson/config.yaml)
        4. User config (~/.config/gibson/config.yaml)
        5. System config (/etc/gibson/config.yaml)
        6. Default values
        """
        config_data: Dict[str, Any] = {}
        
        # Load system config
        system_config = Path("/etc/gibson/config.yaml")
        if system_config.exists():
            logger.debug(f"Loading system config: {system_config}")
            config_data = self._merge_configs(config_data, self._load_yaml(system_config))
        
        # Load user config
        user_config = Path(user_config_dir("gibson")) / "config.yaml"
        if user_config.exists():
            logger.debug(f"Loading user config: {user_config}")
            config_data = self._merge_configs(config_data, self._load_yaml(user_config))
        
        # Load project config
        project_config = Path.cwd() / ".gibson" / "config.yaml"
        if project_config.exists():
            logger.debug(f"Loading project config: {project_config}")
            config_data = self._merge_configs(config_data, self._load_yaml(project_config))
        
        # Load explicit config file
        if self.config_file and self.config_file.exists():
            logger.debug(f"Loading explicit config: {self.config_file}")
            config_data = self._merge_configs(config_data, self._load_yaml(self.config_file))
        
        # Create Config object (environment variables override via Pydantic)
        try:
            return Config(**config_data)
        except ValidationError as e:
            logger.error(f"Configuration validation failed: {e}")
            # Return default config on validation error
            return Config()
    
    def _load_yaml(self, path: Path) -> Dict[str, Any]:
        """Load YAML configuration file."""
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Failed to load config from {path}: {e}")
            return {}
    
    def _merge_configs(self, base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge configuration dictionaries."""
        result = base.copy()
        
        for key, value in update.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _setup_directories(self) -> None:
        """Setup required directories."""
        # Set default directories if not configured
        if not self.config.data_dir:
            self.config.data_dir = Path.home() / ".gibson" / "data"
        if not self.config.cache_dir:
            self.config.cache_dir = Path.home() / ".gibson" / "cache"
        if not self.config.module_dir:
            self.config.module_dir = Path.home() / ".gibson" / "modules"
        
        # Create directories
        for dir_path in [self.config.data_dir, self.config.cache_dir, self.config.module_dir]:
            if dir_path:
                dir_path.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Ensured directory exists: {dir_path}")
    
    def save(self, path: Optional[Path] = None) -> None:
        """Save current configuration to file."""
        save_path = path or self.config_file or Path.home() / ".config" / "gibson" / "config.yaml"
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert config to serializable format
        config_data = self.config.model_dump()
        
        # Convert Path objects to strings
        def convert_paths(obj):
            if isinstance(obj, dict):
                return {k: convert_paths(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_paths(item) for item in obj]
            elif isinstance(obj, Path):
                return str(obj)
            else:
                return obj
        
        serializable_config = convert_paths(config_data)
        
        with open(save_path, "w") as f:
            yaml.dump(serializable_config, f, default_flow_style=False)
        
        logger.info(f"Configuration saved to: {save_path}")


# Global config manager instance
_config_manager: Optional[ConfigManager] = None


def get_config(config_file: Optional[Path] = None) -> Config:
    """
    Get global configuration instance.
    
    Args:
        config_file: Optional explicit config file path
        
    Returns:
        Config instance with hierarchical configuration loaded
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_file=config_file)
    return _config_manager.config