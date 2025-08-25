"""Authentication configuration and path resolution.

Provides hierarchical configuration path resolution for different
deployment environments including development, CI/CD, and containers.
"""

import os
import stat
import json
from pathlib import Path
from typing import Dict, List, Optional, Any

from loguru import logger
from pydantic import BaseModel, Field, ValidationError


class AuthenticationConfig(BaseModel):
    """Authentication system configuration."""
    
    credentials_dir: Optional[Path] = Field(
        default=None,
        description="Directory for credential storage"
    )
    encryption_enabled: bool = Field(
        default=True,
        description="Enable credential encryption"
    )
    validation_enabled: bool = Field(
        default=True,
        description="Enable credential validation"
    )
    validation_interval_hours: int = Field(
        default=24,
        ge=1,
        le=168,  # 1 week max
        description="Hours between credential validations"
    )
    cache_enabled: bool = Field(
        default=True,
        description="Enable credential caching"
    )
    cache_ttl_minutes: int = Field(
        default=60,
        ge=5,
        le=1440,  # 24 hours max
        description="Cache TTL in minutes"
    )
    audit_enabled: bool = Field(
        default=True,
        description="Enable authentication audit logging"
    )
    

class EnvironmentCredential(BaseModel):
    """Environment variable credential configuration."""
    
    target_name: str = Field(
        description="Target name for this credential"
    )
    environment_variable: str = Field(
        description="Environment variable name"
    )
    key_format: str = Field(
        default="bearer_token",
        description="API key format"
    )
    validation_endpoint: Optional[str] = Field(
        default=None,
        description="Endpoint for validation"
    )
    

def resolve_credentials_path() -> Path:
    """Resolve credentials storage path with environment hierarchy.
    
    Path resolution order:
    1. GIBSON_CONFIG_DIR environment variable (highest priority)
    2. HOME/.gibson directory (standard user location)
    3. /app/.gibson directory (container fallback)
    
    Returns:
        Path to credentials directory
    """
    
    # Environment variable override (highest priority)
    if config_dir := os.getenv('GIBSON_CONFIG_DIR'):
        path = Path(config_dir) / 'credentials'
        logger.debug(f"Using credentials path from GIBSON_CONFIG_DIR: {path}")
        return path
    
    # Standard user home directory
    if home_dir := os.getenv('HOME'):
        path = Path(home_dir) / '.gibson' / 'credentials'
        logger.debug(f"Using credentials path from HOME: {path}")
        return path
    
    # Container fallback
    path = Path('/app/.gibson/credentials')
    logger.debug(f"Using container fallback credentials path: {path}")
    return path


def resolve_config_directory() -> Path:
    """Resolve Gibson configuration directory.
    
    Returns:
        Path to Gibson configuration directory
    """
    
    # Environment variable override
    if config_dir := os.getenv('GIBSON_CONFIG_DIR'):
        path = Path(config_dir)
        logger.debug(f"Using config directory from GIBSON_CONFIG_DIR: {path}")
        return path
    
    # Standard user home directory
    if home_dir := os.getenv('HOME'):
        path = Path(home_dir) / '.gibson'
        logger.debug(f"Using config directory from HOME: {path}")
        return path
    
    # Container fallback
    path = Path('/app/.gibson')
    logger.debug(f"Using container fallback config directory: {path}")
    return path


def ensure_directory_permissions(path: Path) -> None:
    """Ensure directory has secure permissions (700).
    
    Args:
        path: Directory path to secure
    """
    try:
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
        
        # Set secure permissions (owner read/write/execute only)
        path.chmod(stat.S_IRWXU)  # 0o700
        
        logger.debug(f"Set secure permissions on directory: {path}")
    except Exception as e:
        logger.warning(f"Failed to set directory permissions on {path}: {e}")


def ensure_file_permissions(path: Path) -> None:
    """Ensure file has secure permissions (600).
    
    Args:
        path: File path to secure
    """
    try:
        if path.exists():
            # Set secure permissions (owner read/write only)
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
            logger.debug(f"Set secure permissions on file: {path}")
    except Exception as e:
        logger.warning(f"Failed to set file permissions on {path}: {e}")


def detect_container_environment() -> bool:
    """Detect if running in a container environment.
    
    Returns:
        True if running in a container
    """
    
    container_indicators = [
        # Docker
        '/.dockerenv',
        # Kubernetes
        '/var/run/secrets/kubernetes.io',
        # Container environment variables
        lambda: os.getenv('container') is not None,
        lambda: os.getenv('KUBERNETES_SERVICE_HOST') is not None,
        lambda: os.getenv('DOCKER_CONTAINER') is not None,
    ]
    
    for indicator in container_indicators:
        try:
            if callable(indicator):
                if indicator():
                    return True
            elif Path(indicator).exists():
                return True
        except Exception:
            continue
    
    return False


def detect_ci_environment() -> Optional[str]:
    """Detect CI/CD environment.
    
    Returns:
        CI environment name or None if not detected
    """
    
    ci_environments = {
        'GITHUB_ACTIONS': 'github-actions',
        'GITLAB_CI': 'gitlab-ci',
        'JENKINS_URL': 'jenkins',
        'CIRCLECI': 'circleci',
        'TRAVIS': 'travis-ci',
        'BUILDKITE': 'buildkite',
        'DRONE': 'drone',
        'CI': 'generic-ci'
    }
    
    for env_var, ci_name in ci_environments.items():
        if os.getenv(env_var):
            return ci_name
    
    return None


def load_environment_credentials() -> Dict[str, str]:
    """Load credentials from environment variables.
    
    Supports patterns:
    - GIBSON_API_KEY_<TARGET_NAME>=<key>
    - GIBSON_CREDENTIALS_JSON={"target1": "key1", "target2": "key2"}
    
    Returns:
        Dictionary mapping target names to API keys
    """
    
    credentials = {}
    
    # Load individual target API keys
    prefix = 'GIBSON_API_KEY_'
    for env_var, value in os.environ.items():
        if env_var.startswith(prefix) and value:
            target_name = env_var[len(prefix):].lower().replace('_', '-')
            credentials[target_name] = value
            logger.debug(f"Found environment credential for target: {target_name}")
    
    # Load bulk credentials from JSON
    if bulk_creds := os.getenv('GIBSON_CREDENTIALS_JSON'):
        try:
            bulk_data = json.loads(bulk_creds)
            if isinstance(bulk_data, dict):
                for target_name, api_key in bulk_data.items():
                    if isinstance(api_key, str) and api_key:
                        credentials[target_name] = api_key
                        logger.debug(f"Found bulk credential for target: {target_name}")
            else:
                logger.warning("GIBSON_CREDENTIALS_JSON is not a valid JSON object")
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse GIBSON_CREDENTIALS_JSON: {e}")
    
    logger.info(f"Loaded {len(credentials)} credentials from environment variables")
    return credentials


def validate_environment_credentials(credentials: Dict[str, str]) -> List[str]:
    """Validate environment credentials format.
    
    Args:
        credentials: Dictionary of target names to API keys
        
    Returns:
        List of validation errors
    """
    
    errors = []
    
    for target_name, api_key in credentials.items():
        # Validate target name format
        if not target_name or not isinstance(target_name, str):
            errors.append(f"Invalid target name: {target_name}")
            continue
        
        if not target_name.replace('-', '').replace('_', '').isalnum():
            errors.append(f"Target name contains invalid characters: {target_name}")
        
        # Validate API key format
        if not api_key or not isinstance(api_key, str):
            errors.append(f"Invalid API key for target {target_name}: empty or non-string")
            continue
        
        if len(api_key) < 8:
            errors.append(f"API key for target {target_name} is too short (minimum 8 characters)")
        
        # Check for obvious test/example keys
        test_patterns = ['test', 'example', 'demo', 'sample', 'fake']
        if any(pattern in api_key.lower() for pattern in test_patterns):
            errors.append(f"API key for target {target_name} appears to be a test/example key")
    
    return errors


def get_config_file_path() -> Path:
    """Get path to authentication configuration file.
    
    Returns:
        Path to auth config file
    """
    return resolve_config_directory() / 'auth_config.yaml'


def load_auth_config() -> AuthenticationConfig:
    """Load authentication configuration from file.
    
    Returns:
        Authentication configuration object
    """
    
    config_path = get_config_file_path()
    
    if not config_path.exists():
        logger.debug("No authentication config file found, using defaults")
        return AuthenticationConfig()
    
    try:
        import yaml
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        return AuthenticationConfig(**config_data)
    
    except Exception as e:
        logger.warning(f"Failed to load authentication config from {config_path}: {e}")
        return AuthenticationConfig()


def save_auth_config(config: AuthenticationConfig) -> bool:
    """Save authentication configuration to file.
    
    Args:
        config: Authentication configuration to save
        
    Returns:
        True if saved successfully
    """
    
    config_path = get_config_file_path()
    
    try:
        # Ensure directory exists with secure permissions
        ensure_directory_permissions(config_path.parent)
        
        import yaml
        with open(config_path, 'w') as f:
            yaml.safe_dump(config.model_dump(), f, default_flow_style=False)
        
        # Set secure file permissions
        ensure_file_permissions(config_path)
        
        logger.info(f"Saved authentication configuration to {config_path}")
        return True
    
    except Exception as e:
        logger.error(f"Failed to save authentication config to {config_path}: {e}")
        return False


def validate_config_setup() -> Dict[str, Any]:
    """Validate authentication configuration setup.
    
    Returns:
        Dictionary with validation results
    """
    
    results = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'info': []
    }
    
    try:
        # Check credentials directory
        creds_dir = resolve_credentials_path()
        if not creds_dir.parent.exists():
            results['warnings'].append(f"Configuration directory does not exist: {creds_dir.parent}")
        
        # Check permissions
        if creds_dir.exists():
            dir_stat = creds_dir.stat()
            if dir_stat.st_mode & 0o077:  # Check if group/other have permissions
                results['warnings'].append(f"Credentials directory has insecure permissions: {creds_dir}")
        
        # Check environment
        is_container = detect_container_environment()
        from gibson.core.auth.env_injector import detect_ci_environment
        ci_env = detect_ci_environment()
        
        results['info'].append(f"Container environment: {is_container}")
        if ci_env:
            results['info'].append(f"CI environment detected: {ci_env}")
        
        # Check environment credentials
        env_creds = load_environment_credentials()
        if env_creds:
            results['info'].append(f"Found {len(env_creds)} environment credentials")
            
            # Validate environment credentials
            cred_errors = validate_environment_credentials(env_creds)
            results['errors'].extend(cred_errors)
        
        # Check configuration file
        config_path = get_config_file_path()
        if config_path.exists():
            try:
                load_auth_config()
                results['info'].append(f"Configuration file loaded: {config_path}")
            except Exception as e:
                results['errors'].append(f"Invalid configuration file: {e}")
        
        results['valid'] = len(results['errors']) == 0
        
    except Exception as e:
        results['valid'] = False
        results['errors'].append(f"Configuration validation failed: {e}")
    
    return results
