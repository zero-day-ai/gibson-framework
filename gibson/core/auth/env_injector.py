"""Environment variable credential injection for automated environments.

Provides automated credential injection from environment variables following
standard patterns for CI/CD systems, containers, and development environments.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from uuid import UUID

from loguru import logger

from gibson.models.auth import (
    ApiKeyCredentialModel,
    ApiKeyFormat,
    ValidationStatus
)
from gibson.core.auth.credential_manager import CredentialManager


class EnvironmentCredentialInjector:
    """Handles automatic credential injection from environment variables."""
    
    # Environment variable patterns
    ENV_PATTERNS = {
        # Standard Gibson patterns
        "gibson_target": re.compile(r"^GIBSON_TARGET_([A-F0-9\-]+)_API_KEY$", re.IGNORECASE),
        "gibson_provider": re.compile(r"^GIBSON_TARGET_([A-F0-9\-]+)_PROVIDER$", re.IGNORECASE),
        "gibson_format": re.compile(r"^GIBSON_TARGET_([A-F0-9\-]+)_FORMAT$", re.IGNORECASE),
        "gibson_header": re.compile(r"^GIBSON_TARGET_([A-F0-9\-]+)_HEADER$", re.IGNORECASE),
        "gibson_prefix": re.compile(r"^GIBSON_TARGET_([A-F0-9\-]+)_PREFIX$", re.IGNORECASE),
        
        # Generic API key patterns
        "openai": re.compile(r"^OPENAI_API_KEY$", re.IGNORECASE),
        "anthropic": re.compile(r"^ANTHROPIC_API_KEY$", re.IGNORECASE),
        "google": re.compile(r"^GOOGLE_API_KEY$", re.IGNORECASE),
        "azure": re.compile(r"^AZURE_API_KEY$", re.IGNORECASE),
        
        # Provider-specific patterns
        "openai_org": re.compile(r"^OPENAI_ORG_ID$", re.IGNORECASE),
        "google_project": re.compile(r"^GOOGLE_PROJECT_ID$", re.IGNORECASE),
        "azure_endpoint": re.compile(r"^AZURE_ENDPOINT$", re.IGNORECASE),
    }
    
    # Default formats for providers
    PROVIDER_FORMATS = {
        "openai": ApiKeyFormat.OPENAI_FORMAT,
        "anthropic": ApiKeyFormat.ANTHROPIC_FORMAT,
        "google": ApiKeyFormat.GOOGLE_FORMAT,
        "azure": ApiKeyFormat.AZURE_FORMAT,
    }
    
    def __init__(
        self,
        credential_manager: Optional[CredentialManager] = None,
        auto_inject: bool = True,
        validate_on_inject: bool = False
    ):
        """Initialize environment credential injector.
        
        Args:
            credential_manager: Credential manager instance
            auto_inject: Automatically inject credentials on initialization
            validate_on_inject: Validate credentials during injection
        """
        self.credential_manager = credential_manager or CredentialManager()
        self.auto_inject = auto_inject
        self.validate_on_inject = validate_on_inject
        
        # Cache for discovered environment credentials
        self._env_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_valid = False
        
        if auto_inject:
            self.discover_and_inject()
    
    def discover_environment_credentials(self) -> Dict[str, Dict[str, Any]]:
        """Discover credentials from environment variables.
        
        Returns:
            Dictionary mapping target IDs to credential information
        """
        if self._cache_valid:
            return self._env_cache
        
        discovered = {}
        env_vars = dict(os.environ)
        
        # Discover Gibson-specific target credentials
        gibson_targets = self._discover_gibson_targets(env_vars)
        discovered.update(gibson_targets)
        
        # Discover generic provider credentials
        provider_creds = self._discover_provider_credentials(env_vars)
        discovered.update(provider_creds)
        
        self._env_cache = discovered
        self._cache_valid = True
        
        logger.info(f"Discovered {len(discovered)} credential sets from environment")
        return discovered
    
    def _discover_gibson_targets(self, env_vars: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """Discover Gibson-specific target credentials."""
        targets = {}
        
        # Find all target API keys
        for env_name, env_value in env_vars.items():
            match = self.ENV_PATTERNS["gibson_target"].match(env_name)
            if match:
                target_id = match.group(1).lower()
                
                # Initialize target if not exists
                if target_id not in targets:
                    targets[target_id] = {
                        "target_id": target_id,
                        "api_key": env_value,
                        "source": "gibson_env"
                    }
                else:
                    targets[target_id]["api_key"] = env_value
        
        # Find additional configuration for discovered targets
        for target_id in list(targets.keys()):
            # Provider
            provider_var = f"GIBSON_TARGET_{target_id.upper()}_PROVIDER"
            if provider_var in env_vars:
                targets[target_id]["provider"] = env_vars[provider_var]
            
            # Format
            format_var = f"GIBSON_TARGET_{target_id.upper()}_FORMAT"
            if format_var in env_vars:
                targets[target_id]["format"] = env_vars[format_var]
            
            # Header name
            header_var = f"GIBSON_TARGET_{target_id.upper()}_HEADER"
            if header_var in env_vars:
                targets[target_id]["header_name"] = env_vars[header_var]
            
            # Token prefix
            prefix_var = f"GIBSON_TARGET_{target_id.upper()}_PREFIX"
            if prefix_var in env_vars:
                targets[target_id]["token_prefix"] = env_vars[prefix_var]
        
        return targets
    
    def _discover_provider_credentials(self, env_vars: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """Discover generic provider credentials."""
        providers = {}
        
        # OpenAI
        if "OPENAI_API_KEY" in env_vars:
            provider_id = "openai_default"
            providers[provider_id] = {
                "target_id": provider_id,
                "api_key": env_vars["OPENAI_API_KEY"],
                "provider": "openai",
                "format": "OPENAI_FORMAT",
                "source": "provider_env"
            }
            
            # Add organization if available
            if "OPENAI_ORG_ID" in env_vars:
                providers[provider_id]["org_id"] = env_vars["OPENAI_ORG_ID"]
        
        # Anthropic
        if "ANTHROPIC_API_KEY" in env_vars:
            provider_id = "anthropic_default"
            providers[provider_id] = {
                "target_id": provider_id,
                "api_key": env_vars["ANTHROPIC_API_KEY"],
                "provider": "anthropic",
                "format": "ANTHROPIC_FORMAT",
                "source": "provider_env"
            }
        
        # Google
        if "GOOGLE_API_KEY" in env_vars:
            provider_id = "google_default"
            providers[provider_id] = {
                "target_id": provider_id,
                "api_key": env_vars["GOOGLE_API_KEY"],
                "provider": "google",
                "format": "GOOGLE_FORMAT",
                "source": "provider_env"
            }
            
            if "GOOGLE_PROJECT_ID" in env_vars:
                providers[provider_id]["project_id"] = env_vars["GOOGLE_PROJECT_ID"]
        
        # Azure
        if "AZURE_API_KEY" in env_vars:
            provider_id = "azure_default"
            providers[provider_id] = {
                "target_id": provider_id,
                "api_key": env_vars["AZURE_API_KEY"],
                "provider": "azure",
                "format": "AZURE_FORMAT",
                "source": "provider_env"
            }
            
            if "AZURE_ENDPOINT" in env_vars:
                providers[provider_id]["endpoint"] = env_vars["AZURE_ENDPOINT"]
        
        return providers
    
    def discover_and_inject(self) -> Dict[str, bool]:
        """Discover and inject all environment credentials.
        
        Returns:
            Dictionary mapping target IDs to injection success status
        """
        discovered = self.discover_environment_credentials()
        results = {}
        
        for target_id, cred_info in discovered.items():
            try:
                success = self.inject_credential(cred_info)
                results[target_id] = success
                
                if success:
                    logger.info(f"Injected environment credential for target: {target_id}")
                else:
                    logger.warning(f"Failed to inject credential for target: {target_id}")
            
            except Exception as e:
                logger.error(f"Error injecting credential for {target_id}: {e}")
                results[target_id] = False
        
        return results
    
    def inject_credential(self, cred_info: Dict[str, Any]) -> bool:
        """Inject a single credential from environment information.
        
        Args:
            cred_info: Credential information dictionary
            
        Returns:
            True if injection was successful
        """
        try:
            # Parse target ID
            target_id_str = cred_info.get("target_id")
            if not target_id_str:
                logger.error("No target_id in credential info")
                return False
            
            # Handle UUID vs string target IDs
            if cred_info.get("source") == "gibson_env":
                try:
                    target_id = UUID(target_id_str)
                except ValueError:
                    logger.error(f"Invalid UUID format for Gibson target: {target_id_str}")
                    return False
            else:
                # For provider defaults, generate deterministic UUID from string
                target_id = self._generate_provider_uuid(target_id_str)
            
            # Check if credential already exists
            existing = self.credential_manager.retrieve_credential(target_id)
            if existing:
                logger.debug(f"Credential already exists for target {target_id}, skipping injection")
                return True
            
            # Parse format
            format_str = cred_info.get("format", "BEARER_TOKEN")
            try:
                if format_str in [f.name for f in ApiKeyFormat]:
                    key_format = ApiKeyFormat[format_str]
                else:
                    key_format = ApiKeyFormat(format_str.upper().replace('-', '_'))
            except (ValueError, KeyError):
                logger.warning(f"Unknown format '{format_str}', using BEARER_TOKEN")
                key_format = ApiKeyFormat.BEARER_TOKEN
            
            # Create credential model
            credential = ApiKeyCredentialModel(
                target_id=target_id,
                token=cred_info["api_key"],
                key_format=key_format,
                provider=cred_info.get("provider"),
                header_name=cred_info.get("header_name"),
                token_prefix=cred_info.get("token_prefix"),
                description=f"Auto-injected from environment ({cred_info.get('source', 'unknown')})"
            )
            
            # Store credential
            self.credential_manager.store_credential(credential)
            
            # Validate if requested
            if self.validate_on_inject:
                from gibson.core.auth.auth_service import AuthenticationService
                import asyncio
                
                auth_service = AuthenticationService()
                result = asyncio.run(auth_service.validate_credential(credential))
                
                if result.status != ValidationStatus.VALID:
                    logger.warning(f"Injected credential for {target_id} failed validation: {result.error_message}")
                else:
                    logger.info(f"Injected credential for {target_id} validated successfully")
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to inject credential: {e}")
            return False
    
    def _generate_provider_uuid(self, provider_id: str) -> UUID:
        """Generate deterministic UUID for provider default credentials."""
        import hashlib
        
        # Create deterministic UUID from provider ID
        namespace = UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # DNS namespace
        name = f"gibson.provider.{provider_id}"
        
        hash_bytes = hashlib.md5(name.encode()).digest()
        return UUID(bytes=hash_bytes)
    
    def clear_cache(self) -> None:
        """Clear the environment credential cache."""
        self._env_cache.clear()
        self._cache_valid = False
        logger.debug("Environment credential cache cleared")
    
    def get_injection_status(self) -> Dict[str, Any]:
        """Get status of environment credential injection.
        
        Returns:
            Dictionary with injection statistics and status
        """
        discovered = self.discover_environment_credentials()
        stored_credentials = self.credential_manager.list_credentials()
        
        # Count injected credentials
        injected_count = 0
        env_target_ids = set()
        
        for target_id, cred_info in discovered.items():
            if cred_info.get("source") == "gibson_env":
                try:
                    env_target_ids.add(UUID(target_id))
                except ValueError:
                    continue
            else:
                env_target_ids.add(self._generate_provider_uuid(target_id))
        
        for cred in stored_credentials:
            if cred.target_id in env_target_ids:
                injected_count += 1
        
        return {
            "discovered_count": len(discovered),
            "injected_count": injected_count,
            "injection_rate": injected_count / len(discovered) if discovered else 0.0,
            "auto_inject_enabled": self.auto_inject,
            "validate_on_inject": self.validate_on_inject,
            "cache_valid": self._cache_valid
        }
    
    def list_environment_variables(self) -> List[str]:
        """List relevant environment variables for credential injection.
        
        Returns:
            List of environment variable names that could contain credentials
        """
        env_vars = []
        
        # Gibson-specific patterns
        for env_name in os.environ:
            for pattern_name, pattern in self.ENV_PATTERNS.items():
                if pattern.match(env_name):
                    env_vars.append(env_name)
                    break
        
        return sorted(env_vars)
    
    def generate_env_template(self, target_ids: List[str] = None) -> str:
        """Generate environment variable template.
        
        Args:
            target_ids: List of target IDs to generate template for
            
        Returns:
            Environment variable template as string
        """
        lines = [
            "# Gibson Framework Authentication Environment Variables",
            "# ",
            "# Target-specific credentials (replace TARGET_ID with actual UUID):",
            "# GIBSON_TARGET_<TARGET_ID>_API_KEY=your_api_key_here",
            "# GIBSON_TARGET_<TARGET_ID>_PROVIDER=openai|anthropic|google|azure",
            "# GIBSON_TARGET_<TARGET_ID>_FORMAT=bearer|custom_header|query_parameter",
            "# GIBSON_TARGET_<TARGET_ID>_HEADER=X-API-Key  # for custom headers",
            "# GIBSON_TARGET_<TARGET_ID>_PREFIX=Bearer     # for bearer tokens",
            "",
        ]
        
        if target_ids:
            lines.extend([
                "# Specific target configurations:",
                ""
            ])
            
            for target_id in target_ids:
                target_id_clean = target_id.replace('-', '').upper()
                lines.extend([
                    f"GIBSON_TARGET_{target_id_clean}_API_KEY=",
                    f"GIBSON_TARGET_{target_id_clean}_PROVIDER=",
                    f"GIBSON_TARGET_{target_id_clean}_FORMAT=bearer",
                    ""
                ])
        
        lines.extend([
            "# Provider default credentials:",
            "# OPENAI_API_KEY=sk-...",
            "# OPENAI_ORG_ID=org-...",
            "# ANTHROPIC_API_KEY=sk-ant-...",
            "# GOOGLE_API_KEY=...",
            "# GOOGLE_PROJECT_ID=...",
            "# AZURE_API_KEY=...",
            "# AZURE_ENDPOINT=https://...",
            "",
            "# CI/CD Environment Detection:",
            "# GIBSON_CI_MODE=true",
            "# GIBSON_AUTO_INJECT=true",
            "# GIBSON_VALIDATE_ON_INJECT=false"
        ])
        
        return "\n".join(lines)
    
    def export_env_file(
        self,
        file_path: Path,
        target_ids: List[str] = None,
        include_values: bool = False
    ) -> None:
        """Export environment variable template to file.
        
        Args:
            file_path: Path to write environment file
            target_ids: List of target IDs to include
            include_values: Include actual credential values (dangerous!)
        """
        template = self.generate_env_template(target_ids)
        
        if include_values:
            # Replace template with actual values (use with caution!)
            discovered = self.discover_environment_credentials()
            for target_id, cred_info in discovered.items():
                if cred_info.get("source") == "gibson_env":
                    target_clean = target_id.replace('-', '').upper()
                    template = template.replace(
                        f"GIBSON_TARGET_{target_clean}_API_KEY=",
                        f"GIBSON_TARGET_{target_clean}_API_KEY={cred_info['api_key']}"
                    )
        
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(template)
        
        logger.info(f"Environment template exported to: {file_path}")
        
        if include_values:
            logger.warning("Environment file contains actual credential values - keep secure!")


def detect_ci_environment() -> Dict[str, Any]:
    """Detect CI/CD environment and return relevant information.
    
    Returns:
        Dictionary with CI environment information
    """
    ci_indicators = {
        "github_actions": "GITHUB_ACTIONS" in os.environ,
        "gitlab_ci": "GITLAB_CI" in os.environ,
        "jenkins": "JENKINS_URL" in os.environ,
        "circleci": "CIRCLECI" in os.environ,
        "travis": "TRAVIS" in os.environ,
        "appveyor": "APPVEYOR" in os.environ,
        "azure_pipelines": "AZURE_HTTP_USER_AGENT" in os.environ,
        "bitbucket": "BITBUCKET_BUILD_NUMBER" in os.environ,
        "drone": "DRONE" in os.environ,
        "bamboo": "bamboo_buildKey" in os.environ,
    }
    
    detected_ci = [name for name, detected in ci_indicators.items() if detected]
    
    # Container detection
    in_container = (
        Path("/.dockerenv").exists() or 
        "KUBERNETES_SERVICE_HOST" in os.environ or
        "container" in os.environ.get("container", "")
    )
    
    return {
        "is_ci": bool(detected_ci) or os.environ.get("CI", "").lower() in ["true", "1"],
        "detected_ci": detected_ci,
        "in_container": in_container,
        "kubernetes": "KUBERNETES_SERVICE_HOST" in os.environ,
        "docker": Path("/.dockerenv").exists(),
        "user_is_root": os.getuid() == 0 if hasattr(os, 'getuid') else False,
    }


def auto_inject_from_environment() -> bool:
    """Automatically inject credentials from environment if appropriate.
    
    Returns:
        True if injection was performed
    """
    # Check if auto-injection is enabled
    auto_inject = os.environ.get("GIBSON_AUTO_INJECT", "").lower() in ["true", "1"]
    ci_info = detect_ci_environment()
    
    # Auto-inject in CI environments unless explicitly disabled
    if ci_info["is_ci"] and not os.environ.get("GIBSON_DISABLE_AUTO_INJECT"):
        auto_inject = True
    
    if not auto_inject:
        return False
    
    try:
        # Perform injection
        validate_on_inject = os.environ.get("GIBSON_VALIDATE_ON_INJECT", "").lower() in ["true", "1"]
        
        injector = EnvironmentCredentialInjector(
            auto_inject=True,
            validate_on_inject=validate_on_inject
        )
        
        results = injector.discover_and_inject()
        success_count = sum(1 for success in results.values() if success)
        
        logger.info(f"Auto-injected {success_count}/{len(results)} credentials from environment")
        return success_count > 0
    
    except Exception as e:
        logger.error(f"Failed to auto-inject environment credentials: {e}")
        return False