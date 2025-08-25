"""Environment variable credential injection for CI/CD integration."""

import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import json
import logging
from pathlib import Path

from gibson.core.auth.providers import Provider, ApiKeyFormat
from gibson.core.auth.credential_manager import CredentialManager, Credential

logger = logging.getLogger(__name__)


@dataclass
class EnvMapping:
    """Maps environment variables to credential fields."""

    env_var: str
    field: str
    required: bool = True
    default: Optional[str] = None


class EnvironmentInjector:
    """Handles credential injection from environment variables."""

    # Standard environment variable mappings by provider
    PROVIDER_MAPPINGS = {
        Provider.OPENAI: [
            EnvMapping("OPENAI_API_KEY", "api_key"),
            EnvMapping("OPENAI_API_BASE", "base_url", required=False),
            EnvMapping("OPENAI_ORG_ID", "org_id", required=False),
        ],
        Provider.ANTHROPIC: [
            EnvMapping("ANTHROPIC_API_KEY", "api_key"),
            EnvMapping("ANTHROPIC_API_BASE", "base_url", required=False),
        ],
        Provider.GOOGLE: [
            EnvMapping("GOOGLE_API_KEY", "api_key"),
            EnvMapping("GOOGLE_APPLICATION_CREDENTIALS", "service_account_path", required=False),
        ],
        Provider.AZURE: [
            EnvMapping("AZURE_OPENAI_API_KEY", "api_key"),
            EnvMapping("AZURE_OPENAI_ENDPOINT", "base_url"),
            EnvMapping("AZURE_OPENAI_DEPLOYMENT", "deployment_id", required=False),
            EnvMapping("AZURE_API_VERSION", "api_version", required=False),
        ],
        Provider.AWS_BEDROCK: [
            EnvMapping("AWS_ACCESS_KEY_ID", "access_key"),
            EnvMapping("AWS_SECRET_ACCESS_KEY", "secret_key"),
            EnvMapping("AWS_SESSION_TOKEN", "session_token", required=False),
            EnvMapping("AWS_REGION", "region", required=False, default="us-east-1"),
        ],
        Provider.CUSTOM: [
            EnvMapping("CUSTOM_API_KEY", "api_key"),
            EnvMapping("CUSTOM_API_URL", "base_url", required=False),
            EnvMapping("CUSTOM_AUTH_HEADER", "auth_header", required=False),
        ],
    }

    # Generic environment variable patterns
    GENERIC_PATTERNS = [
        "API_KEY",
        "AUTH_TOKEN",
        "ACCESS_TOKEN",
        "SECRET_KEY",
        "BEARER_TOKEN",
    ]

    def __init__(self, credential_manager: Optional[CredentialManager] = None):
        """Initialize environment injector.

        Args:
            credential_manager: Optional credential manager instance
        """
        self.credential_manager = credential_manager or CredentialManager()
        self._env_cache: Dict[str, str] = {}

    def scan_environment(self) -> Dict[str, List[str]]:
        """Scan environment for potential credentials.

        Returns:
            Dictionary mapping providers to found environment variables
        """
        found = {}

        # Check provider-specific variables
        for provider, mappings in self.PROVIDER_MAPPINGS.items():
            provider_vars = []
            for mapping in mappings:
                if mapping.env_var in os.environ:
                    provider_vars.append(mapping.env_var)
            if provider_vars:
                found[provider.value] = provider_vars

        # Check for generic patterns
        generic_vars = []
        for var_name in os.environ:
            for pattern in self.GENERIC_PATTERNS:
                if pattern in var_name.upper():
                    generic_vars.append(var_name)
                    break
        if generic_vars:
            found["generic"] = generic_vars

        return found

    async def inject_from_environment(
        self,
        provider: Optional[Provider] = None,
        name: Optional[str] = None,
        auto_detect: bool = True,
    ) -> List[Credential]:
        """Inject credentials from environment variables.

        Args:
            provider: Specific provider to inject for
            name: Optional name for the credential
            auto_detect: Whether to auto-detect provider from variables

        Returns:
            List of injected credentials
        """
        injected = []

        if provider:
            # Inject for specific provider
            cred = await self._inject_provider(provider, name)
            if cred:
                injected.append(cred)
        elif auto_detect:
            # Auto-detect and inject all available
            for prov in Provider:
                cred = await self._inject_provider(prov, name)
                if cred:
                    injected.append(cred)

        return injected

    async def _inject_provider(
        self,
        provider: Provider,
        name: Optional[str] = None,
    ) -> Optional[Credential]:
        """Inject credentials for a specific provider.

        Args:
            provider: Provider to inject for
            name: Optional credential name

        Returns:
            Created credential or None if not available
        """
        mappings = self.PROVIDER_MAPPINGS.get(provider, [])
        if not mappings:
            return None

        # Collect values from environment
        values = {}
        for mapping in mappings:
            value = os.environ.get(mapping.env_var)
            if not value and mapping.required:
                # Required field missing
                return None
            elif value:
                values[mapping.field] = value
            elif mapping.default:
                values[mapping.field] = mapping.default

        if not values:
            return None

        # Create credential
        credential_name = name or f"{provider.value}_env"

        # Determine auth format based on provider
        auth_format = self._get_default_format(provider)

        # Build credential data
        cred_data = {
            "name": credential_name,
            "provider": provider,
            "api_key": values.get("api_key", ""),
            "auth_format": auth_format,
            "metadata": {
                "source": "environment",
                "injected": True,
            },
        }

        # Add provider-specific fields
        if provider == Provider.AWS_BEDROCK:
            cred_data["api_key"] = values.get("access_key", "")
            cred_data["metadata"]["secret_key"] = values.get("secret_key", "")
            cred_data["metadata"]["session_token"] = values.get("session_token")
            cred_data["metadata"]["region"] = values.get("region", "us-east-1")
        elif provider == Provider.AZURE:
            cred_data["metadata"]["endpoint"] = values.get("base_url", "")
            cred_data["metadata"]["deployment"] = values.get("deployment_id")
            cred_data["metadata"]["api_version"] = values.get("api_version")
        elif provider == Provider.GOOGLE:
            if "service_account_path" in values:
                # Load service account JSON
                try:
                    with open(values["service_account_path"], "r") as f:
                        cred_data["metadata"]["service_account"] = json.load(f)
                except Exception as e:
                    logger.warning(f"Failed to load service account: {e}")

        # Add any additional metadata
        for key, value in values.items():
            if key not in ["api_key", "access_key", "secret_key"]:
                cred_data["metadata"][key] = value

        # Store credential
        try:
            credential = await self.credential_manager.store_credential(**cred_data)
            logger.info(f"Injected {provider.value} credentials from environment")
            return credential
        except Exception as e:
            logger.error(f"Failed to inject {provider.value} credentials: {e}")
            return None

    def _get_default_format(self, provider: Provider) -> ApiKeyFormat:
        """Get default authentication format for provider.

        Args:
            provider: Provider type

        Returns:
            Default API key format
        """
        format_map = {
            Provider.OPENAI: ApiKeyFormat.BEARER_TOKEN,
            Provider.ANTHROPIC: ApiKeyFormat.X_API_KEY,
            Provider.GOOGLE: ApiKeyFormat.X_API_KEY,
            Provider.AZURE: ApiKeyFormat.API_KEY_HEADER,
            Provider.AWS_BEDROCK: ApiKeyFormat.CUSTOM_HEADER,
            Provider.CUSTOM: ApiKeyFormat.BEARER_TOKEN,
        }
        return format_map.get(provider, ApiKeyFormat.BEARER_TOKEN)

    def export_template(
        self,
        provider: Optional[Provider] = None,
        format: str = "env",
    ) -> str:
        """Export environment variable template.

        Args:
            provider: Specific provider or all if None
            format: Output format (env, docker, k8s)

        Returns:
            Template string
        """
        templates = []

        providers = [provider] if provider else list(Provider)

        for prov in providers:
            mappings = self.PROVIDER_MAPPINGS.get(prov, [])
            if not mappings:
                continue

            if format == "env":
                # Shell environment format
                templates.append(f"# {prov.value.upper()} Credentials")
                for mapping in mappings:
                    req = "" if mapping.required else " (optional)"
                    templates.append(f'export {mapping.env_var}="your_{mapping.field}_here"{req}')
                templates.append("")

            elif format == "docker":
                # Docker environment format
                templates.append(f"# {prov.value.upper()} Credentials")
                for mapping in mappings:
                    req = "" if mapping.required else " # optional"
                    templates.append(f"      - {mapping.env_var}=${{mapping.env_var}}{req}")
                templates.append("")

            elif format == "k8s":
                # Kubernetes secret format
                templates.append(f"  # {prov.value.upper()} Credentials")
                for mapping in mappings:
                    req = "" if mapping.required else " # optional"
                    templates.append(f"  {mapping.env_var}: <base64-encoded-value>{req}")
                templates.append("")

        return "\n".join(templates)

    async def inject_from_file(
        self,
        env_file: Path,
        override: bool = False,
    ) -> List[Credential]:
        """Inject credentials from .env file.

        Args:
            env_file: Path to .env file
            override: Whether to override existing environment

        Returns:
            List of injected credentials
        """
        if not env_file.exists():
            raise FileNotFoundError(f"Environment file not found: {env_file}")

        # Parse .env file
        env_vars = {}
        with open(env_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        env_vars[key] = value

        # Temporarily set environment variables
        original_env = {}
        for key, value in env_vars.items():
            if key in os.environ and not override:
                continue
            original_env[key] = os.environ.get(key)
            os.environ[key] = value

        try:
            # Inject from environment
            credentials = await self.inject_from_environment(auto_detect=True)
            return credentials
        finally:
            # Restore original environment
            for key, original_value in original_env.items():
                if original_value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = original_value

    def validate_environment(self, provider: Provider) -> Dict[str, Any]:
        """Validate environment has required variables for provider.

        Args:
            provider: Provider to validate for

        Returns:
            Validation results with missing/present variables
        """
        mappings = self.PROVIDER_MAPPINGS.get(provider, [])

        result = {
            "provider": provider.value,
            "valid": True,
            "present": [],
            "missing": [],
            "optional_missing": [],
        }

        for mapping in mappings:
            if mapping.env_var in os.environ:
                result["present"].append(mapping.env_var)
            elif mapping.required:
                result["missing"].append(mapping.env_var)
                result["valid"] = False
            else:
                result["optional_missing"].append(mapping.env_var)

        return result

    async def auto_inject_all(self) -> Dict[str, List[Credential]]:
        """Automatically inject all available credentials from environment.

        Returns:
            Dictionary mapping provider names to injected credentials
        """
        results = {}

        for provider in Provider:
            credentials = await self.inject_from_environment(provider=provider)
            if credentials:
                results[provider.value] = credentials

        return results
