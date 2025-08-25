"""
LiteLLM adapter for unified LLM provider integration.

Provides automatic provider detection and configuration.
"""

import os
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse

from loguru import logger

from gibson.models.target import LLMProvider


class LiteLLMAdapter:
    """Adapter for LiteLLM integration."""

    # Provider URL patterns
    PROVIDER_PATTERNS = {
        LLMProvider.OPENAI: ["openai.com", "api.openai.com"],
        LLMProvider.ANTHROPIC: ["anthropic.com", "api.anthropic.com", "claude.ai"],
        LLMProvider.AZURE: ["azure.com", "openai.azure.com", "cognitiveservices.azure.com"],
        LLMProvider.AWS_BEDROCK: ["amazonaws.com/bedrock", "bedrock.amazonaws.com"],
        LLMProvider.GOOGLE: ["googleapis.com", "google.com/vertex", "vertexai.googleapis.com"],
        LLMProvider.HUGGINGFACE: ["huggingface.co", "api-inference.huggingface.co"],
        LLMProvider.OLLAMA: ["localhost:11434", "127.0.0.1:11434", "0.0.0.0:11434"],
    }

    # Default models per provider
    DEFAULT_MODELS = {
        LLMProvider.OPENAI: "gpt-3.5-turbo",
        LLMProvider.ANTHROPIC: "claude-3-sonnet-20240229",
        LLMProvider.AZURE: "gpt-35-turbo",
        LLMProvider.AWS_BEDROCK: "anthropic.claude-v2",
        LLMProvider.GOOGLE: "chat-bison",
        LLMProvider.HUGGINGFACE: "microsoft/DialoGPT-medium",
        LLMProvider.OLLAMA: "llama2",
        LLMProvider.LITELLM: "gpt-3.5-turbo",
    }

    # Environment variable mappings
    ENV_VARS = {
        LLMProvider.OPENAI: ["OPENAI_API_KEY"],
        LLMProvider.ANTHROPIC: ["ANTHROPIC_API_KEY"],
        LLMProvider.AZURE: ["AZURE_OPENAI_API_KEY", "AZURE_API_KEY"],
        LLMProvider.AWS_BEDROCK: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
        LLMProvider.GOOGLE: ["GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_API_KEY"],
        LLMProvider.HUGGINGFACE: ["HUGGINGFACE_API_KEY", "HF_TOKEN"],
        LLMProvider.OLLAMA: [],  # No auth required for local
    }

    def auto_detect_provider(self, base_url: str) -> LLMProvider:
        """Auto-detect LLM provider from URL.

        Args:
            base_url: Target base URL

        Returns:
            Detected LLM provider
        """
        try:
            parsed = urlparse(base_url)
            host = parsed.netloc.lower()
            path = parsed.path.lower()
            full_url = f"{host}{path}"

            # Check URL patterns
            for provider, patterns in self.PROVIDER_PATTERNS.items():
                for pattern in patterns:
                    if pattern in full_url:
                        logger.debug(f"Detected provider {provider} from URL pattern: {pattern}")
                        return provider

            # Check for environment variables as fallback
            for provider, env_vars in self.ENV_VARS.items():
                if any(os.getenv(var) for var in env_vars):
                    logger.debug(f"Detected provider {provider} from environment variables")
                    return provider

            # Default to LiteLLM for generic endpoints
            logger.debug(f"No specific provider detected for {base_url}, defaulting to LiteLLM")
            return LLMProvider.LITELLM

        except Exception as e:
            logger.error(f"Error detecting provider for {base_url}: {e}")
            return LLMProvider.LITELLM

    def get_provider_config(
        self, provider: LLMProvider, base_url: str, model_hint: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get provider-specific configuration.

        Args:
            provider: LLM provider
            base_url: Target base URL
            model_hint: Optional model name hint

        Returns:
            Provider configuration dictionary
        """
        config = {
            "api_base": base_url,
            "provider": provider.value if hasattr(provider, "value") else provider,
        }

        # Determine model name
        if model_hint:
            config["model"] = self._format_model_name(provider, model_hint)
        else:
            config["model"] = self._get_default_model(provider, base_url)

        # Add provider-specific configuration
        if provider == LLMProvider.AZURE:
            config["api_type"] = "azure"
            config["api_version"] = os.getenv("AZURE_API_VERSION", "2023-12-01-preview")

            # Extract deployment name from URL if possible
            parsed = urlparse(base_url)
            path_parts = parsed.path.strip("/").split("/")
            if "deployments" in path_parts:
                idx = path_parts.index("deployments")
                if idx + 1 < len(path_parts):
                    config["deployment_name"] = path_parts[idx + 1]

        elif provider == LLMProvider.AWS_BEDROCK:
            config["aws_region"] = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
            config["aws_access_key"] = os.getenv("AWS_ACCESS_KEY_ID")
            config["aws_secret_key"] = os.getenv("AWS_SECRET_ACCESS_KEY")

        elif provider == LLMProvider.GOOGLE:
            config["vertex_project"] = os.getenv("GOOGLE_CLOUD_PROJECT")
            config["vertex_location"] = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")

        # Add common configuration
        config.update({"timeout": 3600, "max_retries": 3, "verify_ssl": True})

        return config

    def validate_provider_config(
        self, provider: LLMProvider, config: Dict[str, Any]
    ) -> Tuple[bool, List[str]]:
        """Validate provider configuration.

        Args:
            provider: LLM provider
            config: Configuration dictionary

        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []

        # Check required fields
        if not config.get("api_base"):
            errors.append("Missing api_base URL")

        if not config.get("model"):
            errors.append("Missing model name")

        # Provider-specific validation
        if provider == LLMProvider.AZURE:
            if not config.get("api_version"):
                errors.append("Azure requires api_version")
            if not config.get("deployment_name") and "/deployments/" not in config.get(
                "api_base", ""
            ):
                errors.append("Azure requires deployment_name or deployment in URL")

        elif provider == LLMProvider.AWS_BEDROCK:
            if not config.get("aws_region"):
                errors.append("AWS Bedrock requires aws_region")
            if not (config.get("aws_access_key") and config.get("aws_secret_key")):
                if not os.getenv("AWS_ACCESS_KEY_ID"):
                    errors.append("AWS Bedrock requires AWS credentials")

        elif provider == LLMProvider.GOOGLE:
            if not config.get("vertex_project"):
                errors.append("Google Vertex AI requires vertex_project")

        # Check for authentication
        auth_required = provider not in [LLMProvider.OLLAMA, LLMProvider.LITELLM]
        if auth_required:
            env_vars = self.ENV_VARS.get(provider, [])
            has_auth = any(os.getenv(var) for var in env_vars)
            if not has_auth and provider != LLMProvider.LITELLM:
                provider_name = provider.value if hasattr(provider, "value") else provider
                errors.append(
                    f"No authentication found for {provider_name}. Set one of: {', '.join(env_vars)}"
                )

        return len(errors) == 0, errors

    def get_litellm_model_name(
        self,
        provider: LLMProvider,
        model_hint: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> str:
        """Get LiteLLM-compatible model name.

        Args:
            provider: LLM provider
            model_hint: Optional model name hint
            base_url: Optional base URL for extraction

        Returns:
            LiteLLM-compatible model name
        """
        if model_hint:
            return self._format_model_name(provider, model_hint)

        if base_url:
            # Try to extract from URL
            model = self._extract_model_from_url(base_url)
            if model:
                return self._format_model_name(provider, model)

        # Return default
        return self._get_default_model(provider, base_url)

    def _format_model_name(self, provider: LLMProvider, model: str) -> str:
        """Format model name for LiteLLM.

        Args:
            provider: LLM provider
            model: Model name

        Returns:
            Formatted model name
        """
        # Remove provider prefix if already present
        prefixes = [
            "openai/",
            "anthropic/",
            "azure/",
            "bedrock/",
            "vertex_ai/",
            "huggingface/",
            "ollama/",
        ]
        for prefix in prefixes:
            if model.startswith(prefix):
                return model

        # Add provider prefix for specific providers
        if provider == LLMProvider.OPENAI:
            if not model.startswith("gpt"):
                return f"openai/{model}"
        elif provider == LLMProvider.ANTHROPIC:
            if not model.startswith("claude"):
                return f"anthropic/{model}"
        elif provider == LLMProvider.AZURE:
            return f"azure/{model}"
        elif provider == LLMProvider.AWS_BEDROCK:
            return f"bedrock/{model}"
        elif provider == LLMProvider.GOOGLE:
            return f"vertex_ai/{model}"
        elif provider == LLMProvider.HUGGINGFACE:
            return f"huggingface/{model}"
        elif provider == LLMProvider.OLLAMA:
            return f"ollama/{model}"

        return model

    def _get_default_model(self, provider: LLMProvider, base_url: Optional[str] = None) -> str:
        """Get default model for provider.

        Args:
            provider: LLM provider
            base_url: Optional base URL

        Returns:
            Default model name
        """
        if base_url:
            model = self._extract_model_from_url(base_url)
            if model:
                return self._format_model_name(provider, model)

        default = self.DEFAULT_MODELS.get(provider, "gpt-3.5-turbo")
        return self._format_model_name(provider, default)

    def _extract_model_from_url(self, url: str) -> Optional[str]:
        """Extract model name from URL.

        Args:
            url: URL to parse

        Returns:
            Extracted model name or None
        """
        try:
            parsed = urlparse(url)
            path_parts = [p for p in parsed.path.split("/") if p]

            # Look for common model indicators
            model_keywords = ["gpt", "claude", "llama", "mistral", "gemini", "palm", "chat"]

            for part in path_parts:
                part_lower = part.lower()
                if any(keyword in part_lower for keyword in model_keywords):
                    return part

            # Check for deployments (Azure pattern)
            if "deployments" in path_parts:
                idx = path_parts.index("deployments")
                if idx + 1 < len(path_parts):
                    return path_parts[idx + 1]

            return None

        except Exception as e:
            logger.debug(f"Could not extract model from URL {url}: {e}")
            return None

    def get_required_env_vars(self, provider: LLMProvider) -> List[str]:
        """Get required environment variables for provider.

        Args:
            provider: LLM provider

        Returns:
            List of required environment variable names
        """
        return self.ENV_VARS.get(provider, [])

    def check_provider_availability(self, provider: LLMProvider) -> bool:
        """Check if provider is available (has required auth).

        Args:
            provider: LLM provider

        Returns:
            True if provider is available
        """
        if provider in [LLMProvider.OLLAMA, LLMProvider.LITELLM]:
            return True

        env_vars = self.ENV_VARS.get(provider, [])
        return any(os.getenv(var) for var in env_vars)
