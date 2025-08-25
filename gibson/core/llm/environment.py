"""
Environment configuration manager for LiteLLM integration in Gibson Framework.

This module provides comprehensive environment variable discovery, validation, and setup
instruction generation for all supported LLM providers. It follows Gibson's configuration
patterns and provides production-ready error handling and user guidance.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from enum import Enum
from typing import Optional

from loguru import logger
from pydantic import BaseModel, Field, computed_field

from gibson.core.llm.types import LLMProvider
from gibson.models.base import GibsonBaseModel, ValidatedModel


class ProviderStatus(str, Enum):
    """Provider configuration status."""

    CONFIGURED = "configured"
    MISSING_REQUIRED = "missing_required"
    PARTIAL = "partial"
    INVALID = "invalid"
    DISABLED = "disabled"


class EnvironmentVariablePattern(BaseModel):
    """Pattern for detecting environment variables."""

    name: str = Field(description="Environment variable name")
    required: bool = Field(description="Whether this variable is required")
    description: str = Field(description="Human-readable description")
    example: Optional[str] = Field(default=None, description="Example value")
    validation_pattern: Optional[str] = Field(default=None, description="Regex validation pattern")
    secret: bool = Field(default=True, description="Whether this is a secret value")


class ProviderEnvironmentConfig(GibsonBaseModel):
    """Environment configuration for a specific LLM provider."""

    provider: LLMProvider = Field(description="LLM provider identifier")
    status: ProviderStatus = Field(description="Configuration status")
    detected_variables: dict[str, str] = Field(
        default_factory=dict,
        description="Environment variables detected for this provider"
    )
    missing_variables: list[str] = Field(
        default_factory=list,
        description="Required environment variables that are missing"
    )
    validation_errors: list[str] = Field(
        default_factory=list,
        description="Validation errors for detected variables"
    )
    setup_instructions: Optional[str] = Field(
        default=None,
        description="Setup instructions for missing configuration"
    )

    @computed_field
    @property
    def is_available(self) -> bool:
        """Check if provider is available for use."""
        return self.status == ProviderStatus.CONFIGURED

    @computed_field
    @property
    def completion_percentage(self) -> float:
        """Calculate configuration completion percentage."""
        total_vars = len(self.detected_variables) + len(self.missing_variables)
        if total_vars == 0:
            return 0.0
        return len(self.detected_variables) / total_vars


class EnvironmentDiscoveryResult(ValidatedModel):
    """Result of environment variable discovery process."""

    total_providers: int = Field(description="Total number of providers checked")
    configured_providers: int = Field(description="Number of fully configured providers")
    partially_configured: int = Field(description="Number of partially configured providers")
    missing_providers: int = Field(description="Number of providers with no configuration")

    provider_configs: dict[LLMProvider, ProviderEnvironmentConfig] = Field(
        default_factory=dict,
        description="Configuration details for each provider"
    )

    recommendations: list[str] = Field(
        default_factory=list,
        description="Setup recommendations for missing providers"
    )

    @computed_field
    @property
    def has_any_provider(self) -> bool:
        """Check if at least one provider is configured."""
        return self.configured_providers > 0

    @computed_field
    @property
    def configuration_score(self) -> float:
        """Calculate overall configuration score (0-1)."""
        if self.total_providers == 0:
            return 0.0
        return self.configured_providers / self.total_providers


class EnvironmentManager:
    """
    Environment configuration manager for LiteLLM providers.

    Discovers, validates, and provides setup instructions for LLM provider
    environment variables. Supports all major providers with comprehensive
    validation and user-friendly error reporting.
    """

    # Provider environment variable patterns
    PROVIDER_PATTERNS: dict[LLMProvider, list[EnvironmentVariablePattern]] = {
        LLMProvider.OPENAI: [
            EnvironmentVariablePattern(
                name="OPENAI_API_KEY",
                required=True,
                description="OpenAI API key",
                example="sk-1234567890abcdef...",
                validation_pattern=r"^sk-[a-zA-Z0-9]{48}$"
            ),
            EnvironmentVariablePattern(
                name="OPENAI_ORG_ID",
                required=False,
                description="OpenAI organization ID",
                example="org-1234567890abcdef",
                validation_pattern=r"^org-[a-zA-Z0-9]+$"
            ),
            EnvironmentVariablePattern(
                name="OPENAI_API_BASE",
                required=False,
                description="Custom OpenAI API base URL",
                example="https://api.openai.com/v1",
                validation_pattern=r"^https?://.*",
                secret=False
            ),
            EnvironmentVariablePattern(
                name="OPENAI_PROJECT",
                required=False,
                description="OpenAI project ID",
                example="proj_1234567890abcdef",
                validation_pattern=r"^proj_[a-zA-Z0-9]+$"
            ),
        ],

        LLMProvider.ANTHROPIC: [
            EnvironmentVariablePattern(
                name="ANTHROPIC_API_KEY",
                required=True,
                description="Anthropic API key",
                example="sk-ant-1234567890abcdef...",
                validation_pattern=r"^sk-ant-[a-zA-Z0-9\-_]{48,}$"
            ),
            EnvironmentVariablePattern(
                name="ANTHROPIC_API_BASE",
                required=False,
                description="Custom Anthropic API base URL",
                example="https://api.anthropic.com",
                validation_pattern=r"^https?://.*",
                secret=False
            ),
        ],

        LLMProvider.AZURE_OPENAI: [
            EnvironmentVariablePattern(
                name="AZURE_API_KEY",
                required=True,
                description="Azure OpenAI API key",
                example="1234567890abcdef1234567890abcdef",
                validation_pattern=r"^[a-f0-9]{32}$"
            ),
            EnvironmentVariablePattern(
                name="AZURE_API_BASE",
                required=True,
                description="Azure OpenAI endpoint",
                example="https://your-resource.openai.azure.com/",
                validation_pattern=r"^https://.*\.openai\.azure\.com/?$",
                secret=False
            ),
            EnvironmentVariablePattern(
                name="AZURE_API_VERSION",
                required=False,
                description="Azure OpenAI API version",
                example="2024-02-01",
                validation_pattern=r"^\d{4}-\d{2}-\d{2}$",
                secret=False
            ),
            EnvironmentVariablePattern(
                name="AZURE_AD_TOKEN",
                required=False,
                description="Azure AD authentication token",
                example="eyJ0eXAiOiJKV1QiLCJhbGci..."
            ),
        ],

        LLMProvider.GOOGLE_AI: [
            EnvironmentVariablePattern(
                name="GOOGLE_API_KEY",
                required=True,
                description="Google AI API key",
                example="AIzaSyDaGmWKa4JsXZ-HjGw-12345678901234",
                validation_pattern=r"^AIza[a-zA-Z0-9\-_]{35,}$"
            ),
        ],

        LLMProvider.VERTEX_AI: [
            EnvironmentVariablePattern(
                name="VERTEX_PROJECT",
                required=True,
                description="Google Cloud project ID",
                example="my-project-12345",
                validation_pattern=r"^[a-z][a-z0-9\-]{4,28}[a-z0-9]$",
                secret=False
            ),
            EnvironmentVariablePattern(
                name="VERTEX_LOCATION",
                required=True,
                description="Vertex AI location/region",
                example="us-central1",
                validation_pattern=r"^[a-z0-9\-]+$",
                secret=False
            ),
            EnvironmentVariablePattern(
                name="GOOGLE_APPLICATION_CREDENTIALS",
                required=False,
                description="Path to Google Cloud service account key file",
                example="/path/to/service-account-key.json",
                secret=False
            ),
        ],

        LLMProvider.BEDROCK: [
            EnvironmentVariablePattern(
                name="AWS_ACCESS_KEY_ID",
                required=True,
                description="AWS access key ID",
                example="AKIAIOSFODNN7EXAMPLE",
                validation_pattern=r"^AKIA[A-Z0-9]{16}$"
            ),
            EnvironmentVariablePattern(
                name="AWS_SECRET_ACCESS_KEY",
                required=True,
                description="AWS secret access key",
                example="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            ),
            EnvironmentVariablePattern(
                name="AWS_REGION",
                required=True,
                description="AWS region",
                example="us-east-1",
                validation_pattern=r"^[a-z0-9\-]+$",
                secret=False
            ),
            EnvironmentVariablePattern(
                name="AWS_SESSION_TOKEN",
                required=False,
                description="AWS session token for temporary credentials",
                example="IQoJb3JpZ2luX2VjEND..."
            ),
        ],

        LLMProvider.COHERE: [
            EnvironmentVariablePattern(
                name="COHERE_API_KEY",
                required=True,
                description="Cohere API key",
                example="1234567890abcdef1234567890abcdef"
            ),
        ],

        LLMProvider.REPLICATE: [
            EnvironmentVariablePattern(
                name="REPLICATE_API_TOKEN",
                required=True,
                description="Replicate API token",
                example="r8_1234567890abcdef...",
                validation_pattern=r"^r8_[a-zA-Z0-9]{40}$"
            ),
        ],

        LLMProvider.HUGGINGFACE: [
            EnvironmentVariablePattern(
                name="HUGGINGFACE_API_KEY",
                required=True,
                description="Hugging Face API token",
                example="hf_1234567890abcdef...",
                validation_pattern=r"^hf_[a-zA-Z0-9]{37}$"
            ),
        ],

        LLMProvider.GROQ: [
            EnvironmentVariablePattern(
                name="GROQ_API_KEY",
                required=True,
                description="Groq API key",
                example="gsk_1234567890abcdef...",
                validation_pattern=r"^gsk_[a-zA-Z0-9]{52}$"
            ),
        ],

        LLMProvider.MISTRAL: [
            EnvironmentVariablePattern(
                name="MISTRAL_API_KEY",
                required=True,
                description="Mistral AI API key",
                example="1234567890abcdef1234567890abcdef"
            ),
        ],

        LLMProvider.TOGETHER_AI: [
            EnvironmentVariablePattern(
                name="TOGETHER_API_KEY",
                required=True,
                description="Together AI API key",
                example="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ),
        ],

        LLMProvider.OLLAMA: [
            EnvironmentVariablePattern(
                name="OLLAMA_BASE_URL",
                required=False,
                description="Ollama base URL",
                example="http://localhost:11434",
                validation_pattern=r"^https?://.*",
                secret=False
            ),
        ],

        LLMProvider.VLLM: [
            EnvironmentVariablePattern(
                name="VLLM_BASE_URL",
                required=True,
                description="vLLM server base URL",
                example="http://localhost:8000/v1",
                validation_pattern=r"^https?://.*",
                secret=False
            ),
        ],
    }

    def __init__(self, environment: Optional[Mapping[str, str]] = None) -> None:
        """
        Initialize environment manager.

        Args:
            environment: Environment variables mapping (defaults to os.environ)
        """
        self.environment = environment or os.environ
        logger.debug(f"Initialized EnvironmentManager with {len(self.environment)} variables")

    async def discover_providers(
        self,
        providers: Optional[list[LLMProvider]] = None
    ) -> EnvironmentDiscoveryResult:
        """
        Discover and validate LLM provider configurations from environment.

        Args:
            providers: Specific providers to check (defaults to all supported)

        Returns:
            Discovery result with provider configurations and recommendations
        """
        if providers is None:
            providers = list(self.PROVIDER_PATTERNS.keys())

        logger.info(f"Discovering environment configuration for {len(providers)} providers")

        provider_configs: dict[LLMProvider, ProviderEnvironmentConfig] = {}
        configured_count = 0
        partial_count = 0
        missing_count = 0
        recommendations: list[str] = []

        for provider in providers:
            config = await self._analyze_provider(provider)
            provider_configs[provider] = config

            if config.status == ProviderStatus.CONFIGURED:
                configured_count += 1
                logger.debug(f"Provider {provider} is fully configured")
            elif config.status == ProviderStatus.PARTIAL:
                partial_count += 1
                logger.debug(f"Provider {provider} is partially configured")
            else:
                missing_count += 1
                logger.debug(f"Provider {provider} is not configured")

            # Add setup recommendations for missing providers
            if config.setup_instructions:
                recommendations.append(config.setup_instructions)

        # Generate overall recommendations
        if configured_count == 0:
            recommendations.insert(0,
                "⚠️  No LLM providers are configured. Set up at least one provider to use Gibson's AI features."
            )
        elif partial_count > 0:
            recommendations.insert(0,
                f"📝 {partial_count} provider(s) have partial configuration. Complete setup for better reliability."
            )

        result = EnvironmentDiscoveryResult(
            total_providers=len(providers),
            configured_providers=configured_count,
            partially_configured=partial_count,
            missing_providers=missing_count,
            provider_configs=provider_configs,
            recommendations=recommendations
        )

        logger.info(
            f"Discovery complete: {configured_count} configured, "
            f"{partial_count} partial, {missing_count} missing"
        )

        return result

    async def _analyze_provider(self, provider: LLMProvider) -> ProviderEnvironmentConfig:
        """Analyze environment configuration for a specific provider."""
        patterns = self.PROVIDER_PATTERNS.get(provider, [])
        if not patterns:
            logger.warning(f"No environment patterns defined for provider {provider}")
            return ProviderEnvironmentConfig(
                provider=provider,
                status=ProviderStatus.DISABLED,
                setup_instructions=f"Provider {provider} is not yet supported for environment discovery"
            )

        detected_vars: dict[str, str] = {}
        missing_vars: list[str] = []
        validation_errors: list[str] = []

        # Check each environment variable pattern
        for pattern in patterns:
            value = self.environment.get(pattern.name)

            if value:
                # Variable is present - validate it
                detected_vars[pattern.name] = self._mask_secret(value, pattern.secret)

                if pattern.validation_pattern:
                    if not re.match(pattern.validation_pattern, value):
                        validation_errors.append(
                            f"{pattern.name} format is invalid (expected pattern: {pattern.validation_pattern})"
                        )
            elif pattern.required:
                # Required variable is missing
                missing_vars.append(pattern.name)

        # Determine status
        status = self._determine_status(patterns, detected_vars, missing_vars, validation_errors)

        # Generate setup instructions if needed
        setup_instructions = None
        if status != ProviderStatus.CONFIGURED:
            setup_instructions = self._generate_setup_instructions(provider, patterns, missing_vars)

        return ProviderEnvironmentConfig(
            provider=provider,
            status=status,
            detected_variables=detected_vars,
            missing_variables=missing_vars,
            validation_errors=validation_errors,
            setup_instructions=setup_instructions
        )

    def _determine_status(
        self,
        patterns: list[EnvironmentVariablePattern],
        detected_vars: dict[str, str],
        missing_vars: list[str],
        validation_errors: list[str]
    ) -> ProviderStatus:
        """Determine provider configuration status."""
        required_patterns = [p for p in patterns if p.required]

        if validation_errors:
            return ProviderStatus.INVALID

        if not missing_vars and required_patterns:
            # All required variables are present
            return ProviderStatus.CONFIGURED

        if missing_vars and len(missing_vars) < len(required_patterns):
            # Some but not all required variables are present
            return ProviderStatus.PARTIAL

        if detected_vars:
            # Only optional variables are present
            return ProviderStatus.PARTIAL

        # No variables detected
        return ProviderStatus.MISSING_REQUIRED

    def _mask_secret(self, value: str, is_secret: bool) -> str:
        """Mask secret values for logging/display."""
        if not is_secret:
            return value

        if len(value) <= 8:
            return "***"

        return f"{value[:4]}***{value[-4:]}"

    def _generate_setup_instructions(
        self,
        provider: LLMProvider,
        patterns: list[EnvironmentVariablePattern],
        missing_vars: list[str]
    ) -> str:
        """Generate setup instructions for missing provider configuration."""
        instructions = [f"\n🔧 Setup instructions for {provider.value}:"]

        if provider == LLMProvider.OPENAI:
            instructions.extend([
                "1. Get your API key from https://platform.openai.com/api-keys",
                "2. Set environment variable:",
                "   export OPENAI_API_KEY='sk-your-key-here'",
                "",
                "Optional organization/project setup:",
                "   export OPENAI_ORG_ID='org-your-org-id'",
                "   export OPENAI_PROJECT='proj-your-project-id'"
            ])

        elif provider == LLMProvider.ANTHROPIC:
            instructions.extend([
                "1. Get your API key from https://console.anthropic.com/",
                "2. Set environment variable:",
                "   export ANTHROPIC_API_KEY='sk-ant-your-key-here'"
            ])

        elif provider == LLMProvider.AZURE_OPENAI:
            instructions.extend([
                "1. Create Azure OpenAI resource in Azure portal",
                "2. Set required environment variables:",
                "   export AZURE_API_KEY='your-32-char-key'",
                "   export AZURE_API_BASE='https://your-resource.openai.azure.com/'",
                "",
                "Optional API version:",
                "   export AZURE_API_VERSION='2024-02-01'"
            ])

        elif provider == LLMProvider.GOOGLE_AI:
            instructions.extend([
                "1. Get API key from https://aistudio.google.com/app/apikey",
                "2. Set environment variable:",
                "   export GOOGLE_API_KEY='AIza-your-key-here'"
            ])

        elif provider == LLMProvider.VERTEX_AI:
            instructions.extend([
                "1. Set up Google Cloud project and enable Vertex AI API",
                "2. Set required environment variables:",
                "   export VERTEX_PROJECT='your-project-id'",
                "   export VERTEX_LOCATION='us-central1'",
                "",
                "3. Authentication (choose one):",
                "   - Service account: export GOOGLE_APPLICATION_CREDENTIALS='/path/to/key.json'",
                "   - Default credentials: gcloud auth application-default login"
            ])

        elif provider == LLMProvider.BEDROCK:
            instructions.extend([
                "1. Configure AWS credentials (choose one):",
                "   - Environment variables:",
                "     export AWS_ACCESS_KEY_ID='AKIA...'",
                "     export AWS_SECRET_ACCESS_KEY='your-secret-key'",
                "     export AWS_REGION='us-east-1'",
                "",
                "   - AWS CLI: aws configure",
                "   - IAM roles (for EC2/ECS)"
            ])

        else:
            # Generic instructions for other providers
            instructions.append("Set the following environment variables:")
            for pattern in patterns:
                if pattern.name in missing_vars:
                    required_text = "Required" if pattern.required else "Optional"
                    instructions.append(f"   export {pattern.name}='...'  # {required_text}: {pattern.description}")
                    if pattern.example:
                        instructions.append(f"     Example: {pattern.example}")

        instructions.extend([
            "",
            "After setting variables, restart your shell or run:",
            "   source ~/.bashrc  # or ~/.zshrc"
        ])

        return "\n".join(instructions)

    async def validate_provider(self, provider: LLMProvider) -> bool:
        """
        Validate that a specific provider is properly configured.

        Args:
            provider: Provider to validate

        Returns:
            True if provider is fully configured and valid
        """
        config = await self._analyze_provider(provider)
        return config.status == ProviderStatus.CONFIGURED

    async def get_configured_providers(self) -> list[LLMProvider]:
        """
        Get list of all properly configured providers.

        Returns:
            List of providers that are fully configured
        """
        result = await self.discover_providers()
        return [
            provider for provider, config in result.provider_configs.items()
            if config.status == ProviderStatus.CONFIGURED
        ]

    async def ensure_minimum_configuration(self) -> bool:
        """
        Ensure at least one provider is configured.

        Returns:
            True if at least one provider is configured

        Raises:
            ValueError: If no providers are configured with helpful instructions
        """
        result = await self.discover_providers()

        if not result.has_any_provider:
            error_message = [
                "❌ No LLM providers are configured.",
                "",
                "Gibson requires at least one LLM provider for AI features.",
                "Quick setup options:",
                "",
                "🔥 Fastest: OpenAI",
                "   export OPENAI_API_KEY='sk-your-key-here'",
                "",
                "🆓 Free tier: Google AI",
                "   export GOOGLE_API_KEY='AIza-your-key-here'",
                "",
                "🏢 Enterprise: Azure OpenAI",
                "   export AZURE_API_KEY='your-key'",
                "   export AZURE_API_BASE='https://your-resource.openai.azure.com/'",
                "",
                "Run 'gibson config llm' for detailed setup instructions."
            ]

            raise ValueError("\n".join(error_message))

        return True

    def get_provider_patterns(self, provider: LLMProvider) -> list[EnvironmentVariablePattern]:
        """
        Get environment variable patterns for a specific provider.

        Args:
            provider: Provider to get patterns for

        Returns:
            List of environment variable patterns
        """
        return self.PROVIDER_PATTERNS.get(provider, [])

    async def generate_environment_file(
        self,
        providers: Optional[list[LLMProvider]] = None,
        include_examples: bool = True
    ) -> str:
        """
        Generate .env file template for LLM providers.

        Args:
            providers: Providers to include (defaults to all)
            include_examples: Whether to include example values

        Returns:
            Environment file content as string
        """
        if providers is None:
            providers = list(self.PROVIDER_PATTERNS.keys())

        lines = [
            "# LLM Provider Environment Variables for Gibson Framework",
            "# Copy this file to .env and fill in your actual values",
            "# Load with: export $(cat .env | xargs)",
            ""
        ]

        for provider in sorted(providers, key=lambda p: p.value):
            patterns = self.PROVIDER_PATTERNS.get(provider, [])
            if not patterns:
                continue

            lines.extend([
                f"# {provider.value.upper()} Configuration",
                f"# Provider: {provider.value}",
                ""
            ])

            for pattern in patterns:
                comment_prefix = "# " if not pattern.required else ""
                description = f"  # {pattern.description}"

                if include_examples and pattern.example:
                    value = pattern.example
                else:
                    value = "your-key-here" if pattern.secret else "your-value-here"

                lines.append(f"{comment_prefix}{pattern.name}={value}{description}")

            lines.append("")

        return "\n".join(lines)


# Export convenience functions
async def discover_llm_providers(
    environment: Optional[Mapping[str, str]] = None
) -> EnvironmentDiscoveryResult:
    """
    Convenience function to discover LLM providers in environment.

    Args:
        environment: Environment variables (defaults to os.environ)

    Returns:
        Discovery result with provider configurations
    """
    manager = EnvironmentManager(environment)
    return await manager.discover_providers()


async def validate_llm_environment() -> bool:
    """
    Convenience function to validate LLM environment configuration.

    Returns:
        True if at least one provider is configured

    Raises:
        ValueError: If no providers are configured
    """
    manager = EnvironmentManager()
    return await manager.ensure_minimum_configuration()


async def get_configured_llm_providers() -> list[LLMProvider]:
    """
    Convenience function to get list of configured providers.

    Returns:
        List of fully configured LLM providers
    """
    manager = EnvironmentManager()
    return await manager.get_configured_providers()

