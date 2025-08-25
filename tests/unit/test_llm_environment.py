"""
Unit tests for LLM environment configuration manager.

Tests environment variable discovery, validation, and setup instruction generation
for all supported LLM providers.
"""

import pytest
from typing import Dict, Optional
from unittest.mock import patch

from gibson.core.llm.environment import (
    EnvironmentManager,
    ProviderEnvironmentConfig,
    ProviderStatus,
    EnvironmentDiscoveryResult,
    discover_llm_providers,
    validate_llm_environment,
    get_configured_llm_providers,
)
from gibson.core.llm.types import LLMProvider


class TestEnvironmentManager:
    """Test cases for EnvironmentManager class."""
    
    @pytest.fixture
    def empty_environment(self) -> Dict[str, str]:
        """Empty environment for testing."""
        return {}
    
    @pytest.fixture
    def openai_environment(self) -> Dict[str, str]:
        """Environment with OpenAI configuration."""
        return {
            "OPENAI_API_KEY": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
            "OPENAI_ORG_ID": "org-123456789012345678",
        }
    
    @pytest.fixture
    def invalid_openai_environment(self) -> Dict[str, str]:
        """Environment with invalid OpenAI configuration."""
        return {
            "OPENAI_API_KEY": "invalid-key-format",
        }
    
    @pytest.fixture
    def multi_provider_environment(self) -> Dict[str, str]:
        """Environment with multiple providers configured."""
        return {
            # OpenAI
            "OPENAI_API_KEY": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
            # Anthropic
            "ANTHROPIC_API_KEY": "sk-ant-1234567890abcdef1234567890abcdef1234567890abcdef",
            # Azure OpenAI
            "AZURE_API_KEY": "1234567890abcdef1234567890abcdef",
            "AZURE_API_BASE": "https://myresource.openai.azure.com/",
            # Google AI
            "GOOGLE_API_KEY": "AIzaSyDaGmWKa4JsXZ-HjGw-1234567890123456",
            # AWS Bedrock
            "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AWS_REGION": "us-east-1",
        }
    
    def test_init_with_custom_environment(self, openai_environment: Dict[str, str]):
        """Test initialization with custom environment."""
        manager = EnvironmentManager(openai_environment)
        assert manager.environment == openai_environment
    
    def test_init_with_default_environment(self):
        """Test initialization with default os.environ."""
        with patch("gibson.core.llm.environment.os.environ", {"TEST": "value"}):
            manager = EnvironmentManager()
            assert "TEST" in manager.environment
    
    @pytest.mark.asyncio
    async def test_discover_providers_empty_environment(self, empty_environment: Dict[str, str]):
        """Test provider discovery with empty environment."""
        manager = EnvironmentManager(empty_environment)
        result = await manager.discover_providers()
        
        assert isinstance(result, EnvironmentDiscoveryResult)
        assert result.configured_providers == 0
        assert result.total_providers > 0
        assert not result.has_any_provider
        assert result.configuration_score == 0.0
        assert len(result.recommendations) > 0
    
    @pytest.mark.asyncio
    async def test_discover_providers_openai_configured(self, openai_environment: Dict[str, str]):
        """Test provider discovery with OpenAI configured."""
        manager = EnvironmentManager(openai_environment)
        result = await manager.discover_providers([LLMProvider.OPENAI])
        
        assert result.configured_providers == 1
        assert result.total_providers == 1
        assert result.has_any_provider
        assert result.configuration_score == 1.0
        
        openai_config = result.provider_configs[LLMProvider.OPENAI]
        assert openai_config.status == ProviderStatus.CONFIGURED
        assert openai_config.is_available
        assert "OPENAI_API_KEY" in openai_config.detected_variables
        assert len(openai_config.missing_variables) == 0
        assert len(openai_config.validation_errors) == 0
    
    @pytest.mark.asyncio
    async def test_discover_providers_invalid_configuration(self, invalid_openai_environment: Dict[str, str]):
        """Test provider discovery with invalid configuration."""
        manager = EnvironmentManager(invalid_openai_environment)
        result = await manager.discover_providers([LLMProvider.OPENAI])
        
        assert result.configured_providers == 0
        
        openai_config = result.provider_configs[LLMProvider.OPENAI]
        assert openai_config.status == ProviderStatus.INVALID
        assert not openai_config.is_available
        assert len(openai_config.validation_errors) > 0
    
    @pytest.mark.asyncio
    async def test_discover_providers_partial_configuration(self):
        """Test provider discovery with partial Azure configuration."""
        partial_env = {
            "AZURE_API_KEY": "1234567890abcdef1234567890abcdef",
            # Missing AZURE_API_BASE
        }
        manager = EnvironmentManager(partial_env)
        result = await manager.discover_providers([LLMProvider.AZURE_OPENAI])
        
        assert result.configured_providers == 0
        assert result.partially_configured == 1
        
        azure_config = result.provider_configs[LLMProvider.AZURE_OPENAI]
        assert azure_config.status == ProviderStatus.PARTIAL
        assert not azure_config.is_available
        assert "AZURE_API_KEY" in azure_config.detected_variables
        assert "AZURE_API_BASE" in azure_config.missing_variables
    
    @pytest.mark.asyncio
    async def test_discover_providers_multi_provider(self, multi_provider_environment: Dict[str, str]):
        """Test provider discovery with multiple providers configured."""
        manager = EnvironmentManager(multi_provider_environment)
        providers = [
            LLMProvider.OPENAI,
            LLMProvider.ANTHROPIC,
            LLMProvider.AZURE_OPENAI,
            LLMProvider.GOOGLE_AI,
            LLMProvider.BEDROCK,
        ]
        result = await manager.discover_providers(providers)
        
        assert result.configured_providers == 5
        assert result.total_providers == 5
        assert result.has_any_provider
        assert result.configuration_score == 1.0
        
        # Check each provider is configured
        for provider in providers:
            config = result.provider_configs[provider]
            assert config.status == ProviderStatus.CONFIGURED
            assert config.is_available
    
    @pytest.mark.asyncio
    async def test_validate_provider_configured(self, openai_environment: Dict[str, str]):
        """Test validation of configured provider."""
        manager = EnvironmentManager(openai_environment)
        is_valid = await manager.validate_provider(LLMProvider.OPENAI)
        assert is_valid
    
    @pytest.mark.asyncio
    async def test_validate_provider_not_configured(self, empty_environment: Dict[str, str]):
        """Test validation of non-configured provider."""
        manager = EnvironmentManager(empty_environment)
        is_valid = await manager.validate_provider(LLMProvider.OPENAI)
        assert not is_valid
    
    @pytest.mark.asyncio
    async def test_get_configured_providers(self, multi_provider_environment: Dict[str, str]):
        """Test getting list of configured providers."""
        manager = EnvironmentManager(multi_provider_environment)
        providers = await manager.get_configured_providers()
        
        assert len(providers) >= 5
        assert LLMProvider.OPENAI in providers
        assert LLMProvider.ANTHROPIC in providers
        assert LLMProvider.AZURE_OPENAI in providers
        assert LLMProvider.GOOGLE_AI in providers
        assert LLMProvider.BEDROCK in providers
    
    @pytest.mark.asyncio
    async def test_ensure_minimum_configuration_success(self, openai_environment: Dict[str, str]):
        """Test minimum configuration validation with valid setup."""
        manager = EnvironmentManager(openai_environment)
        result = await manager.ensure_minimum_configuration()
        assert result is True
    
    @pytest.mark.asyncio
    async def test_ensure_minimum_configuration_failure(self, empty_environment: Dict[str, str]):
        """Test minimum configuration validation with no providers."""
        manager = EnvironmentManager(empty_environment)
        with pytest.raises(ValueError) as exc_info:
            await manager.ensure_minimum_configuration()
        
        error_message = str(exc_info.value)
        assert "No LLM providers are configured" in error_message
        assert "export OPENAI_API_KEY" in error_message
    
    def test_get_provider_patterns(self):
        """Test getting provider patterns."""
        manager = EnvironmentManager({})
        patterns = manager.get_provider_patterns(LLMProvider.OPENAI)
        
        assert len(patterns) > 0
        pattern_names = [p.name for p in patterns]
        assert "OPENAI_API_KEY" in pattern_names
    
    def test_mask_secret_values(self):
        """Test secret value masking."""
        manager = EnvironmentManager({})
        
        # Test secret masking
        secret = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"
        masked = manager._mask_secret(secret, True)
        assert masked == "sk-1***cdef"
        
        # Test non-secret passthrough
        non_secret = "https://api.openai.com/v1"
        unmasked = manager._mask_secret(non_secret, False)
        assert unmasked == non_secret
        
        # Test short value masking
        short_secret = "short"
        masked_short = manager._mask_secret(short_secret, True)
        assert masked_short == "***"
    
    @pytest.mark.asyncio
    async def test_generate_environment_file(self):
        """Test environment file generation."""
        manager = EnvironmentManager({})
        env_file = await manager.generate_environment_file(
            providers=[LLMProvider.OPENAI, LLMProvider.ANTHROPIC],
            include_examples=True
        )
        
        assert "OPENAI_API_KEY" in env_file
        assert "ANTHROPIC_API_KEY" in env_file
        assert "sk-your-key-here" in env_file or "sk-ant-your-key-here" in env_file
        assert "# OPENAI Configuration" in env_file
        assert "# ANTHROPIC Configuration" in env_file
    
    @pytest.mark.asyncio
    async def test_generate_environment_file_no_examples(self):
        """Test environment file generation without examples."""
        manager = EnvironmentManager({})
        env_file = await manager.generate_environment_file(
            providers=[LLMProvider.OPENAI],
            include_examples=False
        )
        
        assert "OPENAI_API_KEY=your-key-here" in env_file
        assert "sk-" not in env_file  # No specific examples
    
    def test_setup_instructions_openai(self):
        """Test setup instructions generation for OpenAI."""
        manager = EnvironmentManager({})
        patterns = manager.get_provider_patterns(LLMProvider.OPENAI)
        instructions = manager._generate_setup_instructions(
            LLMProvider.OPENAI, patterns, ["OPENAI_API_KEY"]
        )
        
        assert "platform.openai.com" in instructions
        assert "export OPENAI_API_KEY" in instructions
        assert "sk-your-key-here" in instructions
    
    def test_setup_instructions_azure(self):
        """Test setup instructions generation for Azure OpenAI."""
        manager = EnvironmentManager({})
        patterns = manager.get_provider_patterns(LLMProvider.AZURE_OPENAI)
        instructions = manager._generate_setup_instructions(
            LLMProvider.AZURE_OPENAI, patterns, ["AZURE_API_KEY", "AZURE_API_BASE"]
        )
        
        assert "Azure OpenAI resource" in instructions
        assert "export AZURE_API_KEY" in instructions
        assert "export AZURE_API_BASE" in instructions
    
    def test_setup_instructions_vertex_ai(self):
        """Test setup instructions generation for Vertex AI."""
        manager = EnvironmentManager({})
        patterns = manager.get_provider_patterns(LLMProvider.VERTEX_AI)
        instructions = manager._generate_setup_instructions(
            LLMProvider.VERTEX_AI, patterns, ["VERTEX_PROJECT", "VERTEX_LOCATION"]
        )
        
        assert "Google Cloud project" in instructions
        assert "export VERTEX_PROJECT" in instructions
        assert "export VERTEX_LOCATION" in instructions
        assert "gcloud auth" in instructions


class TestConvenienceFunctions:
    """Test cases for convenience functions."""
    
    @pytest.mark.asyncio
    async def test_discover_llm_providers_function(self):
        """Test discover_llm_providers convenience function."""
        env = {"OPENAI_API_KEY": "sk-1234567890abcdef1234567890abcdef1234567890abcdef"}
        result = await discover_llm_providers(env)
        
        assert isinstance(result, EnvironmentDiscoveryResult)
        assert result.configured_providers >= 1
    
    @pytest.mark.asyncio
    async def test_validate_llm_environment_success(self):
        """Test validate_llm_environment with configured provider."""
        env = {"OPENAI_API_KEY": "sk-1234567890abcdef1234567890abcdef1234567890abcdef"}
        with patch("gibson.core.llm.environment.os.environ", env):
            result = await validate_llm_environment()
            assert result is True
    
    @pytest.mark.asyncio
    async def test_validate_llm_environment_failure(self):
        """Test validate_llm_environment with no providers."""
        with patch("gibson.core.llm.environment.os.environ", {}):
            with pytest.raises(ValueError):
                await validate_llm_environment()
    
    @pytest.mark.asyncio
    async def test_get_configured_llm_providers_function(self):
        """Test get_configured_llm_providers convenience function."""
        env = {"OPENAI_API_KEY": "sk-1234567890abcdef1234567890abcdef1234567890abcdef"}
        with patch("gibson.core.llm.environment.os.environ", env):
            providers = await get_configured_llm_providers()
            assert LLMProvider.OPENAI in providers


class TestProviderSpecificValidation:
    """Test cases for provider-specific validation patterns."""
    
    @pytest.mark.parametrize("provider,env_vars,should_be_valid", [
        # OpenAI valid
        (LLMProvider.OPENAI, 
         {"OPENAI_API_KEY": "sk-1234567890abcdef1234567890abcdef1234567890abcdef"},
         True),
        
        # OpenAI invalid key format
        (LLMProvider.OPENAI,
         {"OPENAI_API_KEY": "invalid-key"},
         False),
        
        # Anthropic valid
        (LLMProvider.ANTHROPIC,
         {"ANTHROPIC_API_KEY": "sk-ant-1234567890abcdef1234567890abcdef1234567890abcdef"},
         True),
        
        # Azure OpenAI valid
        (LLMProvider.AZURE_OPENAI,
         {"AZURE_API_KEY": "1234567890abcdef1234567890abcdef",
          "AZURE_API_BASE": "https://myresource.openai.azure.com/"},
         True),
        
        # Azure OpenAI missing base
        (LLMProvider.AZURE_OPENAI,
         {"AZURE_API_KEY": "1234567890abcdef1234567890abcdef"},
         False),
        
        # Google AI valid
        (LLMProvider.GOOGLE_AI,
         {"GOOGLE_API_KEY": "AIzaSyDaGmWKa4JsXZ-HjGw-1234567890123456"},
         True),
        
        # Bedrock valid
        (LLMProvider.BEDROCK,
         {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
          "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          "AWS_REGION": "us-east-1"},
         True),
        
        # Vertex AI valid
        (LLMProvider.VERTEX_AI,
         {"VERTEX_PROJECT": "my-project-12345",
          "VERTEX_LOCATION": "us-central1"},
         True),
        
        # Replicate valid
        (LLMProvider.REPLICATE,
         {"REPLICATE_API_TOKEN": "r8_1234567890abcdef1234567890abcdef12345678"},
         True),
        
        # Groq valid
        (LLMProvider.GROQ,
         {"GROQ_API_KEY": "gsk_1234567890abcdef1234567890abcdef1234567890abcdef12"},
         True),
        
        # Hugging Face valid
        (LLMProvider.HUGGINGFACE,
         {"HUGGINGFACE_API_KEY": "hf_1234567890abcdef1234567890abcdef123456"},
         True),
    ])
    @pytest.mark.asyncio
    async def test_provider_validation_patterns(
        self, provider: LLMProvider, env_vars: Dict[str, str], should_be_valid: bool
    ):
        """Test validation patterns for various providers."""
        manager = EnvironmentManager(env_vars)
        result = await manager.validate_provider(provider)
        assert result == should_be_valid


class TestEnvironmentVariablePatterns:
    """Test cases for environment variable pattern definitions."""
    
    def test_all_providers_have_patterns(self):
        """Test that all major providers have defined patterns."""
        major_providers = [
            LLMProvider.OPENAI,
            LLMProvider.ANTHROPIC,
            LLMProvider.AZURE_OPENAI,
            LLMProvider.GOOGLE_AI,
            LLMProvider.VERTEX_AI,
            LLMProvider.BEDROCK,
            LLMProvider.COHERE,
            LLMProvider.REPLICATE,
            LLMProvider.HUGGINGFACE,
            LLMProvider.GROQ,
            LLMProvider.MISTRAL,
        ]
        
        manager = EnvironmentManager({})
        for provider in major_providers:
            patterns = manager.get_provider_patterns(provider)
            assert len(patterns) > 0, f"No patterns defined for {provider}"
            
            # Check that at least one pattern is required
            required_patterns = [p for p in patterns if p.required]
            assert len(required_patterns) > 0, f"No required patterns for {provider}"
    
    def test_pattern_validation_regex(self):
        """Test that validation patterns are valid regex."""
        import re
        
        manager = EnvironmentManager({})
        for provider, patterns in manager.PROVIDER_PATTERNS.items():
            for pattern in patterns:
                if pattern.validation_pattern:
                    try:
                        re.compile(pattern.validation_pattern)
                    except re.error as e:
                        pytest.fail(
                            f"Invalid regex pattern for {provider}.{pattern.name}: "
                            f"{pattern.validation_pattern} - {e}"
                        )
    
    def test_required_patterns_have_descriptions(self):
        """Test that all required patterns have descriptions."""
        manager = EnvironmentManager({})
        for provider, patterns in manager.PROVIDER_PATTERNS.items():
            for pattern in patterns:
                if pattern.required:
                    assert pattern.description, f"Missing description for {provider}.{pattern.name}"
                    assert len(pattern.description) > 5, f"Description too short for {provider}.{pattern.name}"