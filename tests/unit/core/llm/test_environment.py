"""
Unit tests for LiteLLM environment discovery.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from gibson.core.llm.environment import (
    EnvironmentManager,
    EnvironmentDiscoveryResult,
)
from gibson.core.llm.types import LLMProvider


class TestEnvironmentManager:
    """Test EnvironmentManager functionality."""

    @pytest.fixture
    def env_manager(self):
        """Create EnvironmentManager instance."""
        return EnvironmentManager()

    def test_discover_no_providers(self, env_manager):
        """Test discovery with no environment variables set."""
        with patch.dict(os.environ, {}, clear=True):
            result = env_manager.discover_providers()

            assert isinstance(result, EnvironmentDiscoveryResult)
            assert len(result.available_providers) == 0
            assert len(result.missing_providers) > 0
            assert result.total_providers == 0

    def test_discover_openai(self, env_manager):
        """Test OpenAI provider discovery."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test123"}):
            result = env_manager.discover_providers()

            assert LLMProvider.OPENAI in result.available_providers
            assert result.provider_configs[LLMProvider.OPENAI]["api_key"] == "sk-test123"
            assert result.total_providers >= 1

    def test_discover_anthropic(self, env_manager):
        """Test Anthropic provider discovery."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test123"}):
            result = env_manager.discover_providers()

            assert LLMProvider.ANTHROPIC in result.available_providers
            assert result.provider_configs[LLMProvider.ANTHROPIC]["api_key"] == "sk-ant-test123"

    def test_discover_azure_openai(self, env_manager):
        """Test Azure OpenAI provider discovery."""
        env_vars = {
            "AZURE_OPENAI_API_KEY": "azure-key",
            "AZURE_OPENAI_ENDPOINT": "https://test.openai.azure.com",
            "AZURE_OPENAI_DEPLOYMENT": "gpt-4",
            "AZURE_OPENAI_API_VERSION": "2024-01-preview",
        }

        with patch.dict(os.environ, env_vars):
            result = env_manager.discover_providers()

            assert LLMProvider.AZURE_OPENAI in result.available_providers
            config = result.provider_configs[LLMProvider.AZURE_OPENAI]
            assert config["api_key"] == "azure-key"
            assert config["api_base"] == "https://test.openai.azure.com"
            assert config["deployment_name"] == "gpt-4"

    def test_discover_multiple_providers(self, env_manager):
        """Test discovery of multiple providers."""
        env_vars = {
            "OPENAI_API_KEY": "sk-openai",
            "ANTHROPIC_API_KEY": "sk-anthropic",
            "COHERE_API_KEY": "co-test",
        }

        with patch.dict(os.environ, env_vars):
            result = env_manager.discover_providers()

            assert LLMProvider.OPENAI in result.available_providers
            assert LLMProvider.ANTHROPIC in result.available_providers
            assert LLMProvider.COHERE in result.available_providers
            assert result.total_providers >= 3

    def test_validate_api_key_openai(self, env_manager):
        """Test OpenAI API key validation."""
        assert env_manager.validate_api_key(LLMProvider.OPENAI, "sk-proj-abcd1234") is True

        assert env_manager.validate_api_key(LLMProvider.OPENAI, "invalid-key") is False

    def test_validate_api_key_anthropic(self, env_manager):
        """Test Anthropic API key validation."""
        assert env_manager.validate_api_key(LLMProvider.ANTHROPIC, "sk-ant-api03-valid123") is True

        assert env_manager.validate_api_key(LLMProvider.ANTHROPIC, "not-anthropic-key") is False

    def test_get_provider_config_exists(self, env_manager):
        """Test getting config for available provider."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            config = env_manager.get_provider_config(LLMProvider.OPENAI)

            assert config is not None
            assert config["api_key"] == "sk-test"

    def test_get_provider_config_not_exists(self, env_manager):
        """Test getting config for unavailable provider."""
        with patch.dict(os.environ, {}, clear=True):
            config = env_manager.get_provider_config(LLMProvider.OPENAI)

            assert config is None

    def test_is_provider_available(self, env_manager):
        """Test checking provider availability."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            assert env_manager.is_provider_available(LLMProvider.OPENAI) is True
            assert env_manager.is_provider_available(LLMProvider.ANTHROPIC) is False

    def test_get_setup_instructions_openai(self, env_manager):
        """Test getting setup instructions for OpenAI."""
        instructions = env_manager.get_setup_instructions(LLMProvider.OPENAI)

        assert "OPENAI_API_KEY" in instructions
        assert "export" in instructions
        assert "https://platform.openai.com" in instructions

    def test_get_setup_instructions_anthropic(self, env_manager):
        """Test getting setup instructions for Anthropic."""
        instructions = env_manager.get_setup_instructions(LLMProvider.ANTHROPIC)

        assert "ANTHROPIC_API_KEY" in instructions
        assert "export" in instructions
        assert "https://console.anthropic.com" in instructions

    def test_get_all_setup_instructions(self, env_manager):
        """Test getting all setup instructions."""
        with patch.dict(os.environ, {}, clear=True):
            result = env_manager.discover_providers()
            instructions = env_manager.get_all_setup_instructions(result.missing_providers)

            assert len(instructions) > 0
            assert "Configuration Instructions" in instructions

    def test_discover_google_vertex(self, env_manager):
        """Test Google Vertex AI discovery."""
        env_vars = {
            "GOOGLE_APPLICATION_CREDENTIALS": "/path/to/creds.json",
            "VERTEX_PROJECT": "my-project",
            "VERTEX_LOCATION": "us-central1",
        }

        with patch.dict(os.environ, env_vars):
            result = env_manager.discover_providers()

            assert LLMProvider.VERTEX_AI in result.available_providers
            config = result.provider_configs[LLMProvider.VERTEX_AI]
            assert config["project"] == "my-project"
            assert config["location"] == "us-central1"

    def test_discover_aws_bedrock(self, env_manager):
        """Test AWS Bedrock discovery."""
        env_vars = {
            "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AWS_REGION": "us-east-1",
        }

        with patch.dict(os.environ, env_vars):
            result = env_manager.discover_providers()

            assert LLMProvider.BEDROCK in result.available_providers
            config = result.provider_configs[LLMProvider.BEDROCK]
            assert config["region_name"] == "us-east-1"

    def test_environment_discovery_result_summary(self, env_manager):
        """Test EnvironmentDiscoveryResult summary generation."""
        with patch.dict(
            os.environ, {"OPENAI_API_KEY": "sk-test", "ANTHROPIC_API_KEY": "sk-ant-test"}
        ):
            result = env_manager.discover_providers()
            summary = result.get_summary()

            assert "Available Providers (2)" in summary
            assert "OpenAI" in summary
            assert "Anthropic" in summary

    def test_provider_priority_ordering(self, env_manager):
        """Test that providers are discovered in priority order."""
        env_vars = {
            "OPENAI_API_KEY": "sk-openai",
            "ANTHROPIC_API_KEY": "sk-anthropic",
            "COHERE_API_KEY": "co-test",
        }

        with patch.dict(os.environ, env_vars):
            result = env_manager.discover_providers()

            # OpenAI should come before Cohere in available providers
            providers_list = list(result.available_providers)
            openai_index = providers_list.index(LLMProvider.OPENAI)
            cohere_index = providers_list.index(LLMProvider.COHERE)

            assert openai_index < cohere_index


class TestEnvironmentDiscoveryResult:
    """Test EnvironmentDiscoveryResult functionality."""

    def test_empty_result(self):
        """Test empty discovery result."""
        result = EnvironmentDiscoveryResult()

        assert len(result.available_providers) == 0
        assert len(result.missing_providers) == 0
        assert len(result.provider_configs) == 0
        assert result.total_providers == 0

    def test_result_with_providers(self):
        """Test discovery result with providers."""
        result = EnvironmentDiscoveryResult()
        result.available_providers.add(LLMProvider.OPENAI)
        result.available_providers.add(LLMProvider.ANTHROPIC)
        result.provider_configs[LLMProvider.OPENAI] = {"api_key": "test"}
        result.provider_configs[LLMProvider.ANTHROPIC] = {"api_key": "test2"}
        result.total_providers = 2

        assert result.total_providers == 2
        assert LLMProvider.OPENAI in result.available_providers
        assert LLMProvider.ANTHROPIC in result.available_providers

    def test_result_summary_formatting(self):
        """Test result summary formatting."""
        result = EnvironmentDiscoveryResult()
        result.available_providers.add(LLMProvider.OPENAI)
        result.missing_providers.add(LLMProvider.ANTHROPIC)
        result.total_providers = 1

        summary = result.get_summary()

        assert "Available Providers (1)" in summary
        assert "Missing Providers" in summary
        assert "OpenAI" in summary
        assert "Anthropic" in summary
