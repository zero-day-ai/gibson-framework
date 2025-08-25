"""
Unit tests for LiteLLM type definitions.
"""

import pytest
from typing import Dict, Any

from gibson.core.llm.types import (
    LLMProvider,
    ModelType,
    TokenType,
    ResponseFormat,
    FinishReason,
    LLMErrorType,
    ChatMessage,
    CompletionRequest,
    TokenUsage,
    CompletionChoice,
    CompletionResponse,
    LLMError,
    BaseProviderConfig,
    OpenAIConfig,
    AnthropicConfig,
    AzureOpenAIConfig,
)


class TestEnums:
    """Test enum definitions."""

    def test_llm_provider_enum(self):
        """Test LLMProvider enum values."""
        assert LLMProvider.OPENAI.value == "openai"
        assert LLMProvider.ANTHROPIC.value == "anthropic"
        assert LLMProvider.AZURE_OPENAI.value == "azure"

        # Test all providers are unique
        providers = list(LLMProvider)
        assert len(providers) == len(set(providers))

    def test_model_type_enum(self):
        """Test ModelType enum values."""
        assert ModelType.CHAT.value == "chat"
        assert ModelType.COMPLETION.value == "completion"
        assert ModelType.EMBEDDING.value == "embedding"

    def test_response_format_enum(self):
        """Test ResponseFormat enum values."""
        assert ResponseFormat.TEXT.value == "text"
        assert ResponseFormat.JSON.value == "json"
        assert ResponseFormat.JSON_OBJECT.value == "json_object"

    def test_finish_reason_enum(self):
        """Test FinishReason enum values."""
        assert FinishReason.STOP.value == "stop"
        assert FinishReason.LENGTH.value == "length"
        assert FinishReason.CONTENT_FILTER.value == "content_filter"
        assert FinishReason.TOOL_CALLS.value == "tool_calls"

    def test_error_type_enum(self):
        """Test LLMErrorType enum values."""
        assert LLMErrorType.AUTHENTICATION.value == "authentication"
        assert LLMErrorType.RATE_LIMIT.value == "rate_limit"
        assert LLMErrorType.INVALID_REQUEST.value == "invalid_request"
        assert LLMErrorType.PROVIDER_ERROR.value == "provider_error"


class TestModels:
    """Test Pydantic models."""

    def test_chat_message_creation(self):
        """Test ChatMessage model creation."""
        message = ChatMessage(role="user", content="Hello, world!")
        assert message.role == "user"
        assert message.content == "Hello, world!"
        assert message.name is None

    def test_chat_message_with_name(self):
        """Test ChatMessage with optional name."""
        message = ChatMessage(role="assistant", content="Hi there!", name="Assistant")
        assert message.name == "Assistant"

    def test_completion_request_minimal(self):
        """Test minimal CompletionRequest."""
        request = CompletionRequest(
            model="gpt-4", messages=[ChatMessage(role="user", content="Test")]
        )
        assert request.model == "gpt-4"
        assert len(request.messages) == 1
        assert request.temperature is None
        assert request.max_tokens is None

    def test_completion_request_full(self):
        """Test CompletionRequest with all parameters."""
        request = CompletionRequest(
            model="gpt-4",
            messages=[
                ChatMessage(role="system", content="You are helpful"),
                ChatMessage(role="user", content="Hello"),
            ],
            temperature=0.7,
            max_tokens=100,
            top_p=0.9,
            frequency_penalty=0.5,
            presence_penalty=0.5,
            stop=["END"],
            stream=False,
            response_format=ResponseFormat.JSON,
            seed=42,
            tools=[{"type": "function", "function": {"name": "test"}}],
            tool_choice="auto",
            user="user123",
        )
        assert request.model == "gpt-4"
        assert len(request.messages) == 2
        assert request.temperature == 0.7
        assert request.max_tokens == 100
        assert request.seed == 42

    def test_token_usage(self):
        """Test TokenUsage model."""
        usage = TokenUsage(prompt_tokens=10, completion_tokens=20, total_tokens=30)
        assert usage.prompt_tokens == 10
        assert usage.completion_tokens == 20
        assert usage.total_tokens == 30

    def test_completion_choice(self):
        """Test CompletionChoice model."""
        choice = CompletionChoice(
            index=0,
            message=ChatMessage(role="assistant", content="Response"),
            finish_reason=FinishReason.STOP,
        )
        assert choice.index == 0
        assert choice.message.content == "Response"
        assert choice.finish_reason == FinishReason.STOP

    def test_completion_response(self):
        """Test CompletionResponse model."""
        response = CompletionResponse(
            id="test-123",
            object="chat.completion",
            created=1234567890,
            model="gpt-4",
            choices=[
                CompletionChoice(
                    index=0,
                    message=ChatMessage(role="assistant", content="Hi"),
                    finish_reason=FinishReason.STOP,
                )
            ],
            usage=TokenUsage(prompt_tokens=5, completion_tokens=10, total_tokens=15),
        )
        assert response.id == "test-123"
        assert response.model == "gpt-4"
        assert len(response.choices) == 1
        assert response.usage.total_tokens == 15


class TestProviderConfigs:
    """Test provider configuration models."""

    def test_base_provider_config(self):
        """Test BaseProviderConfig."""
        config = BaseProviderConfig(
            provider=LLMProvider.OPENAI,
            api_key="test-key",
            base_url="https://api.example.com",
            timeout=30,
            max_retries=3,
        )
        assert config.provider == LLMProvider.OPENAI
        assert config.api_key == "test-key"
        assert config.timeout == 30

    def test_openai_config(self):
        """Test OpenAIConfig."""
        config = OpenAIConfig(api_key="sk-test", organization="org-123", api_version="2024-01")
        assert config.provider == LLMProvider.OPENAI
        assert config.api_key == "sk-test"
        assert config.organization == "org-123"
        assert config.api_version == "2024-01"

    def test_anthropic_config(self):
        """Test AnthropicConfig."""
        config = AnthropicConfig(api_key="claude-key", api_version="2024-01")
        assert config.provider == LLMProvider.ANTHROPIC
        assert config.api_key == "claude-key"
        assert config.api_version == "2024-01"

    def test_azure_openai_config(self):
        """Test AzureOpenAIConfig."""
        config = AzureOpenAIConfig(
            api_key="azure-key",
            api_base="https://test.openai.azure.com",
            api_version="2024-01-preview",
            deployment_name="gpt-4",
        )
        assert config.provider == LLMProvider.AZURE_OPENAI
        assert config.api_key == "azure-key"
        assert config.api_base == "https://test.openai.azure.com"
        assert config.deployment_name == "gpt-4"


class TestLLMError:
    """Test LLMError exception."""

    def test_llm_error_creation(self):
        """Test LLMError creation."""
        error = LLMError(
            type=LLMErrorType.RATE_LIMIT,
            message="Rate limit exceeded",
            provider=LLMProvider.OPENAI,
            status_code=429,
        )
        assert error.type == LLMErrorType.RATE_LIMIT
        assert error.message == "Rate limit exceeded"
        assert error.provider == LLMProvider.OPENAI
        assert error.status_code == 429

    def test_llm_error_string(self):
        """Test LLMError string representation."""
        error = LLMError(type=LLMErrorType.AUTHENTICATION, message="Invalid API key")
        error_str = str(error)
        assert "authentication" in error_str.lower()
        assert "Invalid API key" in error_str

    def test_llm_error_with_details(self):
        """Test LLMError with details."""
        details = {"retry_after": 60, "limit": 100}
        error = LLMError(type=LLMErrorType.RATE_LIMIT, message="Too many requests", details=details)
        assert error.details == details
        assert error.details["retry_after"] == 60


class TestTypeValidation:
    """Test type validation and constraints."""

    def test_chat_message_role_validation(self):
        """Test ChatMessage role validation."""
        valid_roles = ["system", "user", "assistant", "tool", "function"]
        for role in valid_roles:
            message = ChatMessage(role=role, content="Test")
            assert message.role == role

    def test_completion_request_temperature_bounds(self):
        """Test temperature bounds in CompletionRequest."""
        # Valid temperatures
        request = CompletionRequest(
            model="gpt-4", messages=[ChatMessage(role="user", content="Test")], temperature=0.0
        )
        assert request.temperature == 0.0

        request = CompletionRequest(
            model="gpt-4", messages=[ChatMessage(role="user", content="Test")], temperature=2.0
        )
        assert request.temperature == 2.0

    def test_completion_request_top_p_bounds(self):
        """Test top_p bounds in CompletionRequest."""
        request = CompletionRequest(
            model="gpt-4", messages=[ChatMessage(role="user", content="Test")], top_p=0.1
        )
        assert request.top_p == 0.1

        request = CompletionRequest(
            model="gpt-4", messages=[ChatMessage(role="user", content="Test")], top_p=1.0
        )
        assert request.top_p == 1.0

    def test_token_usage_non_negative(self):
        """Test TokenUsage values are non-negative."""
        usage = TokenUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0)
        assert usage.prompt_tokens >= 0
        assert usage.completion_tokens >= 0
        assert usage.total_tokens >= 0


class TestTypeAliases:
    """Test type aliases and unions."""

    def test_provider_config_union(self):
        """Test ProviderConfig union type."""
        from gibson.core.llm.types import ProviderConfig

        # All these should be valid ProviderConfig types
        configs = [
            OpenAIConfig(api_key="test"),
            AnthropicConfig(api_key="test"),
            AzureOpenAIConfig(
                api_key="test", api_base="https://test.openai.azure.com", deployment_name="gpt-4"
            ),
        ]

        for config in configs:
            assert hasattr(config, "provider")
            assert hasattr(config, "api_key")

    def test_llm_response_union(self):
        """Test LLMResponse union type."""
        from gibson.core.llm.types import LLMResponse, StreamResponse

        # CompletionResponse should be valid LLMResponse
        completion = CompletionResponse(
            id="test",
            object="chat.completion",
            created=1234567890,
            model="gpt-4",
            choices=[],
        )

        # StreamResponse should be valid LLMResponse
        stream = StreamResponse(
            id="test", object="chat.completion.chunk", created=1234567890, model="gpt-4", choices=[]
        )

        # Both should have common attributes
        for response in [completion, stream]:
            assert hasattr(response, "id")
            assert hasattr(response, "model")
            assert hasattr(response, "choices")
