"""
Unit tests for LiteLLM client factory.
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import httpx

from gibson.core.llm.client_factory import (
    LLMClientFactory,
    create_llm_client_factory,
)
from gibson.core.llm.types import (
    LLMProvider,
    OpenAIConfig,
    AnthropicConfig,
    CompletionRequest,
    CompletionResponse,
    ChatMessage,
    LLMError,
    LLMErrorType,
)


class TestLLMClientFactory:
    """Test LLMClientFactory functionality."""

    @pytest.fixture
    def factory(self):
        """Create LLMClientFactory instance."""
        return LLMClientFactory()

    @pytest.mark.asyncio
    async def test_initialize(self, factory):
        """Test factory initialization."""
        await factory.initialize()

        assert factory._http_client is not None
        assert isinstance(factory._http_client, httpx.AsyncClient)

        await factory.cleanup()

    @pytest.mark.asyncio
    async def test_cleanup(self, factory):
        """Test factory cleanup."""
        await factory.initialize()
        await factory.cleanup()

        # After cleanup, http client should be None
        assert factory._http_client is None

    @pytest.mark.asyncio
    async def test_add_provider(self, factory):
        """Test adding a provider configuration."""
        config = OpenAIConfig(api_key="sk-test123")

        factory.add_provider(config)

        assert LLMProvider.OPENAI in factory._providers
        assert factory._providers[LLMProvider.OPENAI] == config

    @pytest.mark.asyncio
    async def test_get_client_not_configured(self, factory):
        """Test getting client for unconfigured provider."""
        with pytest.raises(ValueError, match="Provider .* not configured"):
            await factory.get_client(LLMProvider.OPENAI)

    @pytest.mark.asyncio
    async def test_get_client_configured(self, factory):
        """Test getting client for configured provider."""
        config = OpenAIConfig(api_key="sk-test123")
        factory.add_provider(config)

        client = await factory.get_client(LLMProvider.OPENAI)

        assert client is not None
        assert client._provider == LLMProvider.OPENAI
        assert client._config == config

    @pytest.mark.asyncio
    async def test_complete_with_mock_litellm(self, factory):
        """Test completion with mocked LiteLLM."""
        config = OpenAIConfig(api_key="sk-test123")
        factory.add_provider(config)

        request = CompletionRequest(
            model="gpt-4", messages=[ChatMessage(role="user", content="Hello")]
        )

        # Mock LiteLLM response
        mock_response = {
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "gpt-4",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hi there!"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
        }

        with patch("litellm.acompletion", new_callable=AsyncMock) as mock_acompletion:
            mock_acompletion.return_value = mock_response

            client = await factory.get_client(LLMProvider.OPENAI)
            response = await client.complete(request)

            assert response.id == "chatcmpl-123"
            assert response.choices[0].message.content == "Hi there!"
            assert response.usage.total_tokens == 30

            # Verify LiteLLM was called correctly
            mock_acompletion.assert_called_once()
            call_args = mock_acompletion.call_args
            assert call_args.kwargs["model"] == "gpt-4"
            assert call_args.kwargs["api_key"] == "sk-test123"

    @pytest.mark.asyncio
    async def test_stream_with_mock_litellm(self, factory):
        """Test streaming with mocked LiteLLM."""
        config = OpenAIConfig(api_key="sk-test123")
        factory.add_provider(config)

        request = CompletionRequest(
            model="gpt-4", messages=[ChatMessage(role="user", content="Hello")], stream=True
        )

        # Mock streaming response
        async def mock_stream():
            chunks = [
                {
                    "id": "chatcmpl-123",
                    "object": "chat.completion.chunk",
                    "created": 1234567890,
                    "model": "gpt-4",
                    "choices": [{"index": 0, "delta": {"content": "Hi"}, "finish_reason": None}],
                },
                {
                    "id": "chatcmpl-123",
                    "object": "chat.completion.chunk",
                    "created": 1234567890,
                    "model": "gpt-4",
                    "choices": [
                        {"index": 0, "delta": {"content": " there!"}, "finish_reason": "stop"}
                    ],
                },
            ]
            for chunk in chunks:
                yield chunk

        with patch("litellm.acompletion", new_callable=AsyncMock) as mock_acompletion:
            mock_acompletion.return_value = mock_stream()

            client = await factory.get_client(LLMProvider.OPENAI)

            chunks = []
            async for chunk in client.stream(request):
                chunks.append(chunk)

            assert len(chunks) == 2
            assert chunks[0].choices[0].delta.get("content") == "Hi"
            assert chunks[1].choices[0].delta.get("content") == " there!"

    @pytest.mark.asyncio
    async def test_check_health_healthy(self, factory):
        """Test health check for healthy provider."""
        config = OpenAIConfig(api_key="sk-test123")
        factory.add_provider(config)

        with patch("litellm.acompletion", new_callable=AsyncMock) as mock_acompletion:
            mock_acompletion.return_value = {
                "id": "test",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "gpt-3.5-turbo",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "test"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            }

            is_healthy = await factory.check_health(LLMProvider.OPENAI)
            assert is_healthy is True

    @pytest.mark.asyncio
    async def test_check_health_unhealthy(self, factory):
        """Test health check for unhealthy provider."""
        config = OpenAIConfig(api_key="invalid-key")
        factory.add_provider(config)

        with patch("litellm.acompletion", new_callable=AsyncMock) as mock_acompletion:
            mock_acompletion.side_effect = Exception("Authentication failed")

            is_healthy = await factory.check_health(LLMProvider.OPENAI)
            assert is_healthy is False

    @pytest.mark.asyncio
    async def test_check_health_unconfigured(self, factory):
        """Test health check for unconfigured provider."""
        is_healthy = await factory.check_health(LLMProvider.OPENAI)
        assert is_healthy is False

    @pytest.mark.asyncio
    async def test_get_available_providers(self, factory):
        """Test getting list of available providers."""
        config1 = OpenAIConfig(api_key="sk-test1")
        config2 = AnthropicConfig(api_key="sk-ant-test2")

        factory.add_provider(config1)
        factory.add_provider(config2)

        providers = factory.get_available_providers()

        assert LLMProvider.OPENAI in providers
        assert LLMProvider.ANTHROPIC in providers
        assert len(providers) == 2

    @pytest.mark.asyncio
    async def test_error_handling_authentication(self, factory):
        """Test authentication error handling."""
        config = OpenAIConfig(api_key="invalid-key")
        factory.add_provider(config)

        request = CompletionRequest(
            model="gpt-4", messages=[ChatMessage(role="user", content="Test")]
        )

        with patch("litellm.acompletion", new_callable=AsyncMock) as mock_acompletion:
            mock_acompletion.side_effect = Exception("Invalid API key")

            client = await factory.get_client(LLMProvider.OPENAI)

            with pytest.raises(LLMError) as exc_info:
                await client.complete(request)

            assert exc_info.value.type == LLMErrorType.AUTHENTICATION

    @pytest.mark.asyncio
    async def test_error_handling_rate_limit(self, factory):
        """Test rate limit error handling."""
        config = OpenAIConfig(api_key="sk-test123")
        factory.add_provider(config)

        request = CompletionRequest(
            model="gpt-4", messages=[ChatMessage(role="user", content="Test")]
        )

        with patch("litellm.acompletion", new_callable=AsyncMock) as mock_acompletion:
            mock_acompletion.side_effect = Exception("Rate limit exceeded")

            client = await factory.get_client(LLMProvider.OPENAI)

            with pytest.raises(LLMError) as exc_info:
                await client.complete(request)

            assert exc_info.value.type == LLMErrorType.RATE_LIMIT


class TestCreateLLMClientFactory:
    """Test factory creation helper."""

    @pytest.mark.asyncio
    async def test_create_factory_with_env_vars(self):
        """Test creating factory from environment variables."""
        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test123"}):
            factory = await create_llm_client_factory()

            providers = factory.get_available_providers()
            assert LLMProvider.OPENAI in providers

            await factory.cleanup()

    @pytest.mark.asyncio
    async def test_create_factory_with_configs(self):
        """Test creating factory with explicit configs."""
        configs = [OpenAIConfig(api_key="sk-test1"), AnthropicConfig(api_key="sk-ant-test2")]

        factory = await create_llm_client_factory(provider_configs=configs)

        providers = factory.get_available_providers()
        assert LLMProvider.OPENAI in providers
        assert LLMProvider.ANTHROPIC in providers

        await factory.cleanup()

    @pytest.mark.asyncio
    async def test_create_factory_auto_initialize(self):
        """Test factory auto-initialization."""
        factory = await create_llm_client_factory(auto_initialize=True)

        # HTTP client should be initialized
        assert factory._http_client is not None

        await factory.cleanup()
