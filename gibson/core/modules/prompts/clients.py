"""
Client Factory and Model Clients for System Prompt Leakage Module.

Provides abstraction layer for communicating with different AI model providers
and services during system prompt leakage testing.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

try:
    import httpx
except ImportError:
    httpx = None

from .types import (
    AttackContext,
    SystemPromptLeakageConfig,
    ClientError,
    UnsupportedTargetError,
)


logger = logging.getLogger(__name__)


class BaseModelClient(ABC):
    """Base client for interacting with AI models."""

    def __init__(self, target: Any, config: SystemPromptLeakageConfig):
        """
        Initialize base client.

        Args:
            target: Target model configuration
            config: Module configuration
        """
        self.target = target
        self.config = config
        self.provider = self._get_provider()

        # Request configuration
        self.timeout = config.timeout
        self.max_retries = config.retry_attempts

        # Rate limiting
        self.last_request_time = None
        self.request_count = 0

        # Statistics
        self.stats = {
            "requests_sent": 0,
            "requests_failed": 0,
            "avg_response_time": 0.0,
            "total_response_time": 0.0,
        }

    @abstractmethod
    def _get_provider(self) -> str:
        """Get provider name for this client."""
        pass

    @abstractmethod
    async def send_message(self, message: str, context: AttackContext) -> str:
        """
        Send message to model and return response.

        Args:
            message: Message to send to the model
            context: Attack context for additional information

        Returns:
            Model response text
        """
        pass

    @abstractmethod
    async def validate_connection(self) -> bool:
        """
        Validate connection to model.

        Returns:
            True if connection is valid
        """
        pass

    async def _rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        if self.last_request_time:
            time_since_last = (datetime.utcnow() - self.last_request_time).total_seconds()
            min_interval = 60.0 / self.config.rate_limiting.requests_per_minute

            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                await asyncio.sleep(sleep_time)

        self.last_request_time = datetime.utcnow()
        self.request_count += 1

    def _update_stats(self, response_time: float, success: bool) -> None:
        """Update client statistics."""
        self.stats["requests_sent"] += 1
        if not success:
            self.stats["requests_failed"] += 1

        self.stats["total_response_time"] += response_time
        self.stats["avg_response_time"] = (
            self.stats["total_response_time"] / self.stats["requests_sent"]
        )

    async def cleanup(self) -> None:
        """Cleanup client resources."""
        pass


class OpenAIClient(BaseModelClient):
    """Client for OpenAI GPT models."""

    def _get_provider(self) -> str:
        return "openai"

    def __init__(self, target: Any, config: SystemPromptLeakageConfig):
        super().__init__(target, config)

        # Extract OpenAI-specific configuration
        self.api_key = self._get_api_key()
        self.model = getattr(target, "model", "gpt-3.5-turbo")
        self.base_url = getattr(target, "base_url", "https://api.openai.com/v1")

        # OpenAI client (lazy initialization)
        self._client = None

    def _get_api_key(self) -> str:
        """Get OpenAI API key from target or environment."""
        # Try to get from target credentials
        if hasattr(self.target, "credentials") and self.target.credentials:
            api_key = self.target.credentials.get("api_key")
            if api_key:
                return api_key

        # Try environment variable
        import os

        api_key = os.getenv("OPENAI_API_KEY")
        if api_key:
            return api_key

        raise ClientError("OpenAI API key not found in target credentials or environment")

    async def _get_client(self):
        """Get or create OpenAI client."""
        if self._client is None:
            try:
                import openai

                self._client = openai.AsyncOpenAI(
                    api_key=self.api_key, base_url=self.base_url, timeout=self.timeout
                )
            except ImportError:
                raise ClientError("OpenAI library not installed. Install with: pip install openai")

        return self._client

    async def send_message(self, message: str, context: AttackContext) -> str:
        """Send message to OpenAI model."""
        start_time = datetime.utcnow()

        try:
            await self._rate_limit()

            client = await self._get_client()

            # Prepare chat completion request
            messages = [{"role": "user", "content": message}]

            # Add conversation history if available
            if context.conversation_history:
                formatted_history = []
                for i, msg in enumerate(context.conversation_history):
                    role = "user" if i % 2 == 0 else "assistant"
                    formatted_history.append({"role": role, "content": msg})
                messages = formatted_history + messages

            # Send request
            response = await client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=getattr(self.target, "max_tokens", 1000),
                temperature=getattr(self.target, "temperature", 0.7),
            )

            response_time = (datetime.utcnow() - start_time).total_seconds()
            self._update_stats(response_time, True)

            return response.choices[0].message.content

        except Exception as e:
            response_time = (datetime.utcnow() - start_time).total_seconds()
            self._update_stats(response_time, False)

            logger.error(f"OpenAI request failed: {e}")
            raise ClientError(f"OpenAI request failed: {e}")

    async def validate_connection(self) -> bool:
        """Validate OpenAI connection."""
        try:
            client = await self._get_client()

            # Send minimal test request
            response = await client.chat.completions.create(
                model=self.model, messages=[{"role": "user", "content": "Hello"}], max_tokens=5
            )

            return bool(response.choices[0].message.content)

        except Exception as e:
            logger.error(f"OpenAI connection validation failed: {e}")
            return False


class AnthropicClient(BaseModelClient):
    """Client for Anthropic Claude models."""

    def _get_provider(self) -> str:
        return "anthropic"

    def __init__(self, target: Any, config: SystemPromptLeakageConfig):
        super().__init__(target, config)

        self.api_key = self._get_api_key()
        self.model = getattr(target, "model", "claude-3-sonnet-20240229")
        self.base_url = getattr(target, "base_url", "https://api.anthropic.com")

        self._client = None

    def _get_api_key(self) -> str:
        """Get Anthropic API key."""
        if hasattr(self.target, "credentials") and self.target.credentials:
            api_key = self.target.credentials.get("api_key")
            if api_key:
                return api_key

        import os

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if api_key:
            return api_key

        raise ClientError("Anthropic API key not found")

    async def _get_client(self):
        """Get or create Anthropic client."""
        if self._client is None:
            try:
                import anthropic

                self._client = anthropic.AsyncAnthropic(
                    api_key=self.api_key, base_url=self.base_url, timeout=self.timeout
                )
            except ImportError:
                raise ClientError(
                    "Anthropic library not installed. Install with: pip install anthropic"
                )

        return self._client

    async def send_message(self, message: str, context: AttackContext) -> str:
        """Send message to Anthropic model."""
        start_time = datetime.utcnow()

        try:
            await self._rate_limit()

            client = await self._get_client()

            # Prepare messages
            messages = [{"role": "user", "content": message}]

            # Add conversation history
            if context.conversation_history:
                formatted_history = []
                for i, msg in enumerate(context.conversation_history):
                    role = "user" if i % 2 == 0 else "assistant"
                    formatted_history.append({"role": role, "content": msg})
                messages = formatted_history + messages

            # Send request
            response = await client.messages.create(
                model=self.model,
                messages=messages,
                max_tokens=getattr(self.target, "max_tokens", 1000),
                temperature=getattr(self.target, "temperature", 0.7),
            )

            response_time = (datetime.utcnow() - start_time).total_seconds()
            self._update_stats(response_time, True)

            return response.content[0].text

        except Exception as e:
            response_time = (datetime.utcnow() - start_time).total_seconds()
            self._update_stats(response_time, False)

            logger.error(f"Anthropic request failed: {e}")
            raise ClientError(f"Anthropic request failed: {e}")

    async def validate_connection(self) -> bool:
        """Validate Anthropic connection."""
        try:
            client = await self._get_client()

            response = await client.messages.create(
                model=self.model, messages=[{"role": "user", "content": "Hello"}], max_tokens=5
            )

            return bool(response.content[0].text)

        except Exception as e:
            logger.error(f"Anthropic connection validation failed: {e}")
            return False


class GoogleClient(BaseModelClient):
    """Client for Google AI models (PaLM, Gemini)."""

    def _get_provider(self) -> str:
        return "google"

    def __init__(self, target: Any, config: SystemPromptLeakageConfig):
        super().__init__(target, config)

        self.api_key = self._get_api_key()
        self.model = getattr(target, "model", "gemini-pro")
        self.project_id = getattr(target, "project_id", None)

        self._client = None

    def _get_api_key(self) -> str:
        """Get Google API key."""
        if hasattr(self.target, "credentials") and self.target.credentials:
            api_key = self.target.credentials.get("api_key")
            if api_key:
                return api_key

        import os

        api_key = os.getenv("GOOGLE_API_KEY")
        if api_key:
            return api_key

        raise ClientError("Google API key not found")

    async def send_message(self, message: str, context: AttackContext) -> str:
        """Send message to Google model."""
        start_time = datetime.utcnow()

        try:
            await self._rate_limit()

            if not httpx:
                raise ClientError("httpx not installed. Install with: pip install httpx")

            # Use direct HTTP requests for Google AI
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"

            headers = {"Content-Type": "application/json", "x-goog-api-key": self.api_key}

            data = {
                "contents": [{"parts": [{"text": message}]}],
                "generationConfig": {
                    "maxOutputTokens": getattr(self.target, "max_tokens", 1000),
                    "temperature": getattr(self.target, "temperature", 0.7),
                },
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, headers=headers, json=data)
                response.raise_for_status()

                result = response.json()

                if "candidates" in result and result["candidates"]:
                    content = result["candidates"][0]["content"]["parts"][0]["text"]

                    response_time = (datetime.utcnow() - start_time).total_seconds()
                    self._update_stats(response_time, True)

                    return content
                else:
                    raise ClientError("No response content from Google API")

        except Exception as e:
            response_time = (datetime.utcnow() - start_time).total_seconds()
            self._update_stats(response_time, False)

            logger.error(f"Google request failed: {e}")
            raise ClientError(f"Google request failed: {e}")

    async def validate_connection(self) -> bool:
        """Validate Google connection."""
        try:
            response = await self.send_message(
                "Hello",
                AttackContext(
                    target=self.target,
                    payload=None,
                    technique=None,
                    method=None,
                    timestamp=datetime.utcnow(),
                ),
            )
            return bool(response)

        except Exception as e:
            logger.error(f"Google connection validation failed: {e}")
            return False


class LocalModelClient(BaseModelClient):
    """Client for local models and custom endpoints."""

    def _get_provider(self) -> str:
        return "local"

    def __init__(self, target: Any, config: SystemPromptLeakageConfig):
        super().__init__(target, config)

        self.endpoint = getattr(target, "endpoint", getattr(target, "url", None))
        if not self.endpoint:
            raise ClientError("Local model endpoint not specified")

        self.model_type = getattr(target, "model_type", "custom")
        self.headers = self._prepare_headers()

    def _prepare_headers(self) -> Dict[str, str]:
        """Prepare HTTP headers for requests."""
        headers = {"Content-Type": "application/json"}

        # Add authentication if provided
        if hasattr(self.target, "credentials") and self.target.credentials:
            creds = self.target.credentials

            if "api_key" in creds:
                headers["Authorization"] = f"Bearer {creds['api_key']}"
            elif "auth_header" in creds:
                auth_parts = creds["auth_header"].split(": ", 1)
                if len(auth_parts) == 2:
                    headers[auth_parts[0]] = auth_parts[1]

        return headers

    async def send_message(self, message: str, context: AttackContext) -> str:
        """Send message to local model."""
        start_time = datetime.utcnow()

        try:
            await self._rate_limit()

            if not httpx:
                raise ClientError("httpx not installed. Install with: pip install httpx")

            # Prepare request based on model type
            if self.model_type == "openai_compatible":
                data = {
                    "messages": [{"role": "user", "content": message}],
                    "max_tokens": getattr(self.target, "max_tokens", 1000),
                    "temperature": getattr(self.target, "temperature", 0.7),
                }
                endpoint = f"{self.endpoint.rstrip('/')}/chat/completions"
            else:
                # Generic format
                data = {
                    "prompt": message,
                    "max_tokens": getattr(self.target, "max_tokens", 1000),
                    "temperature": getattr(self.target, "temperature", 0.7),
                }
                endpoint = self.endpoint

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(endpoint, headers=self.headers, json=data)
                response.raise_for_status()

                result = response.json()

                # Extract response based on format
                if "choices" in result:
                    # OpenAI-compatible format
                    if "message" in result["choices"][0]:
                        content = result["choices"][0]["message"]["content"]
                    else:
                        content = result["choices"][0]["text"]
                elif "response" in result:
                    content = result["response"]
                elif "text" in result:
                    content = result["text"]
                else:
                    content = str(result)

                response_time = (datetime.utcnow() - start_time).total_seconds()
                self._update_stats(response_time, True)

                return content

        except Exception as e:
            response_time = (datetime.utcnow() - start_time).total_seconds()
            self._update_stats(response_time, False)

            logger.error(f"Local model request failed: {e}")
            raise ClientError(f"Local model request failed: {e}")

    async def validate_connection(self) -> bool:
        """Validate local model connection."""
        try:
            response = await self.send_message(
                "Hello",
                AttackContext(
                    target=self.target,
                    payload=None,
                    technique=None,
                    method=None,
                    timestamp=datetime.utcnow(),
                ),
            )
            return bool(response)

        except Exception as e:
            logger.error(f"Local model connection validation failed: {e}")
            return False


class MockClient(BaseModelClient):
    """Mock client for testing purposes."""

    def _get_provider(self) -> str:
        return "mock"

    async def send_message(self, message: str, context: AttackContext) -> str:
        """Return mock response."""
        await asyncio.sleep(0.1)  # Simulate network delay

        # Generate different responses based on attack technique
        if "system prompt" in message.lower() or "instructions" in message.lower():
            return "I am a helpful AI assistant. My role is to provide accurate and helpful information."
        elif "debug" in message.lower() or "administrator" in message.lower():
            return "I understand you're testing, but I cannot reveal internal information."
        else:
            return "I'm here to help! How can I assist you today?"

    async def validate_connection(self) -> bool:
        """Mock validation always succeeds."""
        return True


class ClientFactory:
    """Factory for creating appropriate model clients."""

    def __init__(self, config: SystemPromptLeakageConfig):
        self.config = config
        self.client_cache: Dict[str, BaseModelClient] = {}

    def create_client(self, target: Any) -> BaseModelClient:
        """
        Create appropriate client for target.

        Args:
            target: Target configuration

        Returns:
            Appropriate model client instance
        """
        try:
            # Get provider from target
            provider = self._get_provider(target)

            # Check cache first
            cache_key = self._get_cache_key(target)
            if cache_key in self.client_cache:
                return self.client_cache[cache_key]

            # Create new client
            client = self._create_client_for_provider(provider, target)

            # Cache the client
            self.client_cache[cache_key] = client

            return client

        except Exception as e:
            logger.error(f"Failed to create client for target: {e}")
            raise ClientError(f"Failed to create client: {e}")

    def _get_provider(self, target: Any) -> str:
        """Determine provider from target configuration."""

        # Check explicit provider field
        if hasattr(target, "provider"):
            return target.provider.lower()

        # Infer from URL/endpoint
        if hasattr(target, "url"):
            url = target.url.lower()
            if "openai" in url or "api.openai.com" in url:
                return "openai"
            elif "anthropic" in url or "api.anthropic.com" in url:
                return "anthropic"
            elif "googleapis.com" in url or "google" in url:
                return "google"
            elif "localhost" in url or "127.0.0.1" in url or "0.0.0.0" in url:
                return "local"

        # Check for specific model names
        if hasattr(target, "model"):
            model = target.model.lower()
            if "gpt" in model:
                return "openai"
            elif "claude" in model:
                return "anthropic"
            elif "gemini" in model or "palm" in model:
                return "google"

        # Default to local/custom
        return "local"

    def _create_client_for_provider(self, provider: str, target: Any) -> BaseModelClient:
        """Create client for specific provider."""

        if provider == "openai":
            return OpenAIClient(target, self.config)
        elif provider == "anthropic":
            return AnthropicClient(target, self.config)
        elif provider == "google":
            return GoogleClient(target, self.config)
        elif provider == "local":
            return LocalModelClient(target, self.config)
        elif provider == "mock":
            return MockClient(target, self.config)
        else:
            raise UnsupportedTargetError(f"Provider '{provider}' not supported")

    def _get_cache_key(self, target: Any) -> str:
        """Generate cache key for target."""
        # Use target ID if available, otherwise generate from key attributes
        if hasattr(target, "id"):
            return str(target.id)

        key_parts = []
        for attr in ["url", "endpoint", "provider", "model"]:
            if hasattr(target, attr):
                key_parts.append(str(getattr(target, attr)))

        return hash(tuple(key_parts))

    async def cleanup(self) -> None:
        """Cleanup all cached clients."""
        for client in self.client_cache.values():
            await client.cleanup()

        self.client_cache.clear()
        logger.info("ClientFactory cleanup completed")

    def get_statistics(self) -> Dict[str, Any]:
        """Get client factory statistics."""
        stats = {"cached_clients": len(self.client_cache), "client_stats": {}}

        for cache_key, client in self.client_cache.items():
            stats["client_stats"][f"{client.provider}_{cache_key}"] = client.stats

        return stats
