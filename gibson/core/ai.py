"""AI interaction service for Gibson security testing framework."""
import asyncio
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union
import httpx
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential
from gibson.core.config import Config


class AIProvider(Enum):
    """Supported AI providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    AZURE = "azure"
    LOCAL = "local"


@dataclass
class Message:
    """Structured message for AI interactions."""

    role: str
    content: str
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AIResponse:
    """Response from AI service."""

    content: str
    provider: str
    model: str
    tokens_used: Optional[int] = None
    response_time: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class RateLimiter:
    """Simple rate limiter for API calls."""

    def __init__(self, max_requests: int, time_window: float = 60.0):
        """Initialize rate limiter.

        Args:
            max_requests: Maximum requests allowed in time window
            time_window: Time window in seconds (default 60 seconds)
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire rate limit slot (blocks if limit exceeded)."""
        async with self._lock:
            now = time.time()
            self.requests = [
                req_time for req_time in self.requests if now - req_time < self.time_window
            ]
            if len(self.requests) >= self.max_requests:
                oldest_request = min(self.requests)
                wait_time = self.time_window - (now - oldest_request)
                if wait_time > 0:
                    logger.debug(f"Rate limit reached, waiting {wait_time:.2f} seconds")
                    await asyncio.sleep(wait_time)
                    return await self.acquire()
            self.requests.append(now)


class AIService:
    """Centralized AI interaction service for all attack domains."""

    def __init__(self, config: Config):
        """Initialize AI service.

        Args:
            config: Gibson configuration object
        """
        self.config = config
        self.http_client = httpx.AsyncClient(
            timeout=config.api.timeout,
            verify=config.api.verify_ssl,
            headers={"User-Agent": "Gibson-Security-Framework"},
        )
        self.rate_limiters = {
            provider: RateLimiter(config.api.rate_limit) for provider in AIProvider
        }
        self.provider_configs = self._load_provider_configs()
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "total_tokens": 0,
            "providers_used": {},
        }

    def _load_provider_configs(self) -> Dict[AIProvider, Dict[str, Any]]:
        """Load provider-specific configurations."""
        return {
            AIProvider.OPENAI: {
                "base_url": "https://api.openai.com/v1",
                "models": ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"],
                "default_model": "gpt-4",
                "max_tokens": 4096,
                "headers": {"Authorization": "Bearer {api_key}"},
            },
            AIProvider.ANTHROPIC: {
                "base_url": "https://api.anthropic.com/v1",
                "models": ["claude-3-5-sonnet-20241022", "claude-3-haiku-20240307"],
                "default_model": "claude-3-5-sonnet-20241022",
                "max_tokens": 4096,
                "headers": {"x-api-key": "{api_key}", "anthropic-version": "2023-06-01"},
            },
            AIProvider.GOOGLE: {
                "base_url": "https://generativelanguage.googleapis.com/v1",
                "models": ["gemini-1.5-pro", "gemini-1.5-flash"],
                "default_model": "gemini-1.5-pro",
                "max_tokens": 4096,
                "headers": {"Authorization": "Bearer {api_key}"},
            },
            AIProvider.AZURE: {
                "base_url": "https://{resource}.openai.azure.com/openai/deployments/{deployment}",
                "models": ["gpt-4", "gpt-35-turbo"],
                "default_model": "gpt-4",
                "max_tokens": 4096,
                "headers": {"api-key": "{api_key}"},
            },
            AIProvider.LOCAL: {
                "base_url": "http://localhost:11434/v1",
                "models": ["llama2", "mistral", "codellama"],
                "default_model": "llama2",
                "max_tokens": 4096,
                "headers": {},
            },
        }

    def _get_api_key(self, provider: AIProvider) -> Optional[str]:
        """Get API key for provider from environment or config."""
        import os

        key_names = {
            AIProvider.OPENAI: ["OPENAI_API_KEY", "GIBSON_OPENAI_KEY"],
            AIProvider.ANTHROPIC: ["ANTHROPIC_API_KEY", "GIBSON_ANTHROPIC_KEY"],
            AIProvider.GOOGLE: ["GOOGLE_API_KEY", "GIBSON_GOOGLE_KEY"],
            AIProvider.AZURE: ["AZURE_OPENAI_KEY", "GIBSON_AZURE_KEY"],
            AIProvider.LOCAL: [],
        }
        for key_name in key_names.get(provider, []):
            api_key = os.getenv(key_name)
            if api_key:
                return api_key
        return None

    async def send_prompt(
        self,
        prompt: str,
        model: Optional[str] = None,
        provider: AIProvider = AIProvider.OPENAI,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        system_prompt: Optional[str] = None,
    ) -> AIResponse:
        """Send a single prompt to AI provider.

        Args:
            prompt: The prompt to send
            model: Specific model to use (uses provider default if None)
            provider: AI provider to use
            temperature: Model temperature (0.0-1.0)
            max_tokens: Maximum tokens in response
            system_prompt: Optional system prompt for context

        Returns:
            AIResponse with result or error
        """
        messages = []
        if system_prompt:
            messages.append(Message("system", system_prompt))
        messages.append(Message("user", prompt))
        return await self.send_with_context(
            messages=messages,
            model=model,
            provider=provider,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def send_with_context(
        self,
        messages: List[Message],
        model: Optional[str] = None,
        provider: AIProvider = AIProvider.OPENAI,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
    ) -> AIResponse:
        """Send messages with conversation context.

        Args:
            messages: List of conversation messages
            model: Specific model to use
            provider: AI provider to use
            temperature: Model temperature
            max_tokens: Maximum tokens in response

        Returns:
            AIResponse with result or error
        """
        start_time = time.time()
        try:
            await self.rate_limiters[provider].acquire()
            provider_config = self.provider_configs[provider]
            model = model or provider_config["default_model"]
            max_tokens = max_tokens or provider_config["max_tokens"]
            request_data = await self._build_request(
                provider, messages, model, temperature, max_tokens, provider_config
            )
            response = await self._send_request(provider, request_data, provider_config)
            ai_response = await self._parse_response(provider, response, model, start_time)
            self._update_stats(provider, ai_response, success=True)
            return ai_response
        except Exception as e:
            logger.error(f"AI request failed for {provider.value}: {e}")
            self._update_stats(provider, None, success=False)
            return AIResponse(
                content="",
                provider=provider.value,
                model=model or "unknown",
                response_time=time.time() - start_time,
                error=str(e),
            )

    async def _build_request(
        self,
        provider: AIProvider,
        messages: List[Message],
        model: str,
        temperature: float,
        max_tokens: int,
        provider_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build provider-specific request payload."""
        if provider == AIProvider.OPENAI:
            return {
                "model": model,
                "messages": [{"role": msg.role, "content": msg.content} for msg in messages],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
        elif provider == AIProvider.ANTHROPIC:
            system_msg = None
            conversation_msgs = []
            for msg in messages:
                if msg.role == "system":
                    system_msg = msg.content
                else:
                    conversation_msgs.append({"role": msg.role, "content": msg.content})
            request = {
                "model": model,
                "messages": conversation_msgs,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if system_msg:
                request["system"] = system_msg
            return request
        elif provider == AIProvider.GOOGLE:
            contents = []
            for msg in messages:
                if msg.role != "system":
                    role = "user" if msg.role in ["user", "system"] else "model"
                    contents.append({"role": role, "parts": [{"text": msg.content}]})
            return {
                "contents": contents,
                "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
            }
        else:
            return {
                "model": model,
                "messages": [{"role": msg.role, "content": msg.content} for msg in messages],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def _send_request(
        self, provider: AIProvider, request_data: Dict[str, Any], provider_config: Dict[str, Any]
    ) -> httpx.Response:
        """Send HTTP request to AI provider."""
        api_key = self._get_api_key(provider)
        headers = {}
        for key, value in provider_config.get("headers", {}).items():
            if "{api_key}" in value and api_key:
                headers[key] = value.format(api_key=api_key)
            elif "{api_key}" not in value:
                headers[key] = value
        base_url = provider_config["base_url"]
        if provider == AIProvider.OPENAI:
            url = f"{base_url}/chat/completions"
        elif provider == AIProvider.ANTHROPIC:
            url = f"{base_url}/messages"
        elif provider == AIProvider.GOOGLE:
            model = request_data.get("model", provider_config["default_model"])
            url = f"{base_url}/models/{model}:generateContent"
            if api_key:
                url += f"?key={api_key}"
        elif provider == AIProvider.AZURE:
            url = f"{base_url}/chat/completions?api-version=2023-12-01-preview"
        else:
            url = f"{base_url}/chat/completions"
        response = await self.http_client.post(url, json=request_data, headers=headers)
        response.raise_for_status()
        return response

    async def _parse_response(
        self, provider: AIProvider, response: httpx.Response, model: str, start_time: float
    ) -> AIResponse:
        """Parse provider-specific response format."""
        response_data = response.model_dump_json()
        response_time = time.time() - start_time
        if (
            provider == AIProvider.OPENAI
            or provider == AIProvider.AZURE
            or provider == AIProvider.LOCAL
        ):
            content = response_data["choices"][0]["message"]["content"]
            tokens_used = response_data.get("usage", {}).get("total_tokens")
        elif provider == AIProvider.ANTHROPIC:
            content = response_data["content"][0]["text"]
            tokens_used = response_data.get("usage", {}).get("output_tokens")
        elif provider == AIProvider.GOOGLE:
            content = response_data["candidates"][0]["content"]["parts"][0]["text"]
            tokens_used = response_data.get("usageMetadata", {}).get("totalTokenCount")
        else:
            content = str(response_data)
            tokens_used = None
        return AIResponse(
            content=content,
            provider=provider.value,
            model=model,
            tokens_used=tokens_used,
            response_time=response_time,
            metadata={"raw_response": response_data},
        )

    def _update_stats(
        self, provider: AIProvider, response: Optional[AIResponse], success: bool
    ) -> None:
        """Update service statistics."""
        self.stats["total_requests"] += 1
        if success:
            self.stats["successful_requests"] += 1
            if response and response.tokens_used:
                self.stats["total_tokens"] += response.tokens_used
        else:
            self.stats["failed_requests"] += 1
        provider_name = provider.value
        if provider_name not in self.stats["providers_used"]:
            self.stats["providers_used"][provider_name] = 0
        self.stats["providers_used"][provider_name] += 1

    async def get_available_models(self, provider: AIProvider) -> List[str]:
        """Get list of available models for provider."""
        return self.provider_configs[provider]["models"]

    async def test_connection(self, provider: AIProvider) -> bool:
        """Test connection to AI provider."""
        try:
            response = await self.send_prompt(
                prompt="Hello, please respond with 'OK' to confirm connectivity.",
                provider=provider,
                max_tokens=10,
            )
            return response.error is None and "ok" in response.content.lower()
        except Exception as e:
            logger.error(f"Connection test failed for {provider.value}: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get service usage statistics."""
        return self.stats.copy()

    async def cleanup(self) -> None:
        """Cleanup resources."""
        if self.http_client:
            await self.http_client.aclose()
        logger.debug("AI service cleanup completed")


_ai_service: Optional[AIService] = None


def get_ai_service(config: Optional[Config] = None) -> AIService:
    """Get or create global AI service instance."""
    global _ai_service
    if _ai_service is None:
        if config is None:
            from gibson.core.config import ConfigManager

            config = ConfigManager().config
        _ai_service = AIService(config)
    return _ai_service


def reset_ai_service() -> None:
    """Reset global AI service (primarily for testing)."""
    global _ai_service
    if _ai_service:
        _ai_service = None
