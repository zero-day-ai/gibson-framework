"""
Async LiteLLM client factory for Gibson Framework.

This module provides a production-ready async client factory for LiteLLM with comprehensive
connection pooling, provider auto-detection, fallback logic, and health checking capabilities.
Designed to integrate seamlessly with Gibson's configuration and error handling patterns.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, AsyncContextManager, AsyncGenerator, Dict, List, Optional, Set, Union
from weakref import WeakSet

import httpx
from loguru import logger
from pydantic import Field

import litellm
from litellm import acompletion, aembedding
from litellm.router import Router

from gibson.core.llm.environment import EnvironmentManager, EnvironmentDiscoveryResult
from gibson.core.llm.types import (
    AsyncLLMClient,
    CompletionRequest,
    CompletionResponse,
    LLMError,
    LLMErrorType,
    LLMProvider,
    ProviderConfig,
    StreamAsyncIterator,
    StreamResponse,
    TokenUsage,
)
from gibson.models.base import GibsonBaseModel, TimestampedModel


class HealthStatus(GibsonBaseModel):
    """Health status for an LLM provider."""

    provider: LLMProvider = Field(description="Provider identifier")
    is_healthy: bool = Field(description="Whether provider is healthy")
    last_check: datetime = Field(description="Last health check timestamp")
    response_time: Optional[float] = Field(default=None, description="Response time in seconds")
    error_message: Optional[str] = Field(default=None, description="Error message if unhealthy")
    consecutive_failures: int = Field(default=0, description="Number of consecutive failures")


class ClientStats(TimestampedModel):
    """Statistics for client usage and performance."""

    total_requests: int = Field(default=0, description="Total requests processed")
    successful_requests: int = Field(default=0, description="Successful requests")
    failed_requests: int = Field(default=0, description="Failed requests")
    total_tokens: int = Field(default=0, description="Total tokens processed")
    avg_response_time: float = Field(default=0.0, description="Average response time")

    # Provider-specific stats
    provider_requests: Dict[str, int] = Field(
        default_factory=dict, description="Requests per provider"
    )
    provider_failures: Dict[str, int] = Field(
        default_factory=dict, description="Failures per provider"
    )


class CircuitBreakerState(GibsonBaseModel):
    """Circuit breaker state for provider failure handling."""

    is_open: bool = Field(default=False, description="Whether circuit is open")
    failure_count: int = Field(default=0, description="Current failure count")
    last_failure: Optional[datetime] = Field(default=None, description="Last failure timestamp")
    next_retry: Optional[datetime] = Field(default=None, description="Next retry attempt time")
    failure_threshold: int = Field(default=5, description="Failures before opening circuit")
    recovery_timeout: int = Field(default=60, description="Recovery timeout in seconds")

    def should_allow_request(self) -> bool:
        """Check if request should be allowed through circuit breaker."""
        if not self.is_open:
            return True

        if self.next_retry and datetime.utcnow() >= self.next_retry:
            # Half-open state - allow one request to test
            return True

        return False

    def record_success(self) -> None:
        """Record successful request."""
        self.failure_count = 0
        self.is_open = False
        self.last_failure = None
        self.next_retry = None

    def record_failure(self) -> None:
        """Record failed request."""
        self.failure_count += 1
        self.last_failure = datetime.utcnow()

        if self.failure_count >= self.failure_threshold:
            self.is_open = True
            self.next_retry = datetime.utcnow() + timedelta(seconds=self.recovery_timeout)


class LiteLLMAsyncClient:
    """Async wrapper for LiteLLM client with enhanced functionality."""

    def __init__(
        self,
        provider_config: ProviderConfig,
        http_client: Optional[httpx.AsyncClient] = None,
        timeout: float = 60.0,
    ) -> None:
        """Initialize LiteLLM async client wrapper."""
        self.provider_config = provider_config
        self.timeout = timeout
        self.http_client = http_client
        self._closed = False

    async def complete(
        self,
        request: CompletionRequest,
        provider_config: Optional[ProviderConfig] = None,
    ) -> CompletionResponse:
        """Generate a completion using LiteLLM."""
        if self._closed:
            raise RuntimeError("Client has been closed")

        config = provider_config or self.provider_config

        try:
            # Convert Gibson request to LiteLLM format
            litellm_kwargs = self._convert_request(request, config)

            # Make request through LiteLLM
            start_time = datetime.utcnow()
            response = await acompletion(**litellm_kwargs)
            end_time = datetime.utcnow()

            # Convert LiteLLM response to Gibson format
            return self._convert_response(response, start_time, end_time)

        except Exception as e:
            raise self._convert_error(e, request.model, config.provider)

    async def complete_stream(
        self,
        request: CompletionRequest,
        provider_config: Optional[ProviderConfig] = None,
    ) -> AsyncGenerator[StreamResponse, None]:
        """Generate streaming completion using LiteLLM."""
        if self._closed:
            raise RuntimeError("Client has been closed")

        config = provider_config or self.provider_config

        try:
            # Convert request and enable streaming
            litellm_kwargs = self._convert_request(request, config)
            litellm_kwargs["stream"] = True

            # Stream response through LiteLLM
            response_stream = await acompletion(**litellm_kwargs)

            async for chunk in response_stream:
                yield self._convert_stream_chunk(chunk)

        except Exception as e:
            raise self._convert_error(e, request.model, config.provider)

    async def embed(
        self,
        texts: List[str],
        model: str,
        provider_config: Optional[ProviderConfig] = None,
    ) -> List[List[float]]:
        """Generate embeddings using LiteLLM."""
        if self._closed:
            raise RuntimeError("Client has been closed")

        config = provider_config or self.provider_config

        try:
            response = await aembedding(
                input=texts,
                model=model,
                api_key=config.api_key,
                api_base=config.api_base,
                timeout=self.timeout,
            )

            return [embedding.embedding for embedding in response.data]

        except Exception as e:
            raise self._convert_error(e, model, config.provider)

    async def moderate(
        self,
        content: str,
        model: str,
        provider_config: Optional[ProviderConfig] = None,
    ) -> Dict[str, Any]:
        """Moderate content (placeholder - implement based on provider)."""
        # This would need provider-specific implementation
        return {"flagged": False, "categories": {}}

    async def health_check(self, provider_config: ProviderConfig) -> bool:
        """Check provider health with a simple completion request."""
        try:
            test_request = CompletionRequest(
                messages=[{"role": "user", "content": "Hi"}],
                model=provider_config.model,
                max_tokens=1,
                temperature=0.0,
            )

            await self.complete(test_request, provider_config)
            return True

        except Exception as e:
            logger.debug(f"Health check failed for {provider_config.provider}: {e}")
            return False

    async def get_models(self, provider_config: ProviderConfig) -> List[str]:
        """Get available models for provider (placeholder)."""
        # This would need provider-specific implementation
        return [provider_config.model]

    def _convert_request(
        self, request: CompletionRequest, config: ProviderConfig
    ) -> Dict[str, Any]:
        """Convert Gibson request to LiteLLM format."""
        # Convert messages to LiteLLM format
        messages = []
        for msg in request.messages:
            message_dict = {
                "role": msg.role,
                "content": msg.content,
            }
            if msg.name:
                message_dict["name"] = msg.name
            if msg.function_call:
                message_dict["function_call"] = msg.function_call
            if msg.tool_calls:
                message_dict["tool_calls"] = msg.tool_calls
            if msg.tool_call_id:
                message_dict["tool_call_id"] = msg.tool_call_id

            messages.append(message_dict)

        # Build LiteLLM kwargs
        kwargs = {
            "model": request.model,
            "messages": messages,
            "api_key": config.api_key,
            "api_base": config.api_base,
            "api_version": config.api_version,
            "timeout": request.timeout or self.timeout,
            "stream": request.stream,
        }

        # Add optional parameters
        if request.max_tokens:
            kwargs["max_tokens"] = request.max_tokens
        if request.temperature is not None:
            kwargs["temperature"] = request.temperature
        if request.top_p is not None:
            kwargs["top_p"] = request.top_p
        if request.frequency_penalty is not None:
            kwargs["frequency_penalty"] = request.frequency_penalty
        if request.presence_penalty is not None:
            kwargs["presence_penalty"] = request.presence_penalty
        if request.stop:
            kwargs["stop"] = request.stop
        if request.functions:
            kwargs["functions"] = request.functions
        if request.tools:
            kwargs["tools"] = request.tools
        if request.tool_choice:
            kwargs["tool_choice"] = request.tool_choice
        if request.response_format:
            kwargs["response_format"] = request.response_format
        if request.seed:
            kwargs["seed"] = request.seed
        if request.logit_bias:
            kwargs["logit_bias"] = request.logit_bias
        if request.user:
            kwargs["user"] = request.user

        # Provider-specific configurations
        if hasattr(config, "organization"):
            kwargs["organization"] = config.organization
        if hasattr(config, "project"):
            kwargs["project"] = config.project

        return kwargs

    def _convert_response(
        self,
        litellm_response: Any,
        start_time: datetime,
        end_time: datetime,
    ) -> CompletionResponse:
        """Convert LiteLLM response to Gibson format."""
        from gibson.core.llm.types import CompletionChoice, ChatMessage

        # Calculate response time
        response_time = (end_time - start_time).total_seconds()

        # Convert choices
        choices = []
        for choice in litellm_response.choices:
            message = ChatMessage(
                role=choice.message.role,
                content=choice.message.content,
                name=getattr(choice.message, "name", None),
                function_call=getattr(choice.message, "function_call", None),
                tool_calls=getattr(choice.message, "tool_calls", None),
                tool_call_id=getattr(choice.message, "tool_call_id", None),
            )

            choices.append(
                CompletionChoice(
                    index=choice.index,
                    message=message,
                    finish_reason=choice.finish_reason,
                    logprobs=getattr(choice, "logprobs", None),
                )
            )

        # Convert usage
        usage = None
        if hasattr(litellm_response, "usage") and litellm_response.usage:
            usage = TokenUsage(
                prompt_tokens=litellm_response.usage.prompt_tokens,
                completion_tokens=litellm_response.usage.completion_tokens,
                total_tokens=litellm_response.usage.total_tokens,
                cached_tokens=getattr(litellm_response.usage, "cached_tokens", None),
            )

        return CompletionResponse(
            id=litellm_response.id,
            object=litellm_response.object,
            created=datetime.fromtimestamp(litellm_response.created),
            model=litellm_response.model,
            provider=getattr(litellm_response, "_hidden_params", {}).get("custom_llm_provider"),
            choices=choices,
            usage=usage,
            system_fingerprint=getattr(litellm_response, "system_fingerprint", None),
            response_time=response_time,
        )

    def _convert_stream_chunk(self, chunk: Any) -> StreamResponse:
        """Convert LiteLLM stream chunk to Gibson format."""
        from gibson.core.llm.types import StreamChoice, ChatMessage

        # Convert choices
        choices = []
        for choice in chunk.choices:
            delta = ChatMessage(
                role=getattr(choice.delta, "role", None),
                content=getattr(choice.delta, "content", None),
                name=getattr(choice.delta, "name", None),
                function_call=getattr(choice.delta, "function_call", None),
                tool_calls=getattr(choice.delta, "tool_calls", None),
                tool_call_id=getattr(choice.delta, "tool_call_id", None),
            )

            choices.append(
                StreamChoice(
                    index=choice.index,
                    delta=delta,
                    finish_reason=choice.finish_reason,
                    logprobs=getattr(choice, "logprobs", None),
                )
            )

        # Convert usage (only in final chunk)
        usage = None
        if hasattr(chunk, "usage") and chunk.usage:
            usage = TokenUsage(
                prompt_tokens=chunk.usage.prompt_tokens,
                completion_tokens=chunk.usage.completion_tokens,
                total_tokens=chunk.usage.total_tokens,
                cached_tokens=getattr(chunk.usage, "cached_tokens", None),
            )

        return StreamResponse(
            id=chunk.id,
            object=chunk.object,
            created=datetime.fromtimestamp(chunk.created),
            model=chunk.model,
            provider=getattr(chunk, "_hidden_params", {}).get("custom_llm_provider"),
            choices=choices,
            usage=usage,
        )

    def _convert_error(self, error: Exception, model: str, provider: LLMProvider) -> Exception:
        """Convert LiteLLM errors to Gibson LLM errors."""
        error_type = LLMErrorType.PROVIDER_ERROR

        # Map common error types
        error_str = str(error).lower()
        if "api key" in error_str or "authentication" in error_str:
            error_type = LLMErrorType.AUTHENTICATION_ERROR
        elif "rate limit" in error_str or "quota" in error_str:
            error_type = LLMErrorType.RATE_LIMIT_EXCEEDED
        elif "timeout" in error_str:
            error_type = LLMErrorType.TIMEOUT_ERROR
        elif "context length" in error_str or "too many tokens" in error_str:
            error_type = LLMErrorType.CONTEXT_LENGTH_EXCEEDED
        elif "model not found" in error_str:
            error_type = LLMErrorType.MODEL_NOT_FOUND
        elif "content filter" in error_str or "safety" in error_str:
            error_type = LLMErrorType.CONTENT_FILTER

        llm_error = LLMError(
            type=error_type,
            message=str(error),
            model=model,
            provider=provider,
        )

        # Create appropriate exception type
        if error_type == LLMErrorType.AUTHENTICATION_ERROR:
            return ValueError(f"Authentication failed: {llm_error.message}")
        elif error_type == LLMErrorType.RATE_LIMIT_EXCEEDED:
            return RuntimeError(f"Rate limit exceeded: {llm_error.message}")
        elif error_type == LLMErrorType.TIMEOUT_ERROR:
            return TimeoutError(f"Request timeout: {llm_error.message}")
        else:
            return RuntimeError(f"LLM error ({error_type}): {llm_error.message}")

    async def close(self) -> None:
        """Close the client and cleanup resources."""
        if self.http_client and not self.http_client.is_closed:
            await self.http_client.aclose()
        self._closed = True


class LLMClientFactory:
    """
    Production-ready async LiteLLM client factory with comprehensive features.

    Provides connection pooling, provider auto-detection, fallback logic, health checking,
    and circuit breaker patterns for robust LLM client management.
    """

    def __init__(
        self,
        max_connections: int = 100,
        max_keepalive_connections: int = 20,
        keepalive_expiry: float = 30.0,
        timeout: float = 60.0,
        health_check_interval: float = 300.0,  # 5 minutes
        enable_circuit_breaker: bool = True,
    ) -> None:
        """
        Initialize LLM client factory.

        Args:
            max_connections: Maximum HTTP connections in pool
            max_keepalive_connections: Maximum keepalive connections
            keepalive_expiry: Keepalive connection expiry time
            timeout: Default request timeout
            health_check_interval: Health check interval in seconds
            enable_circuit_breaker: Enable circuit breaker pattern
        """

        self.timeout = timeout
        self.health_check_interval = health_check_interval
        self.enable_circuit_breaker = enable_circuit_breaker

        # HTTP client pool configuration
        self._http_limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            keepalive_expiry=keepalive_expiry,
        )

        # Client and provider management
        self._http_client: Optional[httpx.AsyncClient] = None
        self._clients: Dict[str, LiteLLMAsyncClient] = {}
        self._provider_configs: Dict[str, ProviderConfig] = {}
        self._environment_manager = EnvironmentManager()

        # Health checking and circuit breaker
        self._health_status: Dict[str, HealthStatus] = {}
        self._circuit_breakers: Dict[str, CircuitBreakerState] = {}
        self._stats = ClientStats()

        # Background tasks
        self._health_check_task: Optional[asyncio.Task] = None
        self._closed = False
        self._active_clients: WeakSet[LiteLLMAsyncClient] = WeakSet()

        # Router for load balancing
        self._router: Optional[Router] = None

        logger.info(f"Initialized LLM client factory with {max_connections} max connections")

    async def __aenter__(self) -> LLMClientFactory:
        """Async context manager entry."""
        await self._initialize()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()

    async def _initialize(self) -> None:
        """Initialize the client factory."""
        if self._http_client is None:
            # Create shared HTTP client with connection pooling
            self._http_client = httpx.AsyncClient(
                limits=self._http_limits,
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=True,
            )

        # Discover providers from environment
        discovery_result = await self._environment_manager.discover_providers()
        await self._setup_providers(discovery_result)

        # Start background health checking
        if self.health_check_interval > 0:
            self._health_check_task = asyncio.create_task(self._health_check_loop())

        logger.info(f"Client factory initialized with {len(self._provider_configs)} providers")

    async def _setup_providers(self, discovery: EnvironmentDiscoveryResult) -> None:
        """Setup provider configurations from discovery result."""
        for provider, config in discovery.provider_configs.items():
            if config.is_available:
                # Create provider configuration
                provider_config = self._create_provider_config(provider, config.detected_variables)
                provider_id = f"{provider.value}_{provider_config.model}"

                self._provider_configs[provider_id] = provider_config

                # Initialize health status and circuit breaker
                self._health_status[provider_id] = HealthStatus(
                    provider=provider,
                    is_healthy=True,
                    last_check=datetime.utcnow(),
                )

                if self.enable_circuit_breaker:
                    self._circuit_breakers[provider_id] = CircuitBreakerState()

                logger.debug(f"Setup provider {provider_id}")

    def _create_provider_config(
        self, provider: LLMProvider, env_vars: Dict[str, str]
    ) -> ProviderConfig:
        """Create provider configuration from environment variables."""
        from gibson.core.llm.types import BaseProviderConfig

        # Extract common fields
        api_key = None
        api_base = None
        api_version = None

        # Provider-specific extraction
        if provider == LLMProvider.OPENAI:
            api_key = env_vars.get("OPENAI_API_KEY")
            api_base = env_vars.get("OPENAI_API_BASE")
            model = "gpt-3.5-turbo"  # Default model

        elif provider == LLMProvider.ANTHROPIC:
            api_key = env_vars.get("ANTHROPIC_API_KEY")
            api_base = env_vars.get("ANTHROPIC_API_BASE")
            model = "claude-3-haiku-20240307"  # Default model

        elif provider == LLMProvider.AZURE_OPENAI:
            api_key = env_vars.get("AZURE_API_KEY")
            api_base = env_vars.get("AZURE_API_BASE")
            api_version = env_vars.get("AZURE_API_VERSION", "2024-02-01")
            model = "gpt-35-turbo"  # Default Azure model

        else:
            # Generic provider
            model = "default"
            for key, value in env_vars.items():
                if "api_key" in key.lower():
                    api_key = value
                elif "api_base" in key.lower():
                    api_base = value

        return BaseProviderConfig(
            provider=provider,
            model=model,
            api_key=api_key,
            api_base=api_base,
            api_version=api_version,
            timeout=self.timeout,
        )

    async def get_client(self, provider: Optional[str] = None) -> AsyncLLMClient:
        """
        Get or create LLM client for specified provider.

        Args:
            provider: Provider identifier (auto-detects if None)

        Returns:
            AsyncLLMClient instance

        Raises:
            ValueError: If no providers are available
            RuntimeError: If provider is unhealthy and circuit breaker is open
        """
        if self._closed:
            raise RuntimeError("Client factory has been closed")

        if not self._http_client:
            await self._initialize()

        if not self._provider_configs:
            raise ValueError("No LLM providers are configured")

        # Select provider
        if provider is None:
            provider = await self._select_best_provider()

        if provider not in self._provider_configs:
            raise ValueError(f"Provider '{provider}' not found")

        # Check circuit breaker
        if self.enable_circuit_breaker:
            circuit_breaker = self._circuit_breakers.get(provider)
            if circuit_breaker and not circuit_breaker.should_allow_request():
                raise RuntimeError(f"Provider '{provider}' circuit breaker is open")

        # Get or create client
        if provider not in self._clients:
            provider_config = self._provider_configs[provider]
            client = LiteLLMAsyncClient(
                provider_config=provider_config,
                http_client=self._http_client,
                timeout=self.timeout,
            )
            self._clients[provider] = client
            self._active_clients.add(client)

        return self._clients[provider]

    async def _select_best_provider(self) -> str:
        """Select best available provider based on health and performance."""
        available_providers = []

        for provider_id, health in self._health_status.items():
            if health.is_healthy:
                # Check circuit breaker
                if self.enable_circuit_breaker:
                    circuit_breaker = self._circuit_breakers.get(provider_id)
                    if circuit_breaker and not circuit_breaker.should_allow_request():
                        continue

                available_providers.append((provider_id, health))

        if not available_providers:
            # Fallback to any provider if none are healthy
            if self._provider_configs:
                return next(iter(self._provider_configs.keys()))
            raise ValueError("No healthy providers available")

        # Sort by response time (ascending) and select best
        available_providers.sort(key=lambda x: x[1].response_time or float("inf"))
        return available_providers[0][0]

    async def get_available_providers(self) -> List[str]:
        """Get list of available provider identifiers."""
        if not self._provider_configs:
            await self._initialize()
        return list(self._provider_configs.keys())

    async def health_check(self, provider: str) -> HealthStatus:
        """
        Perform health check for specific provider.

        Args:
            provider: Provider identifier

        Returns:
            HealthStatus with current provider health
        """
        if provider not in self._provider_configs:
            raise ValueError(f"Provider '{provider}' not found")

        provider_config = self._provider_configs[provider]
        start_time = datetime.utcnow()

        try:
            client = await self.get_client(provider)
            is_healthy = await client.health_check(provider_config)
            end_time = datetime.utcnow()
            response_time = (end_time - start_time).total_seconds()

            health_status = HealthStatus(
                provider=provider_config.provider,
                is_healthy=is_healthy,
                last_check=end_time,
                response_time=response_time,
                consecutive_failures=0
                if is_healthy
                else self._health_status.get(
                    provider,
                    HealthStatus(
                        provider=provider_config.provider,
                        is_healthy=False,
                        last_check=datetime.utcnow(),
                    ),
                ).consecutive_failures
                + 1,
            )

            # Update circuit breaker
            if self.enable_circuit_breaker and provider in self._circuit_breakers:
                if is_healthy:
                    self._circuit_breakers[provider].record_success()
                else:
                    self._circuit_breakers[provider].record_failure()

            self._health_status[provider] = health_status
            return health_status

        except Exception as e:
            error_message = str(e)
            end_time = datetime.utcnow()

            health_status = HealthStatus(
                provider=provider_config.provider,
                is_healthy=False,
                last_check=end_time,
                error_message=error_message,
                consecutive_failures=self._health_status.get(
                    provider,
                    HealthStatus(
                        provider=provider_config.provider,
                        is_healthy=False,
                        last_check=datetime.utcnow(),
                    ),
                ).consecutive_failures
                + 1,
            )

            # Update circuit breaker
            if self.enable_circuit_breaker and provider in self._circuit_breakers:
                self._circuit_breakers[provider].record_failure()

            self._health_status[provider] = health_status
            logger.warning(f"Health check failed for provider {provider}: {error_message}")
            return health_status

    async def create_router(self) -> Optional[Router]:
        """
        Create LiteLLM router for load balancing across providers.

        Returns:
            Router instance for multi-provider support
        """
        if not self._provider_configs:
            await self._initialize()

        if not self._provider_configs:
            logger.warning("No providers available for router creation")
            return None

        try:
            # Build model list for router
            model_list = []
            for provider_id, config in self._provider_configs.items():
                model_info = {
                    "model_name": config.model,
                    "litellm_params": {
                        "model": config.model,
                        "api_key": config.api_key,
                        "api_base": config.api_base,
                        "api_version": config.api_version,
                    },
                }
                model_list.append(model_info)

            # Create router with load balancing
            router = Router(
                model_list=model_list,
                routing_strategy="least-busy",  # Load balancing strategy
                num_retries=3,
                timeout=self.timeout,
                fallbacks=model_list[1:] if len(model_list) > 1 else None,
            )

            self._router = router
            logger.info(f"Created router with {len(model_list)} providers")
            return router

        except Exception as e:
            logger.error(f"Failed to create router: {e}")
            return None

    async def _health_check_loop(self) -> None:
        """Background health checking loop."""
        while not self._closed:
            try:
                # Health check all providers
                health_tasks = [
                    self.health_check(provider_id) for provider_id in self._provider_configs.keys()
                ]

                if health_tasks:
                    results = await asyncio.gather(*health_tasks, return_exceptions=True)

                    healthy_count = sum(
                        1
                        for result in results
                        if isinstance(result, HealthStatus) and result.is_healthy
                    )

                    logger.debug(
                        f"Health check complete: {healthy_count}/{len(results)} providers healthy"
                    )

                # Wait for next health check
                await asyncio.sleep(self.health_check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check loop error: {e}")
                await asyncio.sleep(min(self.health_check_interval, 60))

    def get_stats(self) -> ClientStats:
        """Get client factory usage statistics."""
        return self._stats

    async def close(self) -> None:
        """Close the client factory and cleanup all resources."""
        if self._closed:
            return

        logger.info("Closing LLM client factory")
        self._closed = True

        # Cancel health check task
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass

        # Close all clients
        for client in list(self._active_clients):
            try:
                await client.close()
            except Exception as e:
                logger.warning(f"Error closing client: {e}")

        # Close HTTP client
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()

        # Close router
        if self._router:
            try:
                await self._router.close()
            except Exception as e:
                logger.warning(f"Error closing router: {e}")

        self._clients.clear()
        self._provider_configs.clear()
        self._health_status.clear()
        self._circuit_breakers.clear()

        logger.info("LLM client factory closed successfully")


# Convenience functions for easy usage
@asynccontextmanager
async def create_llm_client_factory(**kwargs) -> AsyncGenerator[LLMClientFactory, None]:
    """
    Create LLM client factory as async context manager.

    Args:
        **kwargs: Arguments to pass to LLMClientFactory constructor

    Yields:
        Initialized LLMClientFactory instance
    """
    factory = LLMClientFactory(**kwargs)
    try:
        async with factory:
            yield factory
    finally:
        pass  # Factory cleanup handled by context manager


async def get_default_client() -> AsyncLLMClient:
    """
    Get default LLM client with auto-detected provider.

    Returns:
        AsyncLLMClient instance for the best available provider
    """
    async with create_llm_client_factory() as factory:
        return await factory.get_client()


async def check_llm_availability() -> Dict[str, bool]:
    """
    Check availability of all LLM providers.

    Returns:
        Dictionary mapping provider IDs to availability status
    """
    async with create_llm_client_factory() as factory:
        providers = await factory.get_available_providers()
        results = {}

        for provider in providers:
            try:
                health = await factory.health_check(provider)
                results[provider] = health.is_healthy
            except Exception:
                results[provider] = False

        return results
