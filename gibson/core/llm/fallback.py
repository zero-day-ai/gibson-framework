"""
Provider fallback and load balancing for LiteLLM integration.

This module provides:
- Automatic provider fallback on failures
- Load balancing across multiple API keys
- Health checking and circuit breaking
- Intelligent routing based on provider capabilities
"""

import asyncio
import hashlib
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from gibson.core.llm.types import (
    CompletionRequest,
    CompletionResponse,
    LLMError,
    LLMErrorType,
    LLMProvider,
    ModelType,
    StreamAsyncIterator,
)


class LoadBalancingStrategy(Enum):
    """Load balancing strategies."""

    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    LEAST_REQUESTS = "least_requests"
    WEIGHTED = "weighted"
    CONSISTENT_HASH = "consistent_hash"
    CAPACITY_AWARE = "capacity_aware"


class FallbackStrategy(Enum):
    """Fallback strategies."""

    SEQUENTIAL = "sequential"  # Try providers in order
    PRIORITY = "priority"  # Try by priority levels
    CAPABILITY = "capability"  # Try based on required capabilities
    COST = "cost"  # Try cheapest first
    LATENCY = "latency"  # Try fastest first


@dataclass
class ProviderEndpoint:
    """Represents a single provider endpoint."""

    provider: LLMProvider
    api_key: str
    base_url: Optional[str] = None
    model: Optional[str] = None
    weight: float = 1.0
    priority: int = 0
    max_requests_per_minute: Optional[int] = None
    max_tokens_per_minute: Optional[int] = None
    capabilities: Set[str] = field(default_factory=set)
    cost_per_1k_tokens: Optional[float] = None
    average_latency_ms: Optional[float] = None

    # Runtime stats
    request_count: int = field(default=0, init=False)
    error_count: int = field(default=0, init=False)
    last_used: Optional[float] = field(default=None, init=False)
    last_error: Optional[float] = field(default=None, init=False)
    consecutive_errors: int = field(default=0, init=False)
    is_healthy: bool = field(default=True, init=False)

    def __hash__(self) -> int:
        """Make endpoint hashable."""
        return hash((self.provider, self.api_key, self.base_url))


@dataclass
class FallbackConfig:
    """Configuration for fallback behavior."""

    strategy: FallbackStrategy = FallbackStrategy.SEQUENTIAL
    max_retries: int = 3
    retry_delay_ms: int = 1000
    exponential_backoff: bool = True
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout_ms: int = 60000
    health_check_interval_ms: int = 30000
    prefer_same_provider: bool = True
    capability_requirements: Set[str] = field(default_factory=set)


@dataclass
class LoadBalancerConfig:
    """Configuration for load balancing."""

    strategy: LoadBalancingStrategy = LoadBalancingStrategy.ROUND_ROBIN
    sticky_sessions: bool = False
    session_timeout_ms: int = 300000
    health_check_enabled: bool = True
    health_check_interval_ms: int = 30000
    max_endpoints_per_provider: int = 10
    rebalance_interval_ms: int = 60000


class ProviderPool:
    """Manages a pool of provider endpoints."""

    def __init__(self, config: LoadBalancerConfig):
        """Initialize provider pool.

        Args:
            config: Load balancer configuration
        """
        self.config = config
        self.endpoints: Dict[LLMProvider, List[ProviderEndpoint]] = defaultdict(list)
        self.all_endpoints: List[ProviderEndpoint] = []
        self.round_robin_index = 0
        self.session_map: Dict[str, ProviderEndpoint] = {}
        self.session_timestamps: Dict[str, float] = {}
        self.consistent_hash_ring: Dict[int, ProviderEndpoint] = {}
        self._lock = asyncio.Lock()
        self._health_check_task: Optional[asyncio.Task] = None

    async def add_endpoint(self, endpoint: ProviderEndpoint) -> None:
        """Add an endpoint to the pool.

        Args:
            endpoint: Provider endpoint to add
        """
        async with self._lock:
            if len(self.endpoints[endpoint.provider]) >= self.config.max_endpoints_per_provider:
                # Remove oldest endpoint
                self.endpoints[endpoint.provider].pop(0)

            self.endpoints[endpoint.provider].append(endpoint)
            self.all_endpoints.append(endpoint)

            # Update consistent hash ring
            if self.config.strategy == LoadBalancingStrategy.CONSISTENT_HASH:
                self._update_hash_ring()

    async def remove_endpoint(self, endpoint: ProviderEndpoint) -> None:
        """Remove an endpoint from the pool.

        Args:
            endpoint: Provider endpoint to remove
        """
        async with self._lock:
            if endpoint in self.endpoints[endpoint.provider]:
                self.endpoints[endpoint.provider].remove(endpoint)
            if endpoint in self.all_endpoints:
                self.all_endpoints.remove(endpoint)

            # Clean up sessions
            sessions_to_remove = [
                session_id for session_id, ep in self.session_map.items() if ep == endpoint
            ]
            for session_id in sessions_to_remove:
                del self.session_map[session_id]
                del self.session_timestamps[session_id]

            # Update consistent hash ring
            if self.config.strategy == LoadBalancingStrategy.CONSISTENT_HASH:
                self._update_hash_ring()

    async def get_endpoint(
        self,
        session_id: Optional[str] = None,
        required_capabilities: Optional[Set[str]] = None,
        excluded_endpoints: Optional[Set[ProviderEndpoint]] = None,
    ) -> Optional[ProviderEndpoint]:
        """Get an endpoint based on load balancing strategy.

        Args:
            session_id: Optional session ID for sticky sessions
            required_capabilities: Optional required capabilities
            excluded_endpoints: Optional endpoints to exclude

        Returns:
            Selected endpoint or None if none available
        """
        async with self._lock:
            # Clean up expired sessions
            if self.config.sticky_sessions:
                await self._cleanup_expired_sessions()

            # Check for sticky session
            if session_id and self.config.sticky_sessions:
                if session_id in self.session_map:
                    endpoint = self.session_map[session_id]
                    if endpoint.is_healthy and endpoint not in (excluded_endpoints or set()):
                        self.session_timestamps[session_id] = time.time()
                        return endpoint

            # Filter available endpoints
            available = [
                ep
                for ep in self.all_endpoints
                if ep.is_healthy
                and ep not in (excluded_endpoints or set())
                and (not required_capabilities or required_capabilities.issubset(ep.capabilities))
            ]

            if not available:
                return None

            # Select based on strategy
            endpoint = await self._select_endpoint(available, session_id)

            # Update session map
            if session_id and self.config.sticky_sessions and endpoint:
                self.session_map[session_id] = endpoint
                self.session_timestamps[session_id] = time.time()

            return endpoint

    async def mark_unhealthy(self, endpoint: ProviderEndpoint) -> None:
        """Mark an endpoint as unhealthy.

        Args:
            endpoint: Endpoint to mark unhealthy
        """
        async with self._lock:
            endpoint.is_healthy = False
            endpoint.last_error = time.time()
            endpoint.consecutive_errors += 1

    async def mark_healthy(self, endpoint: ProviderEndpoint) -> None:
        """Mark an endpoint as healthy.

        Args:
            endpoint: Endpoint to mark healthy
        """
        async with self._lock:
            endpoint.is_healthy = True
            endpoint.consecutive_errors = 0

    async def update_stats(
        self,
        endpoint: ProviderEndpoint,
        success: bool,
        latency_ms: Optional[float] = None,
    ) -> None:
        """Update endpoint statistics.

        Args:
            endpoint: Endpoint to update
            success: Whether request was successful
            latency_ms: Optional request latency
        """
        async with self._lock:
            endpoint.request_count += 1
            endpoint.last_used = time.time()

            if not success:
                endpoint.error_count += 1
                endpoint.consecutive_errors += 1
            else:
                endpoint.consecutive_errors = 0

            if latency_ms is not None:
                # Update average latency
                if endpoint.average_latency_ms is None:
                    endpoint.average_latency_ms = latency_ms
                else:
                    # Exponential moving average
                    alpha = 0.2
                    endpoint.average_latency_ms = (
                        alpha * latency_ms + (1 - alpha) * endpoint.average_latency_ms
                    )

    async def start_health_checks(self) -> None:
        """Start background health checking."""
        if self.config.health_check_enabled and not self._health_check_task:
            self._health_check_task = asyncio.create_task(self._health_check_loop())

    async def stop_health_checks(self) -> None:
        """Stop background health checking."""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
            self._health_check_task = None

    async def _select_endpoint(
        self,
        available: List[ProviderEndpoint],
        session_id: Optional[str] = None,
    ) -> Optional[ProviderEndpoint]:
        """Select endpoint based on strategy.

        Args:
            available: Available endpoints
            session_id: Optional session ID

        Returns:
            Selected endpoint
        """
        if not available:
            return None

        if self.config.strategy == LoadBalancingStrategy.ROUND_ROBIN:
            endpoint = available[self.round_robin_index % len(available)]
            self.round_robin_index += 1
            return endpoint

        elif self.config.strategy == LoadBalancingStrategy.RANDOM:
            return random.choice(available)

        elif self.config.strategy == LoadBalancingStrategy.LEAST_REQUESTS:
            return min(available, key=lambda ep: ep.request_count)

        elif self.config.strategy == LoadBalancingStrategy.WEIGHTED:
            weights = [ep.weight for ep in available]
            return random.choices(available, weights=weights)[0]

        elif self.config.strategy == LoadBalancingStrategy.CONSISTENT_HASH:
            if session_id:
                hash_value = int(hashlib.md5(session_id.encode()).hexdigest(), 16)
                # Find closest endpoint in hash ring
                sorted_hashes = sorted(self.consistent_hash_ring.keys())
                for h in sorted_hashes:
                    if h >= hash_value:
                        endpoint = self.consistent_hash_ring[h]
                        if endpoint in available:
                            return endpoint
                # Wrap around
                if sorted_hashes:
                    endpoint = self.consistent_hash_ring[sorted_hashes[0]]
                    if endpoint in available:
                        return endpoint
            return random.choice(available)

        elif self.config.strategy == LoadBalancingStrategy.CAPACITY_AWARE:
            # Select based on remaining capacity
            capacities = []
            for ep in available:
                if ep.max_requests_per_minute:
                    # Simple capacity estimation
                    capacity = 1.0 - (ep.request_count / ep.max_requests_per_minute)
                else:
                    capacity = 1.0
                capacities.append(capacity)

            if capacities:
                # Weighted selection based on capacity
                return random.choices(available, weights=capacities)[0]
            return random.choice(available)

        return available[0]

    def _update_hash_ring(self) -> None:
        """Update consistent hash ring."""
        self.consistent_hash_ring.clear()
        for endpoint in self.all_endpoints:
            # Add multiple virtual nodes for better distribution
            for i in range(100):
                key = f"{endpoint.provider}:{endpoint.api_key}:{i}"
                hash_value = int(hashlib.md5(key.encode()).hexdigest(), 16)
                self.consistent_hash_ring[hash_value] = endpoint

    async def _cleanup_expired_sessions(self) -> None:
        """Clean up expired sessions."""
        current_time = time.time()
        timeout_seconds = self.config.session_timeout_ms / 1000

        expired_sessions = [
            session_id
            for session_id, timestamp in self.session_timestamps.items()
            if current_time - timestamp > timeout_seconds
        ]

        for session_id in expired_sessions:
            del self.session_map[session_id]
            del self.session_timestamps[session_id]

    async def _health_check_loop(self) -> None:
        """Background health check loop."""
        while True:
            try:
                await asyncio.sleep(self.config.health_check_interval_ms / 1000)
                await self._perform_health_checks()
            except asyncio.CancelledError:
                break
            except Exception:
                # Log error but continue
                pass

    async def _perform_health_checks(self) -> None:
        """Perform health checks on all endpoints."""
        async with self._lock:
            current_time = time.time()

            for endpoint in self.all_endpoints:
                # Check if endpoint should be retried
                if not endpoint.is_healthy and endpoint.last_error:
                    time_since_error = current_time - endpoint.last_error
                    # Exponential backoff for unhealthy endpoints
                    retry_after = min(
                        60 * (2 ** min(endpoint.consecutive_errors, 5)), 300  # Max 5 minutes
                    )

                    if time_since_error > retry_after:
                        # Try to mark as healthy again
                        endpoint.is_healthy = True
                        endpoint.consecutive_errors = max(0, endpoint.consecutive_errors - 1)


class FallbackManager:
    """Manages provider fallback logic."""

    def __init__(
        self,
        config: FallbackConfig,
        provider_pool: ProviderPool,
    ):
        """Initialize fallback manager.

        Args:
            config: Fallback configuration
            provider_pool: Provider pool for endpoint selection
        """
        self.config = config
        self.provider_pool = provider_pool
        self.fallback_chains: Dict[LLMProvider, List[LLMProvider]] = {}
        self.provider_priorities: Dict[LLMProvider, int] = {}
        self.provider_capabilities: Dict[LLMProvider, Set[str]] = {}
        self.provider_costs: Dict[LLMProvider, float] = {}
        self.provider_latencies: Dict[LLMProvider, float] = {}

    def set_fallback_chain(
        self,
        primary: LLMProvider,
        fallbacks: List[LLMProvider],
    ) -> None:
        """Set fallback chain for a provider.

        Args:
            primary: Primary provider
            fallbacks: Ordered list of fallback providers
        """
        self.fallback_chains[primary] = fallbacks

    def set_provider_priority(
        self,
        provider: LLMProvider,
        priority: int,
    ) -> None:
        """Set provider priority.

        Args:
            provider: Provider to set priority for
            priority: Priority level (lower is higher priority)
        """
        self.provider_priorities[provider] = priority

    def set_provider_capabilities(
        self,
        provider: LLMProvider,
        capabilities: Set[str],
    ) -> None:
        """Set provider capabilities.

        Args:
            provider: Provider to set capabilities for
            capabilities: Set of capabilities
        """
        self.provider_capabilities[provider] = capabilities

    async def get_fallback_sequence(
        self,
        primary: LLMProvider,
        required_capabilities: Optional[Set[str]] = None,
    ) -> List[ProviderEndpoint]:
        """Get fallback sequence for a provider.

        Args:
            primary: Primary provider
            required_capabilities: Optional required capabilities

        Returns:
            Ordered list of endpoints to try
        """
        sequence: List[ProviderEndpoint] = []
        tried_endpoints: Set[ProviderEndpoint] = set()

        # Add primary provider endpoints
        primary_endpoints = await self._get_provider_endpoints(
            primary,
            required_capabilities,
            tried_endpoints,
        )
        sequence.extend(primary_endpoints)
        tried_endpoints.update(primary_endpoints)

        # Add fallback providers based on strategy
        if self.config.strategy == FallbackStrategy.SEQUENTIAL:
            # Use predefined fallback chain
            if primary in self.fallback_chains:
                for fallback_provider in self.fallback_chains[primary]:
                    fallback_endpoints = await self._get_provider_endpoints(
                        fallback_provider,
                        required_capabilities,
                        tried_endpoints,
                    )
                    sequence.extend(fallback_endpoints)
                    tried_endpoints.update(fallback_endpoints)

        elif self.config.strategy == FallbackStrategy.PRIORITY:
            # Sort providers by priority
            sorted_providers = sorted(
                self.provider_priorities.keys(),
                key=lambda p: self.provider_priorities.get(p, 999),
            )

            for provider in sorted_providers:
                if provider != primary:
                    fallback_endpoints = await self._get_provider_endpoints(
                        provider,
                        required_capabilities,
                        tried_endpoints,
                    )
                    sequence.extend(fallback_endpoints)
                    tried_endpoints.update(fallback_endpoints)

        elif self.config.strategy == FallbackStrategy.CAPABILITY:
            # Filter by required capabilities
            if required_capabilities:
                capable_providers = [
                    p
                    for p, caps in self.provider_capabilities.items()
                    if required_capabilities.issubset(caps) and p != primary
                ]

                for provider in capable_providers:
                    fallback_endpoints = await self._get_provider_endpoints(
                        provider,
                        required_capabilities,
                        tried_endpoints,
                    )
                    sequence.extend(fallback_endpoints)
                    tried_endpoints.update(fallback_endpoints)

        elif self.config.strategy == FallbackStrategy.COST:
            # Sort by cost
            sorted_providers = sorted(
                self.provider_costs.keys(),
                key=lambda p: self.provider_costs.get(p, float("inf")),
            )

            for provider in sorted_providers:
                if provider != primary:
                    fallback_endpoints = await self._get_provider_endpoints(
                        provider,
                        required_capabilities,
                        tried_endpoints,
                    )
                    sequence.extend(fallback_endpoints)
                    tried_endpoints.update(fallback_endpoints)

        elif self.config.strategy == FallbackStrategy.LATENCY:
            # Sort by latency
            sorted_providers = sorted(
                self.provider_latencies.keys(),
                key=lambda p: self.provider_latencies.get(p, float("inf")),
            )

            for provider in sorted_providers:
                if provider != primary:
                    fallback_endpoints = await self._get_provider_endpoints(
                        provider,
                        required_capabilities,
                        tried_endpoints,
                    )
                    sequence.extend(fallback_endpoints)
                    tried_endpoints.update(fallback_endpoints)

        # Add any remaining healthy endpoints
        if not sequence:
            all_endpoints = await self.provider_pool.get_endpoint(
                required_capabilities=required_capabilities,
                excluded_endpoints=tried_endpoints,
            )
            if all_endpoints:
                sequence.append(all_endpoints)

        return sequence

    async def _get_provider_endpoints(
        self,
        provider: LLMProvider,
        required_capabilities: Optional[Set[str]],
        excluded: Set[ProviderEndpoint],
    ) -> List[ProviderEndpoint]:
        """Get endpoints for a specific provider.

        Args:
            provider: Provider to get endpoints for
            required_capabilities: Optional required capabilities
            excluded: Endpoints to exclude

        Returns:
            List of available endpoints
        """
        endpoints = []

        for endpoint in self.provider_pool.endpoints.get(provider, []):
            if (
                endpoint.is_healthy
                and endpoint not in excluded
                and (
                    not required_capabilities
                    or required_capabilities.issubset(endpoint.capabilities)
                )
            ):
                endpoints.append(endpoint)

        return endpoints


class LoadBalancedClient:
    """Client with load balancing and fallback support."""

    def __init__(
        self,
        provider_pool: ProviderPool,
        fallback_manager: FallbackManager,
        llm_client_factory: Any,  # Avoid circular import
    ):
        """Initialize load balanced client.

        Args:
            provider_pool: Provider pool for load balancing
            fallback_manager: Fallback manager
            llm_client_factory: LLM client factory for making requests
        """
        self.provider_pool = provider_pool
        self.fallback_manager = fallback_manager
        self.llm_client_factory = llm_client_factory

    async def complete(
        self,
        request: CompletionRequest,
        session_id: Optional[str] = None,
        required_capabilities: Optional[Set[str]] = None,
    ) -> CompletionResponse:
        """Execute completion with load balancing and fallback.

        Args:
            request: Completion request
            session_id: Optional session ID for sticky sessions
            required_capabilities: Optional required capabilities

        Returns:
            Completion response

        Raises:
            LLMError: If all providers fail
        """
        # Get primary endpoint
        primary_endpoint = await self.provider_pool.get_endpoint(
            session_id=session_id,
            required_capabilities=required_capabilities,
        )

        if not primary_endpoint:
            raise LLMError(
                type=LLMErrorType.PROVIDER_ERROR,
                message="No available endpoints",
            )

        # Get fallback sequence
        fallback_sequence = await self.fallback_manager.get_fallback_sequence(
            primary_endpoint.provider,
            required_capabilities,
        )

        # Ensure primary is first
        if primary_endpoint not in fallback_sequence:
            fallback_sequence.insert(0, primary_endpoint)

        errors = []

        for attempt, endpoint in enumerate(fallback_sequence):
            if attempt >= self.fallback_manager.config.max_retries:
                break

            try:
                # Track request start time
                start_time = time.time()

                # Make request through endpoint
                response = await self._make_request(request, endpoint)

                # Update stats on success
                latency_ms = (time.time() - start_time) * 1000
                await self.provider_pool.update_stats(
                    endpoint,
                    success=True,
                    latency_ms=latency_ms,
                )

                return response

            except Exception as e:
                # Update stats on failure
                await self.provider_pool.update_stats(endpoint, success=False)

                # Check if should mark unhealthy
                if (
                    endpoint.consecutive_errors
                    >= self.fallback_manager.config.circuit_breaker_threshold
                ):
                    await self.provider_pool.mark_unhealthy(endpoint)

                errors.append((endpoint, e))

                # Delay before retry
                if attempt < len(fallback_sequence) - 1:
                    delay = self.fallback_manager.config.retry_delay_ms / 1000
                    if self.fallback_manager.config.exponential_backoff:
                        delay *= 2**attempt
                    await asyncio.sleep(delay)

        # All attempts failed
        error_messages = [f"{endpoint.provider}: {str(error)}" for endpoint, error in errors]

        raise LLMError(
            type=LLMErrorType.PROVIDER_ERROR,
            message=f"All providers failed: {'; '.join(error_messages)}",
        )

    async def stream(
        self,
        request: CompletionRequest,
        session_id: Optional[str] = None,
        required_capabilities: Optional[Set[str]] = None,
    ) -> StreamAsyncIterator:
        """Execute streaming completion with load balancing and fallback.

        Args:
            request: Completion request
            session_id: Optional session ID for sticky sessions
            required_capabilities: Optional required capabilities

        Returns:
            Async iterator of stream responses

        Raises:
            LLMError: If all providers fail
        """
        # Similar to complete but returns stream
        # Implementation would be similar with streaming support
        raise NotImplementedError("Streaming with fallback not yet implemented")

    async def _make_request(
        self,
        request: CompletionRequest,
        endpoint: ProviderEndpoint,
    ) -> CompletionResponse:
        """Make request through specific endpoint.

        Args:
            request: Completion request
            endpoint: Endpoint to use

        Returns:
            Completion response
        """
        # Update request with endpoint details
        if endpoint.model:
            request.model = endpoint.model

        # Set provider-specific auth
        client = await self.llm_client_factory.get_client(endpoint.provider)

        # Make request
        return await client.complete(request)


def create_load_balancer(
    config: Optional[LoadBalancerConfig] = None,
) -> Tuple[ProviderPool, FallbackManager]:
    """Create load balancer components.

    Args:
        config: Optional load balancer configuration

    Returns:
        Tuple of (provider pool, fallback manager)
    """
    if config is None:
        config = LoadBalancerConfig()

    provider_pool = ProviderPool(config)
    fallback_config = FallbackConfig()
    fallback_manager = FallbackManager(fallback_config, provider_pool)

    return provider_pool, fallback_manager


# Default provider fallback chains
DEFAULT_FALLBACK_CHAINS = {
    LLMProvider.OPENAI: [
        LLMProvider.AZURE_OPENAI,
        LLMProvider.ANTHROPIC,
        LLMProvider.GOOGLE_AI,
    ],
    LLMProvider.ANTHROPIC: [
        LLMProvider.OPENAI,
        LLMProvider.GOOGLE_AI,
        LLMProvider.COHERE,
    ],
    LLMProvider.AZURE_OPENAI: [
        LLMProvider.OPENAI,
        LLMProvider.ANTHROPIC,
        LLMProvider.GOOGLE_AI,
    ],
    LLMProvider.GOOGLE_AI: [
        LLMProvider.ANTHROPIC,
        LLMProvider.OPENAI,
        LLMProvider.COHERE,
    ],
}


# Provider capability mappings
PROVIDER_CAPABILITIES = {
    LLMProvider.OPENAI: {
        "function_calling",
        "json_mode",
        "vision",
        "embeddings",
        "streaming",
        "128k_context",
    },
    LLMProvider.ANTHROPIC: {
        "100k_context",
        "streaming",
        "claude_3",
        "vision",
    },
    LLMProvider.GOOGLE_AI: {
        "function_calling",
        "streaming",
        "gemini_pro",
        "vision",
    },
    LLMProvider.AZURE_OPENAI: {
        "function_calling",
        "json_mode",
        "vision",
        "embeddings",
        "streaming",
        "gpt4",
    },
}


__all__ = [
    "LoadBalancingStrategy",
    "FallbackStrategy",
    "ProviderEndpoint",
    "FallbackConfig",
    "LoadBalancerConfig",
    "ProviderPool",
    "FallbackManager",
    "LoadBalancedClient",
    "create_load_balancer",
    "DEFAULT_FALLBACK_CHAINS",
    "PROVIDER_CAPABILITIES",
]
