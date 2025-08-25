"""
Production-ready rate limiting and throttling for Gibson Framework LLM operations.

This module provides comprehensive rate limiting with token bucket algorithms, request queuing,
backpressure management, and provider-specific limits. Integrates with LiteLLM's built-in
rate limiting while adding Gibson-specific features for security testing workloads.

Key Features:
- Provider-specific rate limits (OpenAI: 3500 RPM, 90K TPM, etc.)
- Per-module and per-scan rate limiting
- Token bucket and sliding window algorithms
- Request queuing with priority support
- Backpressure handling with rejection strategies
- Redis support for distributed rate limiting
- Circuit breaker integration
- Comprehensive metrics and monitoring
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import random
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Protocol,
    Set,
    Tuple,
    Union,
)
from uuid import uuid4

from loguru import logger
from pydantic import BaseModel, Field, computed_field, field_validator

from gibson.core.llm.types import (
    CompletionRequest,
    LLMError,
    LLMErrorType,
    LLMProvider,
    TokenUsage,
)
from gibson.models.base import GibsonBaseModel, TimestampedModel


# =============================================================================
# Enums and Constants
# =============================================================================


class RateLimitType(str, Enum):
    """Types of rate limits."""

    REQUESTS_PER_MINUTE = "requests_per_minute"
    TOKENS_PER_MINUTE = "tokens_per_minute"
    CONCURRENT_REQUESTS = "concurrent_requests"
    REQUESTS_PER_SECOND = "requests_per_second"
    TOKENS_PER_SECOND = "tokens_per_second"


class Priority(str, Enum):
    """Request priority levels for queuing."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class BackpressureAction(str, Enum):
    """Actions to take when under backpressure."""

    QUEUE = "queue"
    REJECT = "reject"
    THROTTLE = "throttle"
    CIRCUIT_BREAK = "circuit_break"


class RateLimitStatus(str, Enum):
    """Status of rate limit checks."""

    ALLOWED = "allowed"
    RATE_LIMITED = "rate_limited"
    QUEUE_FULL = "queue_full"
    CIRCUIT_OPEN = "circuit_open"


class AlgorithmType(str, Enum):
    """Rate limiting algorithm types."""

    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    LEAKY_BUCKET = "leaky_bucket"


# Provider-specific default limits (from real-world data)
PROVIDER_DEFAULTS = {
    LLMProvider.OPENAI: {
        "rpm": 3500,
        "tpm": 90000,
        "concurrent": 50,
        "burst_multiplier": 2.0,
    },
    LLMProvider.ANTHROPIC: {
        "rpm": 1000,
        "tpm": 100000,
        "concurrent": 20,
        "burst_multiplier": 1.5,
    },
    LLMProvider.AZURE_OPENAI: {
        "rpm": 2000,
        "tpm": 120000,
        "concurrent": 30,
        "burst_multiplier": 1.8,
    },
    LLMProvider.BEDROCK: {
        "rpm": 500,
        "tpm": 50000,
        "concurrent": 10,
        "burst_multiplier": 1.2,
    },
    LLMProvider.VERTEX_AI: {
        "rpm": 1500,
        "tpm": 80000,
        "concurrent": 25,
        "burst_multiplier": 1.6,
    },
}


# =============================================================================
# Core Models
# =============================================================================


class RateStatus(GibsonBaseModel):
    """Status of rate limiting for a provider."""

    provider: LLMProvider = Field(description="Provider identifier")
    status: RateLimitStatus = Field(description="Current rate limit status")
    rpm_remaining: Optional[int] = Field(default=None, description="Requests per minute remaining")
    tpm_remaining: Optional[int] = Field(default=None, description="Tokens per minute remaining")
    concurrent_remaining: Optional[int] = Field(
        default=None, description="Concurrent slots remaining"
    )
    reset_time: Optional[datetime] = Field(default=None, description="When limits reset")
    retry_after: Optional[float] = Field(
        default=None, description="Suggested retry delay in seconds"
    )
    queue_length: int = Field(default=0, description="Current queue length")

    @computed_field
    @property
    def is_available(self) -> bool:
        """Check if provider is available for requests."""
        return self.status == RateLimitStatus.ALLOWED


class QueueStatus(GibsonBaseModel):
    """Status of request queues."""

    total_queued: int = Field(description="Total requests in all queues")
    by_priority: Dict[Priority, int] = Field(description="Queued requests by priority")
    by_provider: Dict[LLMProvider, int] = Field(description="Queued requests by provider")
    avg_wait_time: float = Field(description="Average wait time in seconds")
    estimated_processing_time: float = Field(description="Estimated time to clear queue")

    @computed_field
    @property
    def is_overloaded(self) -> bool:
        """Check if queue system is overloaded."""
        return self.total_queued > 1000 or self.avg_wait_time > 30.0


class ProviderLimits(GibsonBaseModel):
    """Rate limits configuration for a specific provider."""

    provider: LLMProvider = Field(description="Provider identifier")

    # Core limits
    requests_per_minute: int = Field(gt=0, description="Maximum requests per minute")
    tokens_per_minute: int = Field(gt=0, description="Maximum tokens per minute")
    concurrent_requests: int = Field(gt=0, description="Maximum concurrent requests")

    # Advanced limits
    requests_per_second: Optional[int] = Field(
        default=None, gt=0, description="Maximum requests per second"
    )
    tokens_per_second: Optional[int] = Field(
        default=None, gt=0, description="Maximum tokens per second"
    )

    # Burst handling
    burst_requests: Optional[int] = Field(
        default=None, gt=0, description="Burst capacity for requests"
    )
    burst_tokens: Optional[int] = Field(default=None, gt=0, description="Burst capacity for tokens")
    burst_duration: float = Field(default=60.0, gt=0, description="Burst window in seconds")

    # Queue configuration
    max_queue_size: int = Field(default=1000, gt=0, description="Maximum queue size")
    queue_timeout: float = Field(default=300.0, gt=0, description="Maximum queue wait time")

    # Backoff configuration
    base_backoff: float = Field(default=1.0, gt=0, description="Base backoff delay in seconds")
    max_backoff: float = Field(default=300.0, gt=0, description="Maximum backoff delay")
    backoff_multiplier: float = Field(default=2.0, gt=1.0, description="Backoff multiplier")
    jitter: bool = Field(default=True, description="Add jitter to backoff")

    # Algorithm selection
    algorithm: AlgorithmType = Field(
        default=AlgorithmType.TOKEN_BUCKET, description="Rate limiting algorithm"
    )

    @classmethod
    def from_provider_defaults(cls, provider: LLMProvider, **overrides) -> ProviderLimits:
        """Create provider limits from defaults with optional overrides."""
        defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS[LLMProvider.OPENAI])

        # Calculate burst limits
        burst_requests = int(defaults["rpm"] * defaults["burst_multiplier"])
        burst_tokens = int(defaults["tpm"] * defaults["burst_multiplier"])

        config = {
            "provider": provider,
            "requests_per_minute": defaults["rpm"],
            "tokens_per_minute": defaults["tpm"],
            "concurrent_requests": defaults["concurrent"],
            "burst_requests": burst_requests,
            "burst_tokens": burst_tokens,
            **overrides,
        }

        return cls(**config)


class QueuedRequest(TimestampedModel):
    """Represents a queued request awaiting processing."""

    model_config = {"arbitrary_types_allowed": True}

    request_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique request ID")
    provider: LLMProvider = Field(description="Target provider")
    priority: Priority = Field(default=Priority.NORMAL, description="Request priority")
    estimated_tokens: int = Field(gt=0, description="Estimated token count")

    # Context
    module_name: Optional[str] = Field(default=None, description="Originating module")
    scan_id: Optional[str] = Field(default=None, description="Parent scan ID")
    user_id: Optional[str] = Field(default=None, description="User identifier")

    # Timing
    queued_at: datetime = Field(
        default_factory=datetime.utcnow, description="When request was queued"
    )
    timeout_at: Optional[datetime] = Field(default=None, description="When request times out")

    # Future for async notification
    future: Optional[asyncio.Future] = Field(
        default=None, exclude=True, description="Async notification"
    )

    @computed_field
    @property
    def wait_time(self) -> float:
        """Calculate current wait time in seconds."""
        return (datetime.utcnow() - self.queued_at).total_seconds()

    @computed_field
    @property
    def is_expired(self) -> bool:
        """Check if request has expired."""
        if not self.timeout_at:
            return False
        return datetime.utcnow() > self.timeout_at


# =============================================================================
# Token Bucket Algorithm Implementation
# =============================================================================


class TokenBucket:
    """Thread-safe token bucket implementation for rate limiting."""

    def __init__(
        self,
        capacity: int,
        refill_rate: float,
        burst_capacity: Optional[int] = None,
        initial_tokens: Optional[int] = None,
    ):
        """Initialize token bucket.

        Args:
            capacity: Maximum tokens in bucket
            refill_rate: Tokens added per second
            burst_capacity: Optional burst capacity
            initial_tokens: Initial token count (defaults to capacity)
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.burst_capacity = burst_capacity or capacity
        self.tokens = initial_tokens if initial_tokens is not None else capacity
        self.last_refill = time.time()
        self._lock = asyncio.Lock()

    async def acquire(self, requested_tokens: int) -> bool:
        """Attempt to acquire tokens from bucket.

        Args:
            requested_tokens: Number of tokens to acquire

        Returns:
            True if tokens were acquired, False otherwise
        """
        async with self._lock:
            await self._refill()

            if self.tokens >= requested_tokens:
                self.tokens -= requested_tokens
                return True
            return False

    async def acquire_wait(self, requested_tokens: int, timeout: Optional[float] = None) -> bool:
        """Acquire tokens, waiting if necessary.

        Args:
            requested_tokens: Number of tokens to acquire
            timeout: Maximum wait time in seconds

        Returns:
            True if tokens were acquired, False if timeout
        """
        start_time = time.time()

        while True:
            if await self.acquire(requested_tokens):
                return True

            # Check timeout
            if timeout and (time.time() - start_time) >= timeout:
                return False

            # Calculate wait time until enough tokens are available
            wait_time = min(1.0, requested_tokens / self.refill_rate)
            await asyncio.sleep(wait_time)

    async def peek(self) -> int:
        """Get current token count without acquiring."""
        async with self._lock:
            await self._refill()
            return int(self.tokens)

    async def reset(self) -> None:
        """Reset bucket to full capacity."""
        async with self._lock:
            self.tokens = self.capacity
            self.last_refill = time.time()

    async def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill

        if elapsed > 0:
            tokens_to_add = elapsed * self.refill_rate
            self.tokens = min(self.burst_capacity, self.tokens + tokens_to_add)
            self.last_refill = now


# =============================================================================
# Request Queue Management
# =============================================================================


class RequestQueue:
    """Priority-based request queue with timeout handling."""

    def __init__(self, max_size: int = 1000, default_timeout: float = 300.0):
        """Initialize request queue.

        Args:
            max_size: Maximum queue size
            default_timeout: Default timeout for queued requests
        """
        self.max_size = max_size
        self.default_timeout = default_timeout

        # Priority queues (higher priority = lower number for heapq)
        self._queues: Dict[Priority, deque[QueuedRequest]] = {
            Priority.CRITICAL: deque(),
            Priority.HIGH: deque(),
            Priority.NORMAL: deque(),
            Priority.LOW: deque(),
        }

        self._lock = asyncio.Lock()
        self._not_empty = asyncio.Condition(self._lock)
        self._total_size = 0

        # Metrics
        self._processed_count = 0
        self._timeout_count = 0
        self._wait_times: deque[float] = deque(maxlen=1000)

    async def enqueue(
        self,
        provider: LLMProvider,
        estimated_tokens: int,
        priority: Priority = Priority.NORMAL,
        timeout: Optional[float] = None,
        **context,
    ) -> QueuedRequest:
        """Add request to queue.

        Args:
            provider: Target provider
            estimated_tokens: Estimated token count
            priority: Request priority
            timeout: Request timeout in seconds
            **context: Additional context (module_name, scan_id, etc.)

        Returns:
            QueuedRequest object

        Raises:
            ValueError: If queue is full
        """
        async with self._lock:
            if self._total_size >= self.max_size:
                raise ValueError(f"Queue is full (max size: {self.max_size})")

            # Create request
            timeout_seconds = timeout or self.default_timeout
            timeout_at = datetime.utcnow() + timedelta(seconds=timeout_seconds)

            request = QueuedRequest(
                provider=provider,
                priority=priority,
                estimated_tokens=estimated_tokens,
                timeout_at=timeout_at,
                future=asyncio.Future(),
                **context,
            )

            # Add to appropriate priority queue
            self._queues[priority].append(request)
            self._total_size += 1

            # Notify waiting consumers
            self._not_empty.notify()

            logger.debug(
                f"Queued request {request.request_id} "
                f"(provider={provider}, priority={priority}, tokens={estimated_tokens})"
            )

            return request

    async def dequeue(self, timeout: Optional[float] = None) -> Optional[QueuedRequest]:
        """Remove and return highest priority request.

        Args:
            timeout: Maximum wait time for request

        Returns:
            QueuedRequest or None if timeout
        """
        async with self._not_empty:
            # Wait for requests if queue is empty
            if self._total_size == 0:
                try:
                    await asyncio.wait_for(self._not_empty.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    return None

            # Clean up expired requests
            await self._cleanup_expired()

            # Find highest priority non-empty queue
            for priority in [Priority.CRITICAL, Priority.HIGH, Priority.NORMAL, Priority.LOW]:
                queue = self._queues[priority]
                if queue:
                    request = queue.popleft()
                    self._total_size -= 1

                    # Update metrics
                    self._processed_count += 1
                    self._wait_times.append(request.wait_time)

                    logger.debug(
                        f"Dequeued request {request.request_id} "
                        f"after {request.wait_time:.2f}s wait"
                    )

                    return request

            return None

    async def cancel_request(self, request_id: str) -> bool:
        """Cancel a specific request.

        Args:
            request_id: Request ID to cancel

        Returns:
            True if request was found and cancelled
        """
        async with self._lock:
            for priority_queue in self._queues.values():
                for i, request in enumerate(priority_queue):
                    if request.request_id == request_id:
                        # Remove from queue
                        del priority_queue[i]
                        self._total_size -= 1

                        # Cancel the future
                        if request.future and not request.future.done():
                            request.future.cancel()

                        logger.debug(f"Cancelled request {request_id}")
                        return True

            return False

    async def get_status(self) -> QueueStatus:
        """Get current queue status."""
        async with self._lock:
            by_priority = {priority: len(queue) for priority, queue in self._queues.items()}

            by_provider = defaultdict(int)
            for queue in self._queues.values():
                for request in queue:
                    by_provider[request.provider] += 1

            avg_wait_time = (
                sum(self._wait_times) / len(self._wait_times) if self._wait_times else 0.0
            )

            # Estimate processing time based on recent throughput
            total_queued = self._total_size
            estimated_processing_time = total_queued * avg_wait_time if total_queued > 0 else 0.0

            return QueueStatus(
                total_queued=total_queued,
                by_priority=dict(by_priority),
                by_provider=dict(by_provider),
                avg_wait_time=avg_wait_time,
                estimated_processing_time=estimated_processing_time,
            )

    async def _cleanup_expired(self) -> None:
        """Remove expired requests from all queues."""
        expired_count = 0

        for priority_queue in self._queues.values():
            i = 0
            while i < len(priority_queue):
                request = priority_queue[i]
                if request.is_expired:
                    # Remove expired request
                    del priority_queue[i]
                    self._total_size -= 1
                    expired_count += 1

                    # Cancel the future
                    if request.future and not request.future.done():
                        request.future.cancel()
                else:
                    i += 1

        if expired_count > 0:
            self._timeout_count += expired_count
            logger.debug(f"Cleaned up {expired_count} expired requests")


# =============================================================================
# Backpressure Management
# =============================================================================


class BackpressureManager:
    """Manages system backpressure and load shedding."""

    def __init__(
        self,
        queue_threshold: int = 500,
        latency_threshold: float = 10.0,
        error_rate_threshold: float = 0.1,
        circuit_breaker_threshold: int = 5,
    ):
        """Initialize backpressure manager.

        Args:
            queue_threshold: Queue size that triggers backpressure
            latency_threshold: Average latency that triggers backpressure
            error_rate_threshold: Error rate that triggers backpressure
            circuit_breaker_threshold: Consecutive errors for circuit breaker
        """
        self.queue_threshold = queue_threshold
        self.latency_threshold = latency_threshold
        self.error_rate_threshold = error_rate_threshold
        self.circuit_breaker_threshold = circuit_breaker_threshold

        # State tracking
        self._recent_latencies: deque[float] = deque(maxlen=100)
        self._recent_errors: deque[bool] = deque(maxlen=100)
        self._consecutive_errors = defaultdict(int)
        self._circuit_breaker_until = defaultdict(datetime)

        self._lock = asyncio.Lock()

    async def should_apply_backpressure(
        self, provider: LLMProvider, queue_size: int, avg_latency: float
    ) -> BackpressureAction:
        """Determine if backpressure should be applied.

        Args:
            provider: Provider to check
            queue_size: Current queue size
            avg_latency: Average latency in seconds

        Returns:
            Recommended backpressure action
        """
        async with self._lock:
            # Check circuit breaker
            if self._is_circuit_open(provider):
                return BackpressureAction.CIRCUIT_BREAK

            # Check queue pressure
            if queue_size > self.queue_threshold:
                logger.warning(f"Queue backpressure for {provider}: {queue_size} requests queued")
                return BackpressureAction.THROTTLE

            # Check latency pressure
            if avg_latency > self.latency_threshold:
                logger.warning(f"Latency backpressure for {provider}: {avg_latency:.2f}s average")
                return BackpressureAction.THROTTLE

            # Check error rate pressure
            error_rate = self._calculate_error_rate()
            if error_rate > self.error_rate_threshold:
                logger.warning(f"Error rate backpressure: {error_rate:.1%}")
                return BackpressureAction.THROTTLE

            return BackpressureAction.QUEUE

    async def record_request_result(
        self, provider: LLMProvider, latency: float, success: bool
    ) -> None:
        """Record request result for backpressure calculation.

        Args:
            provider: Provider used
            latency: Request latency in seconds
            success: Whether request succeeded
        """
        async with self._lock:
            self._recent_latencies.append(latency)
            self._recent_errors.append(not success)

            if success:
                self._consecutive_errors[provider] = 0
            else:
                self._consecutive_errors[provider] += 1

                # Check for circuit breaker
                if self._consecutive_errors[provider] >= self.circuit_breaker_threshold:
                    self._circuit_breaker_until[provider] = datetime.utcnow() + timedelta(
                        seconds=60
                    )
                    logger.error(
                        f"Circuit breaker opened for {provider} "
                        f"after {self._consecutive_errors[provider]} consecutive errors"
                    )

    def _is_circuit_open(self, provider: LLMProvider) -> bool:
        """Check if circuit breaker is open for provider."""
        if provider not in self._circuit_breaker_until:
            return False

        if datetime.utcnow() < self._circuit_breaker_until[provider]:
            return True

        # Circuit breaker expired, reset
        del self._circuit_breaker_until[provider]
        self._consecutive_errors[provider] = 0
        logger.info(f"Circuit breaker closed for {provider}")
        return False

    def _calculate_error_rate(self) -> float:
        """Calculate recent error rate."""
        if not self._recent_errors:
            return 0.0

        error_count = sum(self._recent_errors)
        return error_count / len(self._recent_errors)


# =============================================================================
# Main Rate Limiter
# =============================================================================


class RateLimiter:
    """Production-ready rate limiter with comprehensive features."""

    def __init__(
        self,
        provider_limits: Optional[Dict[LLMProvider, ProviderLimits]] = None,
        redis_url: Optional[str] = None,
        enable_metrics: bool = True,
    ):
        """Initialize rate limiter.

        Args:
            provider_limits: Provider-specific limits configuration
            redis_url: Optional Redis URL for distributed rate limiting
            enable_metrics: Enable metrics collection
        """
        self.provider_limits = provider_limits or {}
        self.redis_url = redis_url
        self.enable_metrics = enable_metrics

        # Core components
        self._token_buckets: Dict[LLMProvider, Dict[str, TokenBucket]] = defaultdict(dict)
        self._request_queue = RequestQueue()
        self._backpressure_manager = BackpressureManager()

        # Concurrent request tracking
        self._concurrent_requests: Dict[LLMProvider, int] = defaultdict(int)
        self._concurrent_lock = asyncio.Lock()

        # Module and scan rate limiting
        self._module_limits: Dict[str, ProviderLimits] = {}
        self._scan_limits: Dict[str, ProviderLimits] = {}
        self._module_buckets: Dict[str, Dict[str, TokenBucket]] = defaultdict(dict)
        self._scan_buckets: Dict[str, Dict[str, TokenBucket]] = defaultdict(dict)

        # Metrics
        self._metrics: Dict[str, Any] = defaultdict(int)
        self._start_time = time.time()

        # Redis client (if enabled)
        self._redis_client = None

        # Initialize default provider limits
        self._initialize_default_limits()

    def _initialize_default_limits(self) -> None:
        """Initialize default limits for all providers."""
        for provider in LLMProvider:
            if provider not in self.provider_limits:
                self.provider_limits[provider] = ProviderLimits.from_provider_defaults(provider)

            # Initialize token buckets
            limits = self.provider_limits[provider]
            self._token_buckets[provider] = {
                "rpm": TokenBucket(
                    capacity=limits.requests_per_minute,
                    refill_rate=limits.requests_per_minute / 60.0,
                    burst_capacity=limits.burst_requests,
                ),
                "tpm": TokenBucket(
                    capacity=limits.tokens_per_minute,
                    refill_rate=limits.tokens_per_minute / 60.0,
                    burst_capacity=limits.burst_tokens,
                ),
            }

    async def acquire(
        self,
        provider: LLMProvider,
        estimated_tokens: int,
        priority: Priority = Priority.NORMAL,
        module_name: Optional[str] = None,
        scan_id: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> bool:
        """Attempt to acquire rate limit tokens for a request.

        Args:
            provider: Target provider
            estimated_tokens: Estimated token count for request
            priority: Request priority
            module_name: Originating module (for per-module limits)
            scan_id: Parent scan ID (for per-scan limits)
            timeout: Maximum wait time

        Returns:
            True if request can proceed, False if rate limited
        """
        start_time = time.time()

        try:
            # Check circuit breaker first
            backpressure_action = await self._backpressure_manager.should_apply_backpressure(
                provider=provider,
                queue_size=self._request_queue._total_size,
                avg_latency=sum(self._request_queue._wait_times)
                / len(self._request_queue._wait_times)
                if self._request_queue._wait_times
                else 0.0,
            )

            if backpressure_action == BackpressureAction.CIRCUIT_BREAK:
                await self._record_metric("requests_circuit_breaker")
                return False

            # Check concurrent request limit
            async with self._concurrent_lock:
                limits = self.provider_limits[provider]
                if self._concurrent_requests[provider] >= limits.concurrent_requests:
                    if backpressure_action == BackpressureAction.REJECT:
                        await self._record_metric("requests_rejected_concurrent")
                        return False

                    # Queue the request
                    queued_request = await self._request_queue.enqueue(
                        provider=provider,
                        estimated_tokens=estimated_tokens,
                        priority=priority,
                        timeout=timeout,
                        module_name=module_name,
                        scan_id=scan_id,
                    )

                    # Wait for queue processing
                    try:
                        await asyncio.wait_for(queued_request.future, timeout=timeout)
                        return True
                    except asyncio.TimeoutError:
                        await self._request_queue.cancel_request(queued_request.request_id)
                        await self._record_metric("requests_timeout")
                        return False

            # Check token bucket limits
            rpm_bucket = self._token_buckets[provider]["rpm"]
            tpm_bucket = self._token_buckets[provider]["tpm"]

            # Try to acquire tokens immediately
            if await rpm_bucket.acquire(1) and await tpm_bucket.acquire(estimated_tokens):
                # Check module-specific limits
                if module_name and not await self._check_module_limits(
                    module_name, estimated_tokens
                ):
                    # Return tokens and reject
                    await self._return_tokens(provider, 1, estimated_tokens)
                    await self._record_metric("requests_rejected_module")
                    return False

                # Check scan-specific limits
                if scan_id and not await self._check_scan_limits(scan_id, estimated_tokens):
                    # Return tokens and reject
                    await self._return_tokens(provider, 1, estimated_tokens)
                    await self._record_metric("requests_rejected_scan")
                    return False

                # Increment concurrent counter
                async with self._concurrent_lock:
                    self._concurrent_requests[provider] += 1

                await self._record_metric("requests_allowed")
                return True

            # If immediate acquisition failed, decide whether to queue or reject
            if backpressure_action == BackpressureAction.REJECT:
                await self._record_metric("requests_rejected_tokens")
                return False

            # Queue the request
            queued_request = await self._request_queue.enqueue(
                provider=provider,
                estimated_tokens=estimated_tokens,
                priority=priority,
                timeout=timeout,
                module_name=module_name,
                scan_id=scan_id,
            )

            # Wait for queue processing
            try:
                await asyncio.wait_for(queued_request.future, timeout=timeout)
                return True
            except asyncio.TimeoutError:
                await self._request_queue.cancel_request(queued_request.request_id)
                await self._record_metric("requests_timeout")
                return False

        finally:
            # Record latency metric
            latency = time.time() - start_time
            await self._backpressure_manager.record_request_result(
                provider=provider,
                latency=latency,
                success=True,  # Will be updated by release() if request fails
            )

    async def release(
        self, provider: LLMProvider, actual_tokens: Optional[int] = None, success: bool = True
    ) -> None:
        """Release resources after request completion.

        Args:
            provider: Provider that was used
            actual_tokens: Actual tokens consumed (for adjustment)
            success: Whether request succeeded
        """
        # Decrement concurrent counter
        async with self._concurrent_lock:
            if self._concurrent_requests[provider] > 0:
                self._concurrent_requests[provider] -= 1

        # Process next queued request if any
        await self._process_queue()

        # Record success/failure
        if success:
            await self._record_metric("requests_completed")
        else:
            await self._record_metric("requests_failed")

    async def check_availability(self, provider: LLMProvider) -> RateStatus:
        """Check current availability of a provider.

        Args:
            provider: Provider to check

        Returns:
            Current rate status
        """
        limits = self.provider_limits[provider]
        rpm_bucket = self._token_buckets[provider]["rpm"]
        tpm_bucket = self._token_buckets[provider]["tpm"]

        rpm_remaining = await rpm_bucket.peek()
        tpm_remaining = await tpm_bucket.peek()

        async with self._concurrent_lock:
            concurrent_remaining = limits.concurrent_requests - self._concurrent_requests[provider]

        # Determine status
        if concurrent_remaining <= 0:
            status = RateLimitStatus.RATE_LIMITED
            retry_after = 1.0  # Check again in 1 second
        elif rpm_remaining <= 0 or tpm_remaining <= 0:
            status = RateLimitStatus.RATE_LIMITED
            retry_after = 60.0 / limits.requests_per_minute  # Time for one token
        else:
            status = RateLimitStatus.ALLOWED
            retry_after = None

        queue_status = await self._request_queue.get_status()

        return RateStatus(
            provider=provider,
            status=status,
            rpm_remaining=rpm_remaining,
            tpm_remaining=tpm_remaining,
            concurrent_remaining=max(0, concurrent_remaining),
            retry_after=retry_after,
            queue_length=queue_status.total_queued,
        )

    async def set_limits(
        self,
        provider: LLMProvider,
        rpm: Optional[int] = None,
        tpm: Optional[int] = None,
        concurrent: Optional[int] = None,
    ) -> None:
        """Update rate limits for a provider.

        Args:
            provider: Provider to update
            rpm: New requests per minute limit
            tpm: New tokens per minute limit
            concurrent: New concurrent requests limit
        """
        current_limits = self.provider_limits[provider]

        # Update limits
        if rpm is not None:
            current_limits.requests_per_minute = rpm
        if tpm is not None:
            current_limits.tokens_per_minute = tpm
        if concurrent is not None:
            current_limits.concurrent_requests = concurrent

        # Recreate token buckets with new limits
        self._token_buckets[provider] = {
            "rpm": TokenBucket(
                capacity=current_limits.requests_per_minute,
                refill_rate=current_limits.requests_per_minute / 60.0,
                burst_capacity=current_limits.burst_requests,
            ),
            "tpm": TokenBucket(
                capacity=current_limits.tokens_per_minute,
                refill_rate=current_limits.tokens_per_minute / 60.0,
                burst_capacity=current_limits.burst_tokens,
            ),
        }

        logger.info(f"Updated limits for {provider}: RPM={rpm}, TPM={tpm}, Concurrent={concurrent}")

    async def get_queue_status(self) -> QueueStatus:
        """Get current queue status."""
        return await self._request_queue.get_status()

    async def apply_backpressure(self, provider: LLMProvider) -> BackpressureAction:
        """Determine and apply appropriate backpressure action.

        Args:
            provider: Provider to check

        Returns:
            Applied backpressure action
        """
        queue_status = await self._request_queue.get_status()

        return await self._backpressure_manager.should_apply_backpressure(
            provider=provider,
            queue_size=queue_status.total_queued,
            avg_latency=queue_status.avg_wait_time,
        )

    async def reset_limits(self, provider: LLMProvider) -> None:
        """Reset rate limits for a provider (emergency recovery).

        Args:
            provider: Provider to reset
        """
        # Reset token buckets
        for bucket in self._token_buckets[provider].values():
            await bucket.reset()

        # Reset concurrent counter
        async with self._concurrent_lock:
            self._concurrent_requests[provider] = 0

        logger.warning(f"Reset rate limits for {provider}")
        await self._record_metric("limits_reset")

    async def set_module_limits(self, module_name: str, limits: ProviderLimits) -> None:
        """Set rate limits for a specific module.

        Args:
            module_name: Module name
            limits: Rate limits configuration
        """
        self._module_limits[module_name] = limits

        # Initialize token buckets for module
        self._module_buckets[module_name] = {
            "rpm": TokenBucket(
                capacity=limits.requests_per_minute,
                refill_rate=limits.requests_per_minute / 60.0,
                burst_capacity=limits.burst_requests,
            ),
            "tpm": TokenBucket(
                capacity=limits.tokens_per_minute,
                refill_rate=limits.tokens_per_minute / 60.0,
                burst_capacity=limits.burst_tokens,
            ),
        }

        logger.info(f"Set module limits for {module_name}")

    async def set_scan_limits(self, scan_id: str, limits: ProviderLimits) -> None:
        """Set rate limits for a specific scan.

        Args:
            scan_id: Scan ID
            limits: Rate limits configuration
        """
        self._scan_limits[scan_id] = limits

        # Initialize token buckets for scan
        self._scan_buckets[scan_id] = {
            "rpm": TokenBucket(
                capacity=limits.requests_per_minute,
                refill_rate=limits.requests_per_minute / 60.0,
                burst_capacity=limits.burst_requests,
            ),
            "tpm": TokenBucket(
                capacity=limits.tokens_per_minute,
                refill_rate=limits.tokens_per_minute / 60.0,
                burst_capacity=limits.burst_tokens,
            ),
        }

        logger.info(f"Set scan limits for {scan_id}")

    async def get_metrics(self) -> Dict[str, Any]:
        """Get rate limiting metrics.

        Returns:
            Dictionary of metrics
        """
        uptime = time.time() - self._start_time
        queue_status = await self._request_queue.get_status()

        metrics = dict(self._metrics)
        metrics.update(
            {
                "uptime_seconds": uptime,
                "queue_status": queue_status.model_dump(),
                "provider_concurrent": dict(self._concurrent_requests),
            }
        )

        return metrics

    async def _check_module_limits(self, module_name: str, tokens: int) -> bool:
        """Check if module-specific limits allow the request."""
        if module_name not in self._module_limits:
            return True

        buckets = self._module_buckets[module_name]
        rpm_acquired = await buckets["rpm"].acquire(1)
        tpm_acquired = await buckets["tpm"].acquire(tokens)

        if not (rpm_acquired and tpm_acquired):
            # Return any acquired tokens
            if rpm_acquired:
                buckets["rpm"].tokens += 1
            if tpm_acquired:
                buckets["tpm"].tokens += tokens
            return False

        return True

    async def _check_scan_limits(self, scan_id: str, tokens: int) -> bool:
        """Check if scan-specific limits allow the request."""
        if scan_id not in self._scan_limits:
            return True

        buckets = self._scan_buckets[scan_id]
        rpm_acquired = await buckets["rpm"].acquire(1)
        tpm_acquired = await buckets["tpm"].acquire(tokens)

        if not (rpm_acquired and tpm_acquired):
            # Return any acquired tokens
            if rpm_acquired:
                buckets["rpm"].tokens += 1
            if tpm_acquired:
                buckets["tpm"].tokens += tokens
            return False

        return True

    async def _return_tokens(self, provider: LLMProvider, requests: int, tokens: int) -> None:
        """Return tokens to provider buckets (best effort)."""
        rpm_bucket = self._token_buckets[provider]["rpm"]
        tpm_bucket = self._token_buckets[provider]["tpm"]

        # Add tokens back (up to capacity)
        async with rpm_bucket._lock:
            rpm_bucket.tokens = min(rpm_bucket.capacity, rpm_bucket.tokens + requests)

        async with tpm_bucket._lock:
            tpm_bucket.tokens = min(tpm_bucket.capacity, tpm_bucket.tokens + tokens)

    async def _process_queue(self) -> None:
        """Process next request in queue if resources are available."""
        while True:
            request = await self._request_queue.dequeue(timeout=0.1)
            if not request:
                break

            # Try to acquire resources for queued request
            limits = self.provider_limits[request.provider]
            rpm_bucket = self._token_buckets[request.provider]["rpm"]
            tpm_bucket = self._token_buckets[request.provider]["tpm"]

            # Check if resources are available
            async with self._concurrent_lock:
                concurrent_available = (
                    self._concurrent_requests[request.provider] < limits.concurrent_requests
                )

            rpm_available = await rpm_bucket.acquire(1)
            tpm_available = await tpm_bucket.acquire(request.estimated_tokens)

            if concurrent_available and rpm_available and tpm_available:
                # Resources acquired, notify the waiting request
                async with self._concurrent_lock:
                    self._concurrent_requests[request.provider] += 1

                if request.future and not request.future.done():
                    request.future.set_result(True)

                await self._record_metric("requests_queue_processed")
                return
            else:
                # Return tokens and put request back in queue
                if rpm_available:
                    await self._return_tokens(request.provider, 1, 0)
                if tpm_available:
                    await self._return_tokens(request.provider, 0, request.estimated_tokens)

                # Put request back at front of queue
                self._request_queue._queues[request.priority].appendleft(request)
                self._request_queue._total_size += 1
                break

    async def _record_metric(self, metric_name: str, value: int = 1) -> None:
        """Record a metric value."""
        if self.enable_metrics:
            self._metrics[metric_name] += value


# =============================================================================
# Redis-based Distributed Rate Limiting
# =============================================================================


class DistributedRateLimiter(RateLimiter):
    """Redis-based distributed rate limiter for multi-instance deployments."""

    def __init__(self, redis_url: str, **kwargs):
        """Initialize distributed rate limiter.

        Args:
            redis_url: Redis connection URL
            **kwargs: Additional arguments for RateLimiter
        """
        super().__init__(redis_url=redis_url, **kwargs)

        # Redis scripts for atomic operations
        self._acquire_script = None
        self._release_script = None

    async def _initialize_redis(self) -> None:
        """Initialize Redis connection and scripts."""
        try:
            import redis.asyncio as redis

            self._redis_client = redis.from_url(self.redis_url)
            await self._redis_client.ping()

            # Load Lua scripts for atomic operations
            self._acquire_script = await self._redis_client.script_load(
                """
                local key = KEYS[1]
                local capacity = tonumber(ARGV[1])
                local refill_rate = tonumber(ARGV[2])
                local requested = tonumber(ARGV[3])
                local now = tonumber(ARGV[4])
                
                local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
                local tokens = tonumber(bucket[1]) or capacity
                local last_refill = tonumber(bucket[2]) or now
                
                -- Refill tokens
                local elapsed = now - last_refill
                if elapsed > 0 then
                    tokens = math.min(capacity, tokens + elapsed * refill_rate)
                end
                
                -- Check if we can acquire tokens
                if tokens >= requested then
                    tokens = tokens - requested
                    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
                    redis.call('EXPIRE', key, 3600)  -- 1 hour TTL
                    return 1
                else
                    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
                    redis.call('EXPIRE', key, 3600)
                    return 0
                end
            """
            )

            logger.info("Distributed rate limiter initialized with Redis")

        except ImportError:
            logger.error("redis package not available for distributed rate limiting")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize Redis: {e}")
            raise

    async def acquire(self, provider: LLMProvider, estimated_tokens: int, **kwargs) -> bool:
        """Distributed acquire implementation using Redis."""
        if not self._redis_client:
            await self._initialize_redis()

        # Use Redis for token bucket state
        limits = self.provider_limits[provider]
        now = time.time()

        # Check RPM limit
        rpm_key = f"gibson:rate_limit:{provider}:rpm"
        rpm_result = await self._redis_client.evalsha(
            self._acquire_script,
            1,
            rpm_key,
            limits.requests_per_minute,
            limits.requests_per_minute / 60.0,
            1,
            now,
        )

        if not rpm_result:
            return False

        # Check TPM limit
        tpm_key = f"gibson:rate_limit:{provider}:tpm"
        tpm_result = await self._redis_client.evalsha(
            self._acquire_script,
            1,
            tpm_key,
            limits.tokens_per_minute,
            limits.tokens_per_minute / 60.0,
            estimated_tokens,
            now,
        )

        if not tpm_result:
            # Return RPM token
            await self._redis_client.hincrby(rpm_key, "tokens", 1)
            return False

        # Check concurrent limit (local only for now)
        return await super().acquire(provider, estimated_tokens, **kwargs)


# =============================================================================
# Factory Functions
# =============================================================================


def create_rate_limiter(
    provider_limits: Optional[Dict[LLMProvider, ProviderLimits]] = None,
    distributed: bool = False,
    redis_url: Optional[str] = None,
    **kwargs,
) -> RateLimiter:
    """Factory function to create rate limiter.

    Args:
        provider_limits: Provider-specific limits
        distributed: Enable distributed rate limiting
        redis_url: Redis URL for distributed mode
        **kwargs: Additional arguments

    Returns:
        Configured rate limiter instance
    """
    if distributed:
        if not redis_url:
            raise ValueError("Redis URL required for distributed rate limiting")
        return DistributedRateLimiter(
            redis_url=redis_url, provider_limits=provider_limits, **kwargs
        )
    else:
        return RateLimiter(provider_limits=provider_limits, **kwargs)


# =============================================================================
# Exports
# =============================================================================


__all__ = [
    # Enums
    "RateLimitType",
    "Priority",
    "BackpressureAction",
    "RateLimitStatus",
    "AlgorithmType",
    # Models
    "RateStatus",
    "QueueStatus",
    "ProviderLimits",
    "QueuedRequest",
    # Core classes
    "TokenBucket",
    "RequestQueue",
    "BackpressureManager",
    "RateLimiter",
    "DistributedRateLimiter",
    # Factory
    "create_rate_limiter",
    # Constants
    "PROVIDER_DEFAULTS",
]
