"""
Comprehensive error handling and retry logic for LiteLLM integration in Gibson Framework.

This module provides production-ready error handling with provider-specific guidance,
exponential backoff retry logic, fallback mechanisms, circuit breaker patterns,
and structured error logging for debugging and monitoring.
"""

from __future__ import annotations

import asyncio
import random
from collections import defaultdict
from collections.abc import Awaitable
from datetime import datetime
from enum import Enum
from functools import wraps
from typing import (
    Any,
    Callable,
    TypeVar,
)
from uuid import uuid4

from loguru import logger
from pydantic import Field

from gibson.core.llm.types import (
    LLMError,
    LLMErrorType,
    LLMProvider,
    LLMRequest,
)
from gibson.models.base import GibsonBaseModel, TimestampedModel

# Type variable for decorated functions
F = TypeVar("F", bound=Callable[..., Awaitable[Any]])

# =============================================================================
# Error Classification and Mapping
# =============================================================================


class ErrorSeverity(str, Enum):
    """Error severity levels for classification and handling."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RetryDecision(str, Enum):
    """Decision on whether to retry an operation."""

    RETRY = "retry"
    NO_RETRY = "no_retry"
    FALLBACK = "fallback"
    CIRCUIT_BREAK = "circuit_break"


class RecoveryStrategy(str, Enum):
    """Available error recovery strategies."""

    NONE = "none"
    RETRY_SAME = "retry_same"
    RETRY_BACKOFF = "retry_backoff"
    FALLBACK_PROVIDER = "fallback_provider"
    REDUCE_PARAMETERS = "reduce_parameters"
    CIRCUIT_BREAKER = "circuit_breaker"


class ProviderErrorMapping:
    """Maps provider-specific errors to Gibson error types."""

    # OpenAI error codes
    OPENAI_ERROR_MAP: dict[str, LLMErrorType] = {
        "invalid_api_key": LLMErrorType.INVALID_API_KEY,
        "insufficient_quota": LLMErrorType.RATE_LIMIT_EXCEEDED,
        "model_not_found": LLMErrorType.MODEL_NOT_FOUND,
        "context_length_exceeded": LLMErrorType.CONTEXT_LENGTH_EXCEEDED,
        "content_filter": LLMErrorType.CONTENT_FILTER,
        "rate_limit_exceeded": LLMErrorType.RATE_LIMIT_EXCEEDED,
        "server_error": LLMErrorType.INTERNAL_SERVER_ERROR,
        "timeout": LLMErrorType.TIMEOUT_ERROR,
    }

    # Anthropic error codes
    ANTHROPIC_ERROR_MAP: dict[str, LLMErrorType] = {
        "authentication_error": LLMErrorType.AUTHENTICATION_ERROR,
        "permission_error": LLMErrorType.PERMISSION_DENIED,
        "not_found_error": LLMErrorType.MODEL_NOT_FOUND,
        "rate_limit_error": LLMErrorType.RATE_LIMIT_EXCEEDED,
        "api_error": LLMErrorType.PROVIDER_ERROR,
        "overloaded_error": LLMErrorType.PROVIDER_UNAVAILABLE,
        "timeout": LLMErrorType.TIMEOUT_ERROR,
    }

    # Generic HTTP status codes
    HTTP_STATUS_MAP: dict[int, LLMErrorType] = {
        400: LLMErrorType.INVALID_REQUEST,
        401: LLMErrorType.AUTHENTICATION_ERROR,
        403: LLMErrorType.PERMISSION_DENIED,
        404: LLMErrorType.MODEL_NOT_FOUND,
        408: LLMErrorType.TIMEOUT_ERROR,
        413: LLMErrorType.CONTEXT_LENGTH_EXCEEDED,
        429: LLMErrorType.RATE_LIMIT_EXCEEDED,
        500: LLMErrorType.INTERNAL_SERVER_ERROR,
        502: LLMErrorType.BAD_GATEWAY,
        503: LLMErrorType.SERVICE_UNAVAILABLE,
        504: LLMErrorType.TIMEOUT_ERROR,
    }

    @classmethod
    def get_error_type(
        cls,
        error: Exception,
        provider: LLMProvider | None = None,
    ) -> LLMErrorType:
        """Map provider-specific error to Gibson error type."""
        error_str = str(error).lower()

        # Try provider-specific mapping first
        if provider == LLMProvider.OPENAI:
            for code, error_type in cls.OPENAI_ERROR_MAP.items():
                if code in error_str:
                    return error_type
        elif provider == LLMProvider.ANTHROPIC:
            for code, error_type in cls.ANTHROPIC_ERROR_MAP.items():
                if code in error_str:
                    return error_type

        # Try HTTP status code mapping
        if hasattr(error, "status_code"):
            return cls.HTTP_STATUS_MAP.get(
                error.status_code, LLMErrorType.PROVIDER_ERROR
            )

        # Fallback to keyword matching
        if any(word in error_str for word in ["timeout", "timed out"]):
            return LLMErrorType.TIMEOUT_ERROR
        elif any(word in error_str for word in ["connection", "network"]):
            return LLMErrorType.CONNECTION_ERROR
        elif any(word in error_str for word in ["authentication", "auth", "api key"]):
            return LLMErrorType.AUTHENTICATION_ERROR
        elif any(word in error_str for word in ["rate limit", "quota"]):
            return LLMErrorType.RATE_LIMIT_EXCEEDED
        elif any(word in error_str for word in ["model not found", "model does not exist"]):
            return LLMErrorType.MODEL_NOT_FOUND

        return LLMErrorType.PROVIDER_ERROR


class ErrorClassifier:
    """Classifies errors and determines handling strategy."""

    # Error severity mapping
    SEVERITY_MAP: dict[LLMErrorType, ErrorSeverity] = {
        LLMErrorType.AUTHENTICATION_ERROR: ErrorSeverity.HIGH,
        LLMErrorType.PERMISSION_DENIED: ErrorSeverity.HIGH,
        LLMErrorType.INVALID_API_KEY: ErrorSeverity.HIGH,
        LLMErrorType.INVALID_REQUEST: ErrorSeverity.MEDIUM,
        LLMErrorType.MODEL_NOT_FOUND: ErrorSeverity.MEDIUM,
        LLMErrorType.CONTEXT_LENGTH_EXCEEDED: ErrorSeverity.MEDIUM,
        LLMErrorType.RATE_LIMIT_EXCEEDED: ErrorSeverity.LOW,
        LLMErrorType.CONTENT_FILTER: ErrorSeverity.MEDIUM,
        LLMErrorType.PROVIDER_ERROR: ErrorSeverity.MEDIUM,
        LLMErrorType.PROVIDER_TIMEOUT: ErrorSeverity.LOW,
        LLMErrorType.PROVIDER_UNAVAILABLE: ErrorSeverity.MEDIUM,
        LLMErrorType.NETWORK_ERROR: ErrorSeverity.LOW,
        LLMErrorType.TIMEOUT_ERROR: ErrorSeverity.LOW,
        LLMErrorType.CONNECTION_ERROR: ErrorSeverity.LOW,
        LLMErrorType.INTERNAL_SERVER_ERROR: ErrorSeverity.MEDIUM,
        LLMErrorType.SERVICE_UNAVAILABLE: ErrorSeverity.MEDIUM,
        LLMErrorType.BAD_GATEWAY: ErrorSeverity.MEDIUM,
    }

    # Retry decision mapping
    RETRY_MAP: dict[LLMErrorType, RetryDecision] = {
        LLMErrorType.AUTHENTICATION_ERROR: RetryDecision.NO_RETRY,
        LLMErrorType.PERMISSION_DENIED: RetryDecision.NO_RETRY,
        LLMErrorType.INVALID_API_KEY: RetryDecision.NO_RETRY,
        LLMErrorType.INVALID_REQUEST: RetryDecision.NO_RETRY,
        LLMErrorType.MODEL_NOT_FOUND: RetryDecision.FALLBACK,
        LLMErrorType.CONTEXT_LENGTH_EXCEEDED: RetryDecision.NO_RETRY,
        LLMErrorType.RATE_LIMIT_EXCEEDED: RetryDecision.RETRY,
        LLMErrorType.CONTENT_FILTER: RetryDecision.NO_RETRY,
        LLMErrorType.PROVIDER_ERROR: RetryDecision.RETRY,
        LLMErrorType.PROVIDER_TIMEOUT: RetryDecision.RETRY,
        LLMErrorType.PROVIDER_UNAVAILABLE: RetryDecision.FALLBACK,
        LLMErrorType.NETWORK_ERROR: RetryDecision.RETRY,
        LLMErrorType.TIMEOUT_ERROR: RetryDecision.RETRY,
        LLMErrorType.CONNECTION_ERROR: RetryDecision.RETRY,
        LLMErrorType.INTERNAL_SERVER_ERROR: RetryDecision.RETRY,
        LLMErrorType.SERVICE_UNAVAILABLE: RetryDecision.FALLBACK,
        LLMErrorType.BAD_GATEWAY: RetryDecision.RETRY,
    }

    # Recovery strategy mapping
    RECOVERY_MAP: dict[LLMErrorType, RecoveryStrategy] = {
        LLMErrorType.AUTHENTICATION_ERROR: RecoveryStrategy.NONE,
        LLMErrorType.PERMISSION_DENIED: RecoveryStrategy.NONE,
        LLMErrorType.INVALID_API_KEY: RecoveryStrategy.NONE,
        LLMErrorType.INVALID_REQUEST: RecoveryStrategy.NONE,
        LLMErrorType.MODEL_NOT_FOUND: RecoveryStrategy.FALLBACK_PROVIDER,
        LLMErrorType.CONTEXT_LENGTH_EXCEEDED: RecoveryStrategy.REDUCE_PARAMETERS,
        LLMErrorType.RATE_LIMIT_EXCEEDED: RecoveryStrategy.RETRY_BACKOFF,
        LLMErrorType.CONTENT_FILTER: RecoveryStrategy.NONE,
        LLMErrorType.PROVIDER_ERROR: RecoveryStrategy.RETRY_BACKOFF,
        LLMErrorType.PROVIDER_TIMEOUT: RecoveryStrategy.RETRY_BACKOFF,
        LLMErrorType.PROVIDER_UNAVAILABLE: RecoveryStrategy.FALLBACK_PROVIDER,
        LLMErrorType.NETWORK_ERROR: RecoveryStrategy.RETRY_BACKOFF,
        LLMErrorType.TIMEOUT_ERROR: RecoveryStrategy.RETRY_BACKOFF,
        LLMErrorType.CONNECTION_ERROR: RecoveryStrategy.RETRY_BACKOFF,
        LLMErrorType.INTERNAL_SERVER_ERROR: RecoveryStrategy.RETRY_BACKOFF,
        LLMErrorType.SERVICE_UNAVAILABLE: RecoveryStrategy.FALLBACK_PROVIDER,
        LLMErrorType.BAD_GATEWAY: RecoveryStrategy.RETRY_BACKOFF,
    }

    def classify_error(self, error_type: LLMErrorType) -> dict[str, Any]:
        """Classify error and return handling metadata."""
        return {
            "severity": self.SEVERITY_MAP.get(error_type, ErrorSeverity.MEDIUM),
            "retry_decision": self.RETRY_MAP.get(error_type, RetryDecision.NO_RETRY),
            "recovery_strategy": self.RECOVERY_MAP.get(error_type, RecoveryStrategy.NONE),
            "should_retry": self.RETRY_MAP.get(error_type) == RetryDecision.RETRY,
            "should_fallback": self.RETRY_MAP.get(error_type) == RetryDecision.FALLBACK,
        }


# =============================================================================
# Retry Strategy and Backoff Logic
# =============================================================================


class RetryConfig(GibsonBaseModel):
    """Configuration for retry logic."""

    max_retries: int = Field(default=3, ge=0, le=10, description="Maximum retry attempts")
    base_delay: float = Field(default=1.0, ge=0.1, description="Base delay in seconds")
    max_delay: float = Field(default=60.0, ge=1.0, description="Maximum delay in seconds")
    exponential_base: float = Field(default=2.0, ge=1.1, description="Exponential backoff base")
    jitter: bool = Field(default=True, description="Add random jitter to delays")
    jitter_max: float = Field(default=0.1, ge=0.0, le=1.0, description="Maximum jitter ratio")

    # Error-specific retry limits
    rate_limit_max_retries: int = Field(default=5, description="Max retries for rate limits")
    timeout_max_retries: int = Field(default=3, description="Max retries for timeouts")
    network_max_retries: int = Field(default=3, description="Max retries for network errors")


class RetryStrategy:
    """Implements exponential backoff with jitter for retry logic."""

    def __init__(self, config: RetryConfig):
        self.config = config

    def get_delay(self, attempt: int, error_type: LLMErrorType | None = None) -> float:
        """Calculate delay for retry attempt."""
        # Use base exponential backoff
        delay = self.config.base_delay * (self.config.exponential_base ** attempt)

        # Apply maximum delay limit
        delay = min(delay, self.config.max_delay)

        # Add jitter if enabled
        if self.config.jitter:
            jitter_range = delay * self.config.jitter_max
            jitter = random.uniform(-jitter_range, jitter_range)
            delay = max(0.1, delay + jitter)

        # Error-specific adjustments
        if error_type == LLMErrorType.RATE_LIMIT_EXCEEDED:
            # Longer delays for rate limits
            delay *= 2
        elif error_type in [LLMErrorType.TIMEOUT_ERROR, LLMErrorType.NETWORK_ERROR]:
            # Shorter delays for network issues
            delay *= 0.5

        return delay

    def get_max_retries(self, error_type: LLMErrorType) -> int:
        """Get maximum retries for specific error type."""
        if error_type == LLMErrorType.RATE_LIMIT_EXCEEDED:
            return self.config.rate_limit_max_retries
        elif error_type == LLMErrorType.TIMEOUT_ERROR:
            return self.config.timeout_max_retries
        elif error_type in [LLMErrorType.NETWORK_ERROR, LLMErrorType.CONNECTION_ERROR]:
            return self.config.network_max_retries
        return self.config.max_retries

    def should_retry(self, attempt: int, error_type: LLMErrorType) -> bool:
        """Determine if operation should be retried."""
        max_retries = self.get_max_retries(error_type)
        return attempt < max_retries


# =============================================================================
# Circuit Breaker Pattern
# =============================================================================


class CircuitBreakerState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerConfig(GibsonBaseModel):
    """Configuration for circuit breaker."""

    failure_threshold: int = Field(default=5, ge=1, description="Failures before opening")
    recovery_timeout: int = Field(default=60, ge=1, description="Seconds before half-open")
    success_threshold: int = Field(default=3, ge=1, description="Successes to close")
    monitoring_window: int = Field(default=300, ge=60, description="Monitoring window in seconds")


class CircuitBreakerStats(TimestampedModel):
    """Circuit breaker statistics."""

    state: CircuitBreakerState = Field(default=CircuitBreakerState.CLOSED)
    failure_count: int = Field(default=0, description="Current failure count")
    success_count: int = Field(default=0, description="Current success count")
    last_failure_time: datetime | None = Field(default=None)
    state_changed_at: datetime = Field(default_factory=datetime.utcnow)

    # Historical stats
    total_failures: int = Field(default=0, description="Total failures")
    total_successes: int = Field(default=0, description="Total successes")
    state_changes: int = Field(default=0, description="Number of state changes")


class CircuitBreaker:
    """Circuit breaker implementation for provider failure handling."""

    def __init__(self, provider: str, config: CircuitBreakerConfig):
        self.provider = provider
        self.config = config
        self.stats = CircuitBreakerStats()
        self._lock = asyncio.Lock()

    async def call(self, func: Callable[[], Awaitable[Any]]) -> Any:
        """Execute function with circuit breaker protection."""
        async with self._lock:
            if not await self._can_execute():
                raise RuntimeError(f"Circuit breaker open for provider {self.provider}")

        try:
            result = await func()
            await self._record_success()
            return result
        except Exception:
            await self._record_failure()
            raise

    async def _can_execute(self) -> bool:
        """Check if execution is allowed."""
        now = datetime.utcnow()

        if self.stats.state == CircuitBreakerState.CLOSED:
            return True
        elif self.stats.state == CircuitBreakerState.OPEN:
            if self.stats.last_failure_time:
                time_since_failure = (now - self.stats.last_failure_time).total_seconds()
                if time_since_failure >= self.config.recovery_timeout:
                    # Transition to half-open
                    self.stats.state = CircuitBreakerState.HALF_OPEN
                    self.stats.state_changed_at = now
                    self.stats.state_changes += 1
                    logger.info(f"Circuit breaker half-open for provider {self.provider}")
                    return True
            return False
        else:  # HALF_OPEN
            return True

    async def _record_success(self) -> None:
        """Record successful execution."""
        self.stats.success_count += 1
        self.stats.total_successes += 1

        if (self.stats.state == CircuitBreakerState.HALF_OPEN and
                self.stats.success_count >= self.config.success_threshold):
                # Close circuit
                self.stats.state = CircuitBreakerState.CLOSED
                self.stats.state_changed_at = datetime.utcnow()
                self.stats.state_changes += 1
                self.stats.failure_count = 0
                self.stats.success_count = 0
                logger.info(f"Circuit breaker closed for provider {self.provider}")

    async def _record_failure(self) -> None:
        """Record failed execution."""
        now = datetime.utcnow()
        self.stats.failure_count += 1
        self.stats.total_failures += 1
        self.stats.last_failure_time = now

        if self.stats.state == CircuitBreakerState.CLOSED:
            if self.stats.failure_count >= self.config.failure_threshold:
                # Open circuit
                self.stats.state = CircuitBreakerState.OPEN
                self.stats.state_changed_at = now
                self.stats.state_changes += 1
                logger.warning(f"Circuit breaker opened for provider {self.provider}")
        elif self.stats.state == CircuitBreakerState.HALF_OPEN:
            # Back to open
            self.stats.state = CircuitBreakerState.OPEN
            self.stats.state_changed_at = now
            self.stats.state_changes += 1
            self.stats.success_count = 0
            logger.warning(f"Circuit breaker reopened for provider {self.provider}")

    def get_stats(self) -> dict[str, Any]:
        """Get circuit breaker statistics."""
        return {
            "provider": self.provider,
            "state": self.stats.state,
            "failure_count": self.stats.failure_count,
            "success_count": self.stats.success_count,
            "total_failures": self.stats.total_failures,
            "total_successes": self.stats.total_successes,
            "state_changes": self.stats.state_changes,
            "last_failure_time": self.stats.last_failure_time,
            "state_changed_at": self.stats.state_changed_at,
        }


# =============================================================================
# Error Recovery Strategies
# =============================================================================


class ErrorRecovery:
    """Implements error recovery strategies."""

    @staticmethod
    async def reduce_parameters(request: LLMRequest) -> LLMRequest:
        """Reduce request parameters to avoid context length issues."""
        # Create a copy of the request
        reduced_request = request.model_copy(deep=True)

        # Reduce max_tokens if set
        if reduced_request.max_tokens:
            reduced_request.max_tokens = min(
                reduced_request.max_tokens,
                int(reduced_request.max_tokens * 0.7)
            )

        # Reduce temperature for more focused responses
        if reduced_request.temperature and reduced_request.temperature > 0.3:
            reduced_request.temperature = 0.3

        # Truncate messages if too long
        if len(reduced_request.messages) > 5:
            # Keep system message and last 4 messages
            system_msgs = [msg for msg in reduced_request.messages if msg.role == "system"]
            other_msgs = [msg for msg in reduced_request.messages if msg.role != "system"]
            reduced_request.messages = system_msgs + other_msgs[-4:]

        logger.info("Reduced request parameters for retry")
        return reduced_request

    @staticmethod
    async def wait_for_rate_limit(retry_after: int | None = None) -> None:
        """Wait for rate limit to reset."""
        wait_time = retry_after or 60  # Default to 60 seconds
        logger.info(f"Rate limit exceeded, waiting {wait_time} seconds")
        await asyncio.sleep(wait_time)


# =============================================================================
# Structured Error Logging
# =============================================================================


class ErrorContext(GibsonBaseModel):
    """Context information for error logging."""

    request_id: str = Field(description="Request correlation ID")
    provider: str | None = Field(default=None, description="Provider that failed")
    model: str | None = Field(default=None, description="Model that failed")
    operation: str = Field(description="Operation being performed")
    attempt: int = Field(default=1, description="Attempt number")

    # Request metadata
    user_id: str | None = Field(default=None, description="User identifier")
    session_id: str | None = Field(default=None, description="Session identifier")

    # Timing information
    start_time: datetime = Field(default_factory=datetime.utcnow)
    duration: float | None = Field(default=None, description="Operation duration")

    # Additional context
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class ErrorLogger:
    """Structured error logging with context."""

    @staticmethod
    def log_error(
        error: LLMError,
        context: ErrorContext,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    ) -> None:
        """Log structured error with context."""
        log_data = {
            "error_type": error.type,
            "error_message": error.message,
            "error_code": error.code,
            "provider": error.provider or context.provider,
            "model": error.model or context.model,
            "request_id": error.request_id or context.request_id,
            "operation": context.operation,
            "attempt": context.attempt,
            "severity": severity,
            "user_id": context.user_id,
            "session_id": context.session_id,
            "duration": context.duration,
            "metadata": context.metadata,
        }

        # Log at appropriate level based on severity
        if severity == ErrorSeverity.CRITICAL:
            logger.critical("LLM Error", **log_data)
        elif severity == ErrorSeverity.HIGH:
            logger.error("LLM Error", **log_data)
        elif severity == ErrorSeverity.MEDIUM:
            logger.warning("LLM Error", **log_data)
        else:
            logger.info("LLM Error", **log_data)

    @staticmethod
    def log_retry(
        error: LLMError,
        context: ErrorContext,
        next_attempt: int,
        delay: float,
    ) -> None:
        """Log retry attempt."""
        logger.info(
            "LLM Retry",
            error_type=error.type,
            provider=error.provider or context.provider,
            request_id=error.request_id or context.request_id,
            attempt=context.attempt,
            next_attempt=next_attempt,
            delay=delay,
            operation=context.operation,
        )

    @staticmethod
    def log_fallback(
        error: LLMError,
        context: ErrorContext,
        fallback_provider: str,
    ) -> None:
        """Log fallback to different provider."""
        logger.warning(
            "LLM Fallback",
            error_type=error.type,
            original_provider=error.provider or context.provider,
            fallback_provider=fallback_provider,
            request_id=error.request_id or context.request_id,
            operation=context.operation,
        )

    @staticmethod
    def log_circuit_breaker(
        provider: str,
        state: CircuitBreakerState,
        failure_count: int,
    ) -> None:
        """Log circuit breaker state change."""
        logger.warning(
            "Circuit Breaker",
            provider=provider,
            state=state,
            failure_count=failure_count,
        )


# =============================================================================
# User-Friendly Error Messages
# =============================================================================


class UserErrorFormatter:
    """Formats errors for user-friendly display."""

    ERROR_MESSAGES: dict[LLMErrorType, str] = {
        LLMErrorType.AUTHENTICATION_ERROR: (
            "Authentication failed. Please check your API key and try again."
        ),
        LLMErrorType.PERMISSION_DENIED: (
            "Access denied. Your API key doesn't have permission for this operation."
        ),
        LLMErrorType.INVALID_API_KEY: (
            "Invalid API key. Please verify your API key is correct and active."
        ),
        LLMErrorType.INVALID_REQUEST: (
            "Invalid request format. Please check your request parameters."
        ),
        LLMErrorType.MODEL_NOT_FOUND: (
            "Model not available. Please check the model name or try a different model."
        ),
        LLMErrorType.CONTEXT_LENGTH_EXCEEDED: (
            "Request too long. Please reduce your message length and try again."
        ),
        LLMErrorType.RATE_LIMIT_EXCEEDED: (
            "Rate limit exceeded. Please wait a moment and try again."
        ),
        LLMErrorType.CONTENT_FILTER: (
            "Content filtered. Please modify your request to comply with content policies."
        ),
        LLMErrorType.PROVIDER_ERROR: (
            "Provider error occurred. Please try again in a moment."
        ),
        LLMErrorType.PROVIDER_TIMEOUT: (
            "Request timed out. Please try again."
        ),
        LLMErrorType.PROVIDER_UNAVAILABLE: (
            "Service temporarily unavailable. Please try again later."
        ),
        LLMErrorType.NETWORK_ERROR: (
            "Network error. Please check your connection and try again."
        ),
        LLMErrorType.TIMEOUT_ERROR: (
            "Request timed out. Please try again."
        ),
        LLMErrorType.CONNECTION_ERROR: (
            "Connection error. Please check your network and try again."
        ),
        LLMErrorType.INTERNAL_SERVER_ERROR: (
            "Internal server error. Please try again in a moment."
        ),
        LLMErrorType.SERVICE_UNAVAILABLE: (
            "Service unavailable. Please try again later."
        ),
        LLMErrorType.BAD_GATEWAY: (
            "Gateway error. Please try again in a moment."
        ),
    }

    ACTIONABLE_GUIDANCE: dict[LLMErrorType, list[str]] = {
        LLMErrorType.AUTHENTICATION_ERROR: [
            "Verify your API key is correct",
            "Check if your API key has expired",
            "Ensure you're using the right authentication method",
        ],
        LLMErrorType.RATE_LIMIT_EXCEEDED: [
            "Wait before making another request",
            "Consider implementing request batching",
            "Upgrade your plan for higher rate limits",
        ],
        LLMErrorType.CONTEXT_LENGTH_EXCEEDED: [
            "Reduce the length of your messages",
            "Split long requests into smaller chunks",
            "Use a model with a larger context window",
        ],
        LLMErrorType.MODEL_NOT_FOUND: [
            "Check the model name for typos",
            "Verify the model is available in your region",
            "Try using a different model",
        ],
        LLMErrorType.PROVIDER_UNAVAILABLE: [
            "Try again in a few minutes",
            "Switch to a different provider if configured",
            "Check the provider's status page",
        ],
    }

    @classmethod
    def format_user_error(cls, error: LLMError) -> str:
        """Format error for user display."""
        base_message = cls.ERROR_MESSAGES.get(
            error.type, f"An error occurred: {error.message}"
        )

        # Add provider-specific context
        if error.provider:
            base_message += f" (Provider: {error.provider})"

        # Add actionable guidance if available
        guidance = cls.ACTIONABLE_GUIDANCE.get(error.type)
        if guidance:
            base_message += "\n\nSuggestions:\n"
            for suggestion in guidance:
                base_message += f"• {suggestion}\n"

        return base_message.strip()

    @classmethod
    def format_retry_message(cls, error: LLMError, attempt: int, max_retries: int) -> str:
        """Format retry message for user display."""
        return f"Retrying after {error.type} (attempt {attempt}/{max_retries})..."

    @classmethod
    def format_fallback_message(cls, from_provider: str, to_provider: str) -> str:
        """Format fallback message for user display."""
        return f"Switching from {from_provider} to {to_provider} due to errors..."


# =============================================================================
# Main Error Handler Class
# =============================================================================


class LLMErrorHandler:
    """Main error handling orchestrator for LLM operations."""

    def __init__(
        self,
        retry_config: RetryConfig | None = None,
        circuit_breaker_config: CircuitBreakerConfig | None = None,
        enable_fallback: bool = True,
        fallback_providers: list[str] | None = None,
    ):
        self.retry_config = retry_config or RetryConfig()
        self.circuit_breaker_config = circuit_breaker_config or CircuitBreakerConfig()
        self.enable_fallback = enable_fallback
        self.fallback_providers = fallback_providers or []

        # Initialize components
        self.error_mapper = ProviderErrorMapping()
        self.error_classifier = ErrorClassifier()
        self.retry_strategy = RetryStrategy(self.retry_config)
        self.error_recovery = ErrorRecovery()
        self.error_logger = ErrorLogger()
        self.user_formatter = UserErrorFormatter()

        # Circuit breakers per provider
        self.circuit_breakers: dict[str, CircuitBreaker] = {}

        # Statistics
        self.stats: dict[str, int] = defaultdict(int)

    async def handle_error(
        self,
        error: Exception,
        context: ErrorContext,
        provider: LLMProvider | None = None,
    ) -> LLMError:
        """Main error handling entry point."""
        # Convert exception to LLM error
        error_type = self.error_mapper.get_error_type(error, provider)

        llm_error = LLMError(
            type=error_type,
            message=str(error),
            provider=provider,
            request_id=context.request_id,
            model=context.model,
        )

        # Extract additional details from exception
        if hasattr(error, "status_code"):
            llm_error.code = str(error.status_code)
        if hasattr(error, "retry_after"):
            llm_error.retry_after = error.retry_after

        # Classify error
        classification = self.error_classifier.classify_error(error_type)

        # Log the error
        self.error_logger.log_error(
            llm_error, context, classification["severity"]
        )

        # Update statistics
        self.stats[f"error_{error_type}"] += 1
        self.stats["total_errors"] += 1

        return llm_error

    async def retry_with_backoff(
        self,
        func: Callable[[], Awaitable[Any]],
        context: ErrorContext,
        max_retries: int | None = None,
    ) -> Any:
        """Retry function with exponential backoff."""
        last_error = None
        max_retries = max_retries or self.retry_config.max_retries

        for attempt in range(max_retries + 1):
            context.attempt = attempt + 1

            try:
                if attempt > 0:
                    # Calculate and apply delay
                    delay = self.retry_strategy.get_delay(attempt - 1, last_error.type if last_error else None)
                    await asyncio.sleep(delay)

                return await func()

            except Exception as e:
                # Handle the error
                last_error = await self.handle_error(e, context)

                # Check if we should retry
                if attempt < max_retries and self.should_retry(last_error):
                    # Log retry
                    delay = self.retry_strategy.get_delay(attempt, last_error.type)
                    self.error_logger.log_retry(last_error, context, attempt + 2, delay)
                    continue
                else:
                    # Final attempt failed
                    break

        # All retries exhausted, raise the last error
        if last_error:
            raise Exception(last_error.message)
        else:
            raise Exception("Unknown error occurred")

    def should_retry(self, error: LLMError) -> bool:
        """Determine if error should be retried."""
        classification = self.error_classifier.classify_error(error.type)
        return bool(classification["should_retry"])

    def classify_error(self, error: Exception, provider: LLMProvider | None = None) -> LLMErrorType:
        """Classify exception into LLM error type."""
        return self.error_mapper.get_error_type(error, provider)

    async def recover_from_error(
        self,
        error: LLMError,
        request: LLMRequest,
    ) -> LLMRequest | None:
        """Attempt to recover from error by modifying request."""
        classification = self.error_classifier.classify_error(error.type)
        strategy = classification["recovery_strategy"]

        if strategy == RecoveryStrategy.REDUCE_PARAMETERS:
            return await self.error_recovery.reduce_parameters(request)
        elif strategy == RecoveryStrategy.RETRY_BACKOFF and error.retry_after:
            await self.error_recovery.wait_for_rate_limit(error.retry_after)
            return request

        return None

    def format_user_error(self, error: LLMError) -> str:
        """Format error for user display."""
        return self.user_formatter.format_user_error(error)

    async def handle_rate_limit(
        self,
        provider: str,
        retry_after: int | None = None,
    ) -> None:
        """Handle rate limit with appropriate backoff."""
        await self.error_recovery.wait_for_rate_limit(retry_after)
        self.stats[f"rate_limit_{provider}"] += 1

    async def handle_quota_exceeded(self, provider: str) -> bool:
        """Handle quota exceeded error."""
        self.stats[f"quota_exceeded_{provider}"] += 1

        # Check if fallback providers are available
        if self.enable_fallback and self.fallback_providers:
            remaining_providers = [p for p in self.fallback_providers if p != provider]
            return len(remaining_providers) > 0

        return False

    async def circuit_breaker_check(self, provider: str) -> bool:
        """Check if provider circuit breaker allows execution."""
        if provider not in self.circuit_breakers:
            self.circuit_breakers[provider] = CircuitBreaker(
                provider, self.circuit_breaker_config
            )

        circuit_breaker = self.circuit_breakers[provider]
        return await circuit_breaker._can_execute()

    def get_stats(self) -> dict[str, Any]:
        """Get error handling statistics."""
        circuit_breaker_stats = {}
        for provider, cb in self.circuit_breakers.items():
            circuit_breaker_stats[provider] = cb.get_stats()

        return {
            "error_counts": dict(self.stats),
            "circuit_breakers": circuit_breaker_stats,
        }


# =============================================================================
# Decorators for Automatic Error Handling
# =============================================================================


def with_retry(
    max_retries: int = 3,
    error_handler: LLMErrorHandler | None = None,
) -> Callable[[F], F]:
    """Decorator to add automatic retry logic to async functions."""

    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            handler = error_handler or LLMErrorHandler()
            context = ErrorContext(
                request_id=str(uuid4()),
                operation=func.__name__,
            )

            return await handler.retry_with_backoff(
                lambda: func(*args, **kwargs),
                context,
                max_retries,
            )

        return wrapper  # type: ignore[return-value]

    return decorator


def with_fallback(
    fallback_providers: list[str],
    error_handler: LLMErrorHandler | None = None,
) -> Callable[[F], F]:
    """Decorator to add automatic fallback to other providers."""

    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            _ = error_handler or LLMErrorHandler(
                enable_fallback=True,
                fallback_providers=fallback_providers,
            )

            last_error = None

            # Try each provider in order
            for provider in [None] + fallback_providers:  # None = original provider
                try:
                    if provider:
                        # Modify kwargs to use fallback provider
                        kwargs_copy = kwargs.copy()
                        if "provider" in kwargs_copy:
                            kwargs_copy["provider"] = provider
                    else:
                        kwargs_copy = kwargs

                    return await func(*args, **kwargs_copy)

                except Exception as e:
                    last_error = e
                    if provider:
                        logger.warning(f"Fallback provider {provider} failed: {e}")
                    continue

            # All providers failed
            raise last_error or Exception("All providers failed")

        return wrapper  # type: ignore[return-value]

    return decorator


def with_circuit_breaker(
    provider: str,
    error_handler: LLMErrorHandler | None = None,
) -> Callable[[F], F]:
    """Decorator to add circuit breaker protection."""

    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            handler = error_handler or LLMErrorHandler()

            if provider not in handler.circuit_breakers:
                handler.circuit_breakers[provider] = CircuitBreaker(
                    provider, handler.circuit_breaker_config
                )

            circuit_breaker = handler.circuit_breakers[provider]
            return await circuit_breaker.call(lambda: func(*args, **kwargs))

        return wrapper  # type: ignore[return-value]

    return decorator


# Example usage and factory function
def create_error_handler(
    max_retries: int = 3,
    enable_circuit_breaker: bool = True,
    enable_fallback: bool = True,
    fallback_providers: list[str] | None = None,
) -> LLMErrorHandler:
    """Factory function to create configured error handler."""

    retry_config = RetryConfig(max_retries=max_retries)
    circuit_breaker_config = CircuitBreakerConfig() if enable_circuit_breaker else None

    return LLMErrorHandler(
        retry_config=retry_config,
        circuit_breaker_config=circuit_breaker_config,
        enable_fallback=enable_fallback,
        fallback_providers=fallback_providers or [],
    )

