"""Authentication error handling and recovery mechanisms."""

import asyncio
import logging
from typing import Optional, Dict, Any, Callable, TypeVar, List
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta
import traceback

from gibson.core.auth.audit import audit_log, AuditEventType


logger = logging.getLogger(__name__)

T = TypeVar("T")


class AuthErrorType(str, Enum):
    """Types of authentication errors."""

    INVALID_CREDENTIALS = "invalid_credentials"
    EXPIRED_TOKEN = "expired_token"
    RATE_LIMITED = "rate_limited"
    NETWORK_ERROR = "network_error"
    PERMISSION_DENIED = "permission_denied"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    MALFORMED_REQUEST = "malformed_request"
    ENCRYPTION_ERROR = "encryption_error"
    STORAGE_ERROR = "storage_error"
    VALIDATION_ERROR = "validation_error"
    UNKNOWN_ERROR = "unknown_error"


@dataclass
class AuthError:
    """Authentication error details."""

    error_type: AuthErrorType
    message: str
    credential_name: Optional[str] = None
    provider: Optional[str] = None
    timestamp: datetime = None
    retry_after: Optional[int] = None
    recoverable: bool = True
    details: Dict[str, Any] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.details is None:
            self.details = {}


class RetryPolicy:
    """Retry policy for authentication operations."""

    def __init__(
        self,
        max_retries: int = 3,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
    ):
        """Initialize retry policy.

        Args:
            max_retries: Maximum number of retry attempts
            initial_delay: Initial delay between retries (seconds)
            max_delay: Maximum delay between retries (seconds)
            exponential_base: Base for exponential backoff
            jitter: Add random jitter to delays
        """
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt."""
        delay = min(self.initial_delay * (self.exponential_base**attempt), self.max_delay)

        if self.jitter:
            import random

            delay *= 0.5 + random.random()

        return delay


class CircuitBreaker:
    """Circuit breaker for authentication services."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        half_open_max_calls: int = 3,
    ):
        """Initialize circuit breaker.

        Args:
            failure_threshold: Failures before opening circuit
            recovery_timeout: Seconds before attempting recovery
            half_open_max_calls: Max calls in half-open state
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half_open
        self.half_open_calls = 0

    def call_succeeded(self):
        """Record successful call."""
        if self.state == "half_open":
            self.half_open_calls += 1
            if self.half_open_calls >= self.half_open_max_calls:
                # Enough successful calls, close circuit
                self.state = "closed"
                self.failure_count = 0
                self.half_open_calls = 0
                logger.info("Circuit breaker closed after recovery")
        elif self.state == "closed":
            self.failure_count = max(0, self.failure_count - 1)

    def call_failed(self):
        """Record failed call."""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()

        if self.state == "half_open":
            # Failure in half-open, back to open
            self.state = "open"
            self.half_open_calls = 0
            logger.warning("Circuit breaker reopened after half-open failure")
        elif self.failure_count >= self.failure_threshold:
            self.state = "open"
            logger.error(f"Circuit breaker opened after {self.failure_count} failures")

    def is_available(self) -> bool:
        """Check if service is available."""
        if self.state == "closed":
            return True

        if self.state == "open":
            # Check if recovery timeout has passed
            if self.last_failure_time:
                elapsed = (datetime.utcnow() - self.last_failure_time).seconds
                if elapsed >= self.recovery_timeout:
                    # Try half-open state
                    self.state = "half_open"
                    self.half_open_calls = 0
                    logger.info("Circuit breaker entering half-open state")
                    return True
            return False

        # Half-open state
        return self.half_open_calls < self.half_open_max_calls


class AuthErrorHandler:
    """Handles authentication errors with recovery strategies."""

    def __init__(
        self,
        retry_policy: Optional[RetryPolicy] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ):
        """Initialize error handler.

        Args:
            retry_policy: Retry policy for operations
            circuit_breaker: Circuit breaker for service protection
        """
        self.retry_policy = retry_policy or RetryPolicy()
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self.error_history: List[AuthError] = []
        self.recovery_strategies: Dict[AuthErrorType, Callable] = {}

        # Register default recovery strategies
        self._register_default_strategies()

    def _register_default_strategies(self):
        """Register default recovery strategies for error types."""
        self.recovery_strategies[AuthErrorType.EXPIRED_TOKEN] = self._recover_expired_token
        self.recovery_strategies[AuthErrorType.RATE_LIMITED] = self._recover_rate_limited
        self.recovery_strategies[AuthErrorType.NETWORK_ERROR] = self._recover_network_error
        self.recovery_strategies[
            AuthErrorType.PROVIDER_UNAVAILABLE
        ] = self._recover_provider_unavailable

    async def handle_error(
        self,
        error: Exception,
        context: Dict[str, Any],
    ) -> Optional[AuthError]:
        """Handle authentication error.

        Args:
            error: The exception that occurred
            context: Context information about the operation

        Returns:
            AuthError object with details
        """
        # Classify error
        auth_error = self._classify_error(error, context)

        # Log error
        self.error_history.append(auth_error)
        logger.error(f"Authentication error: {auth_error.message}", exc_info=error)

        # Audit log
        await audit_log(
            AuditEventType.AUTH_FAILURE,
            success=False,
            credential_name=auth_error.credential_name,
            provider=auth_error.provider,
            message=auth_error.message,
            metadata={
                "error_type": auth_error.error_type.value,
                "recoverable": auth_error.recoverable,
            },
        )

        # Update circuit breaker
        self.circuit_breaker.call_failed()

        return auth_error

    def _classify_error(
        self,
        error: Exception,
        context: Dict[str, Any],
    ) -> AuthError:
        """Classify exception into AuthError."""
        error_str = str(error).lower()

        # Check for specific error patterns
        if "invalid" in error_str or "unauthorized" in error_str:
            error_type = AuthErrorType.INVALID_CREDENTIALS
        elif "expired" in error_str or "token" in error_str:
            error_type = AuthErrorType.EXPIRED_TOKEN
        elif "rate" in error_str or "limit" in error_str:
            error_type = AuthErrorType.RATE_LIMITED
        elif "network" in error_str or "connection" in error_str:
            error_type = AuthErrorType.NETWORK_ERROR
        elif "permission" in error_str or "denied" in error_str:
            error_type = AuthErrorType.PERMISSION_DENIED
        elif "unavailable" in error_str or "service" in error_str:
            error_type = AuthErrorType.PROVIDER_UNAVAILABLE
        elif "encrypt" in error_str or "decrypt" in error_str:
            error_type = AuthErrorType.ENCRYPTION_ERROR
        elif "storage" in error_str or "database" in error_str:
            error_type = AuthErrorType.STORAGE_ERROR
        else:
            error_type = AuthErrorType.UNKNOWN_ERROR

        return AuthError(
            error_type=error_type,
            message=str(error),
            credential_name=context.get("credential_name"),
            provider=context.get("provider"),
            recoverable=error_type
            not in [
                AuthErrorType.INVALID_CREDENTIALS,
                AuthErrorType.PERMISSION_DENIED,
            ],
            details={
                "exception_type": type(error).__name__,
                "traceback": traceback.format_exc(),
                **context,
            },
        )

    async def with_retry(
        self,
        operation: Callable,
        context: Dict[str, Any],
        *args,
        **kwargs,
    ) -> Any:
        """Execute operation with retry logic.

        Args:
            operation: Async operation to execute
            context: Context for error handling
            *args: Arguments for operation
            **kwargs: Keyword arguments for operation

        Returns:
            Result of operation

        Raises:
            Last exception if all retries fail
        """
        last_error = None

        for attempt in range(self.retry_policy.max_retries + 1):
            try:
                # Check circuit breaker
                if not self.circuit_breaker.is_available():
                    raise Exception("Service unavailable (circuit open)")

                # Execute operation
                result = await operation(*args, **kwargs)

                # Success - update circuit breaker
                self.circuit_breaker.call_succeeded()

                # Log recovery if this was a retry
                if attempt > 0:
                    logger.info(f"Operation succeeded after {attempt} retries")
                    await audit_log(
                        AuditEventType.AUTH_SUCCESS,
                        success=True,
                        message=f"Recovered after {attempt} retries",
                        metadata=context,
                    )

                return result

            except Exception as e:
                last_error = e
                auth_error = await self.handle_error(e, context)

                # Check if recoverable
                if not auth_error.recoverable:
                    logger.error(f"Non-recoverable error: {auth_error.message}")
                    raise

                # Check if we have retries left
                if attempt >= self.retry_policy.max_retries:
                    logger.error(f"Max retries ({self.retry_policy.max_retries}) exceeded")
                    raise

                # Calculate delay
                delay = self.retry_policy.get_delay(attempt)

                # Check for rate limit with specific delay
                if auth_error.retry_after:
                    delay = max(delay, auth_error.retry_after)

                logger.warning(f"Retrying after {delay:.1f}s (attempt {attempt + 1})")
                await asyncio.sleep(delay)

                # Try recovery strategy if available
                if auth_error.error_type in self.recovery_strategies:
                    recovery_fn = self.recovery_strategies[auth_error.error_type]
                    await recovery_fn(auth_error, context)

        raise last_error

    async def _recover_expired_token(
        self,
        error: AuthError,
        context: Dict[str, Any],
    ) -> None:
        """Recovery strategy for expired tokens."""
        logger.info("Attempting token refresh for expired credential")
        # In a real implementation, this would refresh the token
        # For now, just log the attempt
        context["token_refreshed"] = True

    async def _recover_rate_limited(
        self,
        error: AuthError,
        context: Dict[str, Any],
    ) -> None:
        """Recovery strategy for rate limiting."""
        logger.info(f"Rate limited, waiting {error.retry_after}s")
        if error.retry_after:
            await asyncio.sleep(error.retry_after)

    async def _recover_network_error(
        self,
        error: AuthError,
        context: Dict[str, Any],
    ) -> None:
        """Recovery strategy for network errors."""
        logger.info("Network error detected, checking connectivity")
        # Could implement connectivity check here
        context["network_retry"] = True

    async def _recover_provider_unavailable(
        self,
        error: AuthError,
        context: Dict[str, Any],
    ) -> None:
        """Recovery strategy for provider unavailability."""
        logger.info("Provider unavailable, considering fallback")
        # Could implement fallback provider logic
        context["fallback_attempted"] = True

    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics."""
        if not self.error_history:
            return {
                "total_errors": 0,
                "error_types": {},
                "recoverable_errors": 0,
                "circuit_state": self.circuit_breaker.state,
            }

        error_types = {}
        recoverable_count = 0

        for error in self.error_history:
            error_type = error.error_type.value
            error_types[error_type] = error_types.get(error_type, 0) + 1
            if error.recoverable:
                recoverable_count += 1

        recent_errors = self.error_history[-10:]

        return {
            "total_errors": len(self.error_history),
            "error_types": error_types,
            "recoverable_errors": recoverable_count,
            "recovery_rate": recoverable_count / len(self.error_history),
            "recent_errors": [
                {
                    "type": e.error_type.value,
                    "message": e.message,
                    "timestamp": e.timestamp.isoformat(),
                }
                for e in recent_errors
            ],
            "circuit_state": self.circuit_breaker.state,
            "circuit_failures": self.circuit_breaker.failure_count,
        }

    def clear_error_history(self, older_than: Optional[timedelta] = None) -> int:
        """Clear error history.

        Args:
            older_than: Clear only errors older than this duration

        Returns:
            Number of errors cleared
        """
        if older_than:
            cutoff = datetime.utcnow() - older_than
            original_count = len(self.error_history)
            self.error_history = [e for e in self.error_history if e.timestamp > cutoff]
            return original_count - len(self.error_history)
        else:
            count = len(self.error_history)
            self.error_history.clear()
            return count


# Global error handler instance
_error_handler: Optional[AuthErrorHandler] = None


def get_error_handler() -> AuthErrorHandler:
    """Get global error handler instance."""
    global _error_handler
    if _error_handler is None:
        _error_handler = AuthErrorHandler()
    return _error_handler
