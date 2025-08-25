"""Error handling utilities for authentication system.

Provides comprehensive error handling, recovery strategies,
and error categorization for the authentication subsystem.
"""

import traceback
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, Union
from uuid import uuid4

from loguru import logger
from pydantic import BaseModel

from gibson.core.auth.audit_logger import AuditEventSeverity, AuditEventType, get_audit_logger


class ErrorCategory(str, Enum):
    """Categories of authentication errors."""

    # Authentication errors
    INVALID_CREDENTIALS = "invalid_credentials"
    EXPIRED_CREDENTIALS = "expired_credentials"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    AUTHENTICATION_TIMEOUT = "authentication_timeout"

    # Configuration errors
    INVALID_CONFIGURATION = "invalid_configuration"
    MISSING_CONFIGURATION = "missing_configuration"
    CONFIGURATION_CONFLICT = "configuration_conflict"

    # Storage errors
    STORAGE_CONNECTION_FAILED = "storage_connection_failed"
    STORAGE_PERMISSION_DENIED = "storage_permission_denied"
    STORAGE_CORRUPTED_DATA = "storage_corrupted_data"
    STORAGE_QUOTA_EXCEEDED = "storage_quota_exceeded"

    # Encryption errors
    ENCRYPTION_FAILED = "encryption_failed"
    DECRYPTION_FAILED = "decryption_failed"
    KEY_MANAGEMENT_ERROR = "key_management_error"
    CRYPTO_ALGORITHM_ERROR = "crypto_algorithm_error"

    # Network errors
    NETWORK_CONNECTION_FAILED = "network_connection_failed"
    NETWORK_TIMEOUT = "network_timeout"
    API_RATE_LIMITED = "api_rate_limited"
    SERVICE_UNAVAILABLE = "service_unavailable"

    # Validation errors
    INVALID_INPUT = "invalid_input"
    SCHEMA_VALIDATION_FAILED = "schema_validation_failed"
    CONSTRAINT_VIOLATION = "constraint_violation"

    # System errors
    RESOURCE_EXHAUSTED = "resource_exhausted"
    SYSTEM_OVERLOAD = "system_overload"
    DEPENDENCY_FAILURE = "dependency_failure"
    UNKNOWN_ERROR = "unknown_error"


class ErrorSeverity(str, Enum):
    """Severity levels for errors."""

    LOW = "low"  # Minor issues, service continues
    MEDIUM = "medium"  # Moderate issues, some functionality affected
    HIGH = "high"  # Serious issues, significant functionality affected
    CRITICAL = "critical"  # Critical issues, service may be unavailable


class RecoveryStrategy(str, Enum):
    """Error recovery strategies."""

    RETRY = "retry"  # Retry the operation
    RETRY_WITH_BACKOFF = "retry_with_backoff"  # Retry with exponential backoff
    FALLBACK = "fallback"  # Use fallback mechanism
    FAIL_FAST = "fail_fast"  # Fail immediately
    IGNORE = "ignore"  # Ignore the error
    ESCALATE = "escalate"  # Escalate to higher level
    CIRCUIT_BREAKER = "circuit_breaker"  # Open circuit breaker


class AuthenticationError(Exception):
    """Base exception for authentication system errors."""

    def __init__(
        self,
        message: str,
        category: ErrorCategory = ErrorCategory.UNKNOWN_ERROR,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        recovery_strategy: RecoveryStrategy = RecoveryStrategy.FAIL_FAST,
        retryable: bool = False,
    ):
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.error_code = error_code or f"AUTH_{category.value.upper()}"
        self.details = details or {}
        self.recovery_strategy = recovery_strategy
        self.retryable = retryable
        self.error_id = str(uuid4())

        # Add stack trace to details
        self.details["stack_trace"] = traceback.format_exc()


class CredentialError(AuthenticationError):
    """Credential-related errors."""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, category=ErrorCategory.INVALID_CREDENTIALS, **kwargs)


class ConfigurationError(AuthenticationError):
    """Configuration-related errors."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.INVALID_CONFIGURATION,
            severity=ErrorSeverity.HIGH,
            **kwargs,
        )


class StorageError(AuthenticationError):
    """Storage-related errors."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.STORAGE_CONNECTION_FAILED,
            retryable=True,
            recovery_strategy=RecoveryStrategy.RETRY_WITH_BACKOFF,
            **kwargs,
        )


class EncryptionError(AuthenticationError):
    """Encryption-related errors."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message, category=ErrorCategory.ENCRYPTION_FAILED, severity=ErrorSeverity.HIGH, **kwargs
        )


class ValidationError(AuthenticationError):
    """Validation-related errors."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message, category=ErrorCategory.INVALID_INPUT, severity=ErrorSeverity.LOW, **kwargs
        )


class NetworkError(AuthenticationError):
    """Network-related errors."""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.NETWORK_CONNECTION_FAILED,
            retryable=True,
            recovery_strategy=RecoveryStrategy.RETRY_WITH_BACKOFF,
            **kwargs,
        )


class ErrorContext(BaseModel):
    """Context information for error handling."""

    operation: str
    target_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    timestamp: str
    additional_context: Dict[str, Any] = {}


class ErrorHandler:
    """Centralized error handler for authentication system."""

    def __init__(self):
        """Initialize error handler."""
        self.error_counts: Dict[str, int] = {}
        self.recovery_handlers: Dict[ErrorCategory, Callable] = {}
        self.circuit_breakers: Dict[str, Dict[str, Any]] = {}

        # Setup default recovery handlers
        self._setup_default_handlers()

    def _setup_default_handlers(self) -> None:
        """Setup default error recovery handlers."""
        self.recovery_handlers = {
            ErrorCategory.NETWORK_CONNECTION_FAILED: self._handle_network_error,
            ErrorCategory.STORAGE_CONNECTION_FAILED: self._handle_storage_error,
            ErrorCategory.API_RATE_LIMITED: self._handle_rate_limit_error,
            ErrorCategory.ENCRYPTION_FAILED: self._handle_encryption_error,
            ErrorCategory.INVALID_CREDENTIALS: self._handle_credential_error,
        }

    def handle_error(
        self, error: Exception, context: Optional[ErrorContext] = None, auto_recover: bool = True
    ) -> Optional[Any]:
        """Handle an error with appropriate recovery strategy.

        Args:
            error: The error to handle
            context: Error context information
            auto_recover: Whether to attempt automatic recovery

        Returns:
            Recovery result if successful, None otherwise
        """
        # Convert to AuthenticationError if needed
        if not isinstance(error, AuthenticationError):
            error = AuthenticationError(
                message=str(error),
                category=self._categorize_error(error),
                details={"original_error": str(error)},
            )

        # Log error
        self._log_error(error, context)

        # Update error counts
        self._update_error_counts(error)

        # Audit log
        self._audit_error(error, context)

        # Attempt recovery if enabled
        if auto_recover:
            return self._attempt_recovery(error, context)

        return None

    def _categorize_error(self, error: Exception) -> ErrorCategory:
        """Categorize an unknown error."""
        error_str = str(error).lower()

        if "connection" in error_str or "network" in error_str:
            return ErrorCategory.NETWORK_CONNECTION_FAILED
        elif "permission" in error_str or "access" in error_str:
            return ErrorCategory.UNAUTHORIZED_ACCESS
        elif "timeout" in error_str:
            return ErrorCategory.NETWORK_TIMEOUT
        elif "encryption" in error_str or "decrypt" in error_str:
            return ErrorCategory.ENCRYPTION_FAILED
        elif "validation" in error_str or "invalid" in error_str:
            return ErrorCategory.INVALID_INPUT
        else:
            return ErrorCategory.UNKNOWN_ERROR

    def _log_error(self, error: AuthenticationError, context: Optional[ErrorContext]) -> None:
        """Log error with appropriate level."""
        log_level = {
            ErrorSeverity.LOW: "info",
            ErrorSeverity.MEDIUM: "warning",
            ErrorSeverity.HIGH: "error",
            ErrorSeverity.CRITICAL: "critical",
        }.get(error.severity, "error")

        log_data = {
            "error_id": error.error_id,
            "error_code": error.error_code,
            "category": error.category.value,
            "severity": error.severity.value,
            "recovery_strategy": error.recovery_strategy.value,
            "retryable": error.retryable,
            "details": error.details,
        }

        if context:
            log_data["context"] = context.model_dump()

        getattr(logger, log_level)(f"Authentication error: {error.message}", **log_data)

    def _update_error_counts(self, error: AuthenticationError) -> None:
        """Update error count statistics."""
        key = f"{error.category.value}:{error.error_code}"
        self.error_counts[key] = self.error_counts.get(key, 0) + 1

        # Check for error thresholds
        if self.error_counts[key] > 10:  # Threshold
            logger.warning(f"High error count for {key}: {self.error_counts[key]}")

    def _audit_error(self, error: AuthenticationError, context: Optional[ErrorContext]) -> None:
        """Log error to audit system."""
        audit_logger = get_audit_logger()

        # Map error severity to audit severity
        audit_severity = {
            ErrorSeverity.LOW: AuditEventSeverity.LOW,
            ErrorSeverity.MEDIUM: AuditEventSeverity.MEDIUM,
            ErrorSeverity.HIGH: AuditEventSeverity.HIGH,
            ErrorSeverity.CRITICAL: AuditEventSeverity.CRITICAL,
        }.get(error.severity, AuditEventSeverity.MEDIUM)

        audit_logger.log_security_event(
            event_type=AuditEventType.AUTH_VALIDATION_ERROR,
            description=f"Authentication error: {error.message}",
            severity=audit_severity,
            user_id=context.user_id if context else None,
            details={
                "error_id": error.error_id,
                "error_code": error.error_code,
                "category": error.category.value,
                "recovery_strategy": error.recovery_strategy.value,
                "operation": context.operation if context else "unknown",
            },
        )

    def _attempt_recovery(
        self, error: AuthenticationError, context: Optional[ErrorContext]
    ) -> Optional[Any]:
        """Attempt error recovery based on strategy."""
        try:
            if error.recovery_strategy == RecoveryStrategy.RETRY:
                return self._retry_operation(error, context)

            elif error.recovery_strategy == RecoveryStrategy.RETRY_WITH_BACKOFF:
                return self._retry_with_backoff(error, context)

            elif error.recovery_strategy == RecoveryStrategy.FALLBACK:
                return self._use_fallback(error, context)

            elif error.recovery_strategy == RecoveryStrategy.CIRCUIT_BREAKER:
                return self._handle_circuit_breaker(error, context)

            elif error.category in self.recovery_handlers:
                return self.recovery_handlers[error.category](error, context)

            else:
                logger.info(f"No recovery strategy for {error.category.value}")
                return None

        except Exception as recovery_error:
            logger.error(f"Recovery failed: {recovery_error}")
            return None

    def _retry_operation(
        self, error: AuthenticationError, context: Optional[ErrorContext], max_retries: int = 3
    ) -> Optional[Any]:
        """Retry operation with simple retry logic."""
        if not error.retryable:
            return None

        retry_count = error.details.get("retry_count", 0)
        if retry_count >= max_retries:
            logger.error(f"Max retries exceeded for {error.error_code}")
            return None

        error.details["retry_count"] = retry_count + 1
        logger.info(f"Retrying operation, attempt {retry_count + 1}/{max_retries}")

        # In a real implementation, would retry the actual operation
        return None

    def _retry_with_backoff(
        self, error: AuthenticationError, context: Optional[ErrorContext], max_retries: int = 3
    ) -> Optional[Any]:
        """Retry operation with exponential backoff."""
        import time

        if not error.retryable:
            return None

        retry_count = error.details.get("retry_count", 0)
        if retry_count >= max_retries:
            logger.error(f"Max retries with backoff exceeded for {error.error_code}")
            return None

        # Calculate backoff delay
        delay = 2**retry_count  # Exponential backoff
        logger.info(
            f"Retrying with backoff, waiting {delay}s, attempt {retry_count + 1}/{max_retries}"
        )

        time.sleep(delay)
        error.details["retry_count"] = retry_count + 1

        # In a real implementation, would retry the actual operation
        return None

    def _use_fallback(
        self, error: AuthenticationError, context: Optional[ErrorContext]
    ) -> Optional[Any]:
        """Use fallback mechanism."""
        logger.info(f"Using fallback for {error.category.value}")

        # Implementation would depend on the specific error type
        # For example, use cached credentials, alternative endpoints, etc.
        return None

    def _handle_circuit_breaker(
        self, error: AuthenticationError, context: Optional[ErrorContext]
    ) -> Optional[Any]:
        """Handle circuit breaker pattern."""
        operation = context.operation if context else "unknown"

        if operation not in self.circuit_breakers:
            self.circuit_breakers[operation] = {
                "state": "closed",  # closed, open, half_open
                "failure_count": 0,
                "last_failure": None,
                "timeout": 60,  # seconds
            }

        circuit = self.circuit_breakers[operation]
        circuit["failure_count"] += 1

        if circuit["failure_count"] >= 5:  # Threshold
            circuit["state"] = "open"
            circuit["last_failure"] = time.time()
            logger.warning(f"Circuit breaker opened for {operation}")

        return None

    # Specific error handlers

    def _handle_network_error(
        self, error: AuthenticationError, context: Optional[ErrorContext]
    ) -> Optional[Any]:
        """Handle network-related errors."""
        logger.info("Handling network error with retry strategy")
        return self._retry_with_backoff(error, context)

    def _handle_storage_error(
        self, error: AuthenticationError, context: Optional[ErrorContext]
    ) -> Optional[Any]:
        """Handle storage-related errors."""
        logger.info("Handling storage error with fallback strategy")

        # Could implement fallback to alternative storage
        return None

    def _handle_rate_limit_error(
        self, error: AuthenticationError, context: Optional[ErrorContext]
    ) -> Optional[Any]:
        """Handle rate limit errors."""
        import time

        # Extract rate limit info if available
        retry_after = error.details.get("retry_after", 60)
        logger.info(f"Rate limited, waiting {retry_after}s")

        time.sleep(retry_after)
        return self._retry_operation(error, context, max_retries=1)

    def _handle_encryption_error(
        self, error: AuthenticationError, context: Optional[ErrorContext]
    ) -> Optional[Any]:
        """Handle encryption-related errors."""
        logger.error("Encryption error detected - manual intervention required")

        # Encryption errors typically require manual intervention
        # Could implement key rotation, re-encryption, etc.
        return None

    def _handle_credential_error(
        self, error: AuthenticationError, context: Optional[ErrorContext]
    ) -> Optional[Any]:
        """Handle credential-related errors."""
        logger.info("Handling credential error")

        # Could implement credential refresh, alternative credentials, etc.
        return None

    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics."""
        total_errors = sum(self.error_counts.values())

        return {
            "total_errors": total_errors,
            "error_counts": dict(self.error_counts),
            "circuit_breakers": dict(self.circuit_breakers),
            "top_errors": sorted(self.error_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        }

    def reset_error_counts(self) -> None:
        """Reset error count statistics."""
        self.error_counts.clear()
        logger.info("Error count statistics reset")


# Global error handler instance
_error_handler: Optional[ErrorHandler] = None


def get_error_handler() -> ErrorHandler:
    """Get the global error handler instance."""
    global _error_handler
    if _error_handler is None:
        _error_handler = ErrorHandler()
    return _error_handler


def handle_auth_error(
    error: Exception,
    operation: str,
    target_id: Optional[str] = None,
    user_id: Optional[str] = None,
    auto_recover: bool = True,
) -> Optional[Any]:
    """Convenience function to handle authentication errors.

    Args:
        error: The error to handle
        operation: Operation being performed
        target_id: Target ID if applicable
        user_id: User ID if applicable
        auto_recover: Whether to attempt automatic recovery

    Returns:
        Recovery result if successful, None otherwise
    """
    import datetime

    context = ErrorContext(
        operation=operation,
        target_id=target_id,
        user_id=user_id,
        timestamp=datetime.datetime.now().isoformat(),
    )

    error_handler = get_error_handler()
    return error_handler.handle_error(error, context, auto_recover)


# Decorator for automatic error handling
def handle_errors(operation: str, auto_recover: bool = True, re_raise: bool = True):
    """Decorator for automatic error handling."""

    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                result = handle_auth_error(error=e, operation=operation, auto_recover=auto_recover)

                if result is not None:
                    return result

                if re_raise:
                    raise

                return None

        return wrapper

    return decorator
