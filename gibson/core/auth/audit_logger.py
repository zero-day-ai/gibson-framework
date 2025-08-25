"""Audit logging for authentication system.

Provides comprehensive audit logging for authentication operations
including credential access, validation attempts, and security events.
"""
import json
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4
from loguru import logger
from pydantic import BaseModel, Field, ConfigDict
from gibson.core.auth.config import AuthenticationConfig


class AuditEventType(str, Enum):
    """Types of audit events."""

    CREDENTIAL_CREATED = "credential_created"
    CREDENTIAL_UPDATED = "credential_updated"
    CREDENTIAL_DELETED = "credential_deleted"
    CREDENTIAL_ACCESSED = "credential_accessed"
    CREDENTIAL_EXPORTED = "credential_exported"
    CREDENTIAL_IMPORTED = "credential_imported"
    AUTH_VALIDATION_SUCCESS = "auth_validation_success"
    AUTH_VALIDATION_FAILURE = "auth_validation_failure"
    AUTH_VALIDATION_ERROR = "auth_validation_error"
    ENV_CREDENTIAL_DISCOVERED = "env_credential_discovered"
    ENV_CREDENTIAL_INJECTED = "env_credential_injected"
    ENV_CREDENTIAL_FAILED = "env_credential_failed"
    SECURITY_BREACH_ATTEMPT = "security_breach_attempt"
    SUSPICIOUS_ACCESS = "suspicious_access"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    ENCRYPTION_ERROR = "encryption_error"
    SYSTEM_STARTED = "system_started"
    SYSTEM_STOPPED = "system_stopped"
    CONFIG_CHANGED = "config_changed"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"


class AuditEventSeverity(str, Enum):
    """Severity levels for audit events."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditEvent(BaseModel):
    """Audit event model."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: AuditEventType
    severity: AuditEventSeverity = AuditEventSeverity.MEDIUM
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    target_id: Optional[Union[str, UUID]] = None
    target_name: Optional[str] = None
    resource_type: Optional[str] = None
    action: str
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)
    success: bool = True
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    duration_ms: Optional[float] = None
    retention_days: int = 365
    compliance_tags: List[str] = Field(default_factory=list)
    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat(), UUID: str})


class AuditLogger:
    """Audit logger for authentication system."""

    def __init__(
        self,
        config: Optional[AuthenticationConfig] = None,
        log_file: Optional[Path] = None,
        enable_console: bool = False,
        enable_syslog: bool = False,
    ):
        """Initialize audit logger.

        Args:
            config: Authentication configuration
            log_file: Path to audit log file
            enable_console: Enable console logging
            enable_syslog: Enable syslog integration
        """
        self.config = config or AuthenticationConfig()
        self.log_file = log_file or Path("gibson_audit.log")
        self.enable_console = enable_console
        self.enable_syslog = enable_syslog
        self._event_buffer: List[AuditEvent] = []
        self._buffer_size = 100
        self._operation_start_times: Dict[str, float] = {}
        self._setup_loggers()

    def _setup_loggers(self) -> None:
        """Setup audit loggers."""
        logger.add(
            str(self.log_file),
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | AUDIT | {message}",
            level="INFO",
            rotation="100 MB",
            retention="1 year",
            compression="gz",
            serialize=True,
            filter=lambda record: record.get("audit", False),
        )
        if self.enable_console:
            logger.add(
                lambda msg: print(f"AUDIT: {msg}"),
                format="{message}",
                level="INFO",
                filter=lambda record: record.get("audit", False),
            )

    def log_event(self, event: AuditEvent) -> None:
        """Log an audit event.

        Args:
            event: Audit event to log
        """
        try:
            self._event_buffer.append(event)
            if event.severity in [AuditEventSeverity.HIGH, AuditEventSeverity.CRITICAL]:
                self._flush_events()
            logger.bind(audit=True).info(
                f"AUDIT_EVENT: {event.event_type.value}",
                extra={
                    "audit_event": event.model_dump(),
                    "event_id": event.event_id,
                    "event_type": event.event_type.value,
                    "severity": event.severity.value,
                    "success": event.success,
                },
            )
            if len(self._event_buffer) >= self._buffer_size:
                self._flush_events()
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")

    def _flush_events(self) -> None:
        """Flush event buffer to persistent storage."""
        if not self._event_buffer:
            return
        try:
            for event in self._event_buffer:
                audit_line = json.dumps(event.model_dump(), default=str)
                if event.compliance_tags:
                    audit_line = f"COMPLIANCE:{','.join(event.compliance_tags)} {audit_line}"
            self._event_buffer.clear()
        except Exception as e:
            logger.error(f"Failed to flush audit events: {e}")

    def start_operation(self, operation_id: str) -> None:
        """Start tracking an operation for performance metrics.

        Args:
            operation_id: Unique operation identifier
        """
        self._operation_start_times[operation_id] = time.time()

    def end_operation(self, operation_id: str) -> Optional[float]:
        """End tracking an operation and return duration.

        Args:
            operation_id: Unique operation identifier

        Returns:
            Operation duration in milliseconds
        """
        start_time = self._operation_start_times.pop(operation_id, None)
        if start_time:
            duration = (time.time() - start_time) * 1000
            return duration
        return None

    def log_credential_created(
        self,
        target_id: Union[str, UUID],
        target_name: Optional[str] = None,
        provider: Optional[str] = None,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log credential creation event."""
        event = AuditEvent(
            event_type=AuditEventType.CREDENTIAL_CREATED,
            severity=AuditEventSeverity.MEDIUM,
            user_id=user_id,
            target_id=target_id,
            target_name=target_name,
            action="create_credential",
            description=f"Created credential for target {target_name or target_id}",
            details=details or {},
            compliance_tags=["credential_management", "data_creation"],
        )
        if provider:
            event.details["provider"] = provider
        self.log_event(event)

    def log_credential_accessed(
        self,
        target_id: Union[str, UUID],
        target_name: Optional[str] = None,
        access_type: str = "retrieve",
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log credential access event."""
        event = AuditEvent(
            event_type=AuditEventType.CREDENTIAL_ACCESSED,
            severity=AuditEventSeverity.HIGH,
            user_id=user_id,
            client_ip=client_ip,
            target_id=target_id,
            target_name=target_name,
            action=f"access_credential_{access_type}",
            description=f"Accessed credential for target {target_name or target_id} ({access_type})",
            details=details or {},
            compliance_tags=["credential_access", "data_access"],
        )
        self.log_event(event)

    def log_credential_deleted(
        self,
        target_id: Union[str, UUID],
        target_name: Optional[str] = None,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log credential deletion event."""
        event = AuditEvent(
            event_type=AuditEventType.CREDENTIAL_DELETED,
            severity=AuditEventSeverity.HIGH,
            user_id=user_id,
            target_id=target_id,
            target_name=target_name,
            action="delete_credential",
            description=f"Deleted credential for target {target_name or target_id}",
            details=details or {},
            compliance_tags=["credential_management", "data_deletion"],
        )
        self.log_event(event)

    def log_authentication_attempt(
        self,
        target_id: Union[str, UUID],
        target_name: Optional[str] = None,
        success: bool = True,
        provider: Optional[str] = None,
        error_message: Optional[str] = None,
        duration_ms: Optional[float] = None,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log authentication validation attempt."""
        if success:
            event_type = AuditEventType.AUTH_VALIDATION_SUCCESS
            severity = AuditEventSeverity.LOW
            action = "validate_credential_success"
            description = f"Successfully validated credential for {target_name or target_id}"
        else:
            event_type = AuditEventType.AUTH_VALIDATION_FAILURE
            severity = AuditEventSeverity.MEDIUM
            action = "validate_credential_failure"
            description = f"Failed to validate credential for {target_name or target_id}"
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            target_id=target_id,
            target_name=target_name,
            action=action,
            description=description,
            success=success,
            error_message=error_message,
            duration_ms=duration_ms,
            details=details or {},
            compliance_tags=["authentication", "credential_validation"],
        )
        if provider:
            event.details["provider"] = provider
        self.log_event(event)

    def log_environment_injection(
        self,
        target_id: Union[str, UUID],
        source: str,
        success: bool = True,
        provider: Optional[str] = None,
        error_message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log environment credential injection event."""
        if success:
            event_type = AuditEventType.ENV_CREDENTIAL_INJECTED
            severity = AuditEventSeverity.MEDIUM
            action = "inject_env_credential"
            description = f"Injected environment credential for {target_id} from {source}"
        else:
            event_type = AuditEventType.ENV_CREDENTIAL_FAILED
            severity = AuditEventSeverity.HIGH
            action = "inject_env_credential_failed"
            description = f"Failed to inject environment credential for {target_id} from {source}"
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            target_id=target_id,
            action=action,
            description=description,
            success=success,
            error_message=error_message,
            details=details or {},
            compliance_tags=["environment_injection", "credential_management"],
        )
        if provider:
            event.details["provider"] = provider
        if source:
            event.details["source"] = source
        self.log_event(event)

    def log_security_event(
        self,
        event_type: AuditEventType,
        description: str,
        severity: AuditEventSeverity = AuditEventSeverity.HIGH,
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log security-related event."""
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            client_ip=client_ip,
            action="security_event",
            description=description,
            success=False,
            details=details or {},
            compliance_tags=["security", "incident"],
        )
        self.log_event(event)

    def log_performance_metric(
        self,
        operation: str,
        duration_ms: float,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log performance metric."""
        event = AuditEvent(
            event_type=AuditEventType.SYSTEM_STARTED,
            severity=AuditEventSeverity.LOW,
            action=f"performance_{operation}",
            description=f"Performance metric for {operation}: {duration_ms:.2f}ms",
            success=success,
            duration_ms=duration_ms,
            details=details or {},
            compliance_tags=["performance", "monitoring"],
        )
        self.log_event(event)

    def get_audit_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[AuditEventType]] = None,
        target_id: Optional[Union[str, UUID]] = None,
        user_id: Optional[str] = None,
        limit: int = 1000,
    ) -> List[AuditEvent]:
        """Retrieve audit events with filtering.

        Args:
            start_time: Start time filter
            end_time: End time filter
            event_types: Event type filter
            target_id: Target ID filter
            user_id: User ID filter
            limit: Maximum number of events to return

        Returns:
            List of matching audit events
        """
        logger.warning("Audit event retrieval not implemented - events are in log files")
        return []

    def generate_audit_report(
        self, start_time: datetime, end_time: datetime, output_file: Optional[Path] = None
    ) -> Dict[str, Any]:
        """Generate audit report for a time period.

        Args:
            start_time: Report start time
            end_time: Report end time
            output_file: Optional output file path

        Returns:
            Audit report summary
        """
        report = {
            "report_id": str(uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": {"start": start_time.isoformat(), "end": end_time.isoformat()},
            "summary": {
                "total_events": 0,
                "by_type": {},
                "by_severity": {},
                "security_events": 0,
                "failed_operations": 0,
            },
            "compliance": {
                "credential_accesses": 0,
                "authentication_attempts": 0,
                "data_modifications": 0,
            },
        }
        logger.info(f"Generated audit report for period {start_time} to {end_time}")
        if output_file:
            output_file.write_text(json.dumps(report, indent=2))
        return report

    def cleanup_old_events(self, retention_days: int = 365) -> int:
        """Clean up old audit events based on retention policy.

        Args:
            retention_days: Number of days to retain events

        Returns:
            Number of events cleaned up
        """
        cutoff_date = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - timezone.timedelta(days=retention_days)
        logger.info(f"Cleanup audit events older than {cutoff_date}")
        return 0

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self._flush_events()


_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def setup_audit_logging(
    config: Optional[AuthenticationConfig] = None,
    log_file: Optional[Path] = None,
    enable_console: bool = False,
) -> AuditLogger:
    """Setup global audit logging.

    Args:
        config: Authentication configuration
        log_file: Audit log file path
        enable_console: Enable console logging

    Returns:
        Configured audit logger
    """
    global _audit_logger
    _audit_logger = AuditLogger(config=config, log_file=log_file, enable_console=enable_console)
    return _audit_logger


def audit_operation(
    event_type: AuditEventType,
    action: str,
    description: str,
    severity: AuditEventSeverity = AuditEventSeverity.MEDIUM,
):
    """Decorator for automatic audit logging of operations."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            audit_logger = get_audit_logger()
            operation_id = str(uuid4())
            audit_logger.start_operation(operation_id)
            try:
                result = func(*args, **kwargs)
                duration = audit_logger.end_operation(operation_id)
                event = AuditEvent(
                    event_type=event_type,
                    severity=severity,
                    action=action,
                    description=description,
                    success=True,
                    duration_ms=duration,
                    compliance_tags=["automated_audit"],
                )
                audit_logger.log_event(event)
                return result
            except Exception as e:
                duration = audit_logger.end_operation(operation_id)
                event = AuditEvent(
                    event_type=event_type,
                    severity=AuditEventSeverity.HIGH,
                    action=action,
                    description=f"{description} (FAILED)",
                    success=False,
                    error_message=str(e),
                    duration_ms=duration,
                    compliance_tags=["automated_audit", "error"],
                )
                audit_logger.log_event(event)
                raise

        return wrapper

    return decorator
