"""Authentication audit logging for security and compliance."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio
from collections import deque


class AuditEventType(str, Enum):
    """Types of audit events."""

    CREDENTIAL_CREATED = "credential_created"
    CREDENTIAL_UPDATED = "credential_updated"
    CREDENTIAL_DELETED = "credential_deleted"
    CREDENTIAL_ACCESSED = "credential_accessed"
    CREDENTIAL_VALIDATED = "credential_validated"
    CREDENTIAL_ROTATED = "credential_rotated"

    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTH_EXPIRED = "auth_expired"
    AUTH_REVOKED = "auth_revoked"

    INJECTION_SUCCESS = "injection_success"
    INJECTION_FAILURE = "injection_failure"

    ENCRYPTION_SUCCESS = "encryption_success"
    ENCRYPTION_FAILURE = "encryption_failure"
    DECRYPTION_SUCCESS = "decryption_success"
    DECRYPTION_FAILURE = "decryption_failure"

    SECURITY_VIOLATION = "security_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


@dataclass
class AuditEvent:
    """Audit event data structure."""

    timestamp: str
    event_type: AuditEventType
    user: Optional[str]
    credential_name: Optional[str]
    provider: Optional[str]
    target: Optional[str]
    success: bool
    message: str
    metadata: Dict[str, Any]
    ip_address: Optional[str] = None
    session_id: Optional[str] = None
    risk_score: Optional[int] = None


class AuditLogger:
    """Handles authentication audit logging."""

    def __init__(
        self,
        log_file: Optional[Path] = None,
        max_memory_events: int = 10000,
        enable_console: bool = True,
        enable_file: bool = True,
        enable_syslog: bool = False,
    ):
        """Initialize audit logger.

        Args:
            log_file: Path to audit log file
            max_memory_events: Maximum events to keep in memory
            enable_console: Enable console logging
            enable_file: Enable file logging
            enable_syslog: Enable syslog forwarding
        """
        self.log_file = log_file or Path.home() / ".gibson" / "auth_audit.log"
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        self.max_memory_events = max_memory_events
        self.memory_events = deque(maxlen=max_memory_events)

        self.enable_console = enable_console
        self.enable_file = enable_file
        self.enable_syslog = enable_syslog

        # Setup loggers
        self.logger = logging.getLogger("gibson.auth.audit")
        self.logger.setLevel(logging.INFO)

        # Console handler
        if enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(
                logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
            )
            self.logger.addHandler(console_handler)

        # File handler
        if enable_file:
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            )
            self.logger.addHandler(file_handler)

        # Statistics
        self.stats = {
            "total_events": 0,
            "success_count": 0,
            "failure_count": 0,
            "security_violations": 0,
            "events_by_type": {},
            "events_by_provider": {},
        }

    async def log_event(
        self,
        event_type: AuditEventType,
        success: bool = True,
        credential_name: Optional[str] = None,
        provider: Optional[str] = None,
        target: Optional[str] = None,
        message: Optional[str] = None,
        user: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> None:
        """Log an audit event.

        Args:
            event_type: Type of event
            success: Whether the operation was successful
            credential_name: Name of credential involved
            provider: Provider name
            target: Target system/URL
            message: Event message
            user: User identifier
            metadata: Additional event metadata
            ip_address: Client IP address
            session_id: Session identifier
        """
        # Create event
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=event_type,
            user=user or self._get_current_user(),
            credential_name=credential_name,
            provider=provider,
            target=target,
            success=success,
            message=message or self._generate_message(event_type, success),
            metadata=metadata or {},
            ip_address=ip_address or self._get_client_ip(),
            session_id=session_id or self._get_session_id(),
            risk_score=self._calculate_risk_score(event_type, success, metadata),
        )

        # Store in memory
        self.memory_events.append(event)

        # Update statistics
        self._update_stats(event)

        # Check for security concerns
        await self._check_security_concerns(event)

        # Log to outputs
        await self._write_event(event)

    async def _write_event(self, event: AuditEvent) -> None:
        """Write event to configured outputs."""
        # Format event
        event_dict = asdict(event)
        event_json = json.dumps(event_dict)

        # Log based on severity
        if event.event_type in [
            AuditEventType.SECURITY_VIOLATION,
            AuditEventType.SUSPICIOUS_ACTIVITY,
        ]:
            self.logger.error(f"SECURITY: {event_json}")
        elif not event.success:
            self.logger.warning(f"FAILURE: {event_json}")
        else:
            self.logger.info(event_json)

        # Write to file if enabled
        if self.enable_file:
            async with asyncio.Lock():
                with open(self.log_file, "a") as f:
                    f.write(event_json + "\n")

        # Forward to syslog if enabled
        if self.enable_syslog:
            await self._forward_to_syslog(event)

    def _generate_message(self, event_type: AuditEventType, success: bool) -> str:
        """Generate default message for event type."""
        messages = {
            AuditEventType.CREDENTIAL_CREATED: "Credential created successfully"
            if success
            else "Failed to create credential",
            AuditEventType.CREDENTIAL_UPDATED: "Credential updated successfully"
            if success
            else "Failed to update credential",
            AuditEventType.CREDENTIAL_DELETED: "Credential deleted successfully"
            if success
            else "Failed to delete credential",
            AuditEventType.CREDENTIAL_ACCESSED: "Credential accessed"
            if success
            else "Credential access denied",
            AuditEventType.CREDENTIAL_VALIDATED: "Credential validation successful"
            if success
            else "Credential validation failed",
            AuditEventType.AUTH_SUCCESS: "Authentication successful",
            AuditEventType.AUTH_FAILURE: "Authentication failed",
            AuditEventType.AUTH_EXPIRED: "Authentication expired",
            AuditEventType.SECURITY_VIOLATION: "Security violation detected",
            AuditEventType.SUSPICIOUS_ACTIVITY: "Suspicious activity detected",
        }
        return messages.get(event_type, f"Event: {event_type.value}")

    def _get_current_user(self) -> str:
        """Get current user identifier."""
        import os
        import getpass

        # Try various methods
        user = os.environ.get("USER")
        if not user:
            try:
                user = getpass.getuser()
            except:
                user = "unknown"

        return user

    def _get_client_ip(self) -> Optional[str]:
        """Get client IP address if available."""
        # In a web context, this would get the real IP
        # For CLI, we can get local network info
        try:
            import socket

            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            return ip
        except:
            return None

    def _get_session_id(self) -> str:
        """Get or generate session ID."""
        import uuid

        # In production, this would be a proper session ID
        return str(uuid.uuid4())[:8]

    def _calculate_risk_score(
        self,
        event_type: AuditEventType,
        success: bool,
        metadata: Optional[Dict[str, Any]],
    ) -> int:
        """Calculate risk score for event (0-100)."""
        score = 0

        # High risk events
        if event_type in [
            AuditEventType.SECURITY_VIOLATION,
            AuditEventType.SUSPICIOUS_ACTIVITY,
        ]:
            score = 90
        elif event_type == AuditEventType.CREDENTIAL_DELETED:
            score = 70
        elif event_type == AuditEventType.AUTH_FAILURE:
            score = 60
            # Multiple failures increase risk
            if metadata and metadata.get("failure_count", 0) > 3:
                score = 80
        elif event_type == AuditEventType.CREDENTIAL_ROTATED:
            score = 30
        elif not success:
            score = max(score, 50)

        return min(score, 100)

    def _update_stats(self, event: AuditEvent) -> None:
        """Update statistics with new event."""
        self.stats["total_events"] += 1

        if event.success:
            self.stats["success_count"] += 1
        else:
            self.stats["failure_count"] += 1

        if event.event_type in [
            AuditEventType.SECURITY_VIOLATION,
            AuditEventType.SUSPICIOUS_ACTIVITY,
        ]:
            self.stats["security_violations"] += 1

        # Count by type
        event_type_str = event.event_type.value
        self.stats["events_by_type"][event_type_str] = (
            self.stats["events_by_type"].get(event_type_str, 0) + 1
        )

        # Count by provider
        if event.provider:
            self.stats["events_by_provider"][event.provider] = (
                self.stats["events_by_provider"].get(event.provider, 0) + 1
            )

    async def _check_security_concerns(self, event: AuditEvent) -> None:
        """Check for security concerns in event patterns."""
        # Check for rapid failure patterns (potential brute force)
        recent_failures = [
            e
            for e in list(self.memory_events)[-100:]
            if not e.success and e.credential_name == event.credential_name
        ]

        if len(recent_failures) > 5:
            await self.log_event(
                event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
                success=False,
                credential_name=event.credential_name,
                message=f"Multiple authentication failures detected ({len(recent_failures)} failures)",
                metadata={"failure_count": len(recent_failures)},
            )

        # Check for unusual access patterns
        if event.event_type == AuditEventType.CREDENTIAL_ACCESSED:
            # Check time-based anomalies
            hour = datetime.fromisoformat(event.timestamp).hour
            if hour < 6 or hour > 22:  # Outside normal hours
                event.metadata["unusual_time"] = True
                event.risk_score = max(event.risk_score or 0, 40)

    async def _forward_to_syslog(self, event: AuditEvent) -> None:
        """Forward event to syslog server."""
        # This would integrate with syslog protocol
        # For now, just a placeholder
        pass

    def get_statistics(self) -> Dict[str, Any]:
        """Get audit statistics."""
        return {
            **self.stats,
            "memory_events": len(self.memory_events),
            "success_rate": (
                self.stats["success_count"] / self.stats["total_events"]
                if self.stats["total_events"] > 0
                else 0
            ),
        }

    def get_recent_events(
        self,
        limit: int = 100,
        event_type: Optional[AuditEventType] = None,
        credential_name: Optional[str] = None,
        success_only: bool = False,
    ) -> List[AuditEvent]:
        """Get recent audit events with optional filtering."""
        events = list(self.memory_events)

        # Apply filters
        if event_type:
            events = [e for e in events if e.event_type == event_type]

        if credential_name:
            events = [e for e in events if e.credential_name == credential_name]

        if success_only:
            events = [e for e in events if e.success]

        # Return most recent
        return events[-limit:]

    async def export_audit_log(
        self,
        output_file: Path,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        format: str = "json",
    ) -> None:
        """Export audit log to file.

        Args:
            output_file: Output file path
            start_date: Start date filter
            end_date: End date filter
            format: Output format (json, csv)
        """
        events = list(self.memory_events)

        # Filter by date
        if start_date or end_date:
            filtered = []
            for event in events:
                event_time = datetime.fromisoformat(event.timestamp)
                if start_date and event_time < start_date:
                    continue
                if end_date and event_time > end_date:
                    continue
                filtered.append(event)
            events = filtered

        # Export based on format
        if format == "json":
            with open(output_file, "w") as f:
                json.dump(
                    [asdict(e) for e in events],
                    f,
                    indent=2,
                )
        elif format == "csv":
            import csv

            with open(output_file, "w", newline="") as f:
                if events:
                    writer = csv.DictWriter(f, fieldnames=asdict(events[0]).keys())
                    writer.writeheader()
                    for event in events:
                        writer.writerow(asdict(event))

    def clear_old_events(self, days: int = 90) -> int:
        """Clear events older than specified days.

        Args:
            days: Number of days to keep

        Returns:
            Number of events cleared
        """
        cutoff = datetime.utcnow().timestamp() - (days * 86400)
        original_count = len(self.memory_events)

        self.memory_events = deque(
            [
                e
                for e in self.memory_events
                if datetime.fromisoformat(e.timestamp).timestamp() > cutoff
            ],
            maxlen=self.max_memory_events,
        )

        return original_count - len(self.memory_events)


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


async def audit_log(event_type: AuditEventType, **kwargs) -> None:
    """Convenience function for audit logging."""
    logger = get_audit_logger()
    await logger.log_event(event_type, **kwargs)
