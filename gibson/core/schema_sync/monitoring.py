"""
Monitoring and alerting for schema synchronization.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from enum import Enum
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from gibson.models.base import GibsonBaseModel


logger = logging.getLogger(__name__)


class AlertLevel(str, Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MetricType(str, Enum):
    """Types of metrics to track."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMING = "timing"


class Alert(GibsonBaseModel):
    """Alert notification."""
    
    level: AlertLevel
    title: str
    message: str
    timestamp: datetime = None
    context: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}
    
    def __init__(self, **data):
        if "timestamp" not in data:
            data["timestamp"] = datetime.utcnow()
        super().__init__(**data)
    
    def format_message(self) -> str:
        """Format alert message for display."""
        emoji = {
            AlertLevel.INFO: "ℹ️",
            AlertLevel.WARNING: "⚠️",
            AlertLevel.ERROR: "❌",
            AlertLevel.CRITICAL: "🚨"
        }.get(self.level, "")
        
        lines = [
            f"{emoji} {self.level.upper()}: {self.title}",
            f"Time: {self.timestamp.isoformat()}",
            "",
            self.message,
        ]
        
        if self.context:
            lines.extend([
                "",
                "Context:",
                json.dumps(self.context, indent=2, default=str)
            ])
        
        return "\n".join(lines)


class Metric(GibsonBaseModel):
    """Performance metric."""
    
    name: str
    type: MetricType
    value: float
    timestamp: datetime = None
    tags: Dict[str, str] = {}
    
    def __init__(self, **data):
        if "timestamp" not in data:
            data["timestamp"] = datetime.utcnow()
        super().__init__(**data)


class AlertHandler:
    """Base class for alert handlers."""
    
    def handle(self, alert: Alert):
        """Handle alert notification."""
        raise NotImplementedError


class LogAlertHandler(AlertHandler):
    """Log alerts to file."""
    
    def __init__(self, log_file: Optional[Path] = None):
        """
        Initialize log handler.
        
        Args:
            log_file: Path to log file
        """
        self.log_file = log_file or Path.home() / ".gibson" / "schema_alerts.log"
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
    
    def handle(self, alert: Alert):
        """Log alert to file."""
        with open(self.log_file, 'a') as f:
            f.write(f"{alert.format_message()}\n")
            f.write("-" * 60 + "\n")
        
        # Also log to standard logger
        if alert.level == AlertLevel.CRITICAL:
            logger.critical(alert.message)
        elif alert.level == AlertLevel.ERROR:
            logger.error(alert.message)
        elif alert.level == AlertLevel.WARNING:
            logger.warning(alert.message)
        else:
            logger.info(alert.message)


class EmailAlertHandler(AlertHandler):
    """Send alerts via email."""
    
    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        from_email: str,
        to_emails: List[str],
        username: Optional[str] = None,
        password: Optional[str] = None
    ):
        """
        Initialize email handler.
        
        Args:
            smtp_host: SMTP server host
            smtp_port: SMTP server port
            from_email: Sender email
            to_emails: Recipient emails
            username: SMTP username
            password: SMTP password
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.from_email = from_email
        self.to_emails = to_emails
        self.username = username
        self.password = password
    
    def handle(self, alert: Alert):
        """Send alert via email."""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            msg['Subject'] = f"[Gibson Schema Alert] {alert.level.upper()}: {alert.title}"
            
            body = alert.format_message()
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.username and self.password:
                    server.starttls()
                    server.login(self.username, self.password)
                
                server.send_message(msg)
            
            logger.info(f"Email alert sent: {alert.title}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")


class WebhookAlertHandler(AlertHandler):
    """Send alerts to webhook."""
    
    def __init__(self, webhook_url: str, headers: Optional[Dict[str, str]] = None):
        """
        Initialize webhook handler.
        
        Args:
            webhook_url: Webhook URL
            headers: Optional headers
        """
        self.webhook_url = webhook_url
        self.headers = headers or {}
    
    def handle(self, alert: Alert):
        """Send alert to webhook."""
        import requests
        
        try:
            payload = {
                "level": alert.level,
                "title": alert.title,
                "message": alert.message,
                "timestamp": alert.timestamp.isoformat(),
                "context": alert.context,
                "metadata": alert.metadata
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers=self.headers,
                timeout=10
            )
            
            response.raise_for_status()
            logger.info(f"Webhook alert sent: {alert.title}")
            
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")


class SchemaMonitor:
    """Monitor schema synchronization operations."""
    
    def __init__(self):
        """Initialize monitor."""
        self.handlers: List[AlertHandler] = []
        self.metrics: List[Metric] = []
        self.alert_history: List[Alert] = []
        self.thresholds: Dict[str, Any] = {}
        self._configure_default_thresholds()
    
    def add_handler(self, handler: AlertHandler):
        """Add alert handler."""
        self.handlers.append(handler)
    
    def set_threshold(self, name: str, value: Any):
        """Set monitoring threshold."""
        self.thresholds[name] = value
    
    def alert(
        self,
        level: AlertLevel,
        title: str,
        message: str,
        context: Optional[Dict[str, Any]] = None
    ):
        """
        Send alert notification.
        
        Args:
            level: Alert severity
            title: Alert title
            message: Alert message
            context: Additional context
        """
        alert = Alert(
            level=level,
            title=title,
            message=message,
            context=context or {}
        )
        
        # Store in history
        self.alert_history.append(alert)
        
        # Send to handlers
        for handler in self.handlers:
            try:
                handler.handle(alert)
            except Exception as e:
                logger.error(f"Alert handler failed: {e}")
    
    def record_metric(
        self,
        name: str,
        value: float,
        metric_type: MetricType = MetricType.GAUGE,
        tags: Optional[Dict[str, str]] = None
    ):
        """
        Record performance metric.
        
        Args:
            name: Metric name
            value: Metric value
            metric_type: Type of metric
            tags: Optional tags
        """
        metric = Metric(
            name=name,
            type=metric_type,
            value=value,
            tags=tags or {}
        )
        
        self.metrics.append(metric)
        
        # Check thresholds
        self._check_thresholds(metric)
    
    def monitor_sync_operation(
        self,
        operation: str,
        duration: float,
        success: bool,
        changes: Optional[Dict[str, Any]] = None
    ):
        """
        Monitor a sync operation.
        
        Args:
            operation: Operation name
            duration: Operation duration in seconds
            success: Whether operation succeeded
            changes: Changes made
        """
        # Record metrics
        self.record_metric(f"sync.{operation}.duration", duration, MetricType.TIMING)
        self.record_metric(f"sync.{operation}.success", 1 if success else 0, MetricType.COUNTER)
        
        if changes:
            self.record_metric(f"sync.{operation}.changes.total", changes.get("total", 0))
            self.record_metric(f"sync.{operation}.changes.added", len(changes.get("added", [])))
            self.record_metric(f"sync.{operation}.changes.removed", len(changes.get("removed", [])))
        
        # Alert on failures
        if not success:
            self.alert(
                AlertLevel.ERROR,
                f"Sync operation failed: {operation}",
                f"Operation {operation} failed after {duration:.2f}s",
                context={"operation": operation, "duration": duration}
            )
        
        # Alert on slow operations
        if duration > self.thresholds.get("max_operation_duration", 60):
            self.alert(
                AlertLevel.WARNING,
                f"Slow sync operation: {operation}",
                f"Operation {operation} took {duration:.2f}s (threshold: {self.thresholds['max_operation_duration']}s)",
                context={"operation": operation, "duration": duration}
            )
    
    def monitor_breaking_changes(
        self,
        changes: List[Dict[str, Any]]
    ):
        """
        Monitor breaking changes.
        
        Args:
            changes: List of breaking changes
        """
        if not changes:
            return
        
        self.record_metric("breaking_changes.count", len(changes), MetricType.GAUGE)
        
        # Alert on breaking changes
        self.alert(
            AlertLevel.WARNING,
            f"Breaking changes detected: {len(changes)}",
            "Schema changes contain breaking modifications that may require data migration",
            context={"changes": changes}
        )
        
        # Critical alert if too many breaking changes
        if len(changes) > self.thresholds.get("max_breaking_changes", 5):
            self.alert(
                AlertLevel.CRITICAL,
                "Excessive breaking changes",
                f"Too many breaking changes detected ({len(changes)}). Manual review required.",
                context={"changes": changes, "threshold": self.thresholds["max_breaking_changes"]}
            )
    
    def monitor_migration_failure(
        self,
        version: str,
        error: str,
        rollback_attempted: bool = False
    ):
        """
        Monitor migration failure.
        
        Args:
            version: Migration version
            error: Error message
            rollback_attempted: Whether rollback was attempted
        """
        self.record_metric("migration.failures", 1, MetricType.COUNTER)
        
        self.alert(
            AlertLevel.CRITICAL,
            f"Migration failed: {version}",
            f"Migration {version} failed with error: {error}",
            context={
                "version": version,
                "error": error,
                "rollback_attempted": rollback_attempted
            }
        )
    
    def monitor_data_loss_risk(
        self,
        fields: List[str],
        affected_rows: int
    ):
        """
        Monitor potential data loss.
        
        Args:
            fields: Fields that may lose data
            affected_rows: Number of affected rows
        """
        self.record_metric("data_loss.risk.fields", len(fields), MetricType.GAUGE)
        self.record_metric("data_loss.risk.rows", affected_rows, MetricType.GAUGE)
        
        if affected_rows > 0:
            self.alert(
                AlertLevel.CRITICAL,
                "Data loss risk detected",
                f"Potential data loss in {len(fields)} fields affecting {affected_rows} rows",
                context={
                    "fields": fields,
                    "affected_rows": affected_rows
                }
            )
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of collected metrics."""
        if not self.metrics:
            return {}
        
        summary = {}
        
        # Group metrics by name
        by_name = {}
        for metric in self.metrics:
            if metric.name not in by_name:
                by_name[metric.name] = []
            by_name[metric.name].append(metric.value)
        
        # Calculate statistics
        for name, values in by_name.items():
            summary[name] = {
                "count": len(values),
                "sum": sum(values),
                "average": sum(values) / len(values),
                "min": min(values),
                "max": max(values)
            }
        
        return summary
    
    def get_alert_summary(self) -> Dict[str, int]:
        """Get summary of alerts."""
        summary = {
            AlertLevel.INFO: 0,
            AlertLevel.WARNING: 0,
            AlertLevel.ERROR: 0,
            AlertLevel.CRITICAL: 0
        }
        
        for alert in self.alert_history:
            summary[alert.level] += 1
        
        return summary
    
    def export_metrics(self, output_path: Path):
        """
        Export metrics to file.
        
        Args:
            output_path: Path to export file
        """
        data = {
            "metrics": [m.model_dump() for m in self.metrics],
            "alerts": [a.model_dump() for a in self.alert_history],
            "summary": {
                "metrics": self.get_metrics_summary(),
                "alerts": self.get_alert_summary()
            },
            "exported_at": datetime.utcnow().isoformat()
        }
        
        output_path.write_text(json.dumps(data, indent=2, default=str))
        logger.info(f"Metrics exported to {output_path}")
    
    def _configure_default_thresholds(self):
        """Configure default monitoring thresholds."""
        self.thresholds = {
            "max_operation_duration": 60,  # seconds
            "max_breaking_changes": 5,
            "max_affected_rows": 10000,
            "min_disk_space_gb": 1,
            "max_memory_usage_mb": 500
        }
    
    def _check_thresholds(self, metric: Metric):
        """Check if metric exceeds thresholds."""
        # Check specific metric thresholds
        if metric.name == "memory_usage_mb":
            if metric.value > self.thresholds.get("max_memory_usage_mb", 500):
                self.alert(
                    AlertLevel.WARNING,
                    "High memory usage",
                    f"Memory usage is {metric.value:.1f}MB (threshold: {self.thresholds['max_memory_usage_mb']}MB)"
                )
        
        elif metric.name == "disk_space_gb":
            if metric.value < self.thresholds.get("min_disk_space_gb", 1):
                self.alert(
                    AlertLevel.WARNING,
                    "Low disk space",
                    f"Only {metric.value:.1f}GB disk space remaining"
                )


# Global monitor instance
_monitor = SchemaMonitor()


def get_monitor() -> SchemaMonitor:
    """Get global monitor instance."""
    return _monitor


def configure_monitoring(config: Dict[str, Any]):
    """
    Configure monitoring from config.
    
    Args:
        config: Monitoring configuration
    """
    monitor = get_monitor()
    
    # Add log handler (always enabled)
    log_file = config.get("log_file")
    monitor.add_handler(LogAlertHandler(log_file))
    
    # Add email handler if configured
    email_config = config.get("email")
    if email_config:
        monitor.add_handler(EmailAlertHandler(**email_config))
    
    # Add webhook handler if configured
    webhook_config = config.get("webhook")
    if webhook_config:
        monitor.add_handler(WebhookAlertHandler(**webhook_config))
    
    # Set custom thresholds
    thresholds = config.get("thresholds", {})
    for name, value in thresholds.items():
        monitor.set_threshold(name, value)
    
    logger.info("Monitoring configured successfully")