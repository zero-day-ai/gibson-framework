"""Performance tracking and metrics for module management."""

import json
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID
from loguru import logger

from gibson.models.module import ExecutionStatus, ModuleResultModel
from gibson.models.domain import Severity


class PerformanceMetrics:
    """Track performance metrics for modules."""
    
    def __init__(self, window_size: int = 100):
        """
        Initialize performance metrics.
        
        Args:
            window_size: Size of rolling window for metrics
        """
        self.window_size = window_size
        self.execution_times: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self.success_counts: Dict[str, int] = defaultdict(int)
        self.failure_counts: Dict[str, int] = defaultdict(int)
        self.timeout_counts: Dict[str, int] = defaultdict(int)
        self.finding_counts: Dict[str, List[int]] = defaultdict(list)
        self.resource_usage: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self.last_execution: Dict[str, datetime] = {}
        self.total_executions: Dict[str, int] = defaultdict(int)
    
    def record_execution(
        self,
        module_name: str,
        result: ModuleResultModel
    ) -> None:
        """
        Record execution metrics.
        
        Args:
            module_name: Name of module
            result: Execution result
        """
        self.total_executions[module_name] += 1
        self.last_execution[module_name] = datetime.utcnow()
        
        # Record execution time
        if result.duration:
            self.execution_times[module_name].append(result.duration)
        
        # Record status
        if result.status == ExecutionStatus.COMPLETED:
            self.success_counts[module_name] += 1
        elif result.status == ExecutionStatus.FAILED:
            self.failure_counts[module_name] += 1
        elif result.status == ExecutionStatus.TIMEOUT:
            self.timeout_counts[module_name] += 1
        
        # Record findings
        self.finding_counts[module_name].append(len(result.findings))
        
        # Record resource usage
        if "resource_usage" in result.metadata:
            self.resource_usage[module_name].append(result.metadata["resource_usage"])
    
    def get_module_stats(self, module_name: str) -> Dict[str, Any]:
        """
        Get statistics for a specific module.
        
        Args:
            module_name: Name of module
            
        Returns:
            Dictionary of statistics
        """
        total = self.total_executions[module_name]
        if total == 0:
            return {
                "total_executions": 0,
                "success_rate": 0.0,
                "average_duration": 0.0,
                "findings_per_run": 0.0
            }
        
        # Calculate success rate
        success_rate = self.success_counts[module_name] / total
        
        # Calculate average execution time
        exec_times = list(self.execution_times[module_name])
        avg_duration = sum(exec_times) / len(exec_times) if exec_times else 0.0
        
        # Calculate average findings
        findings = self.finding_counts[module_name]
        avg_findings = sum(findings) / len(findings) if findings else 0.0
        
        # Calculate resource usage
        resource_data = list(self.resource_usage[module_name])
        avg_memory = 0.0
        avg_cpu = 0.0
        if resource_data:
            avg_memory = sum(r.get("memory_mb", 0) for r in resource_data) / len(resource_data)
            avg_cpu = sum(r.get("cpu_percent", 0) for r in resource_data) / len(resource_data)
        
        return {
            "total_executions": total,
            "success_count": self.success_counts[module_name],
            "failure_count": self.failure_counts[module_name],
            "timeout_count": self.timeout_counts[module_name],
            "success_rate": round(success_rate, 3),
            "average_duration": round(avg_duration, 2),
            "min_duration": min(exec_times) if exec_times else 0.0,
            "max_duration": max(exec_times) if exec_times else 0.0,
            "findings_per_run": round(avg_findings, 2),
            "total_findings": sum(findings),
            "average_memory_mb": round(avg_memory, 2),
            "average_cpu_percent": round(avg_cpu, 2),
            "last_execution": self.last_execution.get(module_name, None)
        }
    
    def get_global_stats(self) -> Dict[str, Any]:
        """
        Get global statistics across all modules.
        
        Returns:
            Dictionary of global statistics
        """
        total_executions = sum(self.total_executions.values())
        total_success = sum(self.success_counts.values())
        total_failures = sum(self.failure_counts.values())
        total_timeouts = sum(self.timeout_counts.values())
        
        if total_executions == 0:
            return {
                "total_executions": 0,
                "global_success_rate": 0.0,
                "module_count": 0
            }
        
        # Collect all execution times
        all_times = []
        for times in self.execution_times.values():
            all_times.extend(times)
        
        # Collect all findings
        all_findings = []
        for findings in self.finding_counts.values():
            all_findings.extend(findings)
        
        return {
            "total_executions": total_executions,
            "total_success": total_success,
            "total_failures": total_failures,
            "total_timeouts": total_timeouts,
            "global_success_rate": round(total_success / total_executions, 3),
            "module_count": len(self.total_executions),
            "average_duration": round(sum(all_times) / len(all_times), 2) if all_times else 0.0,
            "total_findings": sum(all_findings),
            "findings_per_execution": round(sum(all_findings) / total_executions, 2) if total_executions else 0.0
        }
    
    def get_trending_metrics(
        self,
        module_name: str,
        period_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get trending metrics for a module.
        
        Args:
            module_name: Name of module
            period_hours: Period to analyze
            
        Returns:
            Trending metrics
        """
        # This would need timestamp tracking for each execution
        # For now, return recent averages
        stats = self.get_module_stats(module_name)
        
        # Simulate trend data
        recent_times = list(self.execution_times[module_name])[-10:]
        if len(recent_times) >= 2:
            # Check if performance is improving or degrading
            first_half = recent_times[:len(recent_times)//2]
            second_half = recent_times[len(recent_times)//2:]
            
            avg_first = sum(first_half) / len(first_half) if first_half else 0
            avg_second = sum(second_half) / len(second_half) if second_half else 0
            
            if avg_second < avg_first * 0.9:
                trend = "improving"
            elif avg_second > avg_first * 1.1:
                trend = "degrading"
            else:
                trend = "stable"
        else:
            trend = "insufficient_data"
        
        return {
            "module_name": module_name,
            "period_hours": period_hours,
            "performance_trend": trend,
            "recent_success_rate": stats["success_rate"],
            "recent_avg_duration": stats["average_duration"]
        }
    
    def identify_problematic_modules(
        self,
        failure_threshold: float = 0.3,
        timeout_threshold: float = 0.2
    ) -> List[Dict[str, Any]]:
        """
        Identify modules with performance issues.
        
        Args:
            failure_threshold: Failure rate threshold
            timeout_threshold: Timeout rate threshold
            
        Returns:
            List of problematic modules with details
        """
        problematic = []
        
        for module_name in self.total_executions:
            stats = self.get_module_stats(module_name)
            total = stats["total_executions"]
            
            if total < 5:  # Skip modules with too few executions
                continue
            
            failure_rate = stats["failure_count"] / total
            timeout_rate = stats["timeout_count"] / total
            
            issues = []
            severity = "low"
            
            if failure_rate > failure_threshold:
                issues.append(f"High failure rate: {failure_rate:.1%}")
                severity = "high"
            
            if timeout_rate > timeout_threshold:
                issues.append(f"High timeout rate: {timeout_rate:.1%}")
                if severity != "high":
                    severity = "medium"
            
            if stats["success_rate"] < 0.5:
                issues.append(f"Low success rate: {stats['success_rate']:.1%}")
                severity = "high"
            
            if issues:
                problematic.append({
                    "module_name": module_name,
                    "issues": issues,
                    "severity": severity,
                    "stats": stats,
                    "recommendation": self._get_recommendation(issues)
                })
        
        # Sort by severity
        severity_order = {"high": 0, "medium": 1, "low": 2}
        problematic.sort(key=lambda x: severity_order[x["severity"]])
        
        return problematic
    
    def _get_recommendation(self, issues: List[str]) -> str:
        """Get recommendation based on issues."""
        recommendations = []
        
        for issue in issues:
            if "failure rate" in issue:
                recommendations.append("Review module code for bugs")
            elif "timeout rate" in issue:
                recommendations.append("Optimize performance or increase timeout")
            elif "success rate" in issue:
                recommendations.append("Module needs immediate attention")
        
        return "; ".join(recommendations)


class MetricsCollector:
    """Collect and persist metrics."""
    
    def __init__(
        self,
        metrics_dir: Optional[Path] = None,
        persist_interval: int = 300  # 5 minutes
    ):
        """
        Initialize metrics collector.
        
        Args:
            metrics_dir: Directory to store metrics
            persist_interval: Interval to persist metrics (seconds)
        """
        self.metrics_dir = metrics_dir or Path.home() / ".gibson" / "metrics"
        self.metrics_dir.mkdir(parents=True, exist_ok=True)
        
        self.persist_interval = persist_interval
        self.last_persist = time.time()
        
        self.performance_metrics = PerformanceMetrics()
        self.execution_log: List[Dict] = []
        
        self._load_metrics()
    
    def record_execution(
        self,
        module_name: str,
        result: ModuleResultModel,
        target_info: Optional[Dict] = None
    ) -> None:
        """
        Record module execution.
        
        Args:
            module_name: Name of module
            result: Execution result
            target_info: Optional target information
        """
        # Record in performance metrics
        self.performance_metrics.record_execution(module_name, result)
        
        # Log execution details
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "module_name": module_name,
            "execution_id": str(result.execution_id),
            "status": result.status.value if hasattr(result.status, 'value') else result.status,
            "duration": result.duration,
            "finding_count": len(result.findings),
            "finding_severities": self._count_severities(result.findings),
            "target_info": target_info,
            "error": result.error_message
        }
        
        self.execution_log.append(log_entry)
        
        # Persist if interval reached
        if time.time() - self.last_persist > self.persist_interval:
            self.persist_metrics()
    
    def _count_severities(self, findings: List) -> Dict[str, int]:
        """Count findings by severity."""
        severities = defaultdict(int)
        for finding in findings:
            if hasattr(finding, 'severity'):
                severity = finding.severity
                if hasattr(severity, 'value'):
                    severity = severity.value
                severities[severity] += 1
        return dict(severities)
    
    def persist_metrics(self) -> None:
        """Persist metrics to disk."""
        try:
            # Save performance metrics
            metrics_file = self.metrics_dir / "performance_metrics.json"
            metrics_data = {
                "last_updated": datetime.utcnow().isoformat(),
                "modules": {}
            }
            
            for module_name in self.performance_metrics.total_executions:
                metrics_data["modules"][module_name] = self.performance_metrics.get_module_stats(module_name)
            
            with open(metrics_file, "w") as f:
                json.dump(metrics_data, f, indent=2, default=str)
            
            # Save execution log (append mode)
            log_file = self.metrics_dir / f"execution_log_{datetime.utcnow().strftime('%Y%m%d')}.jsonl"
            with open(log_file, "a") as f:
                for entry in self.execution_log:
                    f.write(json.dumps(entry, default=str) + "\n")
            
            # Clear processed log entries
            self.execution_log.clear()
            self.last_persist = time.time()
            
            logger.debug("Metrics persisted successfully")
            
        except Exception as e:
            logger.error(f"Failed to persist metrics: {e}")
    
    def _load_metrics(self) -> None:
        """Load metrics from disk."""
        metrics_file = self.metrics_dir / "performance_metrics.json"
        
        if metrics_file.exists():
            try:
                with open(metrics_file) as f:
                    data = json.load(f)
                
                # Restore metrics
                # Note: This is simplified - full implementation would restore all data
                logger.debug("Loaded existing metrics")
                
            except Exception as e:
                logger.warning(f"Failed to load metrics: {e}")
    
    def generate_report(
        self,
        module_name: Optional[str] = None,
        period_days: int = 7
    ) -> Dict[str, Any]:
        """
        Generate metrics report.
        
        Args:
            module_name: Specific module or None for all
            period_days: Report period in days
            
        Returns:
            Report dictionary
        """
        if module_name:
            stats = self.performance_metrics.get_module_stats(module_name)
            trending = self.performance_metrics.get_trending_metrics(
                module_name,
                period_days * 24
            )
            
            return {
                "report_type": "module",
                "module_name": module_name,
                "period_days": period_days,
                "statistics": stats,
                "trending": trending,
                "generated_at": datetime.utcnow().isoformat()
            }
        else:
            global_stats = self.performance_metrics.get_global_stats()
            problematic = self.performance_metrics.identify_problematic_modules()
            
            # Get top performers
            top_performers = []
            for name in self.performance_metrics.total_executions:
                stats = self.performance_metrics.get_module_stats(name)
                if stats["total_executions"] >= 5 and stats["success_rate"] >= 0.95:
                    top_performers.append({
                        "module_name": name,
                        "success_rate": stats["success_rate"],
                        "avg_duration": stats["average_duration"]
                    })
            
            top_performers.sort(key=lambda x: x["success_rate"], reverse=True)
            
            return {
                "report_type": "global",
                "period_days": period_days,
                "global_statistics": global_stats,
                "problematic_modules": problematic,
                "top_performers": top_performers[:5],
                "generated_at": datetime.utcnow().isoformat()
            }
    
    def cleanup_old_logs(self, days_to_keep: int = 30) -> None:
        """
        Clean up old log files.
        
        Args:
            days_to_keep: Number of days of logs to keep
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        for log_file in self.metrics_dir.glob("execution_log_*.jsonl"):
            # Parse date from filename
            try:
                date_str = log_file.stem.split("_")[-1]
                file_date = datetime.strptime(date_str, "%Y%m%d")
                
                if file_date < cutoff_date:
                    log_file.unlink()
                    logger.info(f"Deleted old log file: {log_file}")
                    
            except Exception as e:
                logger.warning(f"Failed to process log file {log_file}: {e}")