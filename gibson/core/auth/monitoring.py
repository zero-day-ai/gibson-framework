"""Authentication monitoring and metrics."""
import time
from typing import Dict, Any, List
from dataclasses import dataclass, field
from collections import deque

@dataclass
class AuthMetric:
    """Authentication metric data."""
    timestamp: float
    metric_type: str
    value: float
    metadata: Dict[str, Any] = field(default_factory=dict)

class AuthMonitor:
    """Monitors authentication operations."""
    
    def __init__(self, window_size: int = 1000):
        self.metrics = deque(maxlen=window_size)
        self.counters = {
            "auth_requests": 0,
            "auth_successes": 0,
            "auth_failures": 0,
            "credential_loads": 0,
            "validation_calls": 0,
        }
        self.timings = {
            "auth_duration": [],
            "load_duration": [],
            "validation_duration": [],
        }
    
    def record_metric(self, metric_type: str, value: float, metadata: Dict = None):
        """Record a metric."""
        metric = AuthMetric(
            timestamp=time.time(),
            metric_type=metric_type,
            value=value,
            metadata=metadata or {}
        )
        self.metrics.append(metric)
        
        # Update counters
        if metric_type in self.counters:
            self.counters[metric_type] += 1
        
        # Update timings
        if metric_type.endswith("_duration"):
            if metric_type not in self.timings:
                self.timings[metric_type] = []
            self.timings[metric_type].append(value)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary."""
        summary = {
            "counters": self.counters,
            "success_rate": (
                self.counters["auth_successes"] / self.counters["auth_requests"]
                if self.counters["auth_requests"] > 0 else 0
            ),
            "average_timings": {}
        }
        
        for timing_type, values in self.timings.items():
            if values:
                summary["average_timings"][timing_type] = sum(values) / len(values)
                
        return summary
    
    def get_recent_metrics(self, count: int = 100) -> List[AuthMetric]:
        """Get recent metrics."""
        return list(self.metrics)[-count:]
