"""Monitoring and health checks for the payload system."""

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from gibson.models.domain import AttackDomain
from gibson.core.payloads.types import PayloadMetrics
from enum import Enum


class HealthStatus(str, Enum):
    """Health status for monitoring."""

    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class SystemHealth:
    """Overall system health status."""

    status: HealthStatus
    database_connected: bool
    filesystem_accessible: bool
    cache_operational: bool
    sources_reachable: Dict[str, bool]
    last_check: datetime
    issues: List[str]
    metrics: PayloadMetrics


@dataclass
class ConsistencyReport:
    """Report of database-filesystem consistency."""

    total_db_records: int
    total_files: int
    orphaned_records: List[str]  # DB records without files
    orphaned_files: List[str]  # Files without DB records
    mismatched_metadata: List[str]  # Files with incorrect metadata
    consistency_score: float  # 0.0 to 1.0


class PayloadMonitor:
    """Monitors payload system health and performance."""

    def __init__(
        self,
        database,
        organizer,
        cache,
        fetcher,
        check_interval: int = 300,  # 5 minutes
    ):
        """Initialize the monitor.

        Args:
            database: PayloadDatabase instance
            organizer: PayloadOrganizer instance
            cache: PayloadCache instance
            fetcher: PayloadFetcher instance
            check_interval: Seconds between health checks
        """
        self.database = database
        self.organizer = organizer
        self.cache = cache
        self.fetcher = fetcher
        self.check_interval = check_interval

        self._last_health_check: Optional[SystemHealth] = None
        self._monitoring_task: Optional[asyncio.Task] = None
        self._metrics_buffer: List[Dict[str, Any]] = []
        self._performance_samples: List[Dict[str, float]] = []

    async def start_monitoring(self) -> None:
        """Start background monitoring task."""
        if self._monitoring_task and not self._monitoring_task.done():
            return

        self._monitoring_task = asyncio.create_task(self._monitoring_loop())

    async def stop_monitoring(self) -> None:
        """Stop background monitoring task."""
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
            self._monitoring_task = None

    async def _monitoring_loop(self) -> None:
        """Background monitoring loop."""
        while True:
            try:
                await self.health_check()
                await asyncio.sleep(self.check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue monitoring
                print(f"Monitor error: {e}")
                await asyncio.sleep(self.check_interval)

    async def health_check(self) -> SystemHealth:
        """Perform comprehensive health check.

        Returns:
            System health status
        """
        issues = []

        # Check database connectivity
        db_connected = await self._check_database()
        if not db_connected:
            issues.append("Database connection failed")

        # Check filesystem access
        fs_accessible = await self._check_filesystem()
        if not fs_accessible:
            issues.append("Filesystem access failed")

        # Check cache operation
        cache_operational = await self._check_cache()
        if not cache_operational:
            issues.append("Cache not operational")

        # Check external sources
        sources_status = await self._check_sources()
        unreachable = [s for s, reachable in sources_status.items() if not reachable]
        if unreachable:
            issues.append(f"Unreachable sources: {', '.join(unreachable)}")

        # Get current metrics
        metrics = await self.get_metrics()

        # Determine overall status
        if not issues:
            status = HealthStatus.HEALTHY
        elif db_connected and fs_accessible:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.UNHEALTHY

        health = SystemHealth(
            status=status,
            database_connected=db_connected,
            filesystem_accessible=fs_accessible,
            cache_operational=cache_operational,
            sources_reachable=sources_status,
            last_check=datetime.utcnow(),
            issues=issues,
            metrics=metrics,
        )

        self._last_health_check = health
        return health

    async def _check_database(self) -> bool:
        """Check database connectivity."""
        try:
            # Try a simple query
            await self.database.get_statistics()
            return True
        except Exception:
            return False

    async def _check_filesystem(self) -> bool:
        """Check filesystem accessibility."""
        try:
            # Check if payload directory exists and is writable
            test_file = self.organizer.base_dir / ".health_check"
            test_file.touch()
            test_file.unlink()
            return True
        except Exception:
            return False

    async def _check_cache(self) -> bool:
        """Check cache operation."""
        try:
            # Try cache operations
            test_key = "__health_check__"
            await self.cache.set(test_key, {"test": True}, ttl=1)
            result = await self.cache.get(test_key)
            await self.cache.invalidate(test_key)
            return result is not None
        except Exception:
            return False

    async def _check_sources(self) -> Dict[str, bool]:
        """Check external source availability."""
        sources = await self.database.list_sources()
        status = {}

        for source in sources:
            try:
                # Quick connectivity check
                reachable = await self.fetcher.check_source_availability(source.url)
                status[source.name] = reachable
            except Exception:
                status[source.name] = False

        return status

    async def check_consistency(self) -> ConsistencyReport:
        """Check database-filesystem consistency.

        Returns:
            Consistency report
        """
        # Get all database records
        db_records = await self.database.list_all_references()
        db_paths = {record.file_path for record in db_records}

        # Get all filesystem payloads
        fs_files = set()
        for domain in PayloadDomain:
            domain_dir = self.organizer.base_dir / domain.value
            if domain_dir.exists():
                for file_path in domain_dir.rglob("*.yaml"):
                    fs_files.add(str(file_path.relative_to(self.organizer.base_dir)))

        # Find discrepancies
        orphaned_records = list(db_paths - fs_files)
        orphaned_files = list(fs_files - db_paths)

        # Check metadata consistency
        mismatched = []
        for record in db_records:
            if record.file_path in fs_files:
                try:
                    file_path = self.organizer.base_dir / record.file_path
                    # Could check file hash or modification time here
                    if not file_path.exists():
                        mismatched.append(record.file_path)
                except Exception:
                    mismatched.append(record.file_path)

        # Calculate consistency score
        total = len(db_paths) + len(fs_files)
        if total > 0:
            inconsistent = len(orphaned_records) + len(orphaned_files) + len(mismatched)
            consistency_score = 1.0 - (inconsistent / total)
        else:
            consistency_score = 1.0

        return ConsistencyReport(
            total_db_records=len(db_records),
            total_files=len(fs_files),
            orphaned_records=orphaned_records,
            orphaned_files=orphaned_files,
            mismatched_metadata=mismatched,
            consistency_score=consistency_score,
        )

    async def get_metrics(self) -> PayloadMetrics:
        """Get current system metrics.

        Returns:
            System metrics
        """
        # Get database statistics
        db_stats = await self.database.get_statistics()

        # Get cache metrics
        cache_stats = await self.cache.get_stats()

        # Get filesystem metrics
        fs_stats = await self._get_filesystem_stats()

        # Calculate sync metrics
        sync_stats = await self._get_sync_stats()

        return PayloadMetrics(
            total_payloads=db_stats.get("total", 0),
            payloads_by_domain=db_stats.get("by_domain", {}),
            payloads_by_severity=db_stats.get("by_severity", {}),
            cache_metrics={
                "hit_rate": cache_stats.hit_rate,
                "size": cache_stats.size,
                "evictions": cache_stats.evictions,
            },
            storage_metrics=fs_stats,
            sync_metrics=sync_stats,
            effectiveness_metrics=db_stats.get("effectiveness", {}),
        )

    async def _get_filesystem_stats(self) -> Dict[str, Any]:
        """Get filesystem statistics."""
        total_size = 0
        file_count = 0

        for domain in PayloadDomain:
            domain_dir = self.organizer.base_dir / domain.value
            if domain_dir.exists():
                for file_path in domain_dir.rglob("*.yaml"):
                    file_count += 1
                    total_size += file_path.stat().st_size

        return {
            "total_files": file_count,
            "total_size_bytes": total_size,
            "average_file_size": total_size / file_count if file_count > 0 else 0,
        }

    async def _get_sync_stats(self) -> Dict[str, Any]:
        """Get synchronization statistics."""
        sources = await self.database.list_sources()

        total_syncs = 0
        failed_syncs = 0
        last_sync = None

        for source in sources:
            if source.last_sync:
                total_syncs += 1
                if not last_sync or source.last_sync > last_sync:
                    last_sync = source.last_sync

            if source.last_error:
                failed_syncs += 1

        return {
            "total_sources": len(sources),
            "successful_syncs": total_syncs - failed_syncs,
            "failed_syncs": failed_syncs,
            "last_sync": last_sync.isoformat() if last_sync else None,
        }

    async def collect_performance_metrics(self) -> Dict[str, float]:
        """Collect performance metrics.

        Returns:
            Performance metrics
        """
        metrics = {}

        # Test cache performance
        start = time.perf_counter()
        test_key = "__perf_test__"
        await self.cache.set(test_key, {"test": True}, ttl=1)
        cache_hit = await self.cache.get(test_key)
        await self.cache.invalidate(test_key)
        metrics["cache_latency_ms"] = (time.perf_counter() - start) * 1000

        # Test database query performance
        start = time.perf_counter()
        await self.database.query_metadata({"limit": 1})
        metrics["db_query_latency_ms"] = (time.perf_counter() - start) * 1000

        # Test filesystem access
        start = time.perf_counter()
        test_file = self.organizer.base_dir / ".perf_test"
        test_file.touch()
        test_file.unlink()
        metrics["fs_latency_ms"] = (time.perf_counter() - start) * 1000

        # Add to performance samples
        self._performance_samples.append(
            {
                "timestamp": datetime.utcnow().isoformat(),
                **metrics,
            }
        )

        # Keep only last 100 samples
        if len(self._performance_samples) > 100:
            self._performance_samples = self._performance_samples[-100:]

        return metrics

    async def get_alerts(self) -> List[Dict[str, Any]]:
        """Get current system alerts.

        Returns:
            List of alerts
        """
        alerts = []

        # Check last health status
        if self._last_health_check:
            if self._last_health_check.status == HealthStatus.UNHEALTHY:
                alerts.append(
                    {
                        "level": "critical",
                        "message": "System is unhealthy",
                        "details": self._last_health_check.issues,
                    }
                )
            elif self._last_health_check.status == HealthStatus.DEGRADED:
                alerts.append(
                    {
                        "level": "warning",
                        "message": "System is degraded",
                        "details": self._last_health_check.issues,
                    }
                )

        # Check consistency
        consistency = await self.check_consistency()
        if consistency.consistency_score < 0.9:
            alerts.append(
                {
                    "level": "warning",
                    "message": f"Low consistency score: {consistency.consistency_score:.2%}",
                    "details": {
                        "orphaned_records": len(consistency.orphaned_records),
                        "orphaned_files": len(consistency.orphaned_files),
                    },
                }
            )

        # Check cache hit rate
        cache_stats = await self.cache.get_stats()
        if cache_stats.hit_rate < 0.5:
            alerts.append(
                {
                    "level": "info",
                    "message": f"Low cache hit rate: {cache_stats.hit_rate:.2%}",
                    "details": {"consider": "Cache warming or size increase"},
                }
            )

        return alerts

    def get_last_health_check(self) -> Optional[SystemHealth]:
        """Get the last health check result.

        Returns:
            Last health check or None
        """
        return self._last_health_check
