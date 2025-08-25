"""Enhanced database health check system for Gibson framework."""

import logging
import subprocess
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Literal
from pathlib import Path
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from gibson.db.base import Base
from gibson.db.utils.schema_validator import SchemaValidator, ValidationResult

logger = logging.getLogger(__name__)


class HealthCheck(BaseModel):
    """Individual health check result."""
    
    name: str = Field(description="Name of the health check")
    status: Literal["pass", "warn", "fail"] = Field(description="Check status")
    message: str = Field(description="Human-readable status message")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional details")


class MigrationStatus(BaseModel):
    """Migration status information."""
    
    current_revision: Optional[str] = Field(default=None, description="Current database revision")
    head_revision: Optional[str] = Field(default=None, description="Latest available revision")
    is_current: bool = Field(default=False, description="Whether database is at latest revision")
    pending_migrations: int = Field(default=0, description="Number of pending migrations")
    error: Optional[str] = Field(default=None, description="Error message if check failed")


class RegistrationStatus(BaseModel):
    """Model registration status."""
    
    total_models: int = Field(default=0, description="Total number of registered models")
    registered_tables: List[str] = Field(default_factory=list, description="List of registered table names")
    import_errors: List[str] = Field(default_factory=list, description="Import errors encountered")


class HealthReport(BaseModel):
    """Comprehensive database health report."""
    
    overall_status: Literal["healthy", "degraded", "unhealthy"] = Field(description="Overall health status")
    database_exists: bool = Field(description="Whether database file exists")
    all_tables_present: bool = Field(description="Whether all expected tables exist")
    migrations_current: bool = Field(description="Whether migrations are up to date")
    models_registered: bool = Field(description="Whether all models are registered")
    import_paths_valid: bool = Field(description="Whether import paths are correct")
    checks: List[HealthCheck] = Field(default_factory=list, description="Individual health check results")
    recommendations: List[str] = Field(default_factory=list, description="Recommended actions")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class DatabaseHealthChecker:
    """Comprehensive database health checking system."""
    
    def __init__(self, database_path: Optional[Path] = None):
        """Initialize health checker.
        
        Args:
            database_path: Path to database file. Defaults to ./gibson.db
        """
        self.database_path = database_path or Path("./gibson.db")
        self.validator = SchemaValidator()
        
    async def check_health(self, session: AsyncSession) -> HealthReport:
        """Run comprehensive health checks.
        
        Args:
            session: Async database session
            
        Returns:
            HealthReport with all check results
        """
        report = HealthReport(
            overall_status="healthy",
            database_exists=True,
            all_tables_present=True,
            migrations_current=True,
            models_registered=True,
            import_paths_valid=True
        )
        
        # Check 1: Database file existence
        db_check = self._check_database_file()
        report.checks.append(db_check)
        if db_check.status == "fail":
            report.database_exists = False
            report.overall_status = "unhealthy"
            report.recommendations.append("Run 'gibson database init' to create database")
            
        # Check 2: Model registration
        registration_check = self._check_model_registration()
        report.checks.append(registration_check)
        if registration_check.status == "fail":
            report.models_registered = False
            report.overall_status = "unhealthy"
            
        # Check 3: Schema validation
        schema_check = await self._check_schema(session)
        report.checks.append(schema_check)
        if schema_check.status == "fail":
            report.all_tables_present = False
            report.overall_status = "unhealthy"
            report.recommendations.append("Run 'alembic upgrade head' to create missing tables")
            
        # Check 4: Migration status
        migration_check = await self._check_migrations()
        report.checks.append(migration_check)
        if migration_check.status == "fail":
            report.migrations_current = False
            if report.overall_status == "healthy":
                report.overall_status = "degraded"
            report.recommendations.append("Run 'alembic upgrade head' to apply pending migrations")
            
        # Check 5: Import paths
        import_check = self._check_import_paths()
        report.checks.append(import_check)
        if import_check.status == "fail":
            report.import_paths_valid = False
            report.overall_status = "unhealthy"
            report.recommendations.append("Fix import paths as indicated in check details")
            
        # Check 6: Critical tables
        critical_check = await self._check_critical_tables(session)
        report.checks.append(critical_check)
        if critical_check.status == "fail":
            report.overall_status = "unhealthy"
            
        # Set overall status based on individual checks
        fail_count = sum(1 for check in report.checks if check.status == "fail")
        warn_count = sum(1 for check in report.checks if check.status == "warn")
        
        if fail_count > 0:
            report.overall_status = "unhealthy"
        elif warn_count > 0:
            report.overall_status = "degraded"
            
        logger.info(f"Health check complete: {report.overall_status} ({fail_count} failures, {warn_count} warnings)")
        
        return report
        
    def _check_database_file(self) -> HealthCheck:
        """Check if database file exists and is accessible.
        
        Returns:
            HealthCheck result
        """
        if not self.database_path.exists():
            return HealthCheck(
                name="Database File",
                status="fail",
                message=f"Database file not found: {self.database_path}",
                details={"path": str(self.database_path)}
            )
            
        if not self.database_path.is_file():
            return HealthCheck(
                name="Database File",
                status="fail",
                message=f"Database path is not a file: {self.database_path}",
                details={"path": str(self.database_path)}
            )
            
        # Check file size
        size_bytes = self.database_path.stat().st_size
        size_mb = size_bytes / (1024 * 1024)
        
        return HealthCheck(
            name="Database File",
            status="pass",
            message=f"Database file exists ({size_mb:.2f} MB)",
            details={
                "path": str(self.database_path),
                "size_bytes": size_bytes,
                "size_mb": size_mb
            }
        )
        
    def _check_model_registration(self) -> HealthCheck:
        """Check if models are properly registered.
        
        Returns:
            HealthCheck result
        """
        try:
            table_count = len(Base.metadata.tables)
            table_names = sorted(Base.metadata.tables.keys())
            
            if table_count == 0:
                return HealthCheck(
                    name="Model Registration",
                    status="fail",
                    message="No models registered with Base.metadata",
                    details={"table_count": 0}
                )
                
            # Check for expected minimum tables
            expected_core_tables = {'targets', 'scans', 'findings', 'modules', 'payloads', 'prompts'}
            registered_set = set(table_names)
            missing_core = expected_core_tables - registered_set
            
            if missing_core:
                return HealthCheck(
                    name="Model Registration",
                    status="warn",
                    message=f"Some core tables not registered: {missing_core}",
                    details={
                        "table_count": table_count,
                        "registered": table_names,
                        "missing_core": list(missing_core)
                    }
                )
                
            return HealthCheck(
                name="Model Registration",
                status="pass",
                message=f"{table_count} models registered successfully",
                details={
                    "table_count": table_count,
                    "tables": table_names[:10]  # Show first 10 tables
                }
            )
            
        except Exception as e:
            return HealthCheck(
                name="Model Registration",
                status="fail",
                message=f"Failed to check model registration: {str(e)}",
                details={"error": str(e)}
            )
            
    async def _check_schema(self, session: AsyncSession) -> HealthCheck:
        """Check database schema validity.
        
        Args:
            session: Async database session
            
        Returns:
            HealthCheck result
        """
        try:
            result = await self.validator.validate_schema(session)
            
            if result.is_valid:
                return HealthCheck(
                    name="Schema Validation",
                    status="pass",
                    message=f"Schema valid: {len(result.actual_tables)} tables present",
                    details={
                        "expected_count": len(result.expected_tables),
                        "actual_count": len(result.actual_tables)
                    }
                )
                
            if result.missing_tables:
                return HealthCheck(
                    name="Schema Validation",
                    status="fail",
                    message=f"Missing {len(result.missing_tables)} required tables",
                    details={
                        "missing_tables": result.missing_tables,
                        "extra_tables": result.extra_tables
                    }
                )
                
            # Has extra tables but no missing ones
            return HealthCheck(
                name="Schema Validation",
                status="warn",
                message=f"Schema has {len(result.extra_tables)} unexpected tables",
                details={"extra_tables": result.extra_tables}
            )
            
        except Exception as e:
            return HealthCheck(
                name="Schema Validation",
                status="fail",
                message=f"Schema validation failed: {str(e)}",
                details={"error": str(e)}
            )
            
    async def _check_migrations(self) -> HealthCheck:
        """Check Alembic migration status.
        
        Returns:
            HealthCheck result
        """
        try:
            # Run alembic current to get current revision
            current_result = subprocess.run(
                ["alembic", "current"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Run alembic heads to get target revision
            heads_result = subprocess.run(
                ["alembic", "heads"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Parse results
            current_rev = None
            if current_result.returncode == 0 and current_result.stdout:
                # Extract revision from output
                lines = current_result.stdout.strip().split('\n')
                for line in lines:
                    if ' (head)' in line or len(line.split()) > 0:
                        current_rev = line.split()[0] if line.split() else None
                        break
                        
            head_rev = None
            if heads_result.returncode == 0 and heads_result.stdout:
                head_rev = heads_result.stdout.strip().split()[0]
                
            if current_rev == head_rev and current_rev is not None:
                return HealthCheck(
                    name="Migration Status",
                    status="pass",
                    message=f"Migrations current at revision {current_rev[:8]}",
                    details={
                        "current_revision": current_rev,
                        "head_revision": head_rev
                    }
                )
                
            if current_rev != head_rev:
                return HealthCheck(
                    name="Migration Status",
                    status="warn",
                    message="Migrations not at latest revision",
                    details={
                        "current_revision": current_rev,
                        "head_revision": head_rev
                    }
                )
                
            return HealthCheck(
                name="Migration Status",
                status="warn",
                message="Could not determine migration status",
                details={
                    "current_output": current_result.stdout,
                    "heads_output": heads_result.stdout
                }
            )
            
        except subprocess.TimeoutExpired:
            return HealthCheck(
                name="Migration Status",
                status="warn",
                message="Migration check timed out",
                details={"error": "Command timed out after 5 seconds"}
            )
        except Exception as e:
            return HealthCheck(
                name="Migration Status",
                status="warn",
                message=f"Could not check migrations: {str(e)}",
                details={"error": str(e)}
            )
            
    def _check_import_paths(self) -> HealthCheck:
        """Check for common import path issues.
        
        Returns:
            HealthCheck result
        """
        issues = []
        
        # Check for old import paths in key files
        files_to_check = [
            Path("tests/integration/payloads/test_database_operations.py"),
            Path("gibson/cli/commands/payloads.py"),
        ]
        
        for file_path in files_to_check:
            if file_path.exists():
                try:
                    content = file_path.read_text()
                    # Check line by line to skip comments
                    for line_num, line in enumerate(content.splitlines(), 1):
                        # Skip comment lines
                        if line.strip().startswith("#"):
                            continue
                        if "from gibson.core.database import Base" in line:
                            issues.append(f"{file_path}:{line_num}: Uses old 'gibson.core.database' import")
                        if "from gibson.core.base import Base" in line and "payloads.py" in str(file_path):
                            issues.append(f"{file_path}:{line_num}: Imports wrong Base class from gibson.core.base")
                except Exception as e:
                    logger.warning(f"Could not check {file_path}: {e}")
                    
        if issues:
            return HealthCheck(
                name="Import Paths",
                status="fail",
                message=f"Found {len(issues)} import path issues",
                details={"issues": issues}
            )
            
        return HealthCheck(
            name="Import Paths",
            status="pass",
            message="Import paths are correct",
            details={"files_checked": len(files_to_check)}
        )
        
    async def _check_critical_tables(self, session: AsyncSession) -> HealthCheck:
        """Check if critical tables exist and are accessible.
        
        Args:
            session: Async database session
            
        Returns:
            HealthCheck result
        """
        critical_tables = ['targets', 'scans', 'findings', 'modules', 'payloads', 'prompts']
        
        try:
            present = await self.validator.check_critical_tables(session, critical_tables)
            
            if present:
                # Also check if tables are accessible
                accessible = []
                for table in critical_tables:
                    try:
                        result = await session.execute(text(f"SELECT COUNT(*) FROM {table}"))
                        count = result.scalar()
                        accessible.append(table)
                    except Exception:
                        pass
                        
                if len(accessible) == len(critical_tables):
                    return HealthCheck(
                        name="Critical Tables",
                        status="pass",
                        message=f"All {len(critical_tables)} critical tables present and accessible",
                        details={"tables": critical_tables}
                    )
                else:
                    missing_access = set(critical_tables) - set(accessible)
                    return HealthCheck(
                        name="Critical Tables",
                        status="warn",
                        message=f"Some critical tables not accessible: {missing_access}",
                        details={
                            "accessible": accessible,
                            "not_accessible": list(missing_access)
                        }
                    )
            else:
                return HealthCheck(
                    name="Critical Tables",
                    status="fail",
                    message="Critical tables missing",
                    details={"required": critical_tables}
                )
                
        except Exception as e:
            return HealthCheck(
                name="Critical Tables",
                status="fail",
                message=f"Failed to check critical tables: {str(e)}",
                details={"error": str(e)}
            )


# Convenience functions
async def check_health(session: AsyncSession, database_path: Optional[Path] = None) -> HealthReport:
    """Run comprehensive health checks.
    
    Args:
        session: Async database session
        database_path: Optional path to database file
        
    Returns:
        HealthReport
    """
    checker = DatabaseHealthChecker(database_path)
    return await checker.check_health(session)


async def check_migrations() -> MigrationStatus:
    """Check migration status.
    
    Returns:
        MigrationStatus
    """
    checker = DatabaseHealthChecker()
    health_check = await checker._check_migrations()
    
    status = MigrationStatus()
    if health_check.details:
        status.current_revision = health_check.details.get("current_revision")
        status.head_revision = health_check.details.get("head_revision")
        status.is_current = status.current_revision == status.head_revision
        
    return status


def check_model_registration() -> RegistrationStatus:
    """Check model registration status.
    
    Returns:
        RegistrationStatus
    """
    status = RegistrationStatus()
    
    try:
        status.total_models = len(Base.metadata.tables)
        status.registered_tables = sorted(Base.metadata.tables.keys())
    except Exception as e:
        status.import_errors.append(str(e))
        
    return status


class PerformanceMetrics(BaseModel):
    """Database performance metrics."""
    
    query_response_time_ms: float = Field(description="Average query response time")
    connection_pool_usage: float = Field(description="Connection pool usage percentage")
    active_connections: int = Field(description="Number of active connections")
    slow_queries: int = Field(default=0, description="Number of slow queries detected")
    lock_waits: int = Field(default=0, description="Number of lock waits")


class EnhancedHealthReport(BaseModel):
    """Enhanced health report with performance metrics."""
    
    overall_status: Literal["healthy", "degraded", "unhealthy"] = Field(description="Overall health status")
    database_exists: bool = Field(description="Whether database file exists")
    all_tables_present: bool = Field(description="Whether all expected tables exist")
    migrations_current: bool = Field(description="Whether migrations are up to date")
    models_registered: bool = Field(description="Whether all models are registered")
    import_paths_valid: bool = Field(description="Whether import paths are correct")
    performance_metrics: Optional[PerformanceMetrics] = Field(default=None, description="Performance metrics")
    checks: List[HealthCheck] = Field(default_factory=list, description="Individual health check results")
    recommendations: List[str] = Field(default_factory=list, description="Recommended actions")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    check_duration_ms: float = Field(default=0, description="Health check execution time")


class EnhancedDatabaseHealthChecker(DatabaseHealthChecker):
    """Enhanced database health checker with performance monitoring."""
    
    def __init__(self, database_path: Optional[Path] = None):
        """Initialize enhanced health checker."""
        super().__init__(database_path)
        self.performance_thresholds = {
            "query_time_warning_ms": 1000,
            "query_time_critical_ms": 5000,
            "pool_usage_warning": 0.7,
            "pool_usage_critical": 0.9
        }
    
    async def check_enhanced_health(self, session: AsyncSession, engine=None) -> EnhancedHealthReport:
        """Run enhanced health checks with performance monitoring.
        
        Args:
            session: Database session
            engine: Optional SQLAlchemy engine for pool metrics
            
        Returns:
            Enhanced health report
        """
        start_time = time.time()
        
        # Run basic health checks first
        basic_report = await self.check_health(session)
        
        # Create enhanced report
        enhanced_report = EnhancedHealthReport(
            overall_status=basic_report.overall_status,
            database_exists=basic_report.database_exists,
            all_tables_present=basic_report.all_tables_present,
            migrations_current=basic_report.migrations_current,
            models_registered=basic_report.models_registered,
            import_paths_valid=basic_report.import_paths_valid,
            checks=basic_report.checks,
            recommendations=basic_report.recommendations,
            timestamp=basic_report.timestamp
        )
        
        # Add performance checks
        if engine:
            perf_check = await self._check_performance_metrics(session, engine)
            enhanced_report.checks.append(perf_check)
            
            # Extract performance metrics from check details
            if perf_check.details and perf_check.status != "fail":
                enhanced_report.performance_metrics = PerformanceMetrics(
                    query_response_time_ms=perf_check.details.get("avg_response_time_ms", 0),
                    connection_pool_usage=perf_check.details.get("pool_usage_percent", 0),
                    active_connections=perf_check.details.get("active_connections", 0),
                    slow_queries=perf_check.details.get("slow_queries", 0),
                    lock_waits=perf_check.details.get("lock_waits", 0)
                )
                
                # Adjust overall status based on performance
                if perf_check.status == "fail":
                    enhanced_report.overall_status = "unhealthy"
                elif perf_check.status == "warn" and enhanced_report.overall_status == "healthy":
                    enhanced_report.overall_status = "degraded"
        
        # Add repository health check
        repo_check = await self._check_repository_health(session)
        enhanced_report.checks.append(repo_check)
        
        enhanced_report.check_duration_ms = round((time.time() - start_time) * 1000, 2)
        
        return enhanced_report
    
    async def _check_performance_metrics(self, session: AsyncSession, engine) -> HealthCheck:
        """Check database performance metrics.
        
        Args:
            session: Database session
            engine: SQLAlchemy engine
            
        Returns:
            HealthCheck result
        """
        try:
            metrics = {}
            
            # Test query response time
            queries = [
                ("simple_select", "SELECT 1"),
                ("table_count", "SELECT name FROM sqlite_master WHERE type='table'"),
            ]
            
            total_time = 0
            slow_queries = 0
            
            for name, query in queries:
                start = time.time()
                await session.execute(text(query))
                duration_ms = (time.time() - start) * 1000
                total_time += duration_ms
                
                if duration_ms > self.performance_thresholds["query_time_critical_ms"]:
                    slow_queries += 1
            
            avg_response_time = total_time / len(queries)
            metrics["avg_response_time_ms"] = round(avg_response_time, 2)
            metrics["slow_queries"] = slow_queries
            
            # Check connection pool if available
            if hasattr(engine, 'pool'):
                pool = engine.pool
                if hasattr(pool, 'size'):
                    pool_size = pool.size()
                    checked_out = pool.checkedout()
                    pool_usage = (checked_out / pool_size) if pool_size > 0 else 0
                    
                    metrics["pool_usage_percent"] = round(pool_usage * 100, 1)
                    metrics["active_connections"] = checked_out
                    metrics["total_pool_size"] = pool_size
                else:
                    metrics["pool_usage_percent"] = 0
                    metrics["active_connections"] = 1  # Current session
            else:
                metrics["pool_usage_percent"] = 0
                metrics["active_connections"] = 1
            
            # Determine status based on thresholds
            status = "pass"
            issues = []
            
            if avg_response_time > self.performance_thresholds["query_time_critical_ms"]:
                status = "fail"
                issues.append(f"Critical: Average query time {avg_response_time:.2f}ms")
            elif avg_response_time > self.performance_thresholds["query_time_warning_ms"]:
                status = "warn"
                issues.append(f"Warning: Average query time {avg_response_time:.2f}ms")
            
            pool_usage_percent = metrics.get("pool_usage_percent", 0) / 100
            if pool_usage_percent > self.performance_thresholds["pool_usage_critical"]:
                status = "fail"
                issues.append(f"Critical: Connection pool usage {pool_usage_percent*100:.1f}%")
            elif pool_usage_percent > self.performance_thresholds["pool_usage_warning"]:
                if status == "pass":
                    status = "warn"
                issues.append(f"Warning: Connection pool usage {pool_usage_percent*100:.1f}%")
            
            message = "Performance metrics within normal range"
            if issues:
                message = "; ".join(issues)
            
            return HealthCheck(
                name="Performance Metrics",
                status=status,
                message=message,
                details=metrics
            )
            
        except Exception as e:
            return HealthCheck(
                name="Performance Metrics",
                status="fail",
                message=f"Failed to collect performance metrics: {str(e)}",
                details={"error": str(e)}
            )
    
    async def _check_repository_health(self, session: AsyncSession) -> HealthCheck:
        """Check repository system health.
        
        Args:
            session: Database session
            
        Returns:
            HealthCheck result
        """
        try:
            # Test repository factory and basic operations
            from gibson.db.repositories.factory import get_repository_factory
            
            factory = get_repository_factory()
            
            # Test basic repository operations if we have target model
            try:
                from gibson.db.models.target import Target
                repo = factory.get(Target, session)
                
                # Test basic operations
                count = await repo.count()
                
                return HealthCheck(
                    name="Repository System",
                    status="pass",
                    message=f"Repository system operational (tested with {count} target records)",
                    details={
                        "repositories_available": True,
                        "test_count": count,
                        "model_tested": "Target"
                    }
                )
                
            except ImportError:
                return HealthCheck(
                    name="Repository System",
                    status="warn",
                    message="Repository system available but target models not found",
                    details={
                        "repositories_available": True,
                        "models_available": False
                    }
                )
                
        except Exception as e:
            return HealthCheck(
                name="Repository System",
                status="fail",
                message=f"Repository system check failed: {str(e)}",
                details={"error": str(e)}
            )


# Convenience function for enhanced health checks
async def check_enhanced_health(
    session: AsyncSession,
    engine=None,
    database_path: Optional[Path] = None
) -> EnhancedHealthReport:
    """Run enhanced health checks.
    
    Args:
        session: Database session
        engine: Optional SQLAlchemy engine
        database_path: Optional database path
        
    Returns:
        Enhanced health report
    """
    checker = EnhancedDatabaseHealthChecker(database_path)
    return await checker.check_enhanced_health(session, engine)