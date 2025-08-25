"""
Preflight checks module for validating environment before schema changes.
"""

import os
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import logging
import json

from gibson.models.base import GibsonBaseModel


logger = logging.getLogger(__name__)


class PreflightCheck(GibsonBaseModel):
    """Individual preflight check."""
    
    name: str
    description: str
    category: str  # "environment", "database", "dependencies", "permissions"
    severity: str  # "critical", "warning", "info"
    passed: bool = False
    message: Optional[str] = None
    details: Dict[str, Any] = {}
    
    @property
    def is_blocking(self) -> bool:
        """Check if this failure should block migration."""
        return self.severity == "critical" and not self.passed


class PreflightResult(GibsonBaseModel):
    """Result of preflight checks."""
    
    all_passed: bool = False
    checks: List[PreflightCheck] = []
    critical_failures: int = 0
    warnings: int = 0
    execution_time_ms: float = 0
    can_proceed: bool = False
    suggestions: List[str] = []
    
    def add_check(self, check: PreflightCheck):
        """Add a check result."""
        self.checks.append(check)
        
        if not check.passed:
            if check.severity == "critical":
                self.critical_failures += 1
            elif check.severity == "warning":
                self.warnings += 1
        
        # Update overall status
        self.all_passed = all(c.passed for c in self.checks)
        self.can_proceed = self.critical_failures == 0


class PreflightChecker:
    """Performs preflight checks before schema migration."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize preflight checker.
        
        Args:
            config: Optional configuration
        """
        self.config = config or {}
        self.checks_to_run = self._get_default_checks()
    
    def run_checks(
        self,
        skip_categories: Optional[List[str]] = None,
        extra_checks: Optional[List[callable]] = None
    ) -> PreflightResult:
        """
        Run all preflight checks.
        
        Args:
            skip_categories: Categories to skip
            extra_checks: Additional check functions to run
            
        Returns:
            PreflightResult with all check outcomes
        """
        import time
        start_time = time.time()
        
        result = PreflightResult()
        skip_categories = skip_categories or []
        
        # Run default checks
        for check_func in self.checks_to_run:
            check = check_func()
            
            # Skip if category should be skipped
            if check.category in skip_categories:
                continue
            
            result.add_check(check)
        
        # Run extra checks
        if extra_checks:
            for check_func in extra_checks:
                check = check_func()
                result.add_check(check)
        
        # Generate suggestions based on failures
        result.suggestions = self._generate_suggestions(result)
        
        # Set execution time
        result.execution_time_ms = (time.time() - start_time) * 1000
        
        return result
    
    def _get_default_checks(self) -> List[callable]:
        """Get list of default check functions."""
        return [
            self.check_python_version,
            self.check_database_connection,
            self.check_alembic_installed,
            self.check_disk_space,
            self.check_backup_directory,
            self.check_git_status,
            self.check_dependencies,
            self.check_permissions,
            self.check_environment_variables,
            self.check_existing_migrations,
        ]
    
    def check_python_version(self) -> PreflightCheck:
        """Check Python version compatibility."""
        import sys
        
        check = PreflightCheck(
            name="Python Version",
            description="Verify Python version is compatible",
            category="environment",
            severity="critical"
        )
        
        version = sys.version_info
        check.details["version"] = f"{version.major}.{version.minor}.{version.micro}"
        
        if version.major >= 3 and version.minor >= 8:
            check.passed = True
            check.message = f"Python {check.details['version']} is compatible"
        else:
            check.passed = False
            check.message = f"Python {check.details['version']} is too old (requires 3.8+)"
        
        return check
    
    def check_database_connection(self) -> PreflightCheck:
        """Check database connectivity."""
        check = PreflightCheck(
            name="Database Connection",
            description="Verify database is accessible",
            category="database",
            severity="critical"
        )
        
        try:
            # Try to connect to database
            # This is simplified - real implementation would use actual DB config
            import sqlite3
            
            db_path = self.config.get("database_path", "gibson.db")
            if Path(db_path).exists():
                conn = sqlite3.connect(db_path)
                conn.execute("SELECT 1")
                conn.close()
                
                check.passed = True
                check.message = "Database connection successful"
                check.details["database"] = db_path
            else:
                check.passed = True  # New database is OK
                check.message = "Database will be created"
                check.details["database"] = db_path
                
        except Exception as e:
            check.passed = False
            check.message = f"Database connection failed: {str(e)}"
            check.details["error"] = str(e)
        
        return check
    
    def check_alembic_installed(self) -> PreflightCheck:
        """Check if Alembic is installed."""
        check = PreflightCheck(
            name="Alembic Installation",
            description="Verify Alembic migration tool is installed",
            category="dependencies",
            severity="critical"
        )
        
        try:
            import alembic
            check.passed = True
            check.message = f"Alembic {alembic.__version__} is installed"
            check.details["version"] = alembic.__version__
        except ImportError:
            check.passed = False
            check.message = "Alembic is not installed"
            check.details["suggestion"] = "pip install alembic"
        
        return check
    
    def check_disk_space(self) -> PreflightCheck:
        """Check available disk space."""
        check = PreflightCheck(
            name="Disk Space",
            description="Verify sufficient disk space for migrations",
            category="environment",
            severity="warning"
        )
        
        try:
            import shutil
            
            # Get disk usage
            usage = shutil.disk_usage("/")
            free_gb = usage.free / (1024 ** 3)
            total_gb = usage.total / (1024 ** 3)
            percent_free = (usage.free / usage.total) * 100
            
            check.details = {
                "free_gb": round(free_gb, 2),
                "total_gb": round(total_gb, 2),
                "percent_free": round(percent_free, 2)
            }
            
            # Require at least 1GB free or 10% free
            if free_gb >= 1 and percent_free >= 10:
                check.passed = True
                check.message = f"{free_gb:.2f}GB free ({percent_free:.1f}%)"
            else:
                check.passed = False
                check.message = f"Low disk space: {free_gb:.2f}GB free ({percent_free:.1f}%)"
                
        except Exception as e:
            check.passed = True  # Don't block on disk check failure
            check.message = "Could not check disk space"
            check.details["error"] = str(e)
        
        return check
    
    def check_backup_directory(self) -> PreflightCheck:
        """Check backup directory is accessible."""
        check = PreflightCheck(
            name="Backup Directory",
            description="Verify backup directory exists and is writable",
            category="environment",
            severity="warning"
        )
        
        backup_dir = Path(self.config.get(
            "backup_directory",
            Path.home() / ".gibson" / "schema_backups"
        ))
        
        try:
            # Create directory if it doesn't exist
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            # Test write permissions
            test_file = backup_dir / ".write_test"
            test_file.write_text("test")
            test_file.unlink()
            
            check.passed = True
            check.message = f"Backup directory is ready: {backup_dir}"
            check.details["path"] = str(backup_dir)
            
        except Exception as e:
            check.passed = False
            check.message = f"Backup directory not accessible: {str(e)}"
            check.details["path"] = str(backup_dir)
            check.details["error"] = str(e)
        
        return check
    
    def check_git_status(self) -> PreflightCheck:
        """Check Git repository status."""
        check = PreflightCheck(
            name="Git Status",
            description="Check for uncommitted changes",
            category="environment",
            severity="warning"
        )
        
        try:
            # Check if in Git repository
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                uncommitted = result.stdout.strip()
                
                if uncommitted:
                    check.passed = False
                    check.message = "Uncommitted changes detected"
                    check.details["files"] = len(uncommitted.split('\n'))
                else:
                    check.passed = True
                    check.message = "Working directory clean"
            else:
                check.passed = True  # Not a Git repo is OK
                check.message = "Not a Git repository"
                
        except Exception as e:
            check.passed = True  # Don't block if Git not available
            check.message = "Git not available"
            check.details["error"] = str(e)
        
        return check
    
    def check_dependencies(self) -> PreflightCheck:
        """Check required dependencies are installed."""
        check = PreflightCheck(
            name="Dependencies",
            description="Verify required packages are installed",
            category="dependencies",
            severity="critical"
        )
        
        required_packages = [
            "pydantic",
            "sqlalchemy",
            "aiosqlite"
        ]
        
        missing = []
        installed = []
        
        for package in required_packages:
            try:
                __import__(package)
                installed.append(package)
            except ImportError:
                missing.append(package)
        
        check.details = {
            "installed": installed,
            "missing": missing
        }
        
        if not missing:
            check.passed = True
            check.message = f"All {len(installed)} required packages installed"
        else:
            check.passed = False
            check.message = f"Missing packages: {', '.join(missing)}"
        
        return check
    
    def check_permissions(self) -> PreflightCheck:
        """Check file system permissions."""
        check = PreflightCheck(
            name="File Permissions",
            description="Verify write permissions for migrations",
            category="permissions",
            severity="critical"
        )
        
        # Check migrations directory
        migrations_dir = Path(self.config.get(
            "migrations_directory",
            Path.cwd() / "gibson" / "migrations"
        ))
        
        try:
            # Create directory if needed
            migrations_dir.mkdir(parents=True, exist_ok=True)
            
            # Test write permissions
            test_file = migrations_dir / ".permission_test"
            test_file.write_text("test")
            test_file.unlink()
            
            check.passed = True
            check.message = "Write permissions verified"
            check.details["migrations_dir"] = str(migrations_dir)
            
        except Exception as e:
            check.passed = False
            check.message = f"No write permissions: {str(e)}"
            check.details["migrations_dir"] = str(migrations_dir)
            check.details["error"] = str(e)
        
        return check
    
    def check_environment_variables(self) -> PreflightCheck:
        """Check required environment variables."""
        check = PreflightCheck(
            name="Environment Variables",
            description="Verify required environment variables are set",
            category="environment",
            severity="warning"
        )
        
        required_vars = self.config.get("required_env_vars", [])
        missing = []
        present = []
        
        for var in required_vars:
            if os.getenv(var):
                present.append(var)
            else:
                missing.append(var)
        
        check.details = {
            "present": present,
            "missing": missing
        }
        
        if not required_vars:
            check.passed = True
            check.message = "No environment variables required"
        elif not missing:
            check.passed = True
            check.message = f"All {len(present)} required variables set"
        else:
            check.passed = False
            check.message = f"Missing variables: {', '.join(missing)}"
        
        return check
    
    def check_existing_migrations(self) -> PreflightCheck:
        """Check for existing migration conflicts."""
        check = PreflightCheck(
            name="Migration Conflicts",
            description="Check for conflicting migrations",
            category="database",
            severity="warning"
        )
        
        migrations_dir = Path(self.config.get(
            "migrations_directory",
            Path.cwd() / "gibson" / "migrations"
        ))
        
        if not migrations_dir.exists():
            check.passed = True
            check.message = "No existing migrations"
            return check
        
        try:
            # Count migration files
            migration_files = list(migrations_dir.glob("*.py"))
            
            check.details["count"] = len(migration_files)
            
            if migration_files:
                # Check for duplicate version numbers
                versions = []
                for file in migration_files:
                    # Extract version from filename
                    # Format: YYYYMMDD_HHMMSS_description.py
                    parts = file.stem.split('_')
                    if len(parts) >= 2:
                        version = f"{parts[0]}_{parts[1]}"
                        versions.append(version)
                
                duplicates = [v for v in versions if versions.count(v) > 1]
                
                if duplicates:
                    check.passed = False
                    check.message = f"Duplicate migration versions found: {duplicates}"
                    check.details["duplicates"] = duplicates
                else:
                    check.passed = True
                    check.message = f"Found {len(migration_files)} existing migrations"
            else:
                check.passed = True
                check.message = "No migration files found"
                
        except Exception as e:
            check.passed = True  # Don't block on this check
            check.message = "Could not check migrations"
            check.details["error"] = str(e)
        
        return check
    
    def _generate_suggestions(self, result: PreflightResult) -> List[str]:
        """Generate suggestions based on check results."""
        suggestions = []
        
        for check in result.checks:
            if not check.passed:
                if check.name == "Alembic Installation":
                    suggestions.append("Install Alembic: pip install alembic")
                elif check.name == "Dependencies":
                    missing = check.details.get("missing", [])
                    if missing:
                        suggestions.append(f"Install missing packages: pip install {' '.join(missing)}")
                elif check.name == "Git Status":
                    suggestions.append("Commit or stash changes before migration")
                elif check.name == "Disk Space":
                    suggestions.append("Free up disk space before proceeding")
                elif check.name == "Backup Directory":
                    suggestions.append("Ensure backup directory is writable")
                elif check.name == "Environment Variables":
                    missing = check.details.get("missing", [])
                    for var in missing:
                        suggestions.append(f"Set environment variable: export {var}=...")
        
        return suggestions


class PreflightReporter:
    """Generates reports from preflight check results."""
    
    @staticmethod
    def generate_report(result: PreflightResult) -> str:
        """
        Generate human-readable preflight report.
        
        Args:
            result: Preflight result
            
        Returns:
            Formatted report string
        """
        lines = [
            "=" * 60,
            "PREFLIGHT CHECK REPORT",
            "=" * 60,
            "",
            f"Overall Status: {'✓ PASSED' if result.all_passed else '✗ FAILED'}",
            f"Can Proceed: {'Yes' if result.can_proceed else 'No'}",
            f"Execution Time: {result.execution_time_ms:.2f}ms",
            "",
            f"Critical Failures: {result.critical_failures}",
            f"Warnings: {result.warnings}",
            "",
            "Check Results:",
            "-" * 40,
        ]
        
        # Group checks by category
        by_category = {}
        for check in result.checks:
            if check.category not in by_category:
                by_category[check.category] = []
            by_category[check.category].append(check)
        
        # Display checks by category
        for category, checks in sorted(by_category.items()):
            lines.append(f"\n{category.upper()}:")
            
            for check in checks:
                status = "✓" if check.passed else "✗"
                severity_marker = {
                    "critical": "🔴",
                    "warning": "🟡",
                    "info": "🔵"
                }.get(check.severity, "")
                
                lines.append(f"  {status} {check.name} {severity_marker}")
                if check.message:
                    lines.append(f"    {check.message}")
        
        # Add suggestions
        if result.suggestions:
            lines.extend([
                "",
                "Suggestions:",
                "-" * 40,
            ])
            for i, suggestion in enumerate(result.suggestions, 1):
                lines.append(f"  {i}. {suggestion}")
        
        lines.append("")
        lines.append("=" * 60)
        
        return "\n".join(lines)