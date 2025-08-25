"""Safety utilities for database migrations."""

import logging
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from gibson.models.base import GibsonBaseModel


logger = logging.getLogger(__name__)


class BackupInfo(GibsonBaseModel):
    """Information about a database backup."""

    backup_id: str
    backup_path: Path
    original_path: Path
    created_at: datetime
    size_bytes: int
    migration_revision: Optional[str] = None
    description: Optional[str] = None


class MigrationSafetyCheck(GibsonBaseModel):
    """Result of a migration safety check."""

    check_name: str
    passed: bool
    message: str
    severity: str = "info"  # info, warning, error, critical


class MigrationSafety:
    """Safety utilities for database migrations."""

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize migration safety utilities.

        Args:
            db_path: Path to database file
        """
        self.db_path = db_path or Path("./gibson.db")
        self.backup_dir = Path.home() / ".gibson" / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.max_backups = 10

    def create_backup(
        self, migration_revision: Optional[str] = None, description: Optional[str] = None
    ) -> BackupInfo:
        """Create a database backup before migration.

        Args:
            migration_revision: Associated migration revision
            description: Backup description

        Returns:
            Backup information
        """
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {self.db_path}")

        # Generate backup ID and path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_id = f"backup_{timestamp}"
        if migration_revision:
            backup_id += f"_{migration_revision[:8]}"

        backup_path = self.backup_dir / f"{backup_id}.db"

        # Create backup
        logger.info(f"Creating backup: {backup_path}")
        shutil.copy2(self.db_path, backup_path)

        # Get file size
        size_bytes = backup_path.stat().st_size

        # Clean old backups
        self._cleanup_old_backups()

        backup_info = BackupInfo(
            backup_id=backup_id,
            backup_path=backup_path,
            original_path=self.db_path,
            created_at=datetime.now(),
            size_bytes=size_bytes,
            migration_revision=migration_revision,
            description=description,
        )

        logger.info(f"Backup created successfully: {backup_id} ({size_bytes} bytes)")
        return backup_info

    def restore_backup(self, backup_id: str) -> None:
        """Restore database from backup.

        Args:
            backup_id: Backup identifier
        """
        # Find backup file
        backup_files = list(self.backup_dir.glob(f"{backup_id}*.db"))
        if not backup_files:
            raise FileNotFoundError(f"Backup not found: {backup_id}")

        backup_path = backup_files[0]

        # Create safety copy of current database
        if self.db_path.exists():
            safety_copy = self.db_path.with_suffix(".db.safety")
            shutil.copy2(self.db_path, safety_copy)
            logger.info(f"Created safety copy: {safety_copy}")

        # Restore backup
        logger.info(f"Restoring backup: {backup_path}")
        shutil.copy2(backup_path, self.db_path)
        logger.info(f"Database restored from backup: {backup_id}")

    def list_backups(self) -> List[BackupInfo]:
        """List available backups.

        Returns:
            List of backup information
        """
        backups = []

        for backup_file in sorted(self.backup_dir.glob("backup_*.db"), reverse=True):
            # Parse backup filename
            parts = backup_file.stem.split("_")
            timestamp_str = f"{parts[1]}_{parts[2]}" if len(parts) > 2 else parts[1]

            try:
                created_at = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
            except ValueError:
                created_at = datetime.fromtimestamp(backup_file.stat().st_mtime)

            backups.append(
                BackupInfo(
                    backup_id=backup_file.stem,
                    backup_path=backup_file,
                    original_path=self.db_path,
                    created_at=created_at,
                    size_bytes=backup_file.stat().st_size,
                    migration_revision=parts[3] if len(parts) > 3 else None,
                )
            )

        return backups

    def _cleanup_old_backups(self) -> None:
        """Clean up old backups keeping only max_backups most recent."""
        backups = self.list_backups()

        if len(backups) > self.max_backups:
            # Keep most recent backups
            to_delete = backups[self.max_backups :]

            for backup in to_delete:
                logger.info(f"Removing old backup: {backup.backup_id}")
                backup.backup_path.unlink()

    def run_safety_checks(self) -> Tuple[bool, List[MigrationSafetyCheck]]:
        """Run pre-migration safety checks.

        Returns:
            Tuple of (all passed, list of check results)
        """
        checks = []

        # Check 1: Database exists
        if self.db_path.exists():
            checks.append(
                MigrationSafetyCheck(
                    check_name="database_exists",
                    passed=True,
                    message=f"Database found: {self.db_path}",
                    severity="info",
                )
            )
        else:
            checks.append(
                MigrationSafetyCheck(
                    check_name="database_exists",
                    passed=False,
                    message=f"Database not found: {self.db_path}",
                    severity="warning",
                )
            )

        # Check 2: Database is readable
        if self.db_path.exists():
            try:
                with open(self.db_path, "rb") as f:
                    f.read(1)
                checks.append(
                    MigrationSafetyCheck(
                        check_name="database_readable",
                        passed=True,
                        message="Database is readable",
                        severity="info",
                    )
                )
            except Exception as e:
                checks.append(
                    MigrationSafetyCheck(
                        check_name="database_readable",
                        passed=False,
                        message=f"Cannot read database: {e}",
                        severity="error",
                    )
                )

        # Check 3: Backup directory is writable
        try:
            test_file = self.backup_dir / ".test_write"
            test_file.touch()
            test_file.unlink()
            checks.append(
                MigrationSafetyCheck(
                    check_name="backup_directory_writable",
                    passed=True,
                    message=f"Backup directory is writable: {self.backup_dir}",
                    severity="info",
                )
            )
        except Exception as e:
            checks.append(
                MigrationSafetyCheck(
                    check_name="backup_directory_writable",
                    passed=False,
                    message=f"Cannot write to backup directory: {e}",
                    severity="critical",
                )
            )

        # Check 4: Sufficient disk space (at least 2x database size)
        if self.db_path.exists():
            db_size = self.db_path.stat().st_size
            free_space = shutil.disk_usage(self.backup_dir).free

            if free_space > db_size * 2:
                checks.append(
                    MigrationSafetyCheck(
                        check_name="disk_space",
                        passed=True,
                        message=f"Sufficient disk space: {free_space / 1024 / 1024:.1f} MB free",
                        severity="info",
                    )
                )
            else:
                checks.append(
                    MigrationSafetyCheck(
                        check_name="disk_space",
                        passed=False,
                        message=f"Insufficient disk space: {free_space / 1024 / 1024:.1f} MB free",
                        severity="warning",
                    )
                )

        # Check 5: Alembic is installed
        try:
            result = subprocess.run(["alembic", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                checks.append(
                    MigrationSafetyCheck(
                        check_name="alembic_installed",
                        passed=True,
                        message=f"Alembic is installed: {result.stdout.strip()}",
                        severity="info",
                    )
                )
            else:
                checks.append(
                    MigrationSafetyCheck(
                        check_name="alembic_installed",
                        passed=False,
                        message="Alembic command failed",
                        severity="error",
                    )
                )
        except FileNotFoundError:
            checks.append(
                MigrationSafetyCheck(
                    check_name="alembic_installed",
                    passed=False,
                    message="Alembic is not installed",
                    severity="critical",
                )
            )

        # Check 6: Git status (warn if uncommitted changes)
        try:
            result = subprocess.run(
                ["git", "status", "--porcelain"], capture_output=True, text=True, cwd=Path.cwd()
            )
            if result.returncode == 0:
                if result.stdout.strip():
                    checks.append(
                        MigrationSafetyCheck(
                            check_name="git_status",
                            passed=True,
                            message="Warning: Uncommitted changes in repository",
                            severity="warning",
                        )
                    )
                else:
                    checks.append(
                        MigrationSafetyCheck(
                            check_name="git_status",
                            passed=True,
                            message="Git repository is clean",
                            severity="info",
                        )
                    )
        except Exception:
            # Git not available or not a git repo - not critical
            pass

        # Determine overall status
        all_passed = all(check.passed for check in checks if check.severity != "warning")

        return all_passed, checks

    def validate_migration_script(self, script_path: Path) -> Tuple[bool, List[str]]:
        """Validate a migration script for common issues.

        Args:
            script_path: Path to migration script

        Returns:
            Tuple of (is valid, list of issues)
        """
        issues = []

        if not script_path.exists():
            issues.append(f"Migration script not found: {script_path}")
            return False, issues

        try:
            with open(script_path, "r") as f:
                content = f.read()

            # Check for common issues
            if "DROP TABLE" in content and "IF EXISTS" not in content:
                issues.append("DROP TABLE without IF EXISTS clause detected")

            if "TRUNCATE" in content:
                issues.append("TRUNCATE statement detected - data loss risk")

            if "DELETE FROM" in content and "WHERE" not in content:
                issues.append("DELETE without WHERE clause detected - data loss risk")

            if not "def upgrade():" in content:
                issues.append("Missing upgrade() function")

            if not "def downgrade():" in content:
                issues.append("Missing downgrade() function")

            # Check for syntax errors
            try:
                compile(content, script_path, "exec")
            except SyntaxError as e:
                issues.append(f"Syntax error: {e}")

        except Exception as e:
            issues.append(f"Cannot read migration script: {e}")

        return len(issues) == 0, issues

    def create_rollback_plan(self, from_revision: str, to_revision: str) -> Dict[str, any]:
        """Create a rollback plan for reverting migrations.

        Args:
            from_revision: Current revision
            to_revision: Target revision to rollback to

        Returns:
            Rollback plan details
        """
        plan = {
            "from_revision": from_revision,
            "to_revision": to_revision,
            "steps": [],
            "warnings": [],
            "backup_required": True,
        }

        # Add rollback steps
        plan["steps"].append("1. Create full database backup")
        plan["steps"].append("2. Verify backup integrity")
        plan["steps"].append(f"3. Run: alembic downgrade {to_revision}")
        plan["steps"].append("4. Verify database integrity")
        plan["steps"].append("5. Test application functionality")

        # Add warnings
        if to_revision == "base":
            plan["warnings"].append("Rolling back to base will remove all migrations")

        plan["warnings"].append("Data added after target revision may be lost")
        plan["warnings"].append("Ensure all team members are aware of rollback")

        return plan
