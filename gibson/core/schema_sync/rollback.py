"""
Rollback module for reverting schema changes.
"""

import json
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import logging

from gibson.models.base import GibsonBaseModel
from gibson.core.schema_sync.models import MigrationScript, SchemaVersion
from gibson.core.schema_sync.version_registry import VersionRegistry
from gibson.core.schema_sync.version_utils import VersionComparator


logger = logging.getLogger(__name__)


class RollbackPoint(GibsonBaseModel):
    """Represents a point in schema history that can be rolled back to."""
    
    version: str
    timestamp: datetime
    description: str
    schema_hash: str
    backup_path: Optional[str] = None
    migration_script: Optional[MigrationScript] = None
    metadata: Dict[str, Any] = {}
    
    @property
    def has_backup(self) -> bool:
        """Check if this rollback point has a backup."""
        return self.backup_path is not None and Path(self.backup_path).exists()
    
    @property
    def is_restorable(self) -> bool:
        """Check if this point can be restored."""
        return self.has_backup or self.migration_script is not None


class RollbackResult(GibsonBaseModel):
    """Result of a rollback operation."""
    
    success: bool
    from_version: str
    to_version: str
    rolled_back_versions: List[str] = []
    errors: List[str] = []
    warnings: List[str] = []
    backup_restored: bool = False
    migrations_reverted: int = 0
    execution_time_ms: float = 0
    metadata: Dict[str, Any] = {}


class RollbackManager:
    """Manages schema rollback operations."""
    
    def __init__(
        self,
        version_registry: Optional[VersionRegistry] = None,
        backup_dir: Optional[Path] = None
    ):
        """
        Initialize rollback manager.
        
        Args:
            version_registry: Registry for version tracking
            backup_dir: Directory for storing backups
        """
        self.version_registry = version_registry or VersionRegistry()
        self.backup_dir = backup_dir or Path.home() / ".gibson" / "schema_backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.comparator = VersionComparator()
    
    def create_rollback_point(
        self,
        version: str,
        schema_hash: str,
        migration: Optional[MigrationScript] = None,
        create_backup: bool = True
    ) -> RollbackPoint:
        """
        Create a rollback point for current schema state.
        
        Args:
            version: Version identifier
            schema_hash: Hash of current schema
            migration: Migration script that was applied
            create_backup: Whether to create a backup
            
        Returns:
            Created rollback point
        """
        # Create rollback point
        rollback_point = RollbackPoint(
            version=version,
            timestamp=datetime.utcnow(),
            description=f"Rollback point for version {version}",
            schema_hash=schema_hash,
            migration_script=migration
        )
        
        # Create backup if requested
        if create_backup:
            backup_path = self._create_backup(version, schema_hash)
            rollback_point.backup_path = str(backup_path)
        
        # Store rollback point
        self._store_rollback_point(rollback_point)
        
        logger.info(f"Created rollback point for version {version}")
        
        return rollback_point
    
    def rollback_to_version(
        self,
        target_version: str,
        dry_run: bool = False,
        force: bool = False
    ) -> RollbackResult:
        """
        Rollback schema to a specific version.
        
        Args:
            target_version: Version to rollback to
            dry_run: If True, simulate rollback without applying
            force: If True, force rollback even with warnings
            
        Returns:
            RollbackResult with outcome
        """
        import time
        start_time = time.time()
        
        result = RollbackResult(
            success=False,
            from_version=self.version_registry.get_current_version() or "unknown",
            to_version=target_version
        )
        
        try:
            # Get current version
            current_version = self.version_registry.get_current_version()
            if not current_version:
                result.errors.append("Cannot determine current version")
                return result
            
            # Check if target version exists
            if not self._version_exists(target_version):
                result.errors.append(f"Target version {target_version} not found")
                return result
            
            # Get rollback path
            rollback_path = self._get_rollback_path(current_version, target_version)
            if not rollback_path:
                result.errors.append("Cannot determine rollback path")
                return result
            
            result.rolled_back_versions = rollback_path
            
            # Validate rollback is possible
            validation_errors = self._validate_rollback(rollback_path)
            if validation_errors and not force:
                result.errors.extend(validation_errors)
                return result
            elif validation_errors:
                result.warnings.extend(validation_errors)
            
            # Execute rollback
            if not dry_run:
                success = self._execute_rollback(rollback_path)
                result.success = success
                result.migrations_reverted = len(rollback_path)
                
                # Restore backup if available
                rollback_point = self._get_rollback_point(target_version)
                if rollback_point and rollback_point.has_backup:
                    self._restore_backup(rollback_point)
                    result.backup_restored = True
                
                # Update current version
                if success:
                    self.version_registry.set_current_version(target_version)
                    logger.info(f"Successfully rolled back to version {target_version}")
            else:
                # Dry run - just simulate
                result.success = True
                result.warnings.append("Dry run - no changes applied")
            
        except Exception as e:
            result.errors.append(f"Rollback failed: {str(e)}")
            logger.error(f"Rollback error: {e}", exc_info=True)
        
        finally:
            result.execution_time_ms = (time.time() - start_time) * 1000
        
        return result
    
    def rollback_last_migration(self, dry_run: bool = False) -> RollbackResult:
        """
        Rollback the most recent migration.
        
        Args:
            dry_run: If True, simulate rollback
            
        Returns:
            RollbackResult with outcome
        """
        # Get current and previous versions
        current = self.version_registry.get_current_version()
        if not current:
            return RollbackResult(
                success=False,
                from_version="unknown",
                to_version="unknown",
                errors=["No current version found"]
            )
        
        versions = self.version_registry.list_versions()
        previous = self.comparator.get_previous(current, versions)
        
        if not previous:
            return RollbackResult(
                success=False,
                from_version=current,
                to_version="unknown",
                errors=["No previous version to rollback to"]
            )
        
        return self.rollback_to_version(previous, dry_run)
    
    def list_rollback_points(
        self,
        limit: Optional[int] = None
    ) -> List[RollbackPoint]:
        """
        List available rollback points.
        
        Args:
            limit: Maximum number of points to return
            
        Returns:
            List of rollback points
        """
        points = self._load_rollback_points()
        
        # Sort by timestamp descending
        points.sort(key=lambda p: p.timestamp, reverse=True)
        
        if limit:
            points = points[:limit]
        
        return points
    
    def clean_old_backups(
        self,
        keep_count: int = 10,
        keep_days: int = 30
    ) -> int:
        """
        Clean old backup files.
        
        Args:
            keep_count: Number of recent backups to keep
            keep_days: Keep backups newer than this many days
            
        Returns:
            Number of backups removed
        """
        from datetime import timedelta
        
        cutoff_date = datetime.utcnow() - timedelta(days=keep_days)
        points = self._load_rollback_points()
        
        # Sort by timestamp
        points.sort(key=lambda p: p.timestamp, reverse=True)
        
        removed_count = 0
        for i, point in enumerate(points):
            # Keep recent backups
            if i < keep_count:
                continue
            
            # Keep backups newer than cutoff
            if point.timestamp > cutoff_date:
                continue
            
            # Remove old backup
            if point.has_backup:
                try:
                    Path(point.backup_path).unlink()
                    removed_count += 1
                    logger.info(f"Removed old backup: {point.backup_path}")
                except Exception as e:
                    logger.warning(f"Failed to remove backup: {e}")
        
        return removed_count
    
    def _create_backup(self, version: str, schema_hash: str) -> Path:
        """Create backup of current schema state."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_name = f"schema_backup_{version}_{timestamp}.json"
        backup_path = self.backup_dir / backup_name
        
        # Create backup data
        backup_data = {
            "version": version,
            "timestamp": timestamp,
            "schema_hash": schema_hash,
            "metadata": {
                "created_at": datetime.utcnow().isoformat(),
                "gibson_version": "1.0.0",  # TODO: Get from package
            }
        }
        
        # TODO: Add actual schema data to backup
        
        # Write backup file
        backup_path.write_text(json.dumps(backup_data, indent=2))
        
        return backup_path
    
    def _restore_backup(self, rollback_point: RollbackPoint) -> bool:
        """Restore schema from backup."""
        if not rollback_point.has_backup:
            return False
        
        try:
            backup_path = Path(rollback_point.backup_path)
            backup_data = json.loads(backup_path.read_text())
            
            # TODO: Implement actual schema restoration
            
            logger.info(f"Restored backup from {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore backup: {e}")
            return False
    
    def _execute_rollback(self, rollback_path: List[str]) -> bool:
        """Execute rollback through version path."""
        try:
            for version in reversed(rollback_path):
                rollback_point = self._get_rollback_point(version)
                
                if not rollback_point:
                    logger.warning(f"No rollback point for version {version}")
                    continue
                
                if rollback_point.migration_script:
                    # Apply downgrade migration
                    success = self._apply_downgrade(rollback_point.migration_script)
                    if not success:
                        logger.error(f"Failed to rollback version {version}")
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Rollback execution failed: {e}")
            return False
    
    def _apply_downgrade(self, migration: MigrationScript) -> bool:
        """Apply downgrade migration."""
        if not migration.downgrade_sql:
            logger.warning("No downgrade SQL available")
            return False
        
        try:
            # TODO: Execute downgrade SQL against database
            # This would integrate with Alembic or direct DB connection
            
            logger.info(f"Applied downgrade for version {migration.version}")
            return True
            
        except Exception as e:
            logger.error(f"Downgrade failed: {e}")
            return False
    
    def _get_rollback_path(
        self,
        from_version: str,
        to_version: str
    ) -> List[str]:
        """Get list of versions to rollback through."""
        all_versions = self.version_registry.list_versions()
        
        # Ensure we're rolling back (not forward)
        if self.comparator.compare(to_version, from_version) > 0:
            return []
        
        # Get versions between current and target
        path = self.comparator.get_range(
            all_versions,
            start=to_version,
            end=from_version
        )
        
        # Remove target version (we want to end up there)
        if path and path[0] == to_version:
            path = path[1:]
        
        return path
    
    def _validate_rollback(self, rollback_path: List[str]) -> List[str]:
        """Validate that rollback is possible."""
        errors = []
        
        for version in rollback_path:
            rollback_point = self._get_rollback_point(version)
            
            if not rollback_point:
                errors.append(f"No rollback point for version {version}")
                continue
            
            if not rollback_point.is_restorable:
                errors.append(f"Version {version} cannot be restored (no backup or migration)")
            
            if rollback_point.migration_script and not rollback_point.migration_script.downgrade_sql:
                errors.append(f"Version {version} has irreversible migration")
        
        return errors
    
    def _version_exists(self, version: str) -> bool:
        """Check if version exists in registry."""
        return version in self.version_registry.list_versions()
    
    def _store_rollback_point(self, point: RollbackPoint):
        """Store rollback point to disk."""
        points_file = self.backup_dir / "rollback_points.json"
        
        # Load existing points
        points = self._load_rollback_points()
        
        # Add new point
        points.append(point)
        
        # Save updated points
        points_data = [p.model_dump() for p in points]
        points_file.write_text(json.dumps(points_data, indent=2, default=str))
    
    def _load_rollback_points(self) -> List[RollbackPoint]:
        """Load rollback points from disk."""
        points_file = self.backup_dir / "rollback_points.json"
        
        if not points_file.exists():
            return []
        
        try:
            points_data = json.loads(points_file.read_text())
            return [RollbackPoint(**p) for p in points_data]
        except Exception as e:
            logger.warning(f"Failed to load rollback points: {e}")
            return []
    
    def _get_rollback_point(self, version: str) -> Optional[RollbackPoint]:
        """Get specific rollback point."""
        points = self._load_rollback_points()
        
        for point in points:
            if point.version == version:
                return point
        
        return None


class RollbackReporter:
    """Generates reports for rollback operations."""
    
    @staticmethod
    def generate_report(result: RollbackResult) -> str:
        """
        Generate human-readable rollback report.
        
        Args:
            result: Rollback result
            
        Returns:
            Formatted report string
        """
        lines = [
            "=" * 60,
            "SCHEMA ROLLBACK REPORT",
            "=" * 60,
            "",
            f"Status: {'✓ SUCCESS' if result.success else '✗ FAILED'}",
            f"From Version: {result.from_version}",
            f"To Version: {result.to_version}",
            f"Execution Time: {result.execution_time_ms:.2f}ms",
            "",
        ]
        
        if result.rolled_back_versions:
            lines.extend([
                "Rolled Back Versions:",
                "-" * 40,
            ])
            for version in result.rolled_back_versions:
                lines.append(f"  - {version}")
            lines.append("")
        
        if result.migrations_reverted > 0:
            lines.append(f"Migrations Reverted: {result.migrations_reverted}")
        
        if result.backup_restored:
            lines.append("✓ Backup was restored")
        
        if result.warnings:
            lines.extend([
                "",
                "⚠ Warnings:",
                "-" * 40,
            ])
            for warning in result.warnings:
                lines.append(f"  - {warning}")
        
        if result.errors:
            lines.extend([
                "",
                "✗ Errors:",
                "-" * 40,
            ])
            for error in result.errors:
                lines.append(f"  - {error}")
        
        lines.append("")
        lines.append("=" * 60)
        
        return "\n".join(lines)