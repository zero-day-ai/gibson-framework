"""
Version registry for tracking schema versions and migration history.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from loguru import logger

from gibson.core.schema_sync.models import SchemaVersion, MigrationHistory, MigrationStatus


class VersionRegistry:
    """Manages schema version tracking and migration history."""
    
    def __init__(self, registry_path: Optional[Path] = None):
        """
        Initialize the version registry.
        
        Args:
            registry_path: Path to store version registry data
        """
        self.registry_path = registry_path or Path(".schema_versions")
        self.registry_path.mkdir(parents=True, exist_ok=True)
        
        self.versions_file = self.registry_path / "versions.json"
        self.history_file = self.registry_path / "migration_history.json"
        
        self._load_registry()
    
    def register_version(
        self,
        version: str,
        schemas: Dict[str, Any],
        hash: str,
        model_name: str = "PayloadModel"
    ) -> None:
        """
        Register a new schema version.
        
        Args:
            version: Version string
            schemas: Schema bundle data
            hash: Schema hash
            model_name: Name of the model
        """
        logger.info(f"Registering schema version {version} with hash {hash[:8]}")
        
        schema_version = SchemaVersion(
            version=version,
            hash=hash,
            timestamp=datetime.utcnow(),
            model_name=model_name,
            applied=False
        )
        
        # Add to versions list
        self.versions.append(schema_version.model_dump())
        self._save_registry()
        
        logger.debug(f"Registered version {version}")
    
    def get_current_version(self) -> Optional[SchemaVersion]:
        """
        Get the current active schema version.
        
        Returns:
            Current SchemaVersion or None if no versions
        """
        if not self.versions:
            return None
        
        # Find the latest applied version
        applied_versions = [v for v in self.versions if v.get("applied", False)]
        if applied_versions:
            latest = max(applied_versions, key=lambda v: v["timestamp"])
            return SchemaVersion(**latest)
        
        # If no applied versions, return the latest version
        latest = max(self.versions, key=lambda v: v["timestamp"])
        return SchemaVersion(**latest)
    
    def get_migration_history(self) -> List[MigrationHistory]:
        """
        Get migration history.
        
        Returns:
            List of MigrationHistory entries
        """
        return [MigrationHistory(**h) for h in self.history]
    
    def record_migration(
        self,
        migration_id: str,
        version: str,
        status: MigrationStatus,
        execution_time: Optional[float] = None,
        error_message: Optional[str] = None
    ) -> None:
        """
        Record a migration execution.
        
        Args:
            migration_id: Migration revision ID
            version: Schema version
            status: Migration status
            execution_time: Execution time in seconds
            error_message: Error message if failed
        """
        from datetime import timedelta
        
        history_entry = {
            "migration_id": migration_id,
            "version": version,
            "applied_at": datetime.utcnow().isoformat(),
            "execution_time": execution_time or 0,
            "status": status.value if hasattr(status, 'value') else status,
            "error_message": error_message,
            "rolled_back": False,
        }
        
        self.history.append(history_entry)
        
        # Update version as applied if successful
        if status == MigrationStatus.COMPLETED:
            for v in self.versions:
                if v["version"] == version:
                    v["applied"] = True
                    v["applied_at"] = datetime.utcnow().isoformat()
                    v["migration_id"] = migration_id
                    break
        
        self._save_registry()
        logger.info(f"Recorded migration {migration_id} with status {status.value if hasattr(status, 'value') else status}")
    
    def check_version_conflict(self, new_version: str, new_hash: str) -> Optional[str]:
        """
        Check for version conflicts.
        
        Args:
            new_version: Proposed new version
            new_hash: Hash of new schema
            
        Returns:
            Conflict description if conflict exists, None otherwise
        """
        # Check if version already exists with different hash
        for v in self.versions:
            if v["version"] == new_version and v["hash"] != new_hash:
                return f"Version {new_version} already exists with different schema"
        
        # Check if hash exists with different version
        for v in self.versions:
            if v["hash"] == new_hash and v["version"] != new_version:
                return f"Schema hash already exists as version {v['version']}"
        
        return None
    
    def _load_registry(self) -> None:
        """Load registry data from files."""
        # Load versions
        if self.versions_file.exists():
            with open(self.versions_file, "r") as f:
                self.versions = json.load(f)
        else:
            self.versions = []
        
        # Load history
        if self.history_file.exists():
            with open(self.history_file, "r") as f:
                self.history = json.load(f)
        else:
            self.history = []
    
    def _save_registry(self) -> None:
        """Save registry data to files."""
        # Save versions
        with open(self.versions_file, "w") as f:
            json.dump(self.versions, f, indent=2, default=str)
        
        # Save history
        with open(self.history_file, "w") as f:
            json.dump(self.history, f, indent=2, default=str)
    
    def get_pending_migrations(self) -> List[str]:
        """
        Get list of pending migration versions.
        
        Returns:
            List of version strings that haven't been applied
        """
        pending = []
        for v in self.versions:
            if not v.get("applied", False):
                pending.append(v["version"])
        return pending
    
    def rollback_migration(self, migration_id: str) -> bool:
        """
        Mark a migration as rolled back.
        
        Args:
            migration_id: Migration to rollback
            
        Returns:
            True if rollback recorded successfully
        """
        for h in self.history:
            if h["migration_id"] == migration_id:
                h["rolled_back"] = True
                h["rolled_back_at"] = datetime.utcnow().isoformat()
                
                # Mark version as not applied
                version = h["version"]
                for v in self.versions:
                    if v["version"] == version:
                        v["applied"] = False
                        v["applied_at"] = None
                        break
                
                self._save_registry()
                logger.info(f"Rolled back migration {migration_id}")
                return True
        
        logger.warning(f"Migration {migration_id} not found in history")
        return False