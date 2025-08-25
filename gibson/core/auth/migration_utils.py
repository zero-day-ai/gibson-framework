"""Database migration utilities for authentication system.

Provides utilities for managing database schema migrations,
data migrations, and backup/restore operations for the authentication subsystem.
"""

import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from loguru import logger
from sqlalchemy import MetaData, create_engine, inspect, text
from sqlalchemy.engine import Engine

from gibson.core.auth.audit_logger import AuditEventType, get_audit_logger
from gibson.core.auth.config import AuthenticationConfig
from gibson.core.auth.crypto import CredentialEncryption


class MigrationError(Exception):
    """Migration-related errors."""
    pass


class MigrationScript:
    """Represents a database migration script."""
    
    def __init__(
        self,
        version: str,
        description: str,
        up_sql: str,
        down_sql: str,
        dependencies: Optional[List[str]] = None
    ):
        """Initialize migration script.
        
        Args:
            version: Migration version (e.g., "001", "002")
            description: Human-readable description
            up_sql: SQL for applying migration
            down_sql: SQL for reverting migration
            dependencies: List of required migration versions
        """
        self.version = version
        self.description = description
        self.up_sql = up_sql
        self.down_sql = down_sql
        self.dependencies = dependencies or []
        self.created_at = datetime.now(timezone.utc)


class MigrationManager:
    """Manages database migrations for authentication system."""
    
    def __init__(
        self,
        config: Optional[AuthenticationConfig] = None,
        migration_dir: Optional[Path] = None
    ):
        """Initialize migration manager.
        
        Args:
            config: Authentication configuration
            migration_dir: Directory containing migration scripts
        """
        self.config = config or AuthenticationConfig()
        self.migration_dir = migration_dir or Path("gibson/migrations")
        self.migration_dir.mkdir(parents=True, exist_ok=True)
        
        # Database connection
        self.engine: Optional[Engine] = None
        
        # Migration tracking
        self.applied_migrations: List[str] = []
        self.available_migrations: Dict[str, MigrationScript] = {}
        
        # Load migrations
        self._load_migrations()
    
    def _get_engine(self) -> Engine:
        """Get database engine."""
        if self.engine is None:
            # Use configuration database URL or default to SQLite
            db_url = getattr(self.config, 'database_url', 'sqlite:///gibson_auth.db')
            self.engine = create_engine(db_url)
        return self.engine
    
    def _load_migrations(self) -> None:
        """Load migration scripts from directory."""
        self.available_migrations.clear()
        
        # Load from files
        for migration_file in sorted(self.migration_dir.glob("*.py")):
            try:
                migration = self._load_migration_file(migration_file)
                if migration:
                    self.available_migrations[migration.version] = migration
            except Exception as e:
                logger.error(f"Failed to load migration {migration_file}: {e}")
        
        # Add built-in migrations
        self._add_builtin_migrations()
    
    def _load_migration_file(self, file_path: Path) -> Optional[MigrationScript]:
        """Load migration from Python file."""
        # This is a simplified implementation
        # In practice, would use proper Python module loading
        content = file_path.read_text()
        
        # Extract metadata (simplified parsing)
        lines = content.split('\n')
        version = None
        description = ""
        
        for line in lines:
            if line.startswith('# Version:'):
                version = line.split(':', 1)[1].strip()
            elif line.startswith('# Description:'):
                description = line.split(':', 1)[1].strip()
        
        if version:
            return MigrationScript(
                version=version,
                description=description,
                up_sql="",  # Would extract from file
                down_sql=""  # Would extract from file
            )
        
        return None
    
    def _add_builtin_migrations(self) -> None:
        """Add built-in migrations."""
        
        # Initial migration - create migration tracking table
        migration_001 = MigrationScript(
            version="001",
            description="Create migration tracking table",
            up_sql="""
                CREATE TABLE IF NOT EXISTS auth_migrations (
                    version VARCHAR(20) PRIMARY KEY,
                    description TEXT,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    checksum VARCHAR(64)
                );
            """,
            down_sql="DROP TABLE IF EXISTS auth_migrations;"
        )
        self.available_migrations["001"] = migration_001
        
        # Encrypted credentials table migration
        migration_002 = MigrationScript(
            version="002", 
            description="Create encrypted credentials table",
            up_sql="""
                CREATE TABLE IF NOT EXISTS encrypted_credentials (
                    id VARCHAR(36) PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    target_id VARCHAR(36) NOT NULL,
                    encrypted_data TEXT NOT NULL,
                    encryption_key_id VARCHAR(64) NOT NULL,
                    encryption_algorithm VARCHAR(32) DEFAULT 'AES-256-GCM',
                    credential_type VARCHAR(32) DEFAULT 'api_key',
                    key_format VARCHAR(32) NOT NULL,
                    masked_preview VARCHAR(16),
                    validation_status VARCHAR(16) DEFAULT 'pending',
                    last_validated_at TIMESTAMP,
                    validation_error TEXT,
                    last_used_at TIMESTAMP,
                    usage_count INTEGER DEFAULT 0,
                    provider_name VARCHAR(32),
                    validation_endpoint VARCHAR(512),
                    rate_limit_info TEXT,
                    environment VARCHAR(32),
                    environment_variable VARCHAR(128),
                    vault_path VARCHAR(256),
                    created_by VARCHAR(100) NOT NULL,
                    access_log TEXT DEFAULT '[]',
                    rotation_history TEXT DEFAULT '[]'
                );
                
                CREATE INDEX IF NOT EXISTS idx_credentials_target_id 
                    ON encrypted_credentials(target_id);
                CREATE INDEX IF NOT EXISTS idx_credentials_encryption_key 
                    ON encrypted_credentials(encryption_key_id);
                CREATE INDEX IF NOT EXISTS idx_credentials_provider 
                    ON encrypted_credentials(provider_name);
                CREATE INDEX IF NOT EXISTS idx_credentials_status 
                    ON encrypted_credentials(validation_status);
            """,
            down_sql="""
                DROP INDEX IF EXISTS idx_credentials_status;
                DROP INDEX IF EXISTS idx_credentials_provider;
                DROP INDEX IF EXISTS idx_credentials_encryption_key;
                DROP INDEX IF EXISTS idx_credentials_target_id;
                DROP TABLE IF EXISTS encrypted_credentials;
            """,
            dependencies=["001"]
        )
        self.available_migrations["002"] = migration_002
    
    def get_applied_migrations(self) -> List[str]:
        """Get list of applied migration versions."""
        try:
            engine = self._get_engine()
            
            # Check if migration table exists
            inspector = inspect(engine)
            if 'auth_migrations' not in inspector.get_table_names():
                return []
            
            with engine.connect() as conn:
                result = conn.execute(text("SELECT version FROM auth_migrations ORDER BY version"))
                return [row[0] for row in result.fetchall()]
        
        except Exception as e:
            logger.error(f"Failed to get applied migrations: {e}")
            return []
    
    def get_pending_migrations(self) -> List[MigrationScript]:
        """Get list of pending migrations in dependency order."""
        applied = set(self.get_applied_migrations())
        pending = []
        
        # Build dependency graph and sort
        sorted_versions = self._sort_migrations_by_dependencies()
        
        for version in sorted_versions:
            if version not in applied and version in self.available_migrations:
                pending.append(self.available_migrations[version])
        
        return pending
    
    def _sort_migrations_by_dependencies(self) -> List[str]:
        """Sort migrations by dependencies using topological sort."""
        # Simple topological sort
        visited = set()
        temp_mark = set()
        result = []
        
        def visit(version: str):
            if version in temp_mark:
                raise MigrationError(f"Circular dependency detected involving {version}")
            
            if version not in visited:
                temp_mark.add(version)
                
                migration = self.available_migrations.get(version)
                if migration:
                    for dep in migration.dependencies:
                        if dep in self.available_migrations:
                            visit(dep)
                
                temp_mark.remove(version)
                visited.add(version)
                result.append(version)
        
        for version in self.available_migrations.keys():
            if version not in visited:
                visit(version)
        
        return result
    
    def apply_migration(self, migration: MigrationScript) -> bool:
        """Apply a single migration.
        
        Args:
            migration: Migration to apply
            
        Returns:
            True if successful
        """
        try:
            logger.info(f"Applying migration {migration.version}: {migration.description}")
            
            engine = self._get_engine()
            
            with engine.begin() as conn:
                # Execute migration SQL
                if migration.up_sql.strip():
                    for statement in migration.up_sql.split(';'):
                        statement = statement.strip()
                        if statement:
                            conn.execute(text(statement))
                
                # Record migration as applied
                conn.execute(text("""
                    INSERT OR REPLACE INTO auth_migrations (version, description, applied_at)
                    VALUES (:version, :description, :applied_at)
                """), {
                    'version': migration.version,
                    'description': migration.description,
                    'applied_at': datetime.now(timezone.utc)
                })
            
            # Audit log
            audit_logger = get_audit_logger()
            audit_logger.log_event({
                'event_type': AuditEventType.SYSTEM_STARTED,  # Reuse for migrations
                'action': 'apply_migration',
                'description': f"Applied migration {migration.version}: {migration.description}",
                'details': {
                    'migration_version': migration.version,
                    'migration_description': migration.description
                }
            })
            
            logger.info(f"Successfully applied migration {migration.version}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to apply migration {migration.version}: {e}")
            raise MigrationError(f"Migration {migration.version} failed: {e}")
    
    def revert_migration(self, migration: MigrationScript) -> bool:
        """Revert a single migration.
        
        Args:
            migration: Migration to revert
            
        Returns:
            True if successful
        """
        try:
            logger.info(f"Reverting migration {migration.version}: {migration.description}")
            
            engine = self._get_engine()
            
            with engine.begin() as conn:
                # Execute rollback SQL
                if migration.down_sql.strip():
                    for statement in migration.down_sql.split(';'):
                        statement = statement.strip()
                        if statement:
                            conn.execute(text(statement))
                
                # Remove migration record
                conn.execute(text("""
                    DELETE FROM auth_migrations WHERE version = :version
                """), {'version': migration.version})
            
            # Audit log
            audit_logger = get_audit_logger()
            audit_logger.log_event({
                'event_type': AuditEventType.SYSTEM_STARTED,  # Reuse for migrations
                'action': 'revert_migration',
                'description': f"Reverted migration {migration.version}: {migration.description}",
                'details': {
                    'migration_version': migration.version,
                    'migration_description': migration.description
                }
            })
            
            logger.info(f"Successfully reverted migration {migration.version}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to revert migration {migration.version}: {e}")
            raise MigrationError(f"Migration revert {migration.version} failed: {e}")
    
    def migrate_up(self, target_version: Optional[str] = None) -> int:
        """Apply pending migrations up to target version.
        
        Args:
            target_version: Target migration version (None for latest)
            
        Returns:
            Number of migrations applied
        """
        pending = self.get_pending_migrations()
        applied_count = 0
        
        for migration in pending:
            if target_version and migration.version > target_version:
                break
            
            self.apply_migration(migration)
            applied_count += 1
        
        logger.info(f"Applied {applied_count} migrations")
        return applied_count
    
    def migrate_down(self, target_version: str) -> int:
        """Revert migrations down to target version.
        
        Args:
            target_version: Target migration version
            
        Returns:
            Number of migrations reverted
        """
        applied = self.get_applied_migrations()
        reverted_count = 0
        
        # Revert in reverse order
        for version in reversed(applied):
            if version <= target_version:
                break
            
            if version in self.available_migrations:
                migration = self.available_migrations[version]
                self.revert_migration(migration)
                reverted_count += 1
        
        logger.info(f"Reverted {reverted_count} migrations")
        return reverted_count
    
    def get_migration_status(self) -> Dict[str, Any]:
        """Get migration status summary."""
        applied = self.get_applied_migrations()
        pending = self.get_pending_migrations()
        
        return {
            'applied_count': len(applied),
            'pending_count': len(pending),
            'latest_applied': applied[-1] if applied else None,
            'next_pending': pending[0].version if pending else None,
            'applied_migrations': applied,
            'pending_migrations': [m.version for m in pending]
        }


class BackupManager:
    """Manages backup and restore operations for authentication data."""
    
    def __init__(
        self,
        config: Optional[AuthenticationConfig] = None,
        backup_dir: Optional[Path] = None
    ):
        """Initialize backup manager.
        
        Args:
            config: Authentication configuration
            backup_dir: Directory for backup files
        """
        self.config = config or AuthenticationConfig()
        self.backup_dir = backup_dir or Path("gibson/backups")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        self.encryption = CredentialEncryption()
    
    def create_backup(
        self,
        backup_name: Optional[str] = None,
        include_credentials: bool = True,
        encrypt_backup: bool = True
    ) -> Path:
        """Create a backup of authentication data.
        
        Args:
            backup_name: Custom backup name
            include_credentials: Whether to include credential data
            encrypt_backup: Whether to encrypt the backup
            
        Returns:
            Path to created backup file
        """
        if not backup_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"gibson_auth_backup_{timestamp}"
        
        backup_file = self.backup_dir / f"{backup_name}.json"
        
        try:
            # Collect data
            backup_data = {
                'backup_id': str(uuid4()),
                'created_at': datetime.now(timezone.utc).isoformat(),
                'gibson_version': '1.0.0',  # Would get from package
                'include_credentials': include_credentials,
                'encrypted': encrypt_backup,
                'schema': self._export_schema(),
                'data': {}
            }
            
            if include_credentials:
                backup_data['data']['credentials'] = self._export_credentials()
            
            backup_data['data']['migrations'] = self._export_migrations()
            backup_data['data']['audit_summary'] = self._export_audit_summary()
            
            # Encrypt if requested
            if encrypt_backup:
                backup_content = json.dumps(backup_data)
                encrypted_content = self.encryption.encrypt_data(backup_content)
                backup_data = {
                    'encrypted': True,
                    'algorithm': 'AES-256-GCM',
                    'data': encrypted_content
                }
            
            # Write backup file
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2, default=str)
            
            # Audit log
            audit_logger = get_audit_logger()
            audit_logger.log_event({
                'event_type': AuditEventType.BACKUP_CREATED,
                'action': 'create_backup',
                'description': f"Created backup: {backup_name}",
                'details': {
                    'backup_file': str(backup_file),
                    'include_credentials': include_credentials,
                    'encrypted': encrypt_backup
                }
            })
            
            logger.info(f"Created backup: {backup_file}")
            return backup_file
        
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            raise MigrationError(f"Backup creation failed: {e}")
    
    def restore_backup(
        self,
        backup_file: Path,
        restore_credentials: bool = True,
        restore_migrations: bool = True
    ) -> bool:
        """Restore from backup file.
        
        Args:
            backup_file: Path to backup file
            restore_credentials: Whether to restore credentials
            restore_migrations: Whether to restore migration state
            
        Returns:
            True if successful
        """
        try:
            if not backup_file.exists():
                raise MigrationError(f"Backup file not found: {backup_file}")
            
            # Load backup data
            with open(backup_file, 'r') as f:
                backup_data = json.load(f)
            
            # Decrypt if needed
            if backup_data.get('encrypted', False):
                if 'data' in backup_data and isinstance(backup_data['data'], str):
                    decrypted_content = self.encryption.decrypt_data(backup_data['data'])
                    backup_data = json.loads(decrypted_content)
            
            # Validate backup
            if 'backup_id' not in backup_data:
                raise MigrationError("Invalid backup file format")
            
            # Restore data
            if restore_credentials and 'credentials' in backup_data.get('data', {}):
                self._restore_credentials(backup_data['data']['credentials'])
            
            if restore_migrations and 'migrations' in backup_data.get('data', {}):
                self._restore_migrations(backup_data['data']['migrations'])
            
            # Audit log
            audit_logger = get_audit_logger()
            audit_logger.log_event({
                'event_type': AuditEventType.BACKUP_RESTORED,
                'action': 'restore_backup',
                'description': f"Restored backup: {backup_file.name}",
                'details': {
                    'backup_file': str(backup_file),
                    'backup_id': backup_data.get('backup_id'),
                    'restore_credentials': restore_credentials,
                    'restore_migrations': restore_migrations
                }
            })
            
            logger.info(f"Successfully restored backup: {backup_file}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to restore backup: {e}")
            raise MigrationError(f"Backup restore failed: {e}")
    
    def _export_schema(self) -> Dict[str, Any]:
        """Export database schema information."""
        # Would export table schemas, indexes, etc.
        return {
            'tables': ['encrypted_credentials', 'auth_migrations'],
            'version': '1.0'
        }
    
    def _export_credentials(self) -> List[Dict[str, Any]]:
        """Export credential data."""
        # Would export credential records
        return []
    
    def _export_migrations(self) -> List[Dict[str, Any]]:
        """Export migration state."""
        # Would export applied migrations
        return []
    
    def _export_audit_summary(self) -> Dict[str, Any]:
        """Export audit log summary."""
        return {
            'total_events': 0,
            'last_event': None
        }
    
    def _restore_credentials(self, credentials_data: List[Dict[str, Any]]) -> None:
        """Restore credential data."""
        logger.info(f"Restoring {len(credentials_data)} credentials")
        # Would restore credential records
    
    def _restore_migrations(self, migrations_data: List[Dict[str, Any]]) -> None:
        """Restore migration state."""
        logger.info(f"Restoring {len(migrations_data)} migration records")
        # Would restore migration state
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backup files."""
        backups = []
        
        for backup_file in self.backup_dir.glob("*.json"):
            try:
                with open(backup_file, 'r') as f:
                    # Read just the metadata
                    content = f.read(1000)  # First 1KB
                    if content.startswith('{'):
                        data = json.loads(content.split('\n')[0] + '}')  # Simplified
                        
                        backups.append({
                            'name': backup_file.stem,
                            'file': str(backup_file),
                            'size': backup_file.stat().st_size,
                            'created_at': data.get('created_at'),
                            'encrypted': data.get('encrypted', False),
                            'include_credentials': data.get('include_credentials', False)
                        })
            except Exception as e:
                logger.warning(f"Failed to read backup metadata for {backup_file}: {e}")
        
        return sorted(backups, key=lambda x: x['created_at'], reverse=True)
    
    def delete_backup(self, backup_name: str) -> bool:
        """Delete a backup file.
        
        Args:
            backup_name: Name of backup to delete
            
        Returns:
            True if successful
        """
        backup_file = self.backup_dir / f"{backup_name}.json"
        
        if backup_file.exists():
            backup_file.unlink()
            logger.info(f"Deleted backup: {backup_name}")
            return True
        else:
            logger.warning(f"Backup not found: {backup_name}")
            return False


# Utility functions

def get_migration_manager() -> MigrationManager:
    """Get migration manager instance."""
    return MigrationManager()


def get_backup_manager() -> BackupManager:
    """Get backup manager instance."""
    return BackupManager()


def ensure_migrations_applied() -> int:
    """Ensure all migrations are applied.
    
    Returns:
        Number of migrations applied
    """
    manager = get_migration_manager()
    return manager.migrate_up()


def create_auth_backup(backup_name: Optional[str] = None) -> Path:
    """Create authentication data backup.
    
    Args:
        backup_name: Optional backup name
        
    Returns:
        Path to backup file
    """
    manager = get_backup_manager()
    return manager.create_backup(backup_name)