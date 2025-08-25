"""Enhanced migration recovery and safety utilities for Gibson framework."""

import logging
import subprocess
import sqlite3
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any
from datetime import datetime
from dataclasses import dataclass
import shutil

from gibson.db.base import Base
from gibson.db.manager import DatabaseManager
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

logger = logging.getLogger(__name__)


@dataclass
class SafetyCheckResult:
    """Result of migration safety checks."""
    
    is_safe: bool
    issues: List[str]
    warnings: List[str]
    recommendations: List[str]
    backup_required: bool = True
    estimated_time_seconds: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_safe": self.is_safe,
            "issues": self.issues,
            "warnings": self.warnings,
            "recommendations": self.recommendations,
            "backup_required": self.backup_required,
            "estimated_time_seconds": self.estimated_time_seconds
        }


@dataclass 
class MigrationBackup:
    """Information about a database backup."""
    
    backup_path: Path
    original_path: Path
    timestamp: datetime
    size_bytes: int
    migration_version: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "backup_path": str(self.backup_path),
            "original_path": str(self.original_path),
            "timestamp": self.timestamp.isoformat(),
            "size_bytes": self.size_bytes,
            "migration_version": self.migration_version
        }


class MigrationSafetyChecker:
    """Performs safety checks before running migrations."""
    
    def __init__(self, database_path: Path):
        """Initialize safety checker.
        
        Args:
            database_path: Path to database file
        """
        self.database_path = database_path
    
    async def check_migration_safety(
        self,
        session: AsyncSession,
        target_revision: Optional[str] = None
    ) -> SafetyCheckResult:
        """Perform comprehensive migration safety checks.
        
        Args:
            session: Database session
            target_revision: Target migration revision
            
        Returns:
            Safety check result
        """
        result = SafetyCheckResult(
            is_safe=True,
            issues=[],
            warnings=[],
            recommendations=[]
        )
        
        # Check database file permissions
        await self._check_file_permissions(result)
        
        # Check disk space
        await self._check_disk_space(result)
        
        # Check for active connections/locks
        await self._check_active_connections(session, result)
        
        # Check table sizes and estimate migration time
        await self._check_table_sizes(session, result)
        
        # Check for foreign key constraints
        await self._check_foreign_keys(session, result)
        
        # Check for critical data
        await self._check_critical_data(session, result)
        
        return result
    
    async def _check_file_permissions(self, result: SafetyCheckResult):
        """Check database file permissions."""
        try:
            if not self.database_path.exists():
                result.warnings.append("Database file does not exist - will be created")
                return
            
            # Check read/write permissions
            if not self.database_path.is_file():
                result.issues.append(f"Database path is not a file: {self.database_path}")
                result.is_safe = False
                return
            
            # Try to open file for writing
            try:
                with open(self.database_path, 'r+b') as f:
                    pass
            except PermissionError:
                result.issues.append("Insufficient permissions to modify database file")
                result.is_safe = False
            
            # Check parent directory permissions for backup
            parent_dir = self.database_path.parent
            if not parent_dir.exists():
                result.issues.append(f"Parent directory does not exist: {parent_dir}")
                result.is_safe = False
            elif not parent_dir.is_dir():
                result.issues.append(f"Parent path is not a directory: {parent_dir}")
                result.is_safe = False
            else:
                # Check write permissions for backup creation
                test_file = parent_dir / f".gibson_migration_test_{datetime.now().timestamp()}"
                try:
                    test_file.touch()
                    test_file.unlink()
                except (PermissionError, OSError):
                    result.warnings.append("Limited permissions in database directory - backup may fail")
                    
        except Exception as e:
            result.issues.append(f"Failed to check file permissions: {str(e)}")
            result.is_safe = False
    
    async def _check_disk_space(self, result: SafetyCheckResult):
        """Check available disk space."""
        try:
            if not self.database_path.exists():
                return
            
            db_size = self.database_path.stat().st_size
            available_space = shutil.disk_usage(self.database_path.parent).free
            
            # Need at least 2x database size for safe migration (backup + temp files)
            required_space = db_size * 2
            
            if available_space < required_space:
                result.issues.append(
                    f"Insufficient disk space. Need {required_space / 1024 / 1024:.1f}MB, "
                    f"have {available_space / 1024 / 1024:.1f}MB available"
                )
                result.is_safe = False
            elif available_space < db_size * 3:
                result.warnings.append(
                    f"Limited disk space. Have {available_space / 1024 / 1024:.1f}MB available, "
                    f"database is {db_size / 1024 / 1024:.1f}MB"
                )
            
        except Exception as e:
            result.warnings.append(f"Could not check disk space: {str(e)}")
    
    async def _check_active_connections(self, session: AsyncSession, result: SafetyCheckResult):
        """Check for active database connections."""
        try:
            # For SQLite, check if database is locked
            if "sqlite" in str(session.bind.url):
                # Try to get an exclusive lock briefly
                try:
                    await session.execute(text("BEGIN EXCLUSIVE"))
                    await session.execute(text("ROLLBACK"))
                except Exception:
                    result.warnings.append("Database may have active connections - migration could be slower")
            
        except Exception as e:
            result.warnings.append(f"Could not check active connections: {str(e)}")
    
    async def _check_table_sizes(self, session: AsyncSession, result: SafetyCheckResult):
        """Check table sizes and estimate migration time."""
        try:
            total_rows = 0
            large_tables = []
            
            # Get table information
            tables_query = text("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
            """)
            
            tables_result = await session.execute(tables_query)
            table_names = [row[0] for row in tables_result]
            
            for table_name in table_names:
                try:
                    count_query = text(f"SELECT COUNT(*) FROM {table_name}")
                    count_result = await session.execute(count_query)
                    row_count = count_result.scalar()
                    
                    total_rows += row_count
                    
                    if row_count > 100000:  # Large table threshold
                        large_tables.append((table_name, row_count))
                        
                except Exception:
                    # Skip tables we can't count
                    continue
            
            # Estimate migration time (rough: 1000 rows per second)
            if total_rows > 0:
                estimated_seconds = total_rows / 1000
                result.estimated_time_seconds = estimated_seconds
                
                if estimated_seconds > 300:  # 5 minutes
                    result.warnings.append(
                        f"Large dataset detected ({total_rows:,} rows). "
                        f"Migration may take ~{estimated_seconds/60:.1f} minutes"
                    )
                    result.recommendations.append("Consider running migration during low-traffic period")
            
            if large_tables:
                table_info = ", ".join([f"{name} ({count:,} rows)" for name, count in large_tables])
                result.warnings.append(f"Large tables detected: {table_info}")
            
        except Exception as e:
            result.warnings.append(f"Could not analyze table sizes: {str(e)}")
    
    async def _check_foreign_keys(self, session: AsyncSession, result: SafetyCheckResult):
        """Check for foreign key constraints."""
        try:
            # Check if foreign keys are enabled
            fk_check = await session.execute(text("PRAGMA foreign_keys"))
            fk_enabled = fk_check.scalar()
            
            if fk_enabled:
                # Get foreign key information
                fk_query = text("""
                    SELECT m.name as table_name, p.* 
                    FROM sqlite_master m
                    JOIN pragma_foreign_key_list(m.name) p ON m.type = 'table'
                    WHERE m.name NOT LIKE 'sqlite_%'
                """)
                
                fk_result = await session.execute(fk_query)
                foreign_keys = list(fk_result)
                
                if foreign_keys:
                    result.warnings.append(
                        f"Found {len(foreign_keys)} foreign key constraints. "
                        "Migration will need to handle referential integrity"
                    )
                    result.recommendations.append("Verify foreign key constraints after migration")
            
        except Exception as e:
            result.warnings.append(f"Could not check foreign keys: {str(e)}")
    
    async def _check_critical_data(self, session: AsyncSession, result: SafetyCheckResult):
        """Check for critical data that needs special handling."""
        try:
            critical_tables = ['targets', 'scans', 'findings', 'modules']
            
            for table in critical_tables:
                try:
                    count_query = text(f"SELECT COUNT(*) FROM {table}")
                    count_result = await session.execute(count_query)
                    count = count_result.scalar()
                    
                    if count > 0:
                        result.recommendations.append(f"Critical data detected in {table} ({count:,} records)")
                        
                except Exception:
                    # Table might not exist, which is fine
                    continue
            
        except Exception as e:
            result.warnings.append(f"Could not check critical data: {str(e)}")


class MigrationRecovery:
    """Utilities for recovering from migration issues."""
    
    def __init__(self, database_path: Optional[Path] = None):
        """Initialize migration recovery.
        
        Args:
            database_path: Path to database file. Defaults to ./gibson.db
        """
        self.database_path = database_path or Path("./gibson.db")
        self.backup_dir = Path(".gibson_backups")
        self.backup_dir.mkdir(exist_ok=True)
        self.safety_checker = MigrationSafetyChecker(self.database_path)
        
    def reset_migrations(self, backup_first: bool = True) -> bool:
        """Reset migrations to clean state.
        
        WARNING: This will destroy existing database and recreate from scratch.
        
        Args:
            backup_first: Whether to backup database before reset
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Backup if requested
            if backup_first and self.database_path.exists():
                backup_path = self._create_backup("pre-reset")
                logger.info(f"Created backup at: {backup_path}")
                
            # Remove existing database
            if self.database_path.exists():
                self.database_path.unlink()
                logger.info("Removed existing database")
                
            # Remove alembic version history
            result = subprocess.run(
                ["alembic", "stamp", "head"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to stamp head: {result.stderr}")
                return False
                
            # Run migrations fresh
            result = subprocess.run(
                ["alembic", "upgrade", "head"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to upgrade: {result.stderr}")
                return False
                
            logger.info("Migrations reset successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reset migrations: {e}")
            return False
            
    async def repair_missing_tables(self) -> Tuple[bool, List[str]]:
        """Repair missing tables by recreating them.
        
        Returns:
            Tuple of (success, list of repaired tables)
        """
        repaired = []
        
        try:
            # Get database manager
            db_manager = DatabaseManager(f"sqlite:///{self.database_path}")
            
            # Get missing tables
            from gibson.db.utils.schema_validator import SchemaValidator
            validator = SchemaValidator()
            
            async with db_manager.get_session() as session:
                result = await validator.validate_schema(session)
                
                if not result.missing_tables:
                    logger.info("No missing tables to repair")
                    return True, []
                    
                logger.info(f"Found {len(result.missing_tables)} missing tables to repair")
                
                # Try to create missing tables individually
                for table_name in result.missing_tables:
                    if table_name in Base.metadata.tables:
                        table = Base.metadata.tables[table_name]
                        try:
                            async with db_manager.engine.begin() as conn:
                                await conn.run_sync(lambda c: table.create(c, checkfirst=True))
                            repaired.append(table_name)
                            logger.info(f"Repaired table: {table_name}")
                        except Exception as e:
                            logger.error(f"Failed to repair table {table_name}: {e}")
                            
            return len(repaired) == len(result.missing_tables), repaired
            
        except Exception as e:
            logger.error(f"Failed to repair missing tables: {e}")
            return False, repaired
        finally:
            if 'db_manager' in locals():
                await db_manager.close()
                
    def _create_backup(self, suffix: str = "") -> Path:
        """Create database backup.
        
        Args:
            suffix: Optional suffix for backup name
            
        Returns:
            Path to backup file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"gibson_backup_{timestamp}"
        if suffix:
            backup_name += f"_{suffix}"
        backup_name += ".db"
        
        backup_path = self.backup_dir / backup_name
        shutil.copy2(self.database_path, backup_path)
        
        return backup_path
        
    def restore_from_backup(self, backup_path: Path) -> bool:
        """Restore database from backup.
        
        Args:
            backup_path: Path to backup file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False
                
            # Create backup of current database
            if self.database_path.exists():
                self._create_backup("pre-restore")
                
            # Restore from backup
            shutil.copy2(backup_path, self.database_path)
            logger.info(f"Restored database from: {backup_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore from backup: {e}")
            return False
            
    def list_backups(self) -> List[Tuple[Path, float]]:
        """List available backups.
        
        Returns:
            List of (backup_path, size_mb) tuples
        """
        backups = []
        
        if self.backup_dir.exists():
            for backup_file in self.backup_dir.glob("gibson_backup_*.db"):
                size_mb = backup_file.stat().st_size / (1024 * 1024)
                backups.append((backup_file, size_mb))
                
        return sorted(backups, key=lambda x: x[0].stat().st_mtime, reverse=True)
        
    async def verify_and_fix(self) -> bool:
        """Verify database and attempt to fix issues.
        
        Returns:
            True if database is healthy or was fixed, False otherwise
        """
        try:
            # First check if database exists
            if not self.database_path.exists():
                logger.info("Database does not exist, creating new one")
                return await self._create_fresh_database()
                
            # Check for missing tables
            success, repaired = await self.repair_missing_tables()
            
            if not success:
                logger.warning("Could not repair all tables, attempting reset")
                return self.reset_migrations(backup_first=True)
                
            if repaired:
                logger.info(f"Successfully repaired {len(repaired)} tables")
                
            return True
            
        except Exception as e:
            logger.error(f"Failed to verify and fix database: {e}")
            return False
            
    async def _create_fresh_database(self) -> bool:
        """Create a fresh database from scratch.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Run alembic upgrade to create all tables
            result = subprocess.run(
                ["alembic", "upgrade", "head"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                # Fall back to direct table creation
                logger.warning("Alembic failed, creating tables directly")
                db_manager = DatabaseManager(f"sqlite:///{self.database_path}")
                async with db_manager.engine.begin() as conn:
                    await conn.run_sync(Base.metadata.create_all)
                await db_manager.close()
                
            logger.info("Created fresh database successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create fresh database: {e}")
            return False