"""Migration manager for handling database migrations with Alembic."""

import asyncio
import logging
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from gibson.db.manager import DatabaseManager
from gibson.models.base import GibsonBaseModel


logger = logging.getLogger(__name__)


class MigrationInfo(GibsonBaseModel):
    """Information about a migration."""

    revision: str
    description: Optional[str] = None
    branch_labels: Optional[List[str]] = None
    down_revision: Optional[str] = None
    create_date: Optional[datetime] = None
    is_head: bool = False
    is_current: bool = False


class MigrationStatus(GibsonBaseModel):
    """Status of the migration system."""

    current_revision: Optional[str] = None
    head_revision: Optional[str] = None
    pending_migrations: List[MigrationInfo] = []
    applied_migrations: List[MigrationInfo] = []
    is_up_to_date: bool = False
    needs_migration: bool = False


class MigrationManager:
    """Manages database migrations using Alembic."""

    def __init__(self, database_manager: Optional[DatabaseManager] = None):
        """Initialize the migration manager.
        
        Args:
            database_manager: Optional database manager instance
        """
        self.db_manager = database_manager
        # Correctly find project root (gibson-framework directory)
        current = Path(__file__).parent  # gibson/core/migrations
        self.project_root = current.parent.parent.parent  # go up to gibson-framework
        self.alembic_ini = self.project_root / "alembic.ini"
        self.alembic_dir = self.project_root / "alembic"
        self._config: Optional[Config] = None
        self._engine: Optional[AsyncEngine] = None

    @property
    def config(self) -> Config:
        """Get Alembic configuration."""
        if self._config is None:
            self._config = Config(str(self.alembic_ini))
            # Set script location explicitly
            self._config.set_main_option("script_location", str(self.alembic_dir))
            # Set database URL from environment or use default
            db_url = os.getenv("GIBSON_DATABASE_URL", "sqlite+aiosqlite:///./gibson.db")
            self._config.set_main_option("sqlalchemy.url", db_url)
        return self._config

    async def get_engine(self) -> AsyncEngine:
        """Get async SQLAlchemy engine."""
        if self._engine is None:
            db_url = os.getenv("GIBSON_DATABASE_URL", "sqlite+aiosqlite:///./gibson.db")
            self._engine = create_async_engine(db_url)
        return self._engine

    async def init(self) -> None:
        """Initialize the migration system."""
        logger.info("Initializing migration system")
        
        # Ensure alembic directory exists
        if not self.alembic_dir.exists():
            logger.info("Creating alembic directory structure")
            command.init(self.config, str(self.alembic_dir))

    async def create_migration(
        self,
        message: str,
        autogenerate: bool = True,
        sql: bool = False
    ) -> str:
        """Create a new migration.
        
        Args:
            message: Migration message
            autogenerate: Whether to autogenerate based on model changes
            sql: Whether to generate SQL script
            
        Returns:
            Revision ID of the created migration
        """
        logger.info(f"Creating migration: {message}")
        
        # Run in subprocess to avoid event loop issues
        cmd = ["alembic", "revision", "-m", message]
        if autogenerate:
            cmd.append("--autogenerate")
        if sql:
            cmd.append("--sql")
            
        result = subprocess.run(
            cmd,
            cwd=str(self.project_root),
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Failed to create migration: {result.stderr}")
            
        # Extract revision ID from output
        for line in result.stdout.split('\n'):
            if "Generating" in line and ".py" in line:
                # Extract revision from filename
                import re
                match = re.search(r'([a-f0-9]+)_.*\.py', line)
                if match:
                    return match.group(1)
                    
        return "unknown"

    async def upgrade(
        self,
        revision: str = "head",
        sql: bool = False,
        tag: Optional[str] = None
    ) -> None:
        """Upgrade database to a revision.
        
        Args:
            revision: Target revision (default: head)
            sql: Whether to generate SQL script only
            tag: Optional tag for the revision
        """
        logger.info(f"Upgrading database to revision: {revision}")
        
        # Get current revision before upgrade
        from_revision = await self.get_current_revision()
        
        # Start timing
        start_time = time.time()
        
        cmd = ["alembic", "upgrade", revision]
        if sql:
            cmd.append("--sql")
        if tag:
            cmd.extend(["--tag", tag])
            
        result = subprocess.run(
            cmd,
            cwd=str(self.project_root),
            capture_output=True,
            text=True
        )
        
        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Log audit
        await self._log_migration_audit(
            operation="upgrade",
            from_revision=from_revision,
            to_revision=revision,
            duration_ms=duration_ms,
            status="success" if result.returncode == 0 else "failed",
            error_message=result.stderr if result.returncode != 0 else None,
            sql_executed=result.stdout if sql else None
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Failed to upgrade database: {result.stderr}")
            
        logger.info(f"Database upgraded successfully to {revision}")

    async def downgrade(
        self,
        revision: str = "-1",
        sql: bool = False,
        tag: Optional[str] = None
    ) -> None:
        """Downgrade database to a revision.
        
        Args:
            revision: Target revision (default: -1 for previous)
            sql: Whether to generate SQL script only
            tag: Optional tag for the revision
        """
        logger.info(f"Downgrading database to revision: {revision}")
        
        # Get current revision before downgrade
        from_revision = await self.get_current_revision()
        
        # Start timing
        start_time = time.time()
        
        cmd = ["alembic", "downgrade", revision]
        if sql:
            cmd.append("--sql")
        if tag:
            cmd.extend(["--tag", tag])
            
        result = subprocess.run(
            cmd,
            cwd=str(self.project_root),
            capture_output=True,
            text=True
        )
        
        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Log audit
        await self._log_migration_audit(
            operation="downgrade",
            from_revision=from_revision,
            to_revision=revision,
            duration_ms=duration_ms,
            status="success" if result.returncode == 0 else "failed",
            error_message=result.stderr if result.returncode != 0 else None,
            sql_executed=result.stdout if sql else None
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Failed to downgrade database: {result.stderr}")
            
        logger.info(f"Database downgraded successfully to {revision}")

    async def get_current_revision(self) -> Optional[str]:
        """Get current database revision.
        
        Returns:
            Current revision ID or None if not initialized
        """
        engine = await self.get_engine()
        
        async with engine.connect() as conn:
            def get_revision(sync_conn):
                context = MigrationContext.configure(sync_conn)
                return context.get_current_revision()
            
            current = await conn.run_sync(get_revision)
            
        return current

    async def get_head_revision(self) -> Optional[str]:
        """Get head revision from migration scripts.
        
        Returns:
            Head revision ID or None
        """
        script_dir = ScriptDirectory.from_config(self.config)
        head = script_dir.get_current_head()
        return head

    async def get_pending_migrations(self) -> List[MigrationInfo]:
        """Get list of pending migrations.
        
        Returns:
            List of pending migration information
        """
        current = await self.get_current_revision()
        script_dir = ScriptDirectory.from_config(self.config)
        
        pending = []
        for revision in script_dir.walk_revisions():
            if current is None or revision.revision != current:
                pending.append(
                    MigrationInfo(
                        revision=revision.revision,
                        description=revision.doc,
                        branch_labels=revision.branch_labels,
                        down_revision=revision.down_revision,
                        create_date=datetime.fromtimestamp(
                            revision.module.create_date
                        ) if hasattr(revision.module, 'create_date') else None,
                        is_head=revision.is_head,
                        is_current=revision.revision == current
                    )
                )
                
                if revision.revision == current:
                    break
                    
        return list(reversed(pending))

    async def get_migration_history(self) -> List[MigrationInfo]:
        """Get migration history.
        
        Returns:
            List of applied migrations
        """
        current = await self.get_current_revision()
        script_dir = ScriptDirectory.from_config(self.config)
        
        history = []
        found_current = False
        
        for revision in script_dir.walk_revisions():
            if revision.revision == current:
                found_current = True
                
            if found_current:
                history.append(
                    MigrationInfo(
                        revision=revision.revision,
                        description=revision.doc,
                        branch_labels=revision.branch_labels,
                        down_revision=revision.down_revision,
                        create_date=datetime.fromtimestamp(
                            revision.module.create_date
                        ) if hasattr(revision.module, 'create_date') else None,
                        is_head=revision.is_head,
                        is_current=revision.revision == current
                    )
                )
                
        return history

    async def get_status(self) -> MigrationStatus:
        """Get comprehensive migration status.
        
        Returns:
            Migration status information
        """
        current = await self.get_current_revision()
        head = await self.get_head_revision()
        pending = await self.get_pending_migrations()
        history = await self.get_migration_history()
        
        return MigrationStatus(
            current_revision=current,
            head_revision=head,
            pending_migrations=pending,
            applied_migrations=history,
            is_up_to_date=current == head,
            needs_migration=current != head
        )

    async def check_migration_needed(self) -> bool:
        """Check if migration is needed.
        
        Returns:
            True if migrations are pending
        """
        status = await self.get_status()
        return status.needs_migration

    async def auto_upgrade(self) -> None:
        """Automatically upgrade to latest migration."""
        if await self.check_migration_needed():
            logger.info("Migrations needed, upgrading to head")
            await self.upgrade()
        else:
            logger.info("Database is up to date")

    async def stamp(self, revision: str = "head") -> None:
        """Stamp database with a revision without running migrations.
        
        Args:
            revision: Revision to stamp
        """
        logger.info(f"Stamping database with revision: {revision}")
        
        cmd = ["alembic", "stamp", revision]
        result = subprocess.run(
            cmd,
            cwd=str(self.project_root),
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Failed to stamp database: {result.stderr}")
            
        logger.info(f"Database stamped with revision {revision}")

    async def verify_migrations(self) -> Tuple[bool, List[str]]:
        """Verify that all migrations can be applied cleanly.
        
        Returns:
            Tuple of (success, list of issues)
        """
        issues = []
        
        try:
            # Check if alembic directory exists
            if not self.alembic_dir.exists():
                issues.append("Alembic directory not found")
                return False, issues
                
            # Check if we can get current revision
            current = await self.get_current_revision()
            logger.info(f"Current revision: {current}")
            
            # Check if we can get head revision
            head = await self.get_head_revision()
            logger.info(f"Head revision: {head}")
            
            # Check pending migrations
            pending = await self.get_pending_migrations()
            if pending:
                logger.info(f"Found {len(pending)} pending migrations")
                
            return True, issues
            
        except Exception as e:
            issues.append(f"Migration verification failed: {str(e)}")
            return False, issues
    
    async def _log_migration_audit(
        self,
        operation: str,
        from_revision: Optional[str] = None,
        to_revision: Optional[str] = None,
        duration_ms: Optional[int] = None,
        status: str = "success",
        error_message: Optional[str] = None,
        backup_id: Optional[str] = None,
        sql_executed: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log migration operation to audit table.
        
        Args:
            operation: Type of operation (upgrade, downgrade, stamp)
            from_revision: Starting revision
            to_revision: Target revision
            duration_ms: Operation duration in milliseconds
            status: Operation status
            error_message: Error message if failed
            backup_id: Associated backup ID
            sql_executed: SQL statements executed
            metadata: Additional metadata
        """
        try:
            engine = await self.get_engine()
            
            # Get user info
            import getpass
            applied_by = getpass.getuser()
            
            # Prepare audit record
            audit_sql = """
                INSERT INTO migration_audit (
                    revision, operation, from_revision, to_revision,
                    applied_at, applied_by, duration_ms, status, error_message,
                    backup_id, sql_executed, audit_metadata
                ) VALUES (
                    :revision, :operation, :from_revision, :to_revision,
                    :applied_at, :applied_by, :duration_ms, :status, :error_message,
                    :backup_id, :sql_executed, :audit_metadata
                )
            """
            
            # Use target revision as the main revision
            revision = to_revision or from_revision or "unknown"
            
            async with engine.connect() as conn:
                await conn.execute(
                    text(audit_sql),
                    {
                        "revision": revision,
                        "operation": operation,
                        "from_revision": from_revision,
                        "to_revision": to_revision,
                        "applied_at": datetime.utcnow(),
                        "applied_by": applied_by,
                        "duration_ms": duration_ms,
                        "status": status,
                        "error_message": error_message,
                        "backup_id": backup_id,
                        "sql_executed": sql_executed[:10000] if sql_executed else None,  # Limit SQL size
                        "audit_metadata": metadata
                    }
                )
                await conn.commit()
                
            logger.info(f"Migration audit logged: {operation} {revision} ({status})")
            
        except Exception as e:
            # Don't fail migration if audit logging fails
            logger.warning(f"Failed to log migration audit: {e}")